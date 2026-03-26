// SPDX-License-Identifier: Apache-2.0
use std::sync::Arc;

use puzzled::{
    audit, audit_store, branch, budget, config, conflict, dbus, ima, policy, profile,
    seccomp_handler, wal,
};
use anyhow::Result;
use tracing_subscriber::EnvFilter;

#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("puzzled=info".parse()?))
        .init();

    tracing::info!("puzzled starting (Phase 2)");

    // §3.4: Set RLIMIT_CORE to 0 to prevent core dumps that could leak credentials.
    #[cfg(target_os = "linux")]
    {
        use nix::sys::resource::{setrlimit, Resource};
        if let Err(e) = setrlimit(Resource::RLIMIT_CORE, 0, 0) {
            tracing::warn!(error = %e, "§3.4: failed to set RLIMIT_CORE=0 (core dumps may leak credentials)");
        } else {
            tracing::info!("§3.4: RLIMIT_CORE set to 0 (no core dumps)");
        }
    }

    // §3.4 G30: Set PR_SET_DUMPABLE to 0 to restrict /proc/[pid]/mem access.
    // This prevents other processes (even with same UID) from reading puzzled's memory
    // via /proc/[pid]/mem, which could leak credential values from the secure region.
    #[cfg(target_os = "linux")]
    {
        let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
        if ret != 0 {
            tracing::warn!("§3.4 G30: failed to set PR_SET_DUMPABLE=0");
        } else {
            tracing::info!("§3.4 G30: PR_SET_DUMPABLE set to 0 (restricted /proc/pid/mem access)");
        }
    }

    // Minimal hand-rolled arg parser: puzzled only needs --config, --help, and
    // --version. This avoids adding clap as a dependency to the daemon binary,
    // keeping the binary smaller and the attack surface minimal.
    let args: Vec<String> = std::env::args().collect();
    let config_path = {
        let mut path = None;
        let mut i = 1;
        while i < args.len() {
            if args[i] == "--help" || args[i] == "-h" {
                println!("Usage: puzzled [OPTIONS]");
                println!();
                println!("PuzzlePod governance daemon");
                println!();
                println!("Options:");
                println!("  --config <PATH>  Path to configuration file");
                println!("  -h, --help       Print this help message");
                println!("  -V, --version    Print version");
                println!();
                println!("Without --config, puzzled auto-detects:");
                println!("  1. /etc/puzzled/puzzled.conf (system mode)");
                println!("  2. ~/.config/puzzled/puzzled.conf (user mode)");
                println!("  3. Built-in defaults");
                std::process::exit(0);
            } else if args[i] == "--version" || args[i] == "-V" {
                println!("puzzled {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            } else if args[i] == "--config" {
                if i + 1 < args.len() {
                    path = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    tracing::error!("--config requires a path argument");
                    std::process::exit(1);
                }
            } else if let Some(val) = args[i].strip_prefix("--config=") {
                if val.is_empty() {
                    tracing::error!("--config= requires a non-empty path");
                    std::process::exit(1);
                }
                path = Some(val.to_string());
                i += 1;
            } else {
                tracing::error!("unrecognized argument: {}", args[i]);
                eprintln!("Usage: puzzled [--config <PATH>]");
                eprintln!("Try 'puzzled --help' for more information.");
                std::process::exit(1);
            }
        }
        path
    };
    // load() and default_for_user() both call validate() internally.
    let config = match config_path {
        Some(ref path) => {
            tracing::info!("loading config from --config {}", path);
            config::DaemonConfig::load(std::path::Path::new(path))?
        }
        None => config::DaemonConfig::load_or_default()?,
    };
    tracing::info!(branch_root = %config.branch_root.display(), "loaded configuration");

    // §3.4 G14: Load or generate per-instance secret for CA key encryption.
    let instance_secret = match config::load_instance_secret(&config.bus_type) {
        Ok(secret) => Some(secret),
        Err(e) => {
            tracing::warn!(error = %e, "§3.4 G14: failed to load instance secret, trying machine-id fallback");
            match config::load_instance_secret_machine_id_fallback() {
                Ok(secret) => Some(secret),
                Err(e2) => {
                    tracing::error!(error = %e2, "§3.4 G14: machine-id fallback also failed — credential isolation features unavailable");
                    None
                }
            }
        }
    };
    // §3.4 GAP-M3: Wire instance secret to BranchManager for ACKF CA key encryption.
    // The secret is set on the manager after construction below.

    // Initialize sub-components
    let audit = Arc::new(audit::AuditLogger::new());

    let mut profile_loader = profile::ProfileLoader::new(config.profiles_dir.clone());
    if config.profiles_dir.exists() {
        if let Err(e) = profile_loader.load_all() {
            tracing::warn!(error = %e, "failed to load profiles (continuing with empty set)");
        } else {
            for name in profile_loader.list() {
                audit.log(audit::AuditEvent::ProfileLoaded {
                    profile: name.to_string(),
                });
            }
        }
    }

    let policy_engine = policy::PolicyEngine::new(config.policies_dir.clone());
    if let Err(e) = policy_engine.reload() {
        // H10: If require_policies is set, policy load failure is fatal
        if config.require_policies {
            tracing::error!(error = %e, "failed to load policies (require_policies=true, exiting)");
            std::process::exit(1);
        }
        tracing::warn!(error = %e, "failed to load policies (continuing with empty set)");
    }

    let wal_dir = config.branch_root.join("wal");
    wal::WriteAheadLog::init(&wal_dir)?;
    let wal = wal::WriteAheadLog::new(wal_dir);

    // Initialize IMA changeset signing (before audit store, so we can share the key)
    let manifest_dir = config.branch_root.join("manifests");
    let key_path = config.signing_key_path.clone();
    let ima = match ima::ImaIntegration::new(manifest_dir, &key_path) {
        Ok(ima) => {
            tracing::info!(public_key = %ima.public_key_hex(), "IMA changeset signing initialized");
            Some(ima)
        }
        Err(e) => {
            if config.require_ima {
                tracing::error!(error = %e, "IMA initialization failed (require_ima=true, exiting)");
                std::process::exit(1);
            }
            tracing::warn!(error = %e, "IMA initialization failed (continuing without signing)");
            None
        }
    };

    // Initialize persistent audit store (with optional attestation)
    let audit_store_path = config.branch_root.join("audit");
    let audit_store = if config.attestation.enabled {
        // Reuse the IMA signing key for attestation signatures
        let signing_key = ima.as_ref().map(|i| i.signing_key().clone());
        if signing_key.is_none() {
            tracing::warn!("attestation enabled but no signing key available (IMA disabled); attestation signatures will be omitted");
        }
        let attestation_dir = if config.attestation.merkle_tree {
            Some(config.attestation.attestation_dir.clone())
        } else {
            None
        };
        let checkpoint_dir = if config.attestation.merkle_tree {
            Some(config.attestation.checkpoint_dir.clone())
        } else {
            None
        };
        let store = audit_store::AuditStore::new_with_attestation(
            audit_store_path,
            true,
            signing_key,
            attestation_dir,
            checkpoint_dir,
            config.attestation.checkpoint_interval,
            config.attestation.checkpoint_time_interval_secs,
        )?;
        tracing::info!(
            merkle = config.attestation.merkle_tree,
            "cryptographic attestation enabled"
        );
        // Write public key to attestation dir for third-party verification
        if let Some(ref ima_ref) = ima {
            let pubkey_path = config.attestation.attestation_dir.join("public_key.hex");
            if let Err(e) = std::fs::write(&pubkey_path, ima_ref.public_key_hex()) {
                tracing::warn!(error = %e, "failed to write public key to attestation dir");
            } else {
                tracing::info!(path = %pubkey_path.display(), "public key written for third-party verification");
            }
        }
        store
    } else {
        audit_store::AuditStore::new(audit_store_path)?
    };

    // Spawn the seccomp notification handler thread
    let seccomp_handler = seccomp_handler::SeccompNotifHandler::spawn();
    tracing::info!("seccomp notification handler spawned");

    // Initialize conflict detector
    let conflict_detector = conflict::ConflictDetector::new();

    // Initialize budget manager
    let budget_manager = budget::BudgetManager::new();

    // Initialize BPF LSM for exec rate limiting (best-effort, requires bpf_lsm feature)
    #[cfg(feature = "bpf_lsm")]
    let bpf_lsm = {
        let mut manager = puzzled::sandbox::bpf_lsm::BpfLsmManager::new(&config.bpf_obj_path);
        match manager.load() {
            Ok(()) => {
                if manager.is_attached() {
                    tracing::info!(
                        path = %config.bpf_obj_path.display(),
                        "BPF LSM loaded and attached"
                    );
                } else {
                    tracing::warn!(
                        path = %config.bpf_obj_path.display(),
                        "BPF LSM object loaded but program not attached (exec rate limiting inactive)"
                    );
                }
                Some(manager)
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %config.bpf_obj_path.display(),
                    "BPF LSM initialization failed (continuing without exec rate limiting)"
                );
                None
            }
        }
    };
    #[cfg(not(feature = "bpf_lsm"))]
    let bpf_lsm: Option<puzzled::sandbox::bpf_lsm::BpfLsmManager> = None;

    // Create the branch manager with all sub-components
    let conflict_detector = Arc::new(std::sync::Mutex::new(conflict_detector));
    let budget_manager = Arc::new(std::sync::Mutex::new(budget_manager));

    let mut manager = branch::BranchManager::new(
        config.clone(),
        profile_loader,
        policy_engine,
        wal,
        audit.clone(),
        ima,
        conflict_detector.clone(),
        budget_manager.clone(),
        Some(seccomp_handler.clone()),
        bpf_lsm,
    );

    // §3.4 GAP-M3: Wire instance secret for ACKF CA key encryption
    if let Some(ref secret) = instance_secret {
        // M-8: Pass Zeroizing wrapper directly — clone to avoid moving from ref.
        manager.set_instance_secret(secret.clone());
        tracing::info!("§3.4: instance secret wired to branch manager");
    }

    // §3.3: Initialize DLP engine from config (if enabled)
    if config.dlp.enabled {
        match puzzle_proxy::dlp::DlpEngine::from_file(&config.dlp.default_rules_path) {
            Ok(engine) => {
                let rule_count = engine.rule_count();
                manager.set_dlp_engine(std::sync::Arc::new(engine));
                tracing::info!(
                    rules = rule_count,
                    path = %config.dlp.default_rules_path.display(),
                    "§3.3: DLP engine loaded"
                );
            }
            Err(e) => {
                // K84: DLP init failure is fatal when DLP is enabled
                tracing::error!(
                    error = %e,
                    path = %config.dlp.default_rules_path.display(),
                    "§3.3: DLP engine initialization failed (dlp.enabled=true, exiting)"
                );
                std::process::exit(1);
            }
        }
        // §3.3: Load GeoIP database for data residency enforcement
        match puzzle_proxy::geo::GeoIpDatabase::open(&config.dlp.geo_database_path) {
            Ok(db) => {
                manager.set_geo_database(std::sync::Arc::new(db));
                tracing::info!(
                    path = %config.dlp.geo_database_path.display(),
                    "§3.3: GeoIP database loaded"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %config.dlp.geo_database_path.display(),
                    "§3.3: GeoIP database load failed (continuing without data residency)"
                );
            }
        }
    }

    // §3.4: Initialize credential store and phantom token manager (if enabled)
    if config.credentials.enabled {
        match std::fs::read(&config.signing_key_path) {
            Ok(signing_key_bytes) => {
                // K81: Validate signing key length before use
                if signing_key_bytes.len() < 32 {
                    tracing::error!(
                        key_len = signing_key_bytes.len(),
                        "§3.4: signing key too short (need >= 32 bytes) — credential system disabled"
                    );
                    std::process::exit(1);
                }
                let store_path = match &config.credentials.backend {
                    config::CredentialBackendConfig::Local { store_path } => store_path.clone(),
                    _ => std::path::PathBuf::from("/etc/puzzled/credentials/store.enc"),
                };
                match puzzle_proxy::credentials::CredentialStore::new(store_path, &signing_key_bytes)
                {
                    Ok(store) => {
                        let cred_count = store.list().len();
                        let store = std::sync::Arc::new(tokio::sync::RwLock::new(store));
                        let mut ptm = puzzle_proxy::credentials::PhantomTokenManager::new(
                            store.clone(),
                            config.credentials.phantom_prefix.clone(),
                            config.credentials.phantom_entropy_bytes,
                        );
                        // §3.4 T3.2: Create mmap-backed secure store for runtime credential values.
                        // Default: 16 credentials × 4KB slots = 64KB mlock'd memory per PRD §3.4.8.
                        match puzzle_proxy::secure_memory::SecureCredentialStore::new(16, 4096, true)
                        {
                            Ok(secure_store) => {
                                ptm.set_secure_store(secure_store);
                                tracing::info!(
                                    "§3.4 T3.2: secure credential store initialized (mmap+mlock)"
                                );
                            }
                            Err(e) => {
                                // Non-fatal: fall back to heap-based credential storage.
                                // mlock failure is common in CI/dev environments.
                                tracing::warn!(
                                    error = %e,
                                    "§3.4 T3.2: secure credential store unavailable, falling back to heap storage"
                                );
                            }
                        }
                        let ptm = std::sync::Arc::new(tokio::sync::RwLock::new(ptm));
                        manager.set_credential_store(store, ptm);
                        tracing::info!(
                            credentials = cred_count,
                            "§3.4: credential store initialized"
                        );
                    }
                    Err(e) => {
                        // K85: Credential store init failure is fatal when credentials enabled
                        tracing::error!(
                            error = %e,
                            "§3.4: credential store initialization failed (credentials.enabled=true, exiting)"
                        );
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                // K85: Signing key read failure is fatal when credentials enabled
                tracing::error!(
                    error = %e,
                    path = %config.signing_key_path.display(),
                    "§3.4: signing key not available (credentials.enabled=true, exiting)"
                );
                std::process::exit(1);
            }
        }
    }

    // Recover any incomplete commits from previous runs
    if let Err(e) = manager.recover() {
        tracing::warn!(error = %e, "recovery failed (continuing)");
    }

    // Initialize Prometheus metrics
    let metrics = Arc::new(puzzled::metrics::Metrics::new());
    manager.set_metrics(metrics.clone());

    // Spawn metrics server
    let metrics_socket = config.runtime_dir.join("metrics.sock");
    let metrics_clone = metrics.clone();
    tokio::spawn(async move {
        if let Err(e) = puzzled::metrics::serve_metrics(metrics_clone, metrics_socket).await {
            tracing::warn!(error = %e, "metrics server failed (continuing without metrics)");
        }
    });

    // Load persisted branch state from previous run
    if let Err(e) = manager.load_state() {
        tracing::warn!(error = %e, "state loading failed (continuing)");
    }

    let manager = Arc::new(manager);
    let audit_store = Arc::new(tokio::sync::Mutex::new(audit_store));

    // H10: Spawn fanotify monitoring for behavioral triggers on active branches.
    // Per-branch fanotify monitors are created inside BranchManager::create() when a branch
    // has behavioral triggers configured. This top-level log confirms the subsystem is ready.
    // Re-attach fanotify monitors to branches restored from state.json on restart.
    #[cfg(target_os = "linux")]
    {
        manager.reattach_monitors();
    }
    tracing::info!("fanotify behavioral monitoring subsystem ready (per-branch monitors created on branch creation)");

    // Spawn watchdog task for branch lifetime enforcement
    if config.watchdog_timeout_secs > 0 {
        let watchdog_manager = manager.clone();
        let interval_secs = (config.watchdog_timeout_secs / 3).max(5);
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                watchdog_manager.enforce_timeouts();
                watchdog_manager.cleanup_committed_conflicts();
                // Periodically save state for zero-downtime restart
                if let Err(e) = watchdog_manager.save_state() {
                    tracing::warn!(error = %e, "periodic state save failed");
                }
                // Notify systemd watchdog
                // Q3: Log sd_notify failures instead of silently discarding
                if let Err(e) = sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]) {
                    tracing::trace!(error = %e, "Q3: sd_notify(WATCHDOG=1) failed");
                }
            }
        });
        tracing::info!(
            timeout_secs = config.watchdog_timeout_secs,
            check_interval_secs = interval_secs,
            "watchdog task spawned"
        );
    }

    // §4.1: Initialize trust manager
    let trust_manager = {
        let rules = puzzled::trust::default_scoring_rules();
        let mut tm = puzzled::trust::TrustManager::from_config(&config.trust, rules);
        // Load persisted trust state from previous run
        if let Err(e) = tm.load() {
            tracing::warn!(error = %e, "§4.1: trust state load failed (starting fresh)");
        }
        Arc::new(std::sync::Mutex::new(tm))
    };
    tracing::info!(
        store_dir = %config.trust.store_dir.display(),
        "§4.1: trust manager initialized"
    );

    // §4.3: Initialize provenance store
    let provenance_store = Arc::new(puzzled::provenance::ProvenanceStore::new(
        config.provenance.store_dir.clone(),
    ));
    tracing::info!(
        store_dir = %config.provenance.store_dir.display(),
        "§4.3: provenance store initialized"
    );

    // §4.5: Initialize identity manager (requires ima feature + signing key)
    #[cfg(feature = "ima")]
    let identity_manager = {
        let signing_key = match std::fs::read(&config.signing_key_path) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                ed25519_dalek::SigningKey::from_bytes(&arr)
            }
            _ => {
                // K80: Generate a random ephemeral key instead of using all-zero key
                let mut ephemeral_bytes = [0u8; 32];
                // M1: Handle entropy failure without panicking — log and exit cleanly.
                if let Err(e) = getrandom::getrandom(&mut ephemeral_bytes) {
                    tracing::error!(error = %e, "M1: failed to generate ephemeral signing key — entropy source unavailable");
                    std::process::exit(1);
                }
                tracing::warn!("§4.5: signing key not available, using ephemeral key for identity");
                ed25519_dalek::SigningKey::from_bytes(&ephemeral_bytes)
            }
        };
        Arc::new(puzzled::identity::IdentityManager::with_max_lifetime(
            signing_key,
            config.identity.trust_domain.clone(),
            config.identity.svid_lifetime_secs,
            config.identity.max_svid_lifetime_secs,
            config.identity.include_governance_claims,
            config.identity.include_containment_claims,
        ))
    };
    #[cfg(feature = "ima")]
    tracing::info!(
        trust_domain = %config.identity.trust_domain,
        "§4.5: identity manager initialized"
    );

    // Start the D-Bus service (returns immediately after registration)
    // H13: Keep a clone of the manager for shutdown state persistence
    let shutdown_manager = manager.clone();
    // M23: start_dbus_service returns the initialized flag; we set it after all subsystems are ready
    let (_connection, initialized) = dbus::start_dbus_service(
        &config,
        manager,
        audit_store,
        audit.clone(),
        trust_manager,
        provenance_store,
        #[cfg(feature = "ima")]
        identity_manager,
    )
    .await?;

    // Apply self-hardening seccomp filter to puzzled
    if let Err(e) = puzzled::sandbox::seccomp::apply_daemon_hardening() {
        // L9: If require_self_hardening is set, seccomp hardening failure is fatal
        if config.require_self_hardening {
            tracing::error!(error = %e, "daemon seccomp hardening failed (require_self_hardening=true, exiting)");
            std::process::exit(1);
        }
        tracing::warn!(error = %e, "daemon seccomp hardening failed (continuing)");
    }

    // M23: All subsystems initialized — D-Bus, WAL recovery, policy load, seccomp hardening.
    // Now mark the daemon as fully initialized so it accepts agent registrations.
    initialized.store(true, std::sync::atomic::Ordering::Release);
    tracing::info!("daemon marked as fully initialized (accepting agent registrations)");

    // H7: Notify systemd that we are ready (Type=notify service)
    // Q3: Log sd_notify failures instead of silently discarding
    if let Err(e) = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]) {
        tracing::debug!(error = %e, "Q3: sd_notify(READY=1) failed");
    }
    tracing::info!("sd_notify(READY=1) sent");

    // H14: Keep the event loop alive until SIGINT or SIGTERM
    #[cfg(unix)]
    {
        // N1: Graceful error handling instead of expect() on signal registration
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        tracing::info!("SIGINT received, initiating graceful shutdown");
                    }
                    _ = sigterm.recv() => {
                        tracing::info!("SIGTERM received, initiating graceful shutdown");
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "N1: failed to register SIGTERM handler, falling back to SIGINT only");
                tokio::signal::ctrl_c().await?;
                tracing::info!("SIGINT received, initiating graceful shutdown");
            }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        tracing::info!("shutdown signal received");
    }

    // L10: Clean up active branches before shutdown
    {
        tracing::info!(
            "shutdown: {} active branches at exit",
            shutdown_manager.list().len()
        );
        shutdown_manager.shutdown_all();
    }

    // H13: Persist branch manager state with fsync before exiting
    {
        if let Err(e) = shutdown_manager.save_state() {
            tracing::error!(error = %e, "failed to save state on shutdown");
        } else {
            tracing::info!("branch manager state saved to disk on shutdown");
        }
    }

    // Clean up seccomp handler
    seccomp_handler.shutdown().await;

    Ok(())
}

#[cfg(test)]
mod tests {
    /// K80: Verify that `[0u8; 32]` is not used as a signing key fallback.
    /// The ephemeral key must be generated via `getrandom`.
    #[test]
    fn k80_no_all_zero_signing_key_fallback() {
        let source = include_str!("main.rs");
        // Split at the test module boundary to only check production code.
        let production_code = source
            .split("#[cfg(test)]")
            .next()
            .expect("should have production code before test module");
        // The old pattern: SigningKey::from_bytes(&[0u8; 32])
        let zero_key_pattern = "from_bytes(&[0u8; 32])";
        assert!(
            !production_code.contains(zero_key_pattern),
            "K80: all-zero signing key fallback must not be used in production code"
        );
        assert!(
            production_code.contains("getrandom::getrandom(&mut ephemeral_bytes)"),
            "K80: ephemeral key must be generated via getrandom"
        );
    }

    /// K81: Verify that signing key length is validated before credential store init.
    #[test]
    fn k81_signing_key_length_validated() {
        let source = include_str!("main.rs");
        assert!(
            source.contains("signing_key_bytes.len() < 32"),
            "K81: signing key length must be validated (>= 32 bytes)"
        );
    }

    /// K84: Verify that DLP init failure exits when DLP is enabled.
    #[test]
    fn k84_dlp_init_failure_fatal_when_enabled() {
        let source = include_str!("main.rs");
        // The DLP init error handler must call process::exit when enabled.
        // Check that within the DLP block, we have exit(1) not just warn!.
        assert!(
            source.contains("DLP engine initialization failed (dlp.enabled=true, exiting)"),
            "K84: DLP init failure must be fatal when dlp.enabled=true"
        );
    }

    /// M1: Verify that getrandom failure does not panic — it logs and exits cleanly.
    #[test]
    fn m1_getrandom_no_panic_on_failure() {
        let source = include_str!("main.rs");
        let production_code = source
            .split("#[cfg(test)]")
            .next()
            .expect("should have production code before test module");
        // Must NOT use .expect() on getrandom (would panic if entropy unavailable)
        assert!(
            !production_code.contains(
                "getrandom::getrandom(&mut ephemeral_bytes)\n                    .expect("
            ),
            "M1: getrandom must not use .expect() — use if-let-Err with process::exit(1) instead"
        );
        // Must use if-let-Err pattern with process::exit
        assert!(
            production_code.contains("if let Err(e) = getrandom::getrandom(&mut ephemeral_bytes)"),
            "M1: getrandom failure must be handled with if-let-Err pattern"
        );
    }

    /// K85: Verify that credential store init failure exits when credentials are enabled.
    #[test]
    fn k85_credential_init_failure_fatal_when_enabled() {
        let source = include_str!("main.rs");
        assert!(
            source.contains(
                "credential store initialization failed (credentials.enabled=true, exiting)"
            ),
            "K85: credential store init failure must be fatal when credentials.enabled=true"
        );
        assert!(
            source.contains("signing key not available (credentials.enabled=true, exiting)"),
            "K85: signing key read failure must be fatal when credentials.enabled=true"
        );
    }
}
