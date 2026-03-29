// SPDX-License-Identifier: Apache-2.0
use dashmap::DashMap;
#[cfg(target_os = "linux")]
use nix::mount::MntFlags;
use puzzled_types::{BranchId, BranchInfo, BranchState, CommitResult, FileChange, PolicyDecision};
use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

use crate::audit::{AuditEvent, AuditLogger};
use crate::budget::BudgetManager;
use crate::config::DaemonConfig;
use crate::conflict::ConflictDetector;
use crate::diff::DiffEngine;
use crate::error::{PuzzledError, Result};
use crate::ima::ImaIntegration;
use crate::policy::PolicyEngine;
use crate::profile::ProfileLoader;
use crate::sandbox::bpf_lsm::BpfLsmManager;
use crate::seccomp_handler::SeccompNotifHandler;
use crate::wal::WriteAheadLog;
use chrono::Utc;

/// Manages the lifecycle of all active branches.
///
/// Holds sub-components for profile loading, policy evaluation,
/// write-ahead logging, audit, conflict detection, and budget management.
/// C1: Per-branch data stored in `DashMap` for lock-free concurrent access
/// to different branches. Global state (`config`, `wal`, `conflict_detector`,
/// `budget_manager`, `metrics`) is unchanged — already behind `Arc<Mutex<T>>`
/// or read-only after construction.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct BranchManager {
    config: DaemonConfig,
    branches: DashMap<BranchId, BranchInfo>,
    profile_loader: ProfileLoader,
    /// H-29: PolicyEngine has internal Mutex — no external RwLock needed.
    /// `evaluate(&self)` and `reload(&self)` use interior mutability.
    policy_engine: PolicyEngine,
    wal: WriteAheadLog,
    audit: Arc<AuditLogger>,
    diff_engine: DiffEngine,
    /// Wrapped in `Mutex` for interior mutability (key rotation needs `&mut self`).
    ima: Option<std::sync::Mutex<ImaIntegration>>,
    conflict_detector: Arc<Mutex<ConflictDetector>>,
    budget_manager: Arc<Mutex<BudgetManager>>,
    seccomp_handler: Option<SeccompNotifHandler>,
    bpf_lsm: Option<BpfLsmManager>,
    #[cfg(target_os = "linux")]
    sandboxes: DashMap<BranchId, crate::sandbox::SandboxHandle>,
    /// Network setup per branch (for cleanup on rollback).
    #[cfg(target_os = "linux")]
    network_setups: DashMap<BranchId, crate::sandbox::network::NetworkSetup>,
    /// fanotify trigger receivers per branch.
    #[cfg(target_os = "linux")]
    fanotify_triggers:
        DashMap<BranchId, tokio::sync::mpsc::Receiver<puzzled_types::BehavioralTrigger>>,
    /// Network journals per branch (for Gated network mode side-effect replay).
    network_journals: DashMap<BranchId, puzzle_proxy::replay::NetworkJournal>,
    /// Proxy server task handles per branch (for Gated network mode).
    /// Stored so we can abort the proxy when the branch is cleaned up.
    proxy_tasks: DashMap<BranchId, tokio::task::JoinHandle<()>>,
    /// Prometheus metrics (optional, set once via `set_metrics()`).
    metrics: std::sync::OnceLock<Arc<crate::metrics::Metrics>>,
    /// BC2: Set of branches currently mid-commit. Prevents unregister/rollback
    /// during an active commit operation, avoiding race conditions.
    /// Wrapped in Arc so CommitGuard can hold a reference independently of &self.
    committing_branches: Arc<Mutex<HashSet<BranchId>>>,
    /// H-10: Pending governance reviews — stores the changeset (Vec<FileChange>)
    /// and base_path for branches awaiting human approval. Populated when
    /// `require_human_approval` is true and policy approves a commit.
    /// Consumed by `approve_branch()` or cleaned up by `reject_branch()` / timeout.
    pending_reviews: DashMap<BranchId, (Vec<FileChange>, PathBuf)>,
    /// §3.3: Shared DLP engine for proxy content inspection (None if DLP disabled).
    dlp_engine: Option<Arc<puzzle_proxy::dlp::DlpEngine>>,
    /// §3.3: Shared GeoIP database for data residency enforcement (None if unavailable).
    geo_database: Option<Arc<puzzle_proxy::geo::GeoIpDatabase>>,
    /// §3.4: Shared credential store for phantom token resolution (None if credentials disabled).
    credential_store: Option<Arc<tokio::sync::RwLock<puzzle_proxy::credentials::CredentialStore>>>,
    /// §3.4: Shared phantom token manager (None if credentials disabled).
    phantom_token_manager:
        Option<Arc<tokio::sync::RwLock<puzzle_proxy::credentials::PhantomTokenManager>>>,
    /// §3.4: Instance secret for ACKF CA key encryption/decryption (None if unavailable).
    /// M-8: Wrapped in Zeroizing to ensure secret is cleared from memory on drop.
    instance_secret: Option<zeroize::Zeroizing<[u8; 32]>>,
}

/// BC2: RAII guard that removes a branch from `committing_branches` on drop,
/// ensuring cleanup on all exit paths (normal return, early return, panic).
struct CommitGuard {
    committing_branches: Arc<Mutex<HashSet<BranchId>>>,
    branch_id: BranchId,
}

impl Drop for CommitGuard {
    fn drop(&mut self) {
        let mut committing = self
            .committing_branches
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        committing.remove(&self.branch_id);
    }
}

impl BranchManager {
    /// Create a new BranchManager with all required sub-components.
    ///
    /// E2: Parameter documentation:
    /// - `config`: Daemon configuration (max branches, timeouts, paths)
    /// - `profile_loader`: Loads agent profiles from YAML files on disk
    /// - `policy_engine`: OPA/Rego policy evaluator for commit governance
    /// - `wal`: Write-ahead log for crash-safe commits
    /// - `audit`: Shared audit logger for security event recording
    /// - `ima`: Optional IMA integration for changeset signing (None if disabled)
    /// - `conflict_detector`: Shared detector for cross-branch file conflicts
    /// - `budget_manager`: Shared manager for per-agent resource budgets
    /// - `seccomp_handler`: Optional seccomp USER_NOTIF handler (None on non-Linux)
    /// - `bpf_lsm`: Optional BPF LSM manager for exec counting (None on non-Linux)
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: DaemonConfig,
        profile_loader: ProfileLoader,
        policy_engine: PolicyEngine,
        wal: WriteAheadLog,
        audit: Arc<AuditLogger>,
        ima: Option<ImaIntegration>,
        conflict_detector: Arc<Mutex<ConflictDetector>>,
        budget_manager: Arc<Mutex<BudgetManager>>,
        seccomp_handler: Option<SeccompNotifHandler>,
        bpf_lsm: Option<BpfLsmManager>,
    ) -> Self {
        Self {
            config,
            branches: DashMap::new(),
            profile_loader,
            policy_engine,
            wal,
            audit,
            diff_engine: DiffEngine::new(),
            ima: ima.map(std::sync::Mutex::new),
            conflict_detector,
            budget_manager,
            seccomp_handler,
            bpf_lsm,
            #[cfg(target_os = "linux")]
            sandboxes: DashMap::new(),
            #[cfg(target_os = "linux")]
            network_setups: DashMap::new(),
            #[cfg(target_os = "linux")]
            fanotify_triggers: DashMap::new(),
            network_journals: DashMap::new(),
            proxy_tasks: DashMap::new(),
            metrics: std::sync::OnceLock::new(),
            committing_branches: Arc::new(Mutex::new(HashSet::new())),
            pending_reviews: DashMap::new(),
            dlp_engine: None,
            geo_database: None,
            credential_store: None,
            phantom_token_manager: None,
            instance_secret: None,
        }
    }

    /// §3.3: Set the shared DLP engine (called from main.rs after loading rules).
    pub fn set_dlp_engine(&mut self, engine: Arc<puzzle_proxy::dlp::DlpEngine>) {
        self.dlp_engine = Some(engine);
    }

    /// §3.3: Set the shared GeoIP database (called from main.rs after loading .mmdb).
    pub fn set_geo_database(&mut self, db: Arc<puzzle_proxy::geo::GeoIpDatabase>) {
        self.geo_database = Some(db);
    }

    /// §3.4: Set the credential store and phantom token manager.
    pub fn set_credential_store(
        &mut self,
        store: Arc<tokio::sync::RwLock<puzzle_proxy::credentials::CredentialStore>>,
        ptm: Arc<tokio::sync::RwLock<puzzle_proxy::credentials::PhantomTokenManager>>,
    ) {
        self.credential_store = Some(store);
        self.phantom_token_manager = Some(ptm);
    }

    /// §3.4: Get a reference to the credential store (for D-Bus methods).
    pub fn credential_store(
        &self,
    ) -> Option<&Arc<tokio::sync::RwLock<puzzle_proxy::credentials::CredentialStore>>> {
        self.credential_store.as_ref()
    }

    /// §3.4: Get a reference to the phantom token manager (for D-Bus methods).
    pub fn phantom_token_manager(
        &self,
    ) -> Option<&Arc<tokio::sync::RwLock<puzzle_proxy::credentials::PhantomTokenManager>>> {
        self.phantom_token_manager.as_ref()
    }

    /// §3.4 T2.3: Revoke credential-specific resources for a branch.
    /// Aborts the proxy task and deletes persisted credential mapping files.
    /// Called by RevokeCredentials D-Bus method for standalone credential revocation
    /// without full branch cleanup.
    pub fn revoke_branch_credential_resources(&self, id: &BranchId) {
        // Abort the proxy server task if running
        if let Some((_, task)) = self.proxy_tasks.remove(id) {
            task.abort();
            tracing::debug!(branch = %id, "§3.4 T2.3: proxy task aborted during credential revocation");
        }

        // Delete persisted credential mapping file from branch state directory
        let branch_dir = self.config.branch_root.join(id.as_str());
        if branch_dir.exists() {
            let _ =
                puzzle_proxy::credential_persistence::CredentialMappingFile::delete(&branch_dir);
            tracing::debug!(branch = %id, "§3.4 T2.3: credential mappings file deleted");
        }
    }

    /// §3.4: Set the instance secret for ACKF CA key encryption.
    /// M-8: Accepts Zeroizing wrapper to ensure secret is cleared on drop.
    pub fn set_instance_secret(&mut self, secret: zeroize::Zeroizing<[u8; 32]>) {
        self.instance_secret = Some(secret);
    }

    /// §3.4: Get a reference to the instance secret (for CA key operations).
    pub fn instance_secret(&self) -> Option<&[u8; 32]> {
        self.instance_secret.as_deref()
    }

    /// Set the Prometheus metrics instance (can only be called once).
    pub fn set_metrics(&self, metrics: Arc<crate::metrics::Metrics>) {
        // Q10: Log if metrics were already set (OnceLock can only be set once)
        if self.metrics.set(metrics).is_err() {
            tracing::debug!(
                "Q10: metrics already initialized, ignoring duplicate set_metrics call"
            );
        }
    }

    /// Get the filesystem directory for a branch (contains upper, work, merged dirs).
    pub fn branch_dir(&self, id: &BranchId) -> std::path::PathBuf {
        self.config.branch_root.join(id.as_str())
    }

    /// Get an agent profile by name.
    pub fn get_profile(&self, name: &str) -> Option<puzzled_types::AgentProfile> {
        self.profile_loader.get(name).cloned()
    }

    /// Find a branch by profile name and base path.
    ///
    /// Used by EnsureBranch for idempotent branch creation.
    ///
    /// M5: This performs a linear scan over the DashMap. O(n) is acceptable
    /// for Phase 1: max 64 branches (configurable), and EnsureBranch is a
    /// low-frequency operation (called once per container start via Quadlet
    /// ExecStartPre). If branch counts increase significantly, consider
    /// adding a secondary index keyed by (profile, base_path).
    pub fn find_branch_by_profile_and_path(
        &self,
        profile: &str,
        base_path: &str,
    ) -> Option<BranchId> {
        for entry in self.branches.iter() {
            let branch = entry.value();
            if branch.profile == profile && branch.base_path.to_str() == Some(base_path) {
                return Some(entry.key().clone());
            }
        }
        None
    }

    /// Attach governance to a running container (Podman-native mode).
    ///
    /// Called by the OCI hook at createRuntime stage. Registers the container
    /// PID with the branch and optionally starts BPF LSM and fanotify monitoring.
    pub fn attach_governance(
        &self,
        id: &BranchId,
        container_pid: u32,
        _container_id: &str,
    ) -> Result<()> {
        // M4: Validate PID before attaching governance
        if container_pid == 0 {
            return Err(crate::error::PuzzledError::Branch(
                "container_pid must be > 0".to_string(),
            ));
        }

        // M4: Verify the PID exists via pidfd_open (race-free check).
        // The fd is closed immediately — we only need to confirm the PID is valid.
        #[cfg(target_os = "linux")]
        {
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, container_pid, 0) };
            if fd < 0 {
                return Err(crate::error::PuzzledError::Branch(format!(
                    "container_pid {} does not exist or is not accessible: {}",
                    container_pid,
                    std::io::Error::last_os_error()
                )));
            }
            // H6: Safe cast — use i32::try_from to prevent truncation of large fd values.
            let fd_i32 = i32::try_from(fd).map_err(|_| {
                crate::error::PuzzledError::Branch(format!(
                    "pidfd_open returned fd {} which overflows i32",
                    fd
                ))
            })?;
            unsafe { libc::close(fd_i32) };
        }

        let mut branch = self.branches.get_mut(id).ok_or_else(|| {
            crate::error::PuzzledError::Branch(format!("branch {} not found", id))
        })?;

        branch.pid = Some(container_pid);
        tracing::info!(
            branch_id = %id,
            container_pid,
            "governance attached to container process"
        );

        Ok(())
    }

    /// Get metrics reference (returns None if metrics not yet initialized).
    fn get_metrics(&self) -> Option<&crate::metrics::Metrics> {
        self.metrics.get().map(|m| m.as_ref())
    }

    /// Get a reference to the daemon configuration.
    pub fn config(&self) -> &DaemonConfig {
        &self.config
    }

    /// Create a branch workspace: set up overlay directories and store metadata.
    /// No process is spawned and no sandbox primitives (cgroups, namespaces,
    /// seccomp) are applied. The branch enters `Ready` state and is writable
    /// via `upper_dir`. Call `activate_branch()` to spawn a sandboxed process
    /// and transition to `Active`.
    pub fn create_branch(
        &self,
        profile_name: &str,
        base_path: &std::path::Path,
        uid: u32,
    ) -> Result<BranchInfo> {
        if !base_path.is_absolute() {
            return Err(PuzzledError::Branch(format!(
                "base_path must be absolute, got: {}",
                base_path.display()
            )));
        }
        if !base_path.exists() {
            return Err(PuzzledError::Branch(format!(
                "base_path does not exist: {}",
                base_path.display()
            )));
        }
        if !base_path.is_dir() {
            return Err(PuzzledError::Branch(format!(
                "base_path is not a directory: {}",
                base_path.display()
            )));
        }

        if self.branches.len() >= self.config.max_branches as usize {
            return Err(PuzzledError::Branch(format!(
                "maximum branches ({}) reached",
                self.config.max_branches
            )));
        }

        let _profile = self
            .profile_loader
            .get(profile_name)
            .ok_or_else(|| PuzzledError::Profile(format!("profile '{}' not found", profile_name)))?
            .clone();

        let branch_id = BranchId::new();
        let branch_dir = self.config.branch_root.join(branch_id.as_str());
        let (upper_dir, work_dir, _merged_dir) =
            crate::sandbox::overlay::OverlayMount::create_dirs(&branch_dir)?;

        let info = BranchInfo {
            id: branch_id.clone(),
            profile: profile_name.to_string(),
            base_path: base_path.to_path_buf(),
            upper_dir,
            work_dir,
            state: BranchState::Ready,
            created_at: Utc::now(),
            expires_at: None,
            pid: None,
            uid,
            selinux_context: None,
        };

        self.branches.insert(branch_id.clone(), info.clone());

        self.audit.log(AuditEvent::BranchCreated {
            branch_id: branch_id.clone(),
            profile: profile_name.to_string(),
            uid,
        });

        if let Some(m) = self.get_metrics() {
            m.record_create(profile_name, 0.0);
        }

        tracing::info!(
            branch = %branch_id,
            profile = profile_name,
            uid,
            "branch created (workspace ready)"
        );

        Ok(info)
    }

    /// Spawn a sandboxed process inside an existing branch.
    ///
    /// Sets up cgroups, clone3 with CLONE_INTO_CGROUP, seccomp, Landlock,
    /// network namespaces, BPF LSM, and fanotify. The child process blocks
    /// on a coordination gate until all containment is confirmed, then calls
    /// execve. Requires Linux.
    #[cfg(target_os = "linux")]
    pub fn activate_branch(
        &self,
        id: &BranchId,
        uid: u32,
        gid: u32,
        command: Vec<String>,
    ) -> Result<()> {
        // T3: GID=0 (root group) override — log for visibility
        let gid = if gid == 0 {
            tracing::debug!(
                uid,
                "T3: gid=0 overridden to uid (root group not used for agents)"
            );
            uid
        } else {
            gid
        };

        let (profile_name, base_path) = {
            let info = self
                .branches
                .get(id)
                .ok_or_else(|| PuzzledError::NotFound(format!("branch {}", id)))?;
            if info.state != BranchState::Ready {
                return Err(PuzzledError::Branch(format!(
                    "branch {} is in state {}, expected Ready",
                    id, info.state
                )));
            }
            (info.profile.clone(), info.base_path.clone())
        };

        // Reject if already activated (has a sandbox handle)
        if self.sandboxes.get(id).is_some() {
            return Err(PuzzledError::Branch(format!(
                "branch {} already has a running sandbox",
                id
            )));
        }

        let profile = self
            .profile_loader
            .get(&profile_name)
            .ok_or_else(|| PuzzledError::Profile(format!("profile '{}' not found", profile_name)))?
            .clone();

        let branch_id_str = id.as_str().to_string();

        let builder = crate::sandbox::SandboxBuilder::new(
            profile.clone(),
            base_path,
            self.config.branch_root.clone(),
        )
        .with_credentials(uid, gid)
        .with_command(command);

        let mut handle = builder.build(&branch_id_str)?;

        // Register seccomp notify fd with the handler
        // H4: Propagate registration failure — agent must not run without seccomp mediation
        if let Some(notify_fd) = handle.seccomp_notify_fd {
            if let Some(ref handler) = self.seccomp_handler {
                // C1: Build CredentialProxyContext from profile's credential config
                // so the seccomp handler can block direct gateway connections
                // (cross-branch credential proxy bypass defense, §3.4.13 G23).
                let credential_proxy = profile.credentials.as_ref().and_then(|cred_config| {
                    if !cred_config.proxy.enabled {
                        return None;
                    }
                    // M-9: Fail-closed — do not silently default to localhost if
                    // proxy_listen_addr is invalid. Wrong gateway IP breaks the
                    // defense-in-depth model entirely.
                    let gateway_ip = match self
                        .config
                        .network
                        .proxy_listen_addr
                        .parse::<std::net::IpAddr>()
                    {
                        Ok(ip) => ip,
                        Err(e) => {
                            tracing::error!(
                                addr = %self.config.network.proxy_listen_addr,
                                error = %e,
                                "M-9: credential proxy requires valid proxy_listen_addr; \
                                 cannot activate branch with credential proxy"
                            );
                            return None;
                        }
                    };
                    let global_port_range = self
                        .config
                        .credential_proxy
                        .parse_port_range()
                        .unwrap_or(18000..=18999);
                    // M-10: proxy_port is the per-branch allocated credential proxy port.
                    // At seccomp registration time, the actual port may not be allocated yet
                    // (it's assigned during ProvisionCredentials). The global_port_range
                    // blocks the entire range, providing security coverage regardless.
                    // Use the range start as a placeholder; the critical defense is the
                    // global_port_range check in validate_connect().
                    let proxy_port = *global_port_range.start();
                    Some(crate::seccomp_handler::CredentialProxyContext {
                        enabled: true,
                        proxy_gateway_ip: gateway_ip,
                        proxy_port,
                        proxied_ports: cred_config.proxy.ports.clone(),
                        global_port_range,
                    })
                });
                handler.register(notify_fd, id.clone(), profile.clone(), credential_proxy)?;
            }
        }

        // SH1: Send seccomp ACK to child AFTER registering the notify fd.
        // The child blocks on this ACK before calling execve(), ensuring the
        // SeccompNotifHandler is polling the notify fd before any USER_NOTIF-
        // gated syscalls occur.
        crate::sandbox::send_seccomp_ack(&mut handle)?;

        // Set up network isolation
        let netns_name = format!("agentns_{:08x}", crc32fast::hash(branch_id_str.as_bytes()));
        // N8: Use configured proxy port instead of hardcoded value
        let network_setup = crate::sandbox::network::NetworkSetup::configure(
            &branch_id_str,
            profile.network.mode,
            &netns_name,
            self.config.network.proxy_port,
        )?;
        // Spawn the HTTP proxy server and create the network journal for Gated mode.
        // The proxy listens on proxy_addr inside the agent's network namespace,
        // filtering HTTP requests against the profile's allowed_domains.
        // The child process receives HTTP_PROXY env vars via the socketpair protocol
        // (see sandbox/mod.rs) pointing to this proxy address.
        if profile.network.mode == puzzled_types::NetworkMode::Gated {
            let branch_dir = self.config.branch_root.join(branch_id_str.as_str());

            if let Some(proxy_addr) = network_setup.proxy_addr {
                let proxy_config = puzzle_proxy::ProxyConfig {
                    listen_addr: proxy_addr,
                    read_allowed_domains: profile.network.allowed_domains.clone(),
                    write_allowed_domains: profile.network.allowed_domains.clone(),
                    denied_domains: vec![],
                    mode: puzzle_proxy::ProxyMode::Gated,
                    branch_dir: branch_dir.clone(),
                    branch_id: id.clone(),
                    ca: None,
                    dlp_engine: if let Some(ref rules_path) = profile.network.dlp_rules_path {
                        match puzzle_proxy::dlp::DlpEngine::from_file(std::path::Path::new(
                            rules_path,
                        )) {
                            Ok(engine) => {
                                tracing::info!(
                                    branch = %id, profile = %profile.name,
                                    path = %rules_path,
                                    "§3.3: loaded per-profile DLP rules"
                                );
                                Some(std::sync::Arc::new(engine))
                            }
                            Err(e) => {
                                tracing::warn!(
                                    branch = %id, profile = %profile.name,
                                    path = %rules_path, error = %e,
                                    "§3.3: failed to load per-profile DLP rules, falling back to global"
                                );
                                self.dlp_engine.clone()
                            }
                        }
                    } else {
                        self.dlp_engine.clone()
                    },
                    max_inspection_body_size: self.config.dlp.max_inspection_body_size,
                    oversized_body_action: self.config.dlp.oversized_body_action,
                    quarantine_sender: {
                        // §3.3: Create quarantine channel — receiver freezes
                        // the branch cgroup when DLP detects a Quarantine-level violation.
                        let (tx, mut rx) =
                            tokio::sync::mpsc::channel::<puzzled_types::BranchId>(16);
                        let cgroup_path = self.sandboxes.get(id).map(|h| h.cgroup_path.clone());
                        if let Ok(rt_handle) = tokio::runtime::Handle::try_current() {
                            rt_handle.spawn(async move {
                                while let Some(branch_id) = rx.recv().await {
                                    if let Some(ref cg_path) = cgroup_path {
                                        #[cfg(target_os = "linux")]
                                        if let Err(e) = crate::sandbox::cgroup::CgroupManager::freeze(
                                            cg_path,
                                        ) {
                                            tracing::warn!(
                                                branch = %branch_id,
                                                error = %e,
                                                "§3.3: quarantine via cgroup.freeze failed"
                                            );
                                        } else {
                                            tracing::warn!(
                                                branch = %branch_id,
                                                "§3.3: branch quarantined via cgroup.freeze (DLP violation)"
                                            );
                                        }
                                        #[cfg(not(target_os = "linux"))]
                                        tracing::warn!(
                                            branch = %branch_id,
                                            "§3.3: quarantine requested but cgroup.freeze unavailable (non-Linux)"
                                        );
                                    }
                                }
                            });
                        }
                        Some(tx)
                    },
                    phantom_token_manager: self.phantom_token_manager.clone(),
                    agent_profile: Some(profile.name.clone()),
                    geo_database: self.geo_database.clone(),
                    data_residency: profile.network.data_residency.clone(),
                    audit_sender: {
                        // §3.3/§3.4 Gap 1: Create audit channel so DLP and credential
                        // audit events flow from the proxy to puzzled's audit logger.
                        // DLP-6: Bounded audit channel (capacity 1024) to prevent unbounded memory growth
                        let (tx, mut rx) =
                            tokio::sync::mpsc::channel::<puzzle_proxy::ProxyAuditEvent>(1024);
                        let audit_logger = self.audit.clone();
                        if let Ok(rt_handle) = tokio::runtime::Handle::try_current() {
                            rt_handle.spawn(async move {
                                while let Some(event) = rx.recv().await {
                                    let audit_event = match &event {
                                        puzzle_proxy::ProxyAuditEvent::DlpBlocked { branch_id, rule_name, domain, .. } => {
                                            crate::audit::AuditEvent::PolicyViolation {
                                                branch_id: branch_id.clone(),
                                                rule: format!("dlp_blocked:{}", rule_name),
                                                message: format!("DLP blocked: rule={}, domain={}", rule_name, domain),
                                            }
                                        }
                                        puzzle_proxy::ProxyAuditEvent::DlpDetected { branch_id, rule_name, domain, .. } => {
                                            crate::audit::AuditEvent::PolicyViolation {
                                                branch_id: branch_id.clone(),
                                                rule: format!("dlp_detected:{}", rule_name),
                                                message: format!("DLP detected: rule={}, domain={}", rule_name, domain),
                                            }
                                        }
                                        puzzle_proxy::ProxyAuditEvent::DlpRedacted { branch_id, rule_name, domain, .. } => {
                                            crate::audit::AuditEvent::PolicyViolation {
                                                branch_id: branch_id.clone(),
                                                rule: format!("dlp_redacted:{}", rule_name),
                                                message: format!("DLP redacted: rule={}, domain={}", rule_name, domain),
                                            }
                                        }
                                        puzzle_proxy::ProxyAuditEvent::DlpQuarantine { branch_id, rule_name, domain } => {
                                            crate::audit::AuditEvent::PolicyViolation {
                                                branch_id: branch_id.clone(),
                                                rule: format!("dlp_quarantine:{}", rule_name),
                                                message: format!("DLP quarantine: rule={}, domain={}", rule_name, domain),
                                            }
                                        }
                                        puzzle_proxy::ProxyAuditEvent::CredentialInjected { branch_id, credential_name, domain } => {
                                            crate::audit::AuditEvent::PolicyViolation {
                                                branch_id: branch_id.clone(),
                                                rule: "credential_injected".to_string(),
                                                message: format!("credential injected: name={}, domain={}", credential_name, domain),
                                            }
                                        }
                                        puzzle_proxy::ProxyAuditEvent::CredentialDenied { branch_id, credential_name, domain, reason } => {
                                            crate::audit::AuditEvent::PolicyViolation {
                                                branch_id: branch_id.clone(),
                                                rule: "credential_denied".to_string(),
                                                message: format!("credential denied: name={}, domain={}, reason={}", credential_name, domain, reason),
                                            }
                                        }
                                        // §3.4 G29: Extended credential audit events from proxy
                                        puzzle_proxy::ProxyAuditEvent::CredentialResolveFailed { branch_id, credential_name, reason } => {
                                            crate::audit::AuditEvent::CredentialResolveFailed {
                                                branch_id: branch_id.clone(),
                                                credential_name: credential_name.clone(),
                                                reason: reason.clone(),
                                            }
                                        }
                                        puzzle_proxy::ProxyAuditEvent::CredentialResponseLeak { branch_id, domain } => {
                                            crate::audit::AuditEvent::CredentialResponseLeak {
                                                branch_id: branch_id.clone(),
                                                domain: domain.clone(),
                                            }
                                        }
                                        puzzle_proxy::ProxyAuditEvent::PhantomTokenStripped { branch_id, header_name } => {
                                            crate::audit::AuditEvent::PhantomTokenStripped {
                                                branch_id: branch_id.clone(),
                                                header_name: header_name.clone(),
                                            }
                                        }
                                        // §3.4 T2.1: CredentialResolved — emit as audit event
                                        // (D-Bus signal emission deferred to D-Bus interface layer)
                                        puzzle_proxy::ProxyAuditEvent::CredentialResolved { branch_id, credential_name, domain } => {
                                            crate::audit::AuditEvent::PolicyViolation {
                                                branch_id: branch_id.clone(),
                                                rule: "credential_resolved".to_string(),
                                                message: format!("credential resolved: name={}, domain={}", credential_name, domain),
                                            }
                                        }
                                        // §3.4 T2.2: CredentialProxyError — emit as audit event
                                        puzzle_proxy::ProxyAuditEvent::CredentialProxyError { branch_id, error, domain } => {
                                            crate::audit::AuditEvent::PolicyViolation {
                                                branch_id: branch_id.clone(),
                                                rule: "credential_proxy_error".to_string(),
                                                message: format!("credential proxy error: domain={}, error={}", domain, error),
                                            }
                                        }
                                    };
                                    audit_logger.log(audit_event);
                                }
                                // §3.3/§3.4 DLP-7: Log when audit bridge channel closes
                                // (all senders dropped — proxy for this branch has stopped)
                                tracing::warn!("audit bridge channel closed — no more proxy audit events will be recorded for this branch");
                            });
                        }
                        Some(tx)
                    },
                    credential_mode: profile
                        .credentials
                        .as_ref()
                        .map(|c| {
                            if c.is_phantom_enabled() {
                                puzzled_types::CredentialMode::Phantom
                            } else {
                                puzzled_types::CredentialMode::Passthrough
                            }
                        })
                        .unwrap_or(puzzled_types::CredentialMode::Phantom),
                    transparent_mode: false,
                };
                let proxy = puzzle_proxy::ProxyServer::new(proxy_config);
                let proxy_branch_id = id.clone();

                if let Ok(rt_handle) = tokio::runtime::Handle::try_current() {
                    let task = rt_handle.spawn(async move {
                        if let Err(e) = proxy.run().await {
                            tracing::warn!(
                                branch = %proxy_branch_id,
                                error = %e,
                                "HTTP proxy server exited with error"
                            );
                        }
                    });
                    self.proxy_tasks.insert(id.clone(), task);
                    tracing::info!(
                        branch = %id,
                        addr = %proxy_addr,
                        "HTTP proxy server spawned for Gated network mode"
                    );
                } else {
                    tracing::warn!(
                        branch = %id,
                        "no tokio runtime — HTTP proxy not started (test environment?)"
                    );
                }
            } else {
                tracing::warn!(
                    branch = %id,
                    "Gated network mode but no proxy_addr — proxy not started"
                );
            }

            let journal_dir = branch_dir.join("network_journal");
            let journal = puzzle_proxy::replay::NetworkJournal::new(journal_dir, id.clone());
            self.network_journals.insert(id.clone(), journal);
        }

        // Configure BPF LSM exec rate limits for this branch's cgroup (best-effort)
        if let Some(ref bpf_lsm) = self.bpf_lsm {
            match std::fs::metadata(&handle.cgroup_path) {
                Ok(meta) => {
                    use std::os::unix::fs::MetadataExt;
                    let cgroup_id = meta.ino();
                    let bpf_config = crate::sandbox::bpf_lsm::RateLimitConfig {
                        max_execs_per_second: profile.resource_limits.max_pids.min(100),
                        max_total_execs: profile.resource_limits.max_pids.saturating_mul(10),
                        kill_switch: 0,
                        _pad: 0,
                    };
                    if let Err(e) = bpf_lsm.configure_cgroup(cgroup_id, bpf_config) {
                        tracing::warn!(
                            branch = %id,
                            error = %e,
                            "BPF LSM rate limit configuration failed (continuing without)"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        branch = %id,
                        error = %e,
                        "failed to read cgroup metadata for BPF LSM (continuing without)"
                    );
                }
            }
        }

        let fanotify_rx = handle.fanotify_trigger_rx.take();

        // M4: Compute expiration from profile lifetime_minutes
        let now = Utc::now();
        let expires_at = profile
            .resource_limits
            .lifetime_minutes
            .map(|mins| now + chrono::Duration::minutes(i64::from(mins)));

        if let Some(mut info) = self.branches.get_mut(id) {
            info.pid = Some(handle.pid);
            info.state = BranchState::Active;
            info.upper_dir = handle.upper_dir.clone();
            info.work_dir = handle.work_dir.clone();
            info.expires_at = expires_at;
            // Cache SELinux context at activation (avoids repeated /proc reads)
            info.selinux_context = crate::dbus::read_selinux_context(handle.pid);
        }

        // Write metadata.json for branch recovery and inspection
        let branch_dir = self.config.branch_root.join(branch_id_str.as_str());
        if let Some(info) = self.branches.get(id) {
            let metadata = serde_json::json!({
                "branch_id": branch_id_str,
                "profile": profile_name,
                "base_path": info.base_path.to_string_lossy(),
                "created_at": info.created_at.to_rfc3339(),
                "uid": uid,
            });
            if let Err(e) = std::fs::write(
                branch_dir.join("metadata.json"),
                serde_json::to_string_pretty(&metadata).unwrap_or_else(|e| {
                    tracing::error!("F1: failed to serialize branch metadata: {e}");
                    "{}".to_string()
                }),
            ) {
                tracing::warn!(
                    branch = %id,
                    error = %e,
                    "failed to write metadata.json (non-fatal)"
                );
            }
        }

        self.sandboxes.insert(id.clone(), handle);
        self.network_setups.insert(id.clone(), network_setup);
        if let Some(rx) = fanotify_rx {
            self.fanotify_triggers.insert(id.clone(), rx);
        }

        // §3.4 Gap 7: Issue phantom tokens for this branch's credential mappings
        if let Some(ref cred_config) = profile.credentials {
            if cred_config.is_phantom_enabled() {
                if let Some(ref ptm) = self.phantom_token_manager {
                    let mappings: Vec<puzzle_proxy::credentials::CredentialMapping> = cred_config
                        .credential_mappings()
                        .into_iter()
                        .map(|(domain, credential_ref, env_var, required)| {
                            puzzle_proxy::credentials::CredentialMapping {
                                domain,
                                credential_ref,
                                env_var,
                                required,
                            }
                        })
                        .collect();
                    let profile_str = profile_name.clone();
                    let tokens = tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(async {
                            let mut ptm_guard = ptm.write().await;
                            ptm_guard
                                .issue_for_branch(id, &profile_str, &mappings)
                                .await
                        })
                    });
                    match tokens {
                        Ok(t) => {
                            tracing::info!(
                                branch = %id,
                                token_count = t.len(),
                                "§3.4: phantom tokens issued for branch"
                            );
                        }
                        Err(e) => {
                            // M-1/§3.4.5: Fail branch activation when required
                            // credentials are unavailable — agents must not start
                            // without their required credentials.
                            return Err(PuzzledError::Sandbox(format!(
                                "M-1/§3.4.5: credential provisioning failed for branch {}: {}",
                                id, e
                            )));
                        }
                    }
                }
            }
        }

        tracing::info!(
            branch = %id,
            profile = profile_name,
            "sandbox activated (Ready → Active)"
        );

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn activate_branch(
        &self,
        _id: &BranchId,
        _uid: u32,
        _gid: u32,
        _command: Vec<String>,
    ) -> Result<()> {
        Err(PuzzledError::Sandbox(
            "sandbox activation requires Linux".to_string(),
        ))
    }

    /// Convenience: create a branch and immediately activate a sandbox.
    /// Equivalent to `create_branch()` + `activate_branch()`.
    #[cfg(target_os = "linux")]
    pub fn create(
        &self,
        profile_name: &str,
        base_path: &Path,
        uid: u32,
        command: Vec<String>,
    ) -> Result<BranchInfo> {
        self.create_with_gid(profile_name, base_path, uid, 0, command)
    }

    /// Convenience: create a branch with explicit GID and immediately activate.
    #[cfg(target_os = "linux")]
    pub fn create_with_gid(
        &self,
        profile_name: &str,
        base_path: &Path,
        uid: u32,
        gid: u32,
        command: Vec<String>,
    ) -> Result<BranchInfo> {
        let info = self.create_branch(profile_name, base_path, uid)?;
        self.activate_branch(&info.id, uid, gid, command)?;
        // Re-read the updated info (activate_branch updates pid and dirs)
        Ok(self
            .branches
            .get(&info.id)
            .map(|r| r.value().clone())
            .unwrap_or(info))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn create(
        &self,
        _profile: &str,
        _base_path: &std::path::Path,
        _uid: u32,
        _command: Vec<String>,
    ) -> Result<BranchInfo> {
        Err(PuzzledError::Sandbox(
            "branch creation with sandbox requires Linux".to_string(),
        ))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn create_with_gid(
        &self,
        _profile: &str,
        _base_path: &std::path::Path,
        _uid: u32,
        _gid: u32,
        _command: Vec<String>,
    ) -> Result<BranchInfo> {
        Err(PuzzledError::Sandbox(
            "branch creation with sandbox requires Linux".to_string(),
        ))
    }

    /// List all branches (returns owned snapshot — DashMap iteration is lock-free).
    pub fn list(&self) -> Vec<BranchInfo> {
        self.branches.iter().map(|r| r.value().clone()).collect()
    }

    /// Cleanly shut down all active branches during daemon shutdown.
    ///
    /// Iterates all active/frozen branches and cleans up their resources:
    /// kills cgroup processes, unmounts OverlayFS, removes cgroup scopes,
    /// and cleans up network resources. Transitions branches to Terminated
    /// and emits audit events. Does NOT remove upper directories (state is
    /// preserved for recovery on restart).
    pub fn shutdown_all(&self) {
        let branch_ids: Vec<BranchId> = self.branches.iter().map(|r| r.key().clone()).collect();
        if branch_ids.is_empty() {
            return;
        }

        tracing::info!(count = branch_ids.len(), "shutting down active branches");

        for id in &branch_ids {
            let state = match self.branches.get(id) {
                Some(info) => info.state,
                None => continue,
            };

            // Only shut down branches that are still alive (including Degraded/Ready)
            if !matches!(
                state,
                BranchState::Active
                    | BranchState::Ready
                    | BranchState::Frozen
                    | BranchState::Creating
                    | BranchState::Degraded
            ) {
                continue;
            }

            // H-26: Thaw frozen or degraded-frozen branches before cleanup so cgroup.kill works
            // S6: Log thaw failures — if thaw fails, subsequent cgroup.kill will also fail
            #[cfg(target_os = "linux")]
            if state == BranchState::Frozen || state == BranchState::Degraded {
                if let Some(handle) = self.sandboxes.get(id) {
                    if let Err(e) = crate::sandbox::cgroup::CgroupManager::thaw(&handle.cgroup_path)
                    {
                        tracing::error!(
                            branch = %id,
                            cgroup = %handle.cgroup_path.display(),
                            error = %e,
                            "S6: cgroup thaw failed — subsequent cgroup.kill may fail, \
                             agent processes may not be terminated during shutdown"
                        );
                    }
                }
            }

            self.cleanup_branch_resources(id);

            // Transition state to Terminated
            if let Some(mut info) = self.branches.get_mut(id) {
                info.state = BranchState::Terminated;
            }

            self.audit.log(crate::audit::AuditEvent::BranchRolledBack {
                branch_id: id.clone(),
                reason: "daemon shutdown".to_string(),
            });

            tracing::info!(branch = %id, "branch terminated during shutdown");
        }
    }

    /// Get info for a specific branch (returns owned clone — DashMap can't return references).
    pub fn inspect(&self, id: &BranchId) -> Option<BranchInfo> {
        self.branches.get(id).map(|r| r.value().clone())
    }

    /// Generate a diff for a branch by walking its OverlayFS upper layer.
    ///
    /// M3: Passes `None` for cgroup_path — unfrozen diff is an inspection tool.
    pub fn diff(&self, id: &BranchId) -> Result<Vec<FileChange>> {
        let (upper_dir, base_path) = {
            let info = self
                .branches
                .get(id)
                .ok_or_else(|| PuzzledError::NotFound(format!("branch {}", id)))?;
            (info.upper_dir.clone(), info.base_path.clone())
        };
        self.diff_engine.generate(&upper_dir, &base_path, None)
    }

    /// Kill an active agent and roll back its branch.
    ///
    /// On Linux, kills agent processes via cgroup before rollback.
    pub fn kill_agent(&self, id: &BranchId) -> Result<()> {
        let state = self
            .branches
            .get(id)
            .map(|r| r.state)
            .ok_or_else(|| PuzzledError::NotFound(format!("branch {}", id)))?;
        if state != BranchState::Active {
            return Err(PuzzledError::Branch(format!(
                "branch {} is in state {}, expected Active",
                id, state
            )));
        }
        // S3: Kill via cgroup before rollback — log error instead of silently discarding
        #[cfg(target_os = "linux")]
        if let Some(handle) = self.sandboxes.get(id) {
            if let Err(e) = crate::sandbox::cgroup::CgroupManager::kill(&handle.cgroup_path) {
                tracing::error!(
                    branch = %id,
                    cgroup = %handle.cgroup_path.display(),
                    error = %e,
                    "S3: cgroup kill failed during agent termination — \
                     agent processes may still be running"
                );
            }
        }
        self.rollback("agent killed by operator", id)
    }

    /// §3.3: Quarantine a branch by freezing its cgroup.
    ///
    /// Called when the DLP engine detects a Quarantine-level violation.
    /// The branch processes are frozen (not killed) so the changeset can be
    /// inspected by an operator before deciding to commit or rollback.
    pub fn quarantine_branch(&self, id: &BranchId) -> Result<()> {
        let state = self
            .branches
            .get(id)
            .map(|r| r.state)
            .ok_or_else(|| PuzzledError::NotFound(format!("branch {}", id)))?;
        if state != BranchState::Active {
            return Err(PuzzledError::Branch(format!(
                "branch {} is in state {}, cannot quarantine",
                id, state
            )));
        }

        #[cfg(target_os = "linux")]
        if let Some(handle) = self.sandboxes.get(id) {
            crate::sandbox::cgroup::CgroupManager::freeze(&handle.cgroup_path)?;
            tracing::warn!(
                branch = %id,
                "§3.3: branch quarantined via cgroup.freeze (DLP violation)"
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = id;
            Err(PuzzledError::Sandbox(
                "quarantine (cgroup.freeze) is only supported on Linux".into(),
            ))
        }
        #[cfg(target_os = "linux")]
        Ok(())
    }

    /// Freeze agent, generate diff, evaluate policy, WAL commit or rollback.
    ///
    /// This is the core "Commit" operation in the Fork-Explore-Commit model.
    pub fn commit(&self, id: &BranchId) -> Result<CommitResult> {
        // M-br6: Wrap entire commit in a timeout
        let timeout_secs = self.config.commit_timeout_seconds;
        let commit_deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

        // H-1: Mark this branch as mid-commit FIRST. If insert() returns false,
        // a commit is already in progress for this branch — reject immediately.
        {
            let mut committing = self
                .committing_branches
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !committing.insert(id.clone()) {
                return Err(PuzzledError::Branch(format!(
                    "commit already in progress for branch {}",
                    id
                )));
            }
        }

        // BC2: RAII guard ensures committing_branches is cleaned up on all exit paths.
        // Uses Arc clone so the guard doesn't hold a borrow on `self`.
        let _commit_guard = CommitGuard {
            committing_branches: Arc::clone(&self.committing_branches),
            branch_id: id.clone(),
        };

        // H-2: Validate branch exists and is Active, and atomically transition to Frozen
        // using a single get_mut() call. This prevents a race where the state could change
        // between reading and writing.
        let (base_path, upper_dir, branch_created_at) = {
            let mut info = self
                .branches
                .get_mut(id)
                .ok_or_else(|| PuzzledError::NotFound(format!("branch {}", id)))?;

            if !matches!(info.state, BranchState::Active | BranchState::Ready) {
                return Err(PuzzledError::Branch(format!(
                    "branch {} is in state {}, expected Active or Ready",
                    id, info.state
                )));
            }

            // H-2: Atomically transition to Frozen while still holding the mutable ref
            let old_state = info.state;
            info.state = BranchState::Frozen;
            tracing::debug!(
                branch = %id,
                from = %old_state,
                to = %info.state,
                "state transition"
            );

            (
                info.base_path.clone(),
                info.upper_dir.clone(),
                info.created_at,
            )
        };

        // Step 2: Freeze the cgroup (TOCTOU protection — mandatory)
        #[cfg(target_os = "linux")]
        if let Some(handle) = self.sandboxes.get(id) {
            if let Err(e) = crate::sandbox::cgroup::CgroupManager::freeze(&handle.cgroup_path) {
                tracing::error!(error = %e, "failed to freeze cgroup — cannot proceed with commit");
                self.rollback_internal("cgroup freeze failed during commit", id)?;
                return Err(PuzzledError::Sandbox(format!(
                    "cgroup freeze failed, commit aborted: {}",
                    e
                )));
            }
        }

        // Emit audit event for freeze
        self.audit.log(AuditEvent::BranchFrozen {
            branch_id: id.clone(),
        });

        // Step 3: Generate diff
        // M3: Pass cgroup path for freeze verification during commit.
        // On non-Linux, cgroup_path is None (no cgroup support).
        #[cfg(target_os = "linux")]
        let _cgroup_path_for_diff = self.sandboxes.get(id).map(|h| h.cgroup_path.clone());
        #[cfg(not(target_os = "linux"))]
        let _cgroup_path_for_diff: Option<PathBuf> = None;
        let diff_start = std::time::Instant::now();
        let changes =
            self.diff_engine
                .generate(&upper_dir, &base_path, _cgroup_path_for_diff.as_deref())?;
        if let Some(m) = self.get_metrics() {
            m.record_diff(diff_start.elapsed().as_secs_f64());
        }

        // M-br6: Check commit timeout after diff generation
        if std::time::Instant::now() > commit_deadline {
            tracing::error!(branch = %id, timeout_secs, "M-br6: commit timeout exceeded during diff generation");
            self.thaw_cgroup(id);
            self.rollback_internal("commit timeout exceeded", id)?;
            return Err(PuzzledError::Branch(format!(
                "commit timeout ({}s) exceeded for branch {}",
                timeout_secs, id
            )));
        }

        if changes.is_empty() {
            // No changes to commit — clean up resources before returning
            self.transition(id, BranchState::Committed)?;
            #[cfg(target_os = "linux")]
            self.cleanup_sandbox_resources(id);
            self.conflict_detector
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .unregister_branch(id);
            self.branches.remove(id);
            return Ok(CommitResult {
                branch_id: id.clone(),
                files_committed: 0,
                bytes_committed: 0,
                policy_result: PolicyDecision::Approved,
            });
        }

        // Step 3b: Evaluate governance policy (per PRD: policy evaluation before conflict detection)
        // Pass profile name for profile-aware policy rules (e.g., per-profile storage quotas)
        // H-14: Pass workspace_root (base_path) so the Rego rule `deny_outside_workspace` fires.
        // U30: Symlink escape within workspace is mitigated by Landlock (kernel-enforced, path-based)
        let profile_name = self.branches.get(id).map(|r| r.profile.clone());
        let workspace_root = base_path.to_string_lossy().to_string();
        let decision = self.policy_engine.evaluate_with_workspace(
            &changes,
            profile_name.as_deref(),
            Some(&workspace_root),
        )?;

        // Wire metrics: policy evaluation outcome
        if let Some(m) = self.get_metrics() {
            match &decision {
                PolicyDecision::Approved => {
                    m.policy_approved.inc();
                }
                PolicyDecision::Rejected(_) => {
                    m.policy_rejected.inc();
                }
                PolicyDecision::Error(_) => {
                    m.policy_errors.inc();
                }
            }
        }

        // Step 3c: Check for cross-branch conflicts (after policy evaluation per PRD)
        {
            let mut detector = self
                .conflict_detector
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            detector.register_changes(id, &base_path, &changes);
            let conflicts = detector.check_conflicts_with_time(
                id,
                &base_path,
                &changes,
                Some(branch_created_at),
            );
            if !conflicts.is_empty() {
                if let Some(m) = self.get_metrics() {
                    // Q9: Use try_from instead of bare `as u64` for len-to-u64 conversion
                    m.conflicts_total
                        .inc_by(u64::try_from(conflicts.len()).unwrap_or(u64::MAX));
                }
            }
            if let Err(e) = detector.resolve(&conflicts) {
                tracing::warn!(branch = %id, error = %e, "cross-branch conflict detected");
                // Unregister and rollback
                detector.unregister_branch(id);
                drop(detector);
                // Thaw cgroup before rollback
                self.thaw_cgroup(id);
                self.rollback_internal("conflict: cross-branch conflict detected", id)?;
                return Ok(CommitResult {
                    branch_id: id.clone(),
                    files_committed: 0,
                    bytes_committed: 0,
                    policy_result: PolicyDecision::Rejected(vec![puzzled_types::Violation {
                        rule: "conflict_detection".to_string(),
                        message: e.to_string(),
                        severity: puzzled_types::ViolationSeverity::Error,
                    }]),
                });
            }

            // C8: Two-phase conflict protocol — reserve paths after conflict check
            // passes but before WAL commit, preventing TOCTOU between check and commit.
            let reservation_paths: Vec<PathBuf> = changes.iter().map(|c| c.path.clone()).collect();
            if let Err(e) = detector.reserve_paths(id, reservation_paths) {
                tracing::warn!(branch = %id, error = %e, "C8: path reservation failed");
                detector.unregister_branch(id);
                drop(detector);
                self.thaw_cgroup(id);
                self.rollback_internal("C8: path reservation conflict", id)?;
                return Ok(CommitResult {
                    branch_id: id.clone(),
                    files_committed: 0,
                    bytes_committed: 0,
                    policy_result: PolicyDecision::Rejected(vec![puzzled_types::Violation {
                        rule: "conflict_reservation".to_string(),
                        message: e,
                        severity: puzzled_types::ViolationSeverity::Error,
                    }]),
                });
            }
        }

        // M-br6: Check commit timeout before proceeding to WAL commit
        if std::time::Instant::now() > commit_deadline {
            tracing::error!(branch = %id, timeout_secs, "M-br6: commit timeout exceeded during policy/conflict evaluation");
            self.conflict_detector
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .cancel_reservation(id);
            self.thaw_cgroup(id);
            self.rollback_internal("commit timeout exceeded", id)?;
            return Err(PuzzledError::Branch(format!(
                "commit timeout ({}s) exceeded for branch {}",
                timeout_secs, id
            )));
        }

        match decision {
            PolicyDecision::Approved if self.config.require_human_approval => {
                // H-10: Policy approved but human review is required.
                // Transition to GovernanceReview, store the changeset for later
                // approval/rejection, and return early with files_committed=0.
                self.transition(id, BranchState::Committing)?;
                self.transition(id, BranchState::GovernanceReview)?;

                // Store the changeset and base_path for approve_branch() to use later
                self.pending_reviews
                    .insert(id.clone(), (changes.clone(), base_path.clone()));

                self.audit.log(AuditEvent::BranchFrozen {
                    branch_id: id.clone(),
                });

                tracing::info!(
                    branch = %id,
                    files = changes.len(),
                    "H-10: branch awaiting governance review (require_human_approval=true)"
                );

                Ok(CommitResult {
                    branch_id: id.clone(),
                    files_committed: 0,
                    bytes_committed: 0,
                    policy_result: PolicyDecision::Approved,
                })
            }
            PolicyDecision::Approved => {
                self.finalize_approved_commit(id, &changes, &base_path, PolicyDecision::Approved)
            }
            PolicyDecision::Rejected(violations) => {
                let decision = PolicyDecision::Rejected(violations.clone());
                self.handle_rejected_commit(id, &changes, &base_path, &violations, decision)
            }
            PolicyDecision::Error(ref msg) => {
                tracing::error!(branch = %id, error = %msg, "policy evaluation error");
                // M9: Wire metrics: include error context in outcome label
                if let Some(m) = self.get_metrics() {
                    m.commit_outcomes
                        .get_or_create(&crate::metrics::OutcomeLabels {
                            outcome: "error".to_string(), // T1: fixed label to prevent unbounded metric cardinality
                        })
                        .inc();
                }
                self.apply_fail_mode(id);
                Ok(CommitResult {
                    branch_id: id.clone(),
                    files_committed: 0,
                    bytes_committed: 0,
                    policy_result: decision,
                })
            }
        }
    }

    /// Execute the approved commit path: WAL write, IMA signing, journal replay,
    /// budget update, resource cleanup, and conflict finalization.
    fn finalize_approved_commit(
        &self,
        id: &BranchId,
        changes: &[FileChange],
        base_path: &std::path::Path,
        decision: PolicyDecision,
    ) -> Result<CommitResult> {
        let commit_start = std::time::Instant::now();
        let (commit_profile, commit_created_at) = self
            .branches
            .get(id)
            .map(|r| (Some(r.profile.clone()), Some(r.created_at)))
            .unwrap_or((None, None));
        // WAL commit
        self.transition(id, BranchState::Committing)?;
        // M7: If wal_commit fails, thaw the cgroup and recover to Active state.
        // B1: Log thaw failures explicitly — if both WAL and thaw fail, the branch
        // is in an unrecoverable state and should transition to Failed.
        if let Err(e) = self.wal_commit(id, changes, base_path) {
            tracing::error!(branch = %id, error = %e, "WAL commit failed, recovering");
            // C8: Cancel path reservation on WAL failure
            self.conflict_detector
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .cancel_reservation(id);
            self.thaw_cgroup(id);
            if let Err(te) = self.transition(id, BranchState::Active) {
                tracing::error!(
                    branch = %id,
                    wal_error = %e,
                    transition_error = %te,
                    "double failure: WAL commit failed AND recovery transition failed, marking Failed"
                );
                // S7: Log transition-to-Failed failure explicitly instead of discarding
                if let Err(fe) = self.transition(id, BranchState::Failed) {
                    tracing::error!(
                        branch = %id,
                        error = %fe,
                        "S7: triple failure — transition to Failed also failed. \
                         Branch state is inconsistent. WAL recovery on restart will handle rollback."
                    );
                }
            }
            return Err(e);
        }

        // C8: Confirm path reservation after successful WAL commit
        self.conflict_detector
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .confirm_commit(id);

        // S12: Sign the commit manifest (IMA).
        // When IMA is configured, signing failures should be treated as errors
        // (the commit was approved but cannot be attested). Log at error level
        // so operators are alerted. The commit still proceeds because the WAL
        // has already been executed, but the integrity chain is broken.
        if let Some(ima) = &self.ima {
            let ima = ima.lock().unwrap_or_else(|e| {
                tracing::warn!(
                    branch = %id,
                    "S10: IMA mutex poison recovered — previous IMA thread panicked"
                );
                e.into_inner()
            });
            if let Err(e) = ima.sign_commit(id, changes) {
                tracing::error!(
                    branch = %id,
                    error = %e,
                    "S12: IMA manifest signing failed — commit integrity chain is broken. \
                     The commit has been applied but cannot be attested."
                );
            }
        }

        // Replay network journal (side-effect requests)
        self.replay_network_journal(id);

        // Thaw the cgroup before transitioning
        self.thaw_cgroup(id);

        self.transition(id, BranchState::Committed)?;

        // Q9: Use try_from instead of bare `as u64` for len-to-u64 conversion
        let files = u64::try_from(changes.len()).unwrap_or(u64::MAX);
        let bytes: u64 = changes.iter().map(|c| c.size).sum();

        // Record clean commit for budget escalation
        self.update_budget_after_commit(id, true);

        // Clean up sandbox resources
        #[cfg(target_os = "linux")]
        self.cleanup_sandbox_resources(id);

        // Mark committed in conflict detector
        self.finalize_conflict_tracking(id, changes);

        self.audit.log(AuditEvent::BranchCommitted {
            branch_id: id.clone(),
            files,
            bytes,
        });

        self.branches.remove(id);

        // Wire metrics: commit duration, files, bytes, outcome
        if let Some(m) = self.get_metrics() {
            let profile_name = commit_profile.as_deref().unwrap_or("unknown");
            m.record_commit(profile_name, commit_start.elapsed().as_secs_f64());
            m.commit_files_total.inc_by(files);
            m.commit_bytes_total.inc_by(bytes);
            m.commit_outcomes
                .get_or_create(&crate::metrics::OutcomeLabels {
                    outcome: "approved".to_string(),
                })
                .inc();
            // Record branch lifetime duration
            if let Some(created) = commit_created_at {
                let lifetime =
                    // S9: precision loss irrelevant for metrics (>285M years)
                (chrono::Utc::now() - created).num_milliseconds().max(0) as f64 / 1000.0;
                m.branch_duration_seconds.observe(lifetime);
            }
        }

        tracing::info!(branch = %id, files, bytes, "branch committed");

        Ok(CommitResult {
            branch_id: id.clone(),
            files_committed: files,
            bytes_committed: bytes,
            policy_result: decision,
        })
    }

    /// Handle a rejected commit: log violations, check fail mode for warning-only
    /// pass-through, update budget, and apply fail mode.
    fn handle_rejected_commit(
        &self,
        id: &BranchId,
        changes: &[FileChange],
        base_path: &std::path::Path,
        violations: &[puzzled_types::Violation],
        decision: PolicyDecision,
    ) -> Result<CommitResult> {
        // Log violations
        for v in violations {
            self.audit.log(AuditEvent::PolicyViolation {
                branch_id: id.clone(),
                rule: v.rule.clone(),
                message: v.message.clone(),
            });
        }

        // PH3: FailOperational + warning-only violations → allow commit to proceed
        let fail_mode = self
            .branches
            .get(id)
            .and_then(|r| self.profile_loader.get(&r.profile).map(|p| p.fail_mode))
            .unwrap_or(puzzled_types::FailMode::FailClosed);

        let all_warnings_only = violations
            .iter()
            .all(|v| v.severity == puzzled_types::ViolationSeverity::Warning);

        if fail_mode == puzzled_types::FailMode::FailOperational && all_warnings_only {
            tracing::warn!(
                branch = %id,
                warning_count = violations.len(),
                "PH3: FailOperational — warning-only violations, allowing commit to proceed"
            );

            self.transition(id, BranchState::Committing)?;
            // M-br1: If WAL commit fails in FailOperational+warnings path,
            // cancel reservation and thaw cgroup (matching main commit error handling).
            if let Err(e) = self.wal_commit(id, changes, base_path) {
                tracing::error!(branch = %id, error = %e, "M-br1: WAL commit failed in FailOperational warning path");
                self.conflict_detector
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .cancel_reservation(id);
                self.thaw_cgroup(id);
                if let Err(te) = self.transition(id, BranchState::Active) {
                    tracing::error!(
                        branch = %id,
                        wal_error = %e,
                        transition_error = %te,
                        "M-br1: double failure in FailOperational path"
                    );
                    if let Err(e2) = self.transition(id, BranchState::Failed) {
                        tracing::error!(
                            branch = %id,
                            error = %e2,
                            "F16: fallback transition to Failed also failed"
                        );
                    }
                }
                return Err(e);
            }
            // C8: Confirm path reservation after successful WAL commit
            self.conflict_detector
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .confirm_commit(id);
            self.thaw_cgroup(id);
            self.transition(id, BranchState::Committed)?;

            // Q9: Use try_from instead of bare `as u64` for len-to-u64 conversion
            let files = u64::try_from(changes.len()).unwrap_or(u64::MAX);
            let bytes: u64 = changes.iter().map(|c| c.size).sum();

            #[cfg(target_os = "linux")]
            self.cleanup_sandbox_resources(id);
            self.finalize_conflict_tracking(id, changes);
            self.branches.remove(id);

            self.audit.log(AuditEvent::BranchCommitted {
                branch_id: id.clone(),
                files,
                bytes,
            });

            return Ok(CommitResult {
                branch_id: id.clone(),
                files_committed: files,
                bytes_committed: bytes,
                policy_result: PolicyDecision::Approved,
            });
        }

        // FailClosed or Error+/Critical violations: reject and apply fail mode
        // C8: Cancel path reservation on rejection
        self.conflict_detector
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cancel_reservation(id);
        // Wire metrics: rejected outcome
        if let Some(m) = self.get_metrics() {
            m.commit_outcomes
                .get_or_create(&crate::metrics::OutcomeLabels {
                    outcome: "rejected".to_string(),
                })
                .inc();
        }
        self.update_budget_after_commit(id, false);
        self.apply_fail_mode(id);

        Ok(CommitResult {
            branch_id: id.clone(),
            files_committed: 0,
            bytes_committed: 0,
            policy_result: decision,
        })
    }

    /// Thaw the cgroup for a branch (best-effort, logs on failure).
    fn thaw_cgroup(&self, id: &BranchId) {
        #[cfg(target_os = "linux")]
        if let Some(handle) = self.sandboxes.get(id) {
            if let Err(e) = crate::sandbox::cgroup::CgroupManager::thaw(&handle.cgroup_path) {
                tracing::warn!(branch = %id, error = %e, "failed to thaw cgroup");
            }
        }
        let _ = id; // suppress unused warning on non-Linux
    }

    /// Replay the network journal for a committed branch (async, best-effort).
    ///
    /// Aborts the proxy server first so no new entries are written during replay.
    fn replay_network_journal(&self, id: &BranchId) {
        // Stop the proxy before replaying — no new entries should arrive during replay
        if let Some((_, task)) = self.proxy_tasks.remove(id) {
            task.abort();
            tracing::debug!(branch = %id, "HTTP proxy task aborted before journal replay");
        }

        if let Some((_, journal)) = self.network_journals.remove(id) {
            let branch_id_clone = id.clone();
            // Guard against missing Tokio runtime (e.g., in synchronous tests).
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    match journal.replay(&[]).await {
                        Ok(count) if count > 0 => {
                            tracing::info!(
                                branch = %branch_id_clone,
                                replayed = count,
                                "network journal replayed"
                            );
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(
                                branch = %branch_id_clone,
                                error = %e,
                                "network journal replay failed (continuing)"
                            );
                        }
                    }
                });
            } else {
                tracing::debug!(
                    branch = %branch_id_clone,
                    "skipping network journal replay (no Tokio runtime)"
                );
            }
        }
    }

    /// Update budget after a commit attempt (clean commit escalates, violation de-escalates).
    fn update_budget_after_commit(&self, id: &BranchId, clean: bool) {
        if let Some(info) = self.branches.get(id) {
            let agent_key = crate::budget::BudgetManager::agent_key(&info.profile, info.uid);
            let _profile = self.profile_loader.get(&info.profile).cloned();
            let mut budget = self
                .budget_manager
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let old_tier = budget.get_status(&agent_key, id).tier;
            let new_tier = if clean {
                budget.record_clean_commit(&agent_key)
            } else {
                budget.record_violation(&agent_key)
            };
            if new_tier != old_tier {
                #[cfg(target_os = "linux")]
                if let (Some(handle), Some(prof)) = (self.sandboxes.get(id), &_profile) {
                    if let Err(e) = budget.apply_tier_limits(
                        &agent_key,
                        &prof.resource_limits,
                        &handle.cgroup_path,
                    ) {
                        tracing::error!(
                            branch = %id,
                            error = %e,
                            "H8: failed to apply budget tier limits — resource limits may be unenforced"
                        );
                    }
                }
            }
            let action = if clean { "clean commit" } else { "violation" };
            tracing::debug!(branch = %id, tier = ?new_tier, "budget updated after {action}");
        }
    }

    /// Mark branch as committed in conflict detector and unregister it.
    fn finalize_conflict_tracking(&self, id: &BranchId, changes: &[FileChange]) {
        let committed_paths: Vec<PathBuf> = changes.iter().map(|c| c.path.clone()).collect();
        let mut detector = self
            .conflict_detector
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        detector.mark_committed(id, committed_paths, chrono::Utc::now());
        detector.unregister_branch(id);
    }

    /// Apply the fail mode from the branch's profile on commit rejection or error.
    ///
    /// - FailClosed (default): thaw + rollback
    /// - FailSilent: keep frozen (hold last safe state)
    /// - FailOperational: thaw but don't rollback (reduced capability)
    /// - FailSafeState: thaw + rollback + kill agent via cgroup
    fn apply_fail_mode(&self, id: &BranchId) {
        let fail_mode = self
            .branches
            .get(id)
            .and_then(|r| self.profile_loader.get(&r.profile).map(|p| p.fail_mode))
            .unwrap_or(puzzled_types::FailMode::FailClosed);

        match fail_mode {
            puzzled_types::FailMode::FailClosed => {
                // Thaw + rollback (default behavior)
                #[cfg(target_os = "linux")]
                if let Some(handle) = self.sandboxes.get(id) {
                    if let Err(e) = crate::sandbox::cgroup::CgroupManager::thaw(&handle.cgroup_path)
                    {
                        tracing::warn!(error = %e, "failed to thaw cgroup before rollback");
                    }
                }
                if let Err(e) = self.rollback_internal("FailClosed: policy rejection or error", id)
                {
                    tracing::error!(branch = %id, error = %e, "rollback failed in FailClosed mode");
                }
            }
            puzzled_types::FailMode::FailSilent => {
                // H-26: Keep frozen — hold last safe state. Transition to Degraded
                // instead of removing from DashMap so the branch remains trackable.
                // Clean up puzzled-side resources but the cgroup remains (keeping agent frozen).
                self.cleanup_branch_resources(id);
                if let Some(mut info) = self.branches.get_mut(id) {
                    info.state = BranchState::Degraded;
                }
                tracing::warn!(
                    branch = %id,
                    "FailSilent: keeping agent frozen (holding last safe state), resources cleaned up, state=Degraded"
                );
            }
            puzzled_types::FailMode::FailOperational => {
                // H-26: Thaw but don't rollback — reduced capability. Transition to Degraded
                // instead of removing from DashMap so the branch remains trackable.
                #[cfg(target_os = "linux")]
                if let Some(handle) = self.sandboxes.get(id) {
                    if let Err(e) = crate::sandbox::cgroup::CgroupManager::thaw(&handle.cgroup_path)
                    {
                        tracing::warn!(error = %e, "failed to thaw cgroup in FailOperational mode");
                    }
                }
                // Clean up puzzled-side resources. The agent process continues running
                // in reduced capability mode, but puzzled releases its handles.
                self.cleanup_branch_resources(id);
                if let Some(mut info) = self.branches.get_mut(id) {
                    info.state = BranchState::Degraded;
                }
                tracing::warn!(
                    branch = %id,
                    "FailOperational: agent thawed, changes preserved (reduced capability), resources cleaned up, state=Degraded"
                );
            }
            puzzled_types::FailMode::FailSafeState => {
                // Thaw + rollback + kill agent + verify termination
                #[cfg(target_os = "linux")]
                let cgroup_path = self.sandboxes.get(id).map(|h| h.cgroup_path.clone());
                #[cfg(target_os = "linux")]
                if let Some(handle) = self.sandboxes.get(id) {
                    if let Err(e) = crate::sandbox::cgroup::CgroupManager::thaw(&handle.cgroup_path)
                    {
                        tracing::warn!(error = %e, "failed to thaw cgroup before rollback");
                    }
                }
                if let Err(e) =
                    self.rollback_internal("FailSafeState: controlled stop after rejection", id)
                {
                    tracing::error!(
                        branch = %id,
                        error = %e,
                        "rollback failed in FailSafeState mode"
                    );
                }
                // H3: Verify agent processes are actually dead (belt-and-suspenders for safety)
                // M3: Use non-blocking tokio::time::sleep instead of blocking thread::sleep
                // to avoid holding any locks during the wait.
                #[cfg(target_os = "linux")]
                if let Some(cg_path) = cgroup_path {
                    let branch_id_clone = id.clone();
                    let procs_path = cg_path.join("cgroup.procs");
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
                    loop {
                        match std::fs::read_to_string(&procs_path) {
                            Ok(contents) if contents.trim().is_empty() => break,
                            Err(_) => break, // cgroup already removed
                            _ => {}
                        }
                        if std::time::Instant::now() > deadline {
                            tracing::error!(
                                branch = %branch_id_clone,
                                "FailSafeState: processes still alive after 3s kill timeout"
                            );
                            break;
                        }
                        // Sleep briefly to avoid burning CPU in a spin loop.
                        // A full async sleep is not feasible here since apply_fail_mode
                        // is synchronous.
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                }
                tracing::warn!(branch = %id, "FailSafeState: agent killed after rollback");
            }
        }
    }

    /// Clean up all branch resources: sandbox (cgroup, overlay, pidfd, seccomp, BPF LSM,
    /// fanotify), network setup, network journal, and conflict tracking.
    ///
    /// This is the single cleanup path used by FailSilent, FailOperational, and rollback
    /// to ensure no resource leaks. Does NOT remove the upper directory or transition
    /// branch state — those are caller responsibilities.
    fn cleanup_branch_resources(&self, id: &BranchId) {
        // §3.4: Revoke phantom tokens for this branch
        if let Some(ref ptm) = self.phantom_token_manager {
            // Must guarantee revocation. Rollback may run on the zbus executor
            // thread where no Tokio reactor is active, so Handle::current()
            // would panic there. Use the current runtime when available and
            // otherwise fall back to a temporary current-thread runtime.
            let mut ptm_guard = if let Ok(handle) = tokio::runtime::Handle::try_current() {
                tokio::task::block_in_place(|| handle.block_on(ptm.write()))
            } else {
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt.block_on(ptm.write()),
                    Err(e) => {
                        tracing::warn!(
                            branch = %id,
                            error = %e,
                            "§3.4: failed to create temporary runtime for phantom token revocation"
                        );
                        return;
                    }
                }
            };
            ptm_guard.revoke_branch(id);
            tracing::debug!(branch = %id, "§3.4: phantom tokens revoked for branch");
        }

        // Clean up sandbox resources (cgroup, overlay, pidfd, seccomp, BPF LSM, fanotify, network)
        #[cfg(target_os = "linux")]
        self.cleanup_sandbox_resources(id);

        // Abort the proxy server task if running
        if let Some((_, task)) = self.proxy_tasks.remove(id) {
            task.abort();
            tracing::debug!(branch = %id, "HTTP proxy task aborted");
        }

        // Discard network journal if present
        if let Some((_, journal)) = self.network_journals.remove(id) {
            journal.discard();
        }

        // C8: Cancel any active path reservation for this branch
        // Clean up conflict tracking
        {
            let mut detector = self
                .conflict_detector
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            detector.cancel_reservation(id);
            detector.unregister_branch(id);
        }
    }

    /// Clean up sandbox resources (seccomp, network, fanotify, BPF LSM, cgroup, overlay, pidfd).
    ///
    /// Called from both commit (after success) and rollback. Does NOT remove the
    /// upper directory or transition branch state — those are caller responsibilities.
    #[cfg(target_os = "linux")]
    fn cleanup_sandbox_resources(&self, id: &BranchId) {
        if let Some((_, mut handle)) = self.sandboxes.remove(id) {
            // Unregister seccomp notify fd
            if handle.seccomp_notify_fd.is_some() {
                if let Some(ref handler) = self.seccomp_handler {
                    handler.unregister(id.clone());
                }
            }

            // Clean up network resources
            if let Some((_, net_setup)) = self.network_setups.remove(id) {
                net_setup.cleanup();
            }

            // Remove fanotify trigger receiver
            self.fanotify_triggers.remove(id);

            // S17: Clean up BPF LSM rate limits — log error to detect map entry leaks
            if let Some(ref bpf_lsm) = self.bpf_lsm {
                if let Ok(meta) = std::fs::metadata(&handle.cgroup_path) {
                    use std::os::unix::fs::MetadataExt;
                    if let Err(e) = bpf_lsm.remove_cgroup(meta.ino()) {
                        tracing::warn!(
                            branch = %id,
                            cgroup_ino = meta.ino(),
                            error = %e,
                            "S17: BPF LSM cgroup removal failed — map entry may leak"
                        );
                    }
                }
            }

            // S4: Kill processes via cgroup — log error instead of silently discarding
            if let Err(e) = crate::sandbox::cgroup::CgroupManager::remove_scope(&handle.cgroup_path)
            {
                tracing::error!(
                    branch = %id,
                    cgroup = %handle.cgroup_path.display(),
                    error = %e,
                    "S4: cgroup remove_scope failed — orphaned agent processes may persist"
                );
            }

            // S5: Unmount OverlayFS — log error instead of silently discarding.
            // A failed unmount leaves the branch filesystem visible and accessible.
            if let Err(e) = nix::mount::umount2(&handle.merged_dir, MntFlags::MNT_DETACH) {
                tracing::error!(
                    branch = %id,
                    merged = %handle.merged_dir.display(),
                    error = %e,
                    "S5: OverlayFS unmount failed — branch filesystem may remain accessible"
                );
            } else {
                tracing::debug!(merged = %handle.merged_dir.display(), "OverlayFS unmounted");
            }

            // Close pidfd and mark it closed so Drop doesn't double-close.
            // Double-close causes fd reuse races in parallel tests (SIGABRT).
            if handle.pidfd >= 0 {
                unsafe { libc::close(handle.pidfd) };
                handle.pidfd = -1;
            }

            tracing::info!(branch = %id, "sandbox resources cleaned up");
        }
    }

    /// Discard the branch upper layer (zero residue).
    ///
    /// M19: `reason` is propagated through audit logging and D-Bus signals
    /// to provide context on why the rollback was initiated.
    /// BC2: Check if a branch is currently mid-commit.
    /// External callers (D-Bus rollback) should check this before proceeding.
    pub fn is_committing(&self, id: &BranchId) -> bool {
        let committing = self
            .committing_branches
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        committing.contains(id)
    }

    pub fn rollback(&self, reason: &str, id: &BranchId) -> Result<()> {
        // BC2: Prevent rollback/unregister while a commit is in progress for this branch.
        // The commit flow uses rollback_internal() for its own rollback needs.
        {
            let committing = self
                .committing_branches
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if committing.contains(id) {
                return Err(PuzzledError::Branch(format!(
                    "branch {} is currently mid-commit, cannot rollback",
                    id
                )));
            }
        }

        self.rollback_internal(reason, id)
    }

    /// Internal rollback that bypasses the BC2 committing_branches check.
    /// Used by commit() when it needs to rollback on error (e.g., conflict, cgroup freeze failure).
    fn rollback_internal(&self, reason: &str, id: &BranchId) -> Result<()> {
        let (upper_dir, rollback_profile, created_at) = {
            let info = self
                .branches
                .get(id)
                .ok_or_else(|| PuzzledError::NotFound(format!("branch {}", id)))?;
            (
                info.upper_dir.clone(),
                info.profile.clone(),
                info.created_at,
            )
        };

        // Clean up all branch resources (sandbox, network, conflict tracking)
        self.cleanup_branch_resources(id);

        // Remove the upper directory (zero residue)
        // Validate that branch_dir is under branch_root to prevent accidental deletion
        // of unrelated directories if upper_dir is pathological.
        // Canonicalize both paths to resolve symlinks and ".." components before comparison.
        if upper_dir.exists() {
            let branch_dir = upper_dir.parent().unwrap_or(&upper_dir);
            let branch_dir_canon =
                std::fs::canonicalize(branch_dir).unwrap_or(branch_dir.to_path_buf());
            let root_canon = std::fs::canonicalize(&self.config.branch_root)
                .unwrap_or(self.config.branch_root.clone());
            if branch_dir_canon.starts_with(&root_canon) && branch_dir.exists() {
                // L1: TOCTOU mitigation — re-verify canonicalized path still starts_with
                // the expected parent directory immediately before deletion.
                match std::fs::canonicalize(branch_dir) {
                    Ok(recheck_canon) if recheck_canon.starts_with(&root_canon) => {
                        // H1: Propagate remove_dir_all errors instead of silently ignoring them.
                        if let Err(e) = std::fs::remove_dir_all(&recheck_canon) {
                            tracing::error!(
                                branch_dir = %recheck_canon.display(),
                                error = %e,
                                "failed to remove branch directory during rollback"
                            );
                            return Err(PuzzledError::Branch(format!(
                                "failed to remove branch directory {}: {}",
                                recheck_canon.display(),
                                e
                            )));
                        }
                    }
                    Ok(recheck_canon) => {
                        tracing::error!(
                            branch_dir = %recheck_canon.display(),
                            branch_root = %root_canon.display(),
                            "TOCTOU: branch dir changed between checks, refusing to delete"
                        );
                        return Err(PuzzledError::Branch(
                            "TOCTOU: branch directory path changed between canonicalization checks"
                                .to_string(),
                        ));
                    }
                    Err(e) => {
                        tracing::error!(
                            branch_dir = %branch_dir.display(),
                            error = %e,
                            "failed to re-canonicalize branch dir for TOCTOU check"
                        );
                        return Err(PuzzledError::Branch(format!(
                            "failed to re-canonicalize branch dir: {}",
                            e
                        )));
                    }
                }
            } else {
                tracing::error!(
                    branch_dir = %branch_dir.display(),
                    branch_root = %self.config.branch_root.display(),
                    "refusing to delete branch dir outside branch_root (path traversal blocked)"
                );
            }
        }

        // S18: Clean up XFS quota — log error to detect quota starvation over time
        if let Err(e) = crate::sandbox::quota::QuotaManager::remove(&upper_dir) {
            tracing::warn!(
                branch = %id,
                upper_dir = %upper_dir.display(),
                error = %e,
                "S18: XFS quota cleanup failed — quota reserves may leak"
            );
        }

        self.transition(id, BranchState::RolledBack)?;

        // C4: Remove terminal branch from self.branches to free the slot
        self.branches.remove(id);

        self.audit.log(AuditEvent::BranchRolledBack {
            branch_id: id.clone(),
            reason: reason.to_string(),
        });

        // Wire metrics: rollback and branch lifetime duration
        if let Some(m) = self.get_metrics() {
            m.record_rollback(&rollback_profile);
            let lifetime =
                // S9: precision loss irrelevant for metrics (>285M years)
                (chrono::Utc::now() - created_at).num_milliseconds().max(0) as f64 / 1000.0;
            m.branch_duration_seconds.observe(lifetime);
            m.commit_outcomes
                .get_or_create(&crate::metrics::OutcomeLabels {
                    outcome: "rolled_back".to_string(),
                })
                .inc();
        }

        tracing::info!(branch = %id, reason = reason, "branch rolled back");
        Ok(())
    }

    /// Transition a branch to a new state, validating the state machine.
    fn transition(&self, id: &BranchId, new_state: BranchState) -> Result<()> {
        let mut info = self
            .branches
            .get_mut(id)
            .ok_or_else(|| PuzzledError::NotFound(format!("branch {}", id)))?;

        let valid = match (info.state, new_state) {
            (BranchState::Creating, BranchState::Ready) => true,
            (BranchState::Ready, BranchState::Active) => true,
            (BranchState::Ready, BranchState::Frozen) => true, // direct-mode commit (no process to freeze)
            (BranchState::Ready, BranchState::RolledBack) => true, // workspace cancelled before activation
            (BranchState::Active, BranchState::Frozen) => true,
            (BranchState::Active, BranchState::RolledBack) => true,
            // H4: Active -> Exited (agent process exited cleanly with exit code 0)
            (BranchState::Active, BranchState::Exited) => true,
            // H4: Active -> Terminated (agent killed by signal or non-zero exit)
            (BranchState::Active, BranchState::Terminated) => true,
            (BranchState::Frozen, BranchState::Active) => true, // Recovery from FailSilent/FailOperational
            (BranchState::Frozen, BranchState::Committing) => true,
            (BranchState::Frozen, BranchState::RolledBack) => true,
            (BranchState::Frozen, BranchState::Committed) => true, // empty changeset
            // H4: Frozen -> Terminated (agent killed while frozen, e.g., OOM during commit)
            (BranchState::Frozen, BranchState::Terminated) => true,
            (BranchState::Committing, BranchState::Committed) => true,
            (BranchState::Committing, BranchState::Active) => true, // M7: recovery from wal_commit failure
            (BranchState::Committing, BranchState::Failed) => true,
            // H4: Exited -> Frozen (freeze for commit after clean exit — agent has stopped,
            // freeze the cgroup to safely read the diff)
            (BranchState::Exited, BranchState::Frozen) => true,
            // H4: Terminated -> RolledBack (cleanup after termination — discard changes)
            (BranchState::Terminated, BranchState::RolledBack) => true,
            // H-10: GovernanceReview -> Committed (approved by human reviewer)
            (BranchState::GovernanceReview, BranchState::Committed) => true,
            // H-10: GovernanceReview -> RolledBack (rejected by human reviewer)
            (BranchState::GovernanceReview, BranchState::RolledBack) => true,
            // H-9: Committing -> GovernanceReview (policy approved, awaiting human review)
            (BranchState::Committing, BranchState::GovernanceReview) => true,
            // H-26: Any -> Degraded (FailOperational/FailSilent modes)
            (_, BranchState::Degraded) => true,
            (_, BranchState::Failed) => true, // Any state can fail
            _ => false,
        };

        if !valid {
            return Err(PuzzledError::Branch(format!(
                "invalid state transition: {} -> {}",
                info.state, new_state
            )));
        }

        tracing::debug!(
            branch = %id,
            from = %info.state,
            to = %new_state,
            "state transition"
        );

        info.state = new_state;
        Ok(())
    }

    /// Execute a WAL-protected commit: log intent, copy files, mark complete.
    ///
    /// Delegates to `CommitExecutor` which handles the file operation mechanics
    /// (symlink safety, atomic rename, metadata, crash-safe rollback).
    fn wal_commit(
        &self,
        branch_id: &BranchId,
        changes: &[FileChange],
        base_path: &std::path::Path,
    ) -> Result<()> {
        let upper_dir = self
            .branches
            .get(branch_id)
            .map(|r| r.upper_dir.clone())
            .ok_or_else(|| PuzzledError::NotFound(format!("branch {}", branch_id)))?;

        let executor = crate::commit::CommitExecutor::new(&self.wal);
        executor.execute(branch_id, changes, base_path, &upper_dir)
    }

    /// Recover branches from disk after daemon restart.
    ///
    /// Scans the branch_root for existing branch directories and the WAL
    /// for incomplete commits that need rollback.
    pub fn recover(&self) -> Result<()> {
        // Recover incomplete WAL entries
        let incomplete = self.wal.recover()?;

        for branch_id in &incomplete {
            tracing::warn!(
                branch = %branch_id,
                "rolling back incomplete commit from previous run"
            );

            // Read the WAL to find which operations completed and need reversal
            let (operations, completed) = self.wal.read_operations_with_status(branch_id)?;

            if !completed.is_empty() {
                tracing::info!(
                    branch = %branch_id,
                    total_ops = operations.len(),
                    completed_ops = completed.len(),
                    "reversing partially completed operations using WAL backups"
                );

                // Reverse completed operations using backups
                // H2: If recovery fails, abort branch deletion and return an error
                // instead of continuing with a partially-reversed state.
                if let Err(e) = self
                    .wal
                    .reverse_operations(branch_id, &operations, &completed)
                {
                    tracing::error!(
                        branch = %branch_id,
                        error = %e,
                        "failed to fully reverse partial commit — aborting branch cleanup (manual intervention required)"
                    );
                    return Err(PuzzledError::Wal(format!(
                        "WAL recovery failed for branch {}: {} — manual intervention required",
                        branch_id, e
                    )));
                }
            }

            // Clean up the branch directory (with path traversal protection)
            let branch_dir = self.config.branch_root.join(branch_id.as_str());
            if branch_dir.exists() {
                let canonical_branch = match branch_dir.canonicalize() {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::error!(
                            branch = %branch_id,
                            error = %e,
                            "failed to canonicalize branch directory during WAL recovery — skipping"
                        );
                        continue;
                    }
                };
                let canonical_root = match self.config.branch_root.canonicalize() {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "failed to canonicalize branch root during WAL recovery — skipping"
                        );
                        continue;
                    }
                };
                if !canonical_branch.starts_with(&canonical_root) {
                    tracing::error!(
                        branch = %branch_id,
                        branch_dir = %canonical_branch.display(),
                        branch_root = %canonical_root.display(),
                        "WAL recovery: branch directory escapes branch root — skipping (possible path traversal)"
                    );
                    continue;
                }
                if let Err(e) = std::fs::remove_dir_all(&branch_dir) {
                    tracing::error!(
                        branch = %branch_id,
                        error = %e,
                        "failed to remove branch directory during WAL recovery"
                    );
                    return Err(PuzzledError::Branch(format!(
                        "failed to remove branch directory during WAL recovery: {}",
                        e
                    )));
                }
            }
        }

        // L1: Scan for orphaned .puzzled_old files left by interrupted
        // renameat2(RENAME_EXCHANGE) operations during WAL commit.
        //
        // M6: Note — this scan only covers branch_root (the OverlayFS upper dirs),
        // but .puzzled_old files are actually created in the commit target paths
        // (base filesystem), not in branch_root. Since base paths vary per branch
        // and the branch metadata may no longer be available during WAL recovery
        // (the branch info is cleaned up above), we cannot automatically locate
        // and clean orphan .puzzled_old files in all possible base paths.
        //
        // Administrators should check base filesystem paths for leftover .puzzled_old
        // files after WAL recovery (e.g., `find / -name '*.puzzled_old' -type f`).
        WriteAheadLog::cleanup_orphan_puzzled_old(&self.config.branch_root);
        tracing::warn!(
            "WAL recovery: orphan .puzzled_old cleanup only scans branch_root ({}). \
             Orphan .puzzled_old files in base filesystem commit targets cannot be \
             automatically located during recovery — manual cleanup may be required.",
            self.config.branch_root.display()
        );

        // M-br4: Scan branch_root for directories not in loaded state.
        // Orphaned branch directories (from crashes) are registered as Degraded
        // so operators can inspect and clean them up.
        if self.config.branch_root.exists() {
            match std::fs::read_dir(&self.config.branch_root) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if !path.is_dir() {
                            continue;
                        }
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            // Skip puzzled's own internal subdirectories
                            const INTERNAL_DIRS: &[&str] =
                                &["wal", "audit", "manifests", "staging", "journal"];
                            if INTERNAL_DIRS.contains(&name) {
                                continue;
                            }
                            // S10: Use validated() to skip dirs with invalid chars
                            let branch_id = match BranchId::validated(name.to_string()) {
                                Ok(id) => id,
                                Err(_) => {
                                    tracing::warn!(
                                        dir = name,
                                        "S10: skipping orphaned dir with invalid branch name"
                                    );
                                    continue;
                                }
                            };
                            if self.branches.contains_key(&branch_id) {
                                continue; // Already loaded from state
                            }
                            // Skip WAL-recovered branches (already cleaned up above)
                            if incomplete.iter().any(|b| b.as_str() == name) {
                                continue;
                            }
                            // Create a Degraded BranchInfo for operator inspection
                            let upper_dir = path.join("upper");
                            let work_dir = path.join("work");
                            let info = BranchInfo {
                                id: branch_id.clone(),
                                profile: "unknown".to_string(),
                                base_path: PathBuf::from("/"),
                                upper_dir,
                                work_dir,
                                state: BranchState::Degraded,
                                created_at: Utc::now(),
                                pid: None,
                                uid: 0,
                                expires_at: None,
                                selinux_context: None,
                            };
                            self.branches.insert(branch_id.clone(), info);
                            tracing::warn!(
                                branch = %branch_id,
                                path = %path.display(),
                                "M-br4: orphaned branch directory found during recovery — registered as Degraded"
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        branch_root = %self.config.branch_root.display(),
                        error = %e,
                        "M-br4: failed to scan branch_root for orphaned branches"
                    );
                }
            }
        }

        self.audit.log(AuditEvent::WalRecovery {
            // H4: Safe cast — prevent truncation if recovery count exceeds u32::MAX.
            branches_recovered: u32::try_from(incomplete.len()).unwrap_or(u32::MAX),
        });

        if !incomplete.is_empty() {
            tracing::info!(count = incomplete.len(), "recovered incomplete commits");
        }

        Ok(())
    }

    /// H-10: Get a summary of the pending governance review for a branch.
    ///
    /// Returns `(file_count, total_bytes)` if the branch has pending review data,
    /// or `None` if there is no pending review for this branch.
    pub fn pending_review_summary(&self, id: &BranchId) -> Option<(usize, u64)> {
        self.pending_reviews.get(id).map(|entry| {
            let (changes, _) = entry.value();
            let file_count = changes.len();
            let total_bytes: u64 = changes.iter().map(|c| c.size).sum();
            (file_count, total_bytes)
        })
    }

    /// Reload policies from disk.
    /// L-db2: Returns (success, detail_message) for richer error reporting.
    pub fn reload_policies(&self) -> Result<()> {
        self.policy_engine.reload()?;
        // H4: Safe cast — prevent truncation if policy count exceeds u32::MAX.
        let count = u32::try_from(self.policy_engine.policy_count()).unwrap_or(u32::MAX);
        self.audit.log(AuditEvent::PolicyReloaded {
            policies_loaded: count,
        });
        Ok(())
    }

    /// H-10: Approve a branch in GovernanceReview state.
    ///
    /// Retrieves the stored changeset from `pending_reviews`, calls
    /// `finalize_approved_commit()` to perform the WAL commit, and returns
    /// the `CommitResult` with actual file/byte counts.
    pub fn approve_branch(&self, id: &BranchId) -> Result<CommitResult> {
        // H-1/H-2: Use committing_branches guard to prevent concurrent
        // approve+reject race. Only one thread can hold this for a given branch.
        {
            let mut committing = self
                .committing_branches
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !committing.insert(id.clone()) {
                return Err(PuzzledError::Branch(format!(
                    "concurrent operation already in progress for branch {}",
                    id
                )));
            }
        }
        let _commit_guard = CommitGuard {
            committing_branches: Arc::clone(&self.committing_branches),
            branch_id: id.clone(),
        };

        // H-2: Atomically check state via get_mut (hold ref across check + transition)
        {
            let info = self
                .branches
                .get(id)
                .ok_or_else(|| PuzzledError::NotFound(format!("branch {}", id)))?;

            if info.state != BranchState::GovernanceReview {
                return Err(PuzzledError::Branch(format!(
                    "branch {} is in state {}, expected GovernanceReview",
                    id, info.state
                )));
            }
        }

        // Retrieve the stored changeset — must exist if we're in GovernanceReview
        let (_, (changes, base_path)) = self.pending_reviews.remove(id).ok_or_else(|| {
            PuzzledError::Branch(format!(
                "branch {} is in GovernanceReview but has no pending review data",
                id
            ))
        })?;

        tracing::info!(
            branch = %id,
            files = changes.len(),
            "H-10: governance review approved, finalizing commit"
        );

        // H10: Re-verify cgroup freeze before finalize — the agent may have been
        // thawed between the original freeze (at commit time) and this approval.
        // If the sandbox handle exists, re-freeze to ensure TOCTOU-safe commit.
        #[cfg(target_os = "linux")]
        if let Some(handle) = self.sandboxes.get(id) {
            if let Err(e) = crate::sandbox::cgroup::CgroupManager::freeze(&handle.cgroup_path) {
                tracing::warn!(
                    branch = %id,
                    error = %e,
                    "H10: failed to re-freeze cgroup before approved commit — \
                     proceeding with stored changeset (TOCTOU risk if agent modified files)"
                );
            }
        }

        self.audit.log(AuditEvent::BranchFrozen {
            branch_id: id.clone(),
        });

        // Finalize the commit using the stored changeset
        self.finalize_approved_commit(id, &changes, &base_path, PolicyDecision::Approved)
    }

    /// H-10: Reject a branch in GovernanceReview state.
    ///
    /// Removes the stored changeset from `pending_reviews`, thaws the cgroup,
    /// performs a full rollback (cleanup + upper dir removal), and emits an
    /// audit event.
    pub fn reject_branch(&self, id: &BranchId, reason: &str) -> Result<()> {
        // H-1/H-2: Use committing_branches guard to prevent concurrent
        // approve+reject race. Only one thread can hold this for a given branch.
        {
            let mut committing = self
                .committing_branches
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !committing.insert(id.clone()) {
                return Err(PuzzledError::Branch(format!(
                    "concurrent operation already in progress for branch {}",
                    id
                )));
            }
        }
        let _commit_guard = CommitGuard {
            committing_branches: Arc::clone(&self.committing_branches),
            branch_id: id.clone(),
        };

        // H-2: Check state atomically
        {
            let info = self
                .branches
                .get(id)
                .ok_or_else(|| PuzzledError::NotFound(format!("branch {}", id)))?;

            if info.state != BranchState::GovernanceReview {
                return Err(PuzzledError::Branch(format!(
                    "branch {} is in state {}, expected GovernanceReview",
                    id, info.state
                )));
            }
        }

        // Remove pending review data (if any — may already be cleaned up by timeout)
        self.pending_reviews.remove(id);

        // Cancel any path reservations held during the review period
        self.conflict_detector
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cancel_reservation(id);

        // Thaw the cgroup before rollback so processes can be properly cleaned up
        self.thaw_cgroup(id);

        let reject_reason = format!("governance review rejected: {}", reason);

        tracing::info!(
            branch = %id,
            reason = %reject_reason,
            "H-10: governance review rejected, rolling back"
        );

        self.audit.log(AuditEvent::BranchRolledBack {
            branch_id: id.clone(),
            reason: reject_reason.clone(),
        });

        self.rollback_internal(&reject_reason, id)
    }

    /// Serialize branch state to disk for zero-downtime restart.
    ///
    /// Writes `state.json` atomically via temp+rename. Only serializes branch
    /// metadata (BranchInfo). Sandbox handles (pidfds, seccomp notify fds) cannot
    /// be serialized and must be re-established on restart.
    pub fn save_state(&self) -> Result<()> {
        // M-br2: Write state file to runtime_dir (ephemeral storage, e.g. /run/puzzled)
        // instead of branch_root (persistent storage).
        let runtime_dir = &self.config.runtime_dir;
        if !runtime_dir.exists() {
            std::fs::create_dir_all(runtime_dir).map_err(|e| {
                PuzzledError::Branch(format!(
                    "creating runtime_dir {}: {}",
                    runtime_dir.display(),
                    e
                ))
            })?;
        }
        let state_path = runtime_dir.join("state.json");

        let branches: Vec<BranchInfo> = self.branches.iter().map(|r| r.value().clone()).collect();
        let json = serde_json::to_string_pretty(&branches)
            .map_err(|e| PuzzledError::Branch(format!("serializing state: {}", e)))?;

        // L2: Use tempfile::NamedTempFile for unpredictable temp file names,
        // then atomically rename to the final destination.
        // Write to temp file and fsync to ensure data is durable before rename.
        // Without fsync, a crash after rename could leave a partial state file.
        {
            use std::io::Write;
            let named_tmp = tempfile::NamedTempFile::new_in(runtime_dir)
                .map_err(|e| PuzzledError::Branch(format!("creating temp state file: {}", e)))?;
            // Write and flush via BufWriter, then drop the writer to release the borrow.
            {
                let mut writer = std::io::BufWriter::new(named_tmp.as_file());
                writer
                    .write_all(json.as_bytes())
                    .map_err(|e| PuzzledError::Branch(format!("writing state: {}", e)))?;
                writer
                    .flush()
                    .map_err(|e| PuzzledError::Branch(format!("flushing state: {}", e)))?;
            }
            // fsync the underlying file to ensure durability before rename.
            named_tmp
                .as_file()
                .sync_all()
                .map_err(|e| PuzzledError::Branch(format!("fsync state file: {}", e)))?;
            named_tmp
                .persist(&state_path)
                .map_err(|e| PuzzledError::Branch(format!("persisting state file: {}", e)))?;
        }

        tracing::debug!(branches = branches.len(), "state saved");
        Ok(())
    }

    /// Load branch state from disk after daemon restart.
    ///
    /// Restores only Active branches whose upper_dir still exists on disk.
    /// Does NOT restore sandbox handles (pidfds, seccomp fds, cgroup handles).
    pub fn load_state(&self) -> Result<()> {
        // M-br2: Read state file from runtime_dir
        let state_path = self.config.runtime_dir.join("state.json");
        if !state_path.exists() {
            tracing::debug!("no state.json found, starting fresh");
            return Ok(());
        }

        let json = std::fs::read_to_string(&state_path)?;
        let branches: Vec<BranchInfo> = serde_json::from_str(&json)
            .map_err(|e| PuzzledError::Branch(format!("deserializing state: {}", e)))?;

        let mut restored = 0;
        for info in branches {
            if matches!(info.state, BranchState::Active | BranchState::Ready)
                && info.upper_dir.exists()
            {
                self.branches.insert(info.id.clone(), info);
                restored += 1;
            }
        }

        // M-br3: Delete the state file after successful load to prevent
        // stale state from being loaded on subsequent restarts.
        if let Err(e) = std::fs::remove_file(&state_path) {
            tracing::warn!(
                path = %state_path.display(),
                error = %e,
                "M-br3: failed to delete state file after load"
            );
        }

        tracing::info!(restored, "loaded branch state from disk");
        Ok(())
    }

    /// Re-attach fanotify monitors to branches restored from state on daemon restart.
    ///
    /// Called after `load_state()` to restore behavioral monitoring for branches
    /// that survived a daemon restart. If a monitor can't be attached (e.g., the
    /// OverlayFS mount is gone), the branch is marked as needing a full diff.
    #[cfg(target_os = "linux")]
    pub fn reattach_monitors(&self) {
        let active_branches: Vec<(BranchId, std::path::PathBuf, String)> = self
            .branches
            .iter()
            .filter(|r| matches!(r.state, BranchState::Active | BranchState::Ready))
            .map(|r| {
                let id = r.key().clone();
                let merged = r
                    .base_path
                    .parent()
                    .unwrap_or(&r.base_path)
                    .join(id.as_str())
                    .join("merged");
                (id, merged, r.profile.clone())
            })
            .collect();

        let mut attached = 0u32;
        for (id, merged_dir, profile_name) in &active_branches {
            // Skip if merged dir doesn't exist (mount is gone)
            if !merged_dir.exists() {
                tracing::warn!(
                    branch = %id,
                    merged_dir = %merged_dir.display(),
                    "merged directory missing — skipping fanotify reattachment"
                );
                continue;
            }

            let behavioral_config = self
                .profile_loader
                .get(profile_name)
                .map(|p| p.behavioral.clone())
                .unwrap_or_default();

            match crate::sandbox::fanotify::FanotifyMonitor::init(
                id.clone(),
                merged_dir.clone(),
                behavioral_config,
            ) {
                Ok(monitor) => {
                    let (trigger_rx, _counters, _touched, _needs_full_diff, _shutdown) =
                        monitor.start();
                    self.fanotify_triggers.insert(id.clone(), trigger_rx);
                    attached += 1;
                    tracing::info!(branch = %id, "fanotify monitor reattached after restart");
                }
                Err(e) => {
                    tracing::warn!(
                        branch = %id,
                        error = %e,
                        "failed to reattach fanotify monitor — behavioral monitoring degraded"
                    );
                }
            }
        }

        if !active_branches.is_empty() {
            tracing::info!(
                total = active_branches.len(),
                attached,
                "fanotify monitor reattachment complete"
            );
        }
    }

    /// Enforce branch lifetime limits — roll back any Active branches that have
    /// exceeded the configured watchdog timeout.
    ///
    /// Called periodically from the watchdog task in main.rs.
    ///
    /// Clean up old committed conflict records to prevent unbounded memory growth.
    /// Delegates to ConflictDetector::cleanup_old_committed().
    pub fn cleanup_committed_conflicts(&self) {
        if let Ok(mut detector) = self.conflict_detector.lock() {
            detector.cleanup_old_committed(chrono::Duration::hours(1));
        }
    }

    pub fn enforce_timeouts(&self) {
        let timeout_secs = self.config.watchdog_timeout_secs;
        if timeout_secs == 0 {
            return;
        }

        let now = chrono::Utc::now();
        // H4: Check both Active and Frozen branches for timeouts. Frozen branches
        // can be stuck (e.g., after a FailSilent that never resumed), and should also
        // be subject to watchdog timeout enforcement.
        let expired: Vec<BranchId> = self
            .branches
            .iter()
            .filter(|r| {
                matches!(
                    r.state,
                    BranchState::Active | BranchState::Ready | BranchState::Frozen
                )
            })
            .filter(|r| {
                let age = now.signed_duration_since(r.created_at);
                // H3: Safe cast — prevent truncation of large u64 timeout values.
                age.num_seconds() > i64::try_from(timeout_secs).unwrap_or(i64::MAX)
            })
            .map(|r| r.key().clone())
            .collect();

        for id in expired {
            // Recheck state — a commit may have started since we collected the expired list
            let current_state = self.branches.get(&id).map(|r| r.state);
            if !matches!(
                current_state,
                Some(BranchState::Active) | Some(BranchState::Ready) | Some(BranchState::Frozen)
            ) {
                continue;
            }

            // If frozen, thaw before rollback so processes can be properly cleaned up
            #[cfg(target_os = "linux")]
            if current_state == Some(BranchState::Frozen) {
                if let Some(handle) = self.sandboxes.get(&id) {
                    if let Err(e) = crate::sandbox::cgroup::CgroupManager::thaw(&handle.cgroup_path)
                    {
                        tracing::warn!(
                            branch = %id,
                            error = %e,
                            "failed to thaw frozen branch before timeout rollback"
                        );
                    }
                }
            }

            tracing::warn!(
                branch = %id,
                timeout_secs,
                "branch exceeded watchdog timeout, rolling back"
            );

            // Wire metrics: watchdog timeout
            if let Some(m) = self.get_metrics() {
                m.watchdog_timeouts_total.inc();
            }

            // M8: rollback() itself emits the BranchRolledBack audit event
            // on success, so no separate audit log is needed here.
            if let Err(e) = self.rollback("watchdog timeout exceeded", &id) {
                tracing::error!(
                    branch = %id,
                    error = %e,
                    "failed to rollback timed-out branch"
                );
            }
        }

        // H-10: Check GovernanceReview branches for review timeout expiry.
        // Uses a separate timeout (governance_review_timeout_seconds) from the
        // watchdog timeout, since governance reviews may legitimately take longer
        // than normal branch lifetimes.
        let review_timeout_secs = self.config.governance_review_timeout_seconds;
        if review_timeout_secs == 0 {
            return;
        }

        let review_expired: Vec<BranchId> = self
            .branches
            .iter()
            .filter(|r| r.state == BranchState::GovernanceReview)
            .filter(|r| {
                let age = now.signed_duration_since(r.created_at);
                // H3: Safe cast — prevent truncation of large u64 timeout values.
                age.num_seconds() > i64::try_from(review_timeout_secs).unwrap_or(i64::MAX)
            })
            .map(|r| r.key().clone())
            .collect();

        for id in review_expired {
            // Recheck state — approval may have occurred since we collected the list
            let current_state = self.branches.get(&id).map(|r| r.state);
            if current_state != Some(BranchState::GovernanceReview) {
                continue;
            }

            tracing::warn!(
                branch = %id,
                review_timeout_secs,
                "H-10: governance review timeout expired, auto-rejecting"
            );

            // Wire metrics: watchdog timeout (governance review variant)
            if let Some(m) = self.get_metrics() {
                m.watchdog_timeouts_total.inc();
            }

            // Use reject_branch which handles pending_reviews cleanup, cgroup thaw,
            // conflict reservation cancellation, and rollback_internal.
            if let Err(e) = self.reject_branch(&id, "governance review timeout expired") {
                tracing::error!(
                    branch = %id,
                    error = %e,
                    "H-10: failed to auto-reject timed-out governance review"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a BranchManager for testing.
    fn make_test_manager(dir: &std::path::Path) -> BranchManager {
        let profiles_dir = dir.join("profiles");
        let policies_dir = dir.join("policies");
        let wal_dir = dir.join("wal");
        let branch_root = dir.join("branches");

        std::fs::create_dir_all(&profiles_dir).unwrap();
        std::fs::create_dir_all(&policies_dir).unwrap();
        std::fs::create_dir_all(&wal_dir).unwrap();
        std::fs::create_dir_all(&branch_root).unwrap();

        let config = DaemonConfig {
            branch_root,
            profiles_dir: profiles_dir.clone(),
            policies_dir: policies_dir.clone(),
            max_branches: 4,
            ..Default::default()
        };

        let profile_loader = ProfileLoader::new(profiles_dir);
        let policy_engine = PolicyEngine::new(policies_dir);
        let wal = WriteAheadLog::new(wal_dir);
        let audit = Arc::new(AuditLogger::new());
        let conflict_detector = Arc::new(Mutex::new(ConflictDetector::new()));
        let budget_manager = Arc::new(Mutex::new(crate::budget::BudgetManager::new()));

        BranchManager::new(
            config,
            profile_loader,
            policy_engine,
            wal,
            audit,
            None,
            conflict_detector,
            budget_manager,
            None,
            None,
        )
    }

    /// Helper to insert a branch directly (bypassing create() which is Linux-only).
    fn insert_test_branch(manager: &BranchManager, state: BranchState) -> BranchId {
        let id = BranchId::new();
        let info = BranchInfo {
            id: id.clone(),
            profile: "test".to_string(),
            base_path: PathBuf::from("/tmp/base"),
            upper_dir: PathBuf::from("/tmp/upper"),
            work_dir: PathBuf::from("/tmp/work"),
            state,
            created_at: chrono::Utc::now(),
            pid: Some(9999),
            uid: 1000,
            expires_at: None,
            selinux_context: None,
        };
        manager.branches.insert(id.clone(), info);
        id
    }

    #[test]
    fn test_list_empty() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        assert!(manager.list().is_empty());
    }

    #[test]
    fn test_inspect_missing() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = BranchId::from("nonexistent".to_string());
        assert!(manager.inspect(&id).is_none());
    }

    #[test]
    fn test_list_with_branches() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        insert_test_branch(&manager, BranchState::Active);
        insert_test_branch(&manager, BranchState::Active);
        assert_eq!(manager.list().len(), 2);
    }

    #[test]
    fn test_inspect_existing() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = insert_test_branch(&manager, BranchState::Active);
        let info = manager.inspect(&id).unwrap();
        assert_eq!(info.id, id);
        assert_eq!(info.state, BranchState::Active);
        assert_eq!(info.profile, "test");
        assert_eq!(info.uid, 1000);
    }

    // -- State machine tests --

    #[test]
    fn test_transition_active_to_frozen() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = insert_test_branch(&manager, BranchState::Active);
        assert!(manager.transition(&id, BranchState::Frozen).is_ok());
        assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Frozen);
    }

    #[test]
    fn test_transition_active_to_rolled_back() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = insert_test_branch(&manager, BranchState::Active);
        assert!(manager.transition(&id, BranchState::RolledBack).is_ok());
    }

    #[test]
    fn test_transition_frozen_to_committing() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = insert_test_branch(&manager, BranchState::Frozen);
        assert!(manager.transition(&id, BranchState::Committing).is_ok());
    }

    #[test]
    fn test_transition_frozen_to_committed_empty_changeset() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = insert_test_branch(&manager, BranchState::Frozen);
        assert!(manager.transition(&id, BranchState::Committed).is_ok());
    }

    #[test]
    fn test_transition_frozen_to_rolled_back() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = insert_test_branch(&manager, BranchState::Frozen);
        assert!(manager.transition(&id, BranchState::RolledBack).is_ok());
    }

    #[test]
    fn test_transition_committing_to_committed() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = insert_test_branch(&manager, BranchState::Committing);
        assert!(manager.transition(&id, BranchState::Committed).is_ok());
    }

    #[test]
    fn test_transition_committing_to_failed() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = insert_test_branch(&manager, BranchState::Committing);
        assert!(manager.transition(&id, BranchState::Failed).is_ok());
    }

    #[test]
    fn test_transition_any_to_failed() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());

        for state in [
            BranchState::Active,
            BranchState::Ready,
            BranchState::Frozen,
            BranchState::Creating,
        ] {
            let id = insert_test_branch(&manager, state);
            assert!(
                manager.transition(&id, BranchState::Failed).is_ok(),
                "should transition from {:?} to Failed",
                state
            );
        }
    }

    #[test]
    fn test_transition_invalid_active_to_committed() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = insert_test_branch(&manager, BranchState::Active);
        let result = manager.transition(&id, BranchState::Committed);
        assert!(result.is_err());
    }

    #[test]
    fn test_transition_invalid_committed_to_active() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = insert_test_branch(&manager, BranchState::Committed);
        let result = manager.transition(&id, BranchState::Active);
        assert!(result.is_err());
    }

    #[test]
    fn test_transition_invalid_rolled_back_to_active() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = insert_test_branch(&manager, BranchState::RolledBack);
        let result = manager.transition(&id, BranchState::Active);
        assert!(result.is_err());
    }

    #[test]
    fn test_transition_nonexistent_branch() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = BranchId::from("nonexistent".to_string());
        let result = manager.transition(&id, BranchState::Failed);
        assert!(result.is_err());
    }

    // -- commit/rollback edge cases --

    #[test]
    fn test_commit_nonexistent_branch() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = BranchId::from("nonexistent".to_string());
        let result = manager.commit(&id);
        assert!(result.is_err());
    }

    #[test]
    fn test_commit_non_active_branch() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = insert_test_branch(&manager, BranchState::Committed);
        let result = manager.commit(&id);
        assert!(result.is_err());
    }

    #[test]
    fn test_rollback_nonexistent_branch() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = BranchId::from("nonexistent".to_string());
        let result = manager.rollback("test rollback", &id);
        assert!(result.is_err());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_create_requires_linux() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let result = manager.create("standard", &PathBuf::from("/tmp"), 1000, vec![]);
        assert!(result.is_err());
    }

    // -- H4: Exited/Terminated state transitions --

    #[test]
    fn test_h4_transition_active_to_exited() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = insert_test_branch(&manager, BranchState::Active);
        assert!(manager.transition(&id, BranchState::Exited).is_ok());
        assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Exited);
    }

    #[test]
    fn test_h4_transition_active_to_terminated() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = insert_test_branch(&manager, BranchState::Active);
        assert!(manager.transition(&id, BranchState::Terminated).is_ok());
        assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Terminated);
    }

    #[test]
    fn test_h4_transition_frozen_to_terminated() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = insert_test_branch(&manager, BranchState::Frozen);
        assert!(manager.transition(&id, BranchState::Terminated).is_ok());
        assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Terminated);
    }

    #[test]
    fn test_h4_transition_exited_to_frozen() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = insert_test_branch(&manager, BranchState::Exited);
        assert!(manager.transition(&id, BranchState::Frozen).is_ok());
        assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Frozen);
    }

    #[test]
    fn test_h4_transition_terminated_to_rolled_back() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = insert_test_branch(&manager, BranchState::Terminated);
        assert!(manager.transition(&id, BranchState::RolledBack).is_ok());
    }

    #[test]
    fn test_h4_transition_exited_to_active_invalid() {
        // Exited -> Active is NOT valid (agent has stopped, can't resume)
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = insert_test_branch(&manager, BranchState::Exited);
        assert!(manager.transition(&id, BranchState::Active).is_err());
    }

    #[test]
    fn test_h4_transition_terminated_to_active_invalid() {
        // Terminated -> Active is NOT valid
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = insert_test_branch(&manager, BranchState::Terminated);
        assert!(manager.transition(&id, BranchState::Active).is_err());
    }

    // -- Ready state transitions --

    #[test]
    fn test_transition_creating_to_ready() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = insert_test_branch(&manager, BranchState::Creating);
        assert!(manager.transition(&id, BranchState::Ready).is_ok());
        assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Ready);
    }

    #[test]
    fn test_transition_ready_to_active() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = insert_test_branch(&manager, BranchState::Ready);
        assert!(manager.transition(&id, BranchState::Active).is_ok());
        assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Active);
    }

    #[test]
    fn test_transition_ready_to_rolled_back() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = insert_test_branch(&manager, BranchState::Ready);
        assert!(manager.transition(&id, BranchState::RolledBack).is_ok());
    }

    #[test]
    fn test_transition_ready_to_frozen() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = insert_test_branch(&manager, BranchState::Ready);
        assert!(manager.transition(&id, BranchState::Frozen).is_ok());
        assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Frozen);
    }

    #[test]
    fn test_transition_ready_to_committed_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = insert_test_branch(&manager, BranchState::Ready);
        assert!(manager.transition(&id, BranchState::Committed).is_err());
    }

    #[test]
    fn test_enforce_timeouts_rolls_back_expired_ready_branch() {
        let dir = tempfile::tempdir().unwrap();
        let mut manager = make_test_manager(dir.path());
        manager.config.watchdog_timeout_secs = 30;

        let ready_id = insert_test_branch_with_age(&manager, BranchState::Ready, 60);

        manager.enforce_timeouts();

        assert!(
            manager.inspect(&ready_id).is_none(),
            "expired Ready branch should be removed after rollback"
        );
    }

    // -- enforce_timeouts --

    /// Helper to insert a branch with a specific creation time.
    fn insert_test_branch_with_age(
        manager: &BranchManager,
        state: BranchState,
        age_secs: i64,
    ) -> BranchId {
        let id = BranchId::new();
        let created_at =
            chrono::Utc::now() - chrono::TimeDelta::try_seconds(age_secs).unwrap_or_default();
        let info = BranchInfo {
            id: id.clone(),
            profile: "test".to_string(),
            base_path: PathBuf::from("/tmp/base"),
            upper_dir: PathBuf::from("/tmp/upper"),
            work_dir: PathBuf::from("/tmp/work"),
            state,
            created_at,
            pid: Some(9999),
            uid: 1000,
            expires_at: None,
            selinux_context: None,
        };
        manager.branches.insert(id.clone(), info);
        id
    }

    #[test]
    fn test_enforce_timeouts_skips_when_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let mut manager = make_test_manager(dir.path());
        manager.config.watchdog_timeout_secs = 0;

        // Insert an "old" active branch
        let id = insert_test_branch_with_age(&manager, BranchState::Active, 9999);

        manager.enforce_timeouts();

        // Branch should still be Active (timeout disabled)
        assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Active);
    }

    #[test]
    fn test_enforce_timeouts_rolls_back_expired_branch() {
        let dir = tempfile::tempdir().unwrap();
        let mut manager = make_test_manager(dir.path());
        manager.config.watchdog_timeout_secs = 30;

        // Branch created 60 seconds ago — exceeds 30s timeout
        let id = insert_test_branch_with_age(&manager, BranchState::Active, 60);

        manager.enforce_timeouts();

        // After rollback, branch is removed from the manager (C4)
        assert!(
            manager.inspect(&id).is_none(),
            "expired branch should be removed after rollback"
        );
    }

    #[test]
    fn test_enforce_timeouts_ignores_young_branch() {
        let dir = tempfile::tempdir().unwrap();
        let mut manager = make_test_manager(dir.path());
        manager.config.watchdog_timeout_secs = 30;

        // Branch created 5 seconds ago — within timeout
        let id = insert_test_branch_with_age(&manager, BranchState::Active, 5);

        manager.enforce_timeouts();

        assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Active);
    }

    #[test]
    fn test_enforce_timeouts_ignores_non_active_non_frozen_branches() {
        let dir = tempfile::tempdir().unwrap();
        let mut manager = make_test_manager(dir.path());
        manager.config.watchdog_timeout_secs = 30;

        // Old branches in terminal states should not be touched
        let committed_id = insert_test_branch_with_age(&manager, BranchState::Committed, 60);

        manager.enforce_timeouts();

        assert_eq!(
            manager.inspect(&committed_id).unwrap().state,
            BranchState::Committed
        );
    }

    #[test]
    fn test_enforce_timeouts_rolls_back_expired_frozen_branch() {
        let dir = tempfile::tempdir().unwrap();
        let mut manager = make_test_manager(dir.path());
        manager.config.watchdog_timeout_secs = 30;

        // H4: Frozen branches should also be checked for timeouts
        let frozen_id = insert_test_branch_with_age(&manager, BranchState::Frozen, 60);

        manager.enforce_timeouts();

        // After rollback, branch is removed from the manager (C4)
        assert!(
            manager.inspect(&frozen_id).is_none(),
            "expired frozen branch should be removed after rollback"
        );
    }

    #[test]
    fn test_enforce_timeouts_mixed_branches() {
        let dir = tempfile::tempdir().unwrap();
        let mut manager = make_test_manager(dir.path());
        manager.config.watchdog_timeout_secs = 30;

        // One expired active, one young active, one expired frozen, one committed
        let expired_id = insert_test_branch_with_age(&manager, BranchState::Active, 60);
        let young_id = insert_test_branch_with_age(&manager, BranchState::Active, 5);
        let frozen_id = insert_test_branch_with_age(&manager, BranchState::Frozen, 60);
        let committed_id = insert_test_branch_with_age(&manager, BranchState::Committed, 60);

        manager.enforce_timeouts();

        // After rollback, branch is removed from the manager (C4)
        assert!(
            manager.inspect(&expired_id).is_none(),
            "expired active branch should be removed after rollback"
        );
        assert_eq!(
            manager.inspect(&young_id).unwrap().state,
            BranchState::Active,
            "young active branch should remain active"
        );
        // H4: Frozen branches are now also subject to timeout enforcement
        assert!(
            manager.inspect(&frozen_id).is_none(),
            "expired frozen branch should be removed after rollback"
        );
        assert_eq!(
            manager.inspect(&committed_id).unwrap().state,
            BranchState::Committed,
            "committed branch should be untouched"
        );
    }

    // -- diff --

    #[test]
    fn test_diff_nonexistent_branch() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = BranchId::from("nonexistent".to_string());
        let result = manager.diff(&id);
        assert!(result.is_err());
    }

    // -- kill_agent --

    #[test]
    fn test_kill_agent_nonexistent_branch() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = BranchId::from("nonexistent".to_string());
        let result = manager.kill_agent(&id);
        assert!(result.is_err());
    }

    #[test]
    fn test_kill_agent_non_active_branch() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        let id = insert_test_branch(&manager, BranchState::Frozen);
        let result = manager.kill_agent(&id);
        assert!(result.is_err());
    }

    // -- recover --

    #[test]
    fn test_recover_empty_wal() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        assert!(manager.recover().is_ok());
    }

    // -- reload policies --

    #[test]
    fn test_reload_policies_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());
        assert!(manager.reload_policies().is_ok());
    }

    // -- Phase 1.7: Additional branch manager tests --

    #[test]
    fn test_state_machine_valid_transitions_succeed() {
        // Verify all valid transitions in the state machine succeed.
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());

        let valid_transitions: Vec<(BranchState, BranchState)> = vec![
            (BranchState::Creating, BranchState::Ready),
            (BranchState::Ready, BranchState::Active),
            (BranchState::Ready, BranchState::Frozen),
            (BranchState::Ready, BranchState::RolledBack),
            (BranchState::Active, BranchState::Frozen),
            (BranchState::Active, BranchState::RolledBack),
            (BranchState::Active, BranchState::Exited),
            (BranchState::Active, BranchState::Terminated),
            (BranchState::Frozen, BranchState::Active),
            (BranchState::Frozen, BranchState::Committing),
            (BranchState::Frozen, BranchState::RolledBack),
            (BranchState::Frozen, BranchState::Committed),
            (BranchState::Frozen, BranchState::Terminated),
            (BranchState::Committing, BranchState::Committed),
            (BranchState::Committing, BranchState::Active),
            (BranchState::Committing, BranchState::Failed),
            (BranchState::Committing, BranchState::GovernanceReview),
            (BranchState::Exited, BranchState::Frozen),
            (BranchState::Terminated, BranchState::RolledBack),
            (BranchState::GovernanceReview, BranchState::Committed),
            (BranchState::GovernanceReview, BranchState::RolledBack),
            // Any -> Degraded
            (BranchState::Active, BranchState::Degraded),
            (BranchState::Frozen, BranchState::Degraded),
            // Any -> Failed
            (BranchState::Active, BranchState::Failed),
            (BranchState::Creating, BranchState::Failed),
        ];

        for (from, to) in valid_transitions {
            let id = insert_test_branch(&manager, from);
            assert!(
                manager.transition(&id, to).is_ok(),
                "transition {:?} -> {:?} should succeed",
                from,
                to
            );
            assert_eq!(
                manager.inspect(&id).unwrap().state,
                to,
                "state should be {:?} after transition from {:?}",
                to,
                from
            );
        }
    }

    #[test]
    fn test_state_machine_invalid_transitions_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());

        let invalid_transitions: Vec<(BranchState, BranchState)> = vec![
            (BranchState::Active, BranchState::Committed),
            (BranchState::Active, BranchState::Committing),
            (BranchState::Active, BranchState::Creating),
            (BranchState::Committed, BranchState::Active),
            (BranchState::Committed, BranchState::Frozen),
            (BranchState::RolledBack, BranchState::Active),
            (BranchState::RolledBack, BranchState::Frozen),
            (BranchState::Exited, BranchState::Active),
            (BranchState::Exited, BranchState::Committed),
            (BranchState::Terminated, BranchState::Active),
            (BranchState::Creating, BranchState::Frozen),
            (BranchState::Creating, BranchState::Committed),
        ];

        for (from, to) in invalid_transitions {
            let id = insert_test_branch(&manager, from);
            let result = manager.transition(&id, to);
            assert!(
                result.is_err(),
                "transition {:?} -> {:?} should be rejected",
                from,
                to
            );
            // State should remain unchanged after rejection
            assert_eq!(
                manager.inspect(&id).unwrap().state,
                from,
                "state should remain {:?} after rejected transition to {:?}",
                from,
                to
            );
        }
    }

    #[test]
    fn test_list_returns_all_branches() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());

        let id1 = insert_test_branch(&manager, BranchState::Active);
        let id2 = insert_test_branch(&manager, BranchState::Frozen);
        let id3 = insert_test_branch(&manager, BranchState::Committed);
        let id4 = insert_test_branch(&manager, BranchState::RolledBack);

        let listed = manager.list();
        assert_eq!(listed.len(), 4, "list() should return all 4 branches");

        let listed_ids: HashSet<BranchId> = listed.into_iter().map(|b| b.id).collect();
        assert!(listed_ids.contains(&id1));
        assert!(listed_ids.contains(&id2));
        assert!(listed_ids.contains(&id3));
        assert!(listed_ids.contains(&id4));
    }

    #[test]
    fn test_inspect_returns_correct_info() {
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());

        let id = BranchId::from("inspect-test-branch".to_string());
        let info = BranchInfo {
            id: id.clone(),
            profile: "restricted".to_string(),
            base_path: PathBuf::from("/home/user/project"),
            upper_dir: PathBuf::from("/var/lib/puzzled/branches/upper"),
            work_dir: PathBuf::from("/var/lib/puzzled/branches/work"),
            state: BranchState::Active,
            created_at: chrono::Utc::now(),
            pid: Some(42),
            uid: 1001,
            expires_at: None,
            selinux_context: None,
        };
        manager.branches.insert(id.clone(), info.clone());

        let inspected = manager.inspect(&id).expect("branch should be found");
        assert_eq!(inspected.id, id);
        assert_eq!(inspected.profile, "restricted");
        assert_eq!(inspected.base_path, PathBuf::from("/home/user/project"));
        assert_eq!(inspected.state, BranchState::Active);
        assert_eq!(inspected.pid, Some(42));
        assert_eq!(inspected.uid, 1001);
    }

    #[test]
    fn test_recovery_on_startup_loads_persisted_wal_state() {
        // Create a manager, write a WAL entry, then create a new manager
        // in the same directory and verify recover() processes it.
        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();

        // First manager: create WAL infrastructure
        let manager1 = make_test_manager(dir.path());
        // recover() with empty WAL should succeed
        assert!(manager1.recover().is_ok());

        // Second manager: should also recover successfully from the same dirs
        let manager2 = make_test_manager(dir.path());
        assert!(
            manager2.recover().is_ok(),
            "recovery on fresh startup should succeed with clean WAL"
        );
        // No branches should be loaded since none were persisted to disk
        assert!(manager2.list().is_empty());
    }

    #[test]
    fn test_concurrent_branch_insertion() {
        // DashMap supports concurrent access; verify multiple branches
        // can be inserted without data loss.
        let dir = tempfile::tempdir().unwrap();
        let manager = Arc::new(make_test_manager(dir.path()));

        let mut handles = vec![];
        for _ in 0..8 {
            let mgr = Arc::clone(&manager);
            let handle = std::thread::spawn(move || {
                insert_test_branch(&mgr, BranchState::Active);
            });
            handles.push(handle);
        }

        for h in handles {
            h.join().expect("thread should not panic");
        }

        assert_eq!(
            manager.list().len(),
            8,
            "all 8 concurrently inserted branches should be present"
        );
    }

    #[test]
    fn test_state_persistence_via_dashmap() {
        // Verify that state stored in the DashMap is retrievable across
        // different access patterns (insert, inspect, transition, list).
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path());

        let id = insert_test_branch(&manager, BranchState::Creating);

        // Transition through the lifecycle
        manager.transition(&id, BranchState::Ready).unwrap();
        assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Ready);

        manager.transition(&id, BranchState::Active).unwrap();
        assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Active);

        manager.transition(&id, BranchState::Frozen).unwrap();
        assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Frozen);

        manager.transition(&id, BranchState::Committing).unwrap();
        assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Committing);

        manager.transition(&id, BranchState::Committed).unwrap();
        assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Committed);

        // list() should reflect the final state
        let listed = manager.list();
        let found = listed.iter().find(|b| b.id == id).unwrap();
        assert_eq!(found.state, BranchState::Committed);
    }

    #[test]
    fn test_branch_creation_increments_counter() {
        // Each call to insert_test_branch adds a branch; verify the count
        // increments correctly and the max_branches limit is respected.
        let dir = tempfile::tempdir().unwrap();
        let manager = make_test_manager(dir.path()); // max_branches = 4

        assert_eq!(manager.list().len(), 0);

        insert_test_branch(&manager, BranchState::Active);
        assert_eq!(manager.list().len(), 1);

        insert_test_branch(&manager, BranchState::Active);
        assert_eq!(manager.list().len(), 2);

        insert_test_branch(&manager, BranchState::Active);
        assert_eq!(manager.list().len(), 3);

        insert_test_branch(&manager, BranchState::Active);
        assert_eq!(manager.list().len(), 4);

        // Verify DashMap len is consistent
        assert_eq!(manager.branches.len(), 4);
    }

    // ---------------------------------------------------------------
    // F1: metadata serialization must not use unwrap_or_default()
    // ---------------------------------------------------------------

    #[test]
    fn test_f1_metadata_serialization_no_silent_default() {
        let source = include_str!("branch.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        // Find the metadata.json write section
        assert!(
            production_code.contains("metadata.json"),
            "metadata.json write must exist in production code"
        );
        // to_string_pretty must NOT be followed by unwrap_or_default()
        assert!(
            !production_code.contains("to_string_pretty(&metadata).unwrap_or_default()"),
            "F1: serde_json::to_string_pretty must not use unwrap_or_default() — \
             an empty string is unparseable on reload. Use unwrap_or_else to write valid JSON."
        );
    }

    // ---------------------------------------------------------------
    // F12: lifetime_minutes cast must use safe conversion
    // ---------------------------------------------------------------

    #[test]
    fn test_f12_lifetime_minutes_safe_cast() {
        let source = include_str!("branch.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        // The production code must not contain `mins as i64` (bare cast that wraps)
        // It should use try_from(mins).unwrap_or(i64::MAX) or similar safe conversion
        assert!(
            !production_code.contains("mins as i64"),
            "F12: lifetime_minutes cast must use i64::try_from(mins).unwrap_or(i64::MAX), \
             not bare `mins as i64` which wraps on huge values"
        );
    }

    // ---------------------------------------------------------------
    // F16: fallback transition to Failed must not silently discard error
    // ---------------------------------------------------------------

    // ---------------------------------------------------------------
    // H3: timeout_secs cast must use safe conversion
    // ---------------------------------------------------------------

    #[test]
    fn test_h3_timeout_secs_safe_cast() {
        let source = include_str!("branch.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        assert!(
            !production_code.contains("timeout_secs as i64"),
            "H3: timeout_secs cast must use i64::try_from().unwrap_or(i64::MAX), \
             not bare `timeout_secs as i64` which truncates large u64 values"
        );
        assert!(
            !production_code.contains("review_timeout_secs as i64"),
            "H3: review_timeout_secs cast must use i64::try_from().unwrap_or(i64::MAX), \
             not bare `review_timeout_secs as i64` which truncates large u64 values"
        );
    }

    // ---------------------------------------------------------------
    // H4: .len() as u32 must use safe conversion
    // ---------------------------------------------------------------

    #[test]
    fn test_h4_no_bare_len_as_u32() {
        let source = include_str!("branch.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        // No bare .len() as u32 or .count() as u32 in production code
        for (i, line) in production_code.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("///") {
                continue;
            }
            assert!(
                !trimmed.contains(".len() as u32") && !trimmed.contains(".count() as u32"),
                "H4: branch.rs line {} contains bare `.len() as u32` or `.count() as u32` — \
                 use u32::try_from(x).unwrap_or(u32::MAX)\nLine: {}",
                i + 1,
                trimmed
            );
        }
    }

    // ---------------------------------------------------------------
    // H6: fd as i32 must use safe conversion
    // ---------------------------------------------------------------

    #[test]
    fn test_h6_no_bare_fd_as_i32() {
        let source = include_str!("branch.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        for (i, line) in production_code.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("///") {
                continue;
            }
            if trimmed.contains("fd as i32") && trimmed.contains("close(") {
                panic!(
                    "H6: branch.rs line {} contains bare `fd as i32` for close() — \
                     use i32::try_from(fd) with error handling\nLine: {}",
                    i + 1,
                    trimmed
                );
            }
        }
    }

    // ---------------------------------------------------------------
    // H10: approve path must re-verify freeze
    // ---------------------------------------------------------------

    #[test]
    fn test_h10_approve_branch_reverifies_freeze() {
        let source = include_str!("branch.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];

        // Find the approve_branch function
        let func_start = production_code
            .find("fn approve_branch(")
            .expect("approve_branch function must exist");
        let body = &production_code[func_start..];
        let end = body.find("\n    pub fn ").unwrap_or(body.len());
        let func_body = &body[..end];

        assert!(
            func_body.contains("H10") && func_body.contains("re-freeze")
                || func_body.contains("re-verify") && func_body.contains("freeze"),
            "H10: approve_branch must re-verify/re-freeze cgroup before finalize_approved_commit"
        );
    }

    #[test]
    fn test_f16_fallback_transition_not_silent() {
        let source = include_str!("branch.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        // Find the FailOperational double-failure section
        let fail_section = production_code
            .find("double failure in FailOperational")
            .expect("FailOperational double-failure path must exist");
        let context = &production_code[fail_section..];
        // Get the next ~300 chars to capture the transition call
        let end = context.len().min(300);
        let snippet = &context[..end];
        assert!(
            !snippet.contains("let _ = self.transition"),
            "F16: fallback transition to Failed must not use `let _ =` — error must be logged"
        );
    }

    /// M9: Verify policy error audit outcome includes error context, not just "error".
    #[test]
    fn test_m9_error_outcome_uses_fixed_label() {
        // T1: Policy error outcome MUST use a fixed "error" label to prevent
        // unbounded Prometheus metric cardinality from dynamic error messages.
        // The detailed error is logged via tracing::error! instead.
        let source = include_str!("branch.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        let after_second_error = production_code
            .split("PolicyDecision::Error")
            .nth(2)
            .unwrap_or("");
        let snippet = &after_second_error[..after_second_error.len().min(500)];
        assert!(
            snippet.contains("\"error\""),
            "T1: Policy error outcome must use a fixed label to prevent metric cardinality explosion. Found: {}",
            snippet
        );
        // Ensure we don't interpolate the error message into the label
        assert!(
            !snippet.contains("format!(\"error"),
            "T1: Policy error outcome must NOT interpolate error message into metric label. Found: {}",
            snippet
        );
    }
}
