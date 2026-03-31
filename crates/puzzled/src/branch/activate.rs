// SPDX-License-Identifier: Apache-2.0
use puzzled_types::{BranchId, BranchInfo, BranchState};
#[cfg(target_os = "linux")]
use std::path::Path;

use crate::error::{PuzzledError, Result};

use super::BranchManager;

impl BranchManager {
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
        let now = chrono::Utc::now();
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
            info.selinux_context = crate::dbus::helpers::read_selinux_context(handle.pid);
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
}
