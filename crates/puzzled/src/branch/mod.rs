// SPDX-License-Identifier: Apache-2.0
mod activate;
mod cleanup;
mod commit_flow;

#[cfg(test)]
mod tests;

use dashmap::DashMap;
use puzzled_types::{BranchId, BranchInfo, BranchState, FileChange, PolicyDecision};
use std::collections::HashSet;
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
use crate::sync_util::unlock_poisoned;
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
    pub(super) config: DaemonConfig,
    pub(super) branches: DashMap<BranchId, BranchInfo>,
    pub(super) profile_loader: ProfileLoader,
    /// H-29: PolicyEngine is usable concurrently without an external RwLock.
    /// `evaluate(&self)` and `reload(&self)` use interior mutability.
    pub(super) policy_engine: PolicyEngine,
    pub(super) wal: WriteAheadLog,
    pub(super) audit: Arc<AuditLogger>,
    pub(super) diff_engine: DiffEngine,
    /// Wrapped in `Mutex` for interior mutability (key rotation needs `&mut self`).
    pub(super) ima: Option<std::sync::Mutex<ImaIntegration>>,
    pub(super) conflict_detector: Arc<Mutex<ConflictDetector>>,
    pub(super) budget_manager: Arc<Mutex<BudgetManager>>,
    pub(super) seccomp_handler: Option<SeccompNotifHandler>,
    pub(super) bpf_lsm: Option<BpfLsmManager>,
    #[cfg(target_os = "linux")]
    pub(super) sandboxes: DashMap<BranchId, crate::sandbox::SandboxHandle>,
    /// Network setup per branch (for cleanup on rollback).
    #[cfg(target_os = "linux")]
    pub(super) network_setups: DashMap<BranchId, crate::sandbox::network::NetworkSetup>,
    /// fanotify trigger receivers per branch.
    #[cfg(target_os = "linux")]
    pub(super) fanotify_triggers:
        DashMap<BranchId, tokio::sync::mpsc::Receiver<puzzled_types::BehavioralTrigger>>,
    /// Network journals per branch (for Gated network mode side-effect replay).
    pub(super) network_journals: DashMap<BranchId, puzzle_proxy::replay::NetworkJournal>,
    /// Proxy server task handles per branch (for Gated network mode).
    /// Stored so we can abort the proxy when the branch is cleaned up.
    pub(super) proxy_tasks: DashMap<BranchId, tokio::task::JoinHandle<()>>,
    /// Prometheus metrics (optional, set once via `set_metrics()`).
    pub(super) metrics: std::sync::OnceLock<Arc<crate::metrics::Metrics>>,
    /// BC2: Set of branches currently mid-commit. Prevents unregister/rollback
    /// during an active commit operation, avoiding race conditions.
    /// Wrapped in Arc so CommitGuard can hold a reference independently of &self.
    pub(super) committing_branches: Arc<Mutex<HashSet<BranchId>>>,
    /// H-10: Pending governance reviews — stores the changeset (Vec<FileChange>)
    /// and base_path for branches awaiting human approval. Populated when
    /// `require_human_approval` is true and policy approves a commit.
    /// Consumed by `approve_branch()` or cleaned up by `reject_branch()` / timeout.
    pub(super) pending_reviews: DashMap<BranchId, (Vec<FileChange>, PathBuf)>,
    /// §3.3: Shared DLP engine for proxy content inspection (None if DLP disabled).
    pub(super) dlp_engine: Option<Arc<puzzle_proxy::dlp::DlpEngine>>,
    /// §3.3: Shared GeoIP database for data residency enforcement (None if unavailable).
    pub(super) geo_database: Option<Arc<puzzle_proxy::geo::GeoIpDatabase>>,
    /// §3.4: Shared credential store for phantom token resolution (None if credentials disabled).
    pub(super) credential_store:
        Option<Arc<tokio::sync::RwLock<puzzle_proxy::credentials::CredentialStore>>>,
    /// §3.4: Shared phantom token manager (None if credentials disabled).
    pub(super) phantom_token_manager:
        Option<Arc<tokio::sync::RwLock<puzzle_proxy::credentials::PhantomTokenManager>>>,
    /// §3.4: Instance secret for ACKF CA key encryption/decryption (None if unavailable).
    /// M-8: Wrapped in Zeroizing to ensure secret is cleared from memory on drop.
    pub(super) instance_secret: Option<zeroize::Zeroizing<[u8; 32]>>,
}

/// BC2: RAII guard that removes a branch from `committing_branches` on drop,
/// ensuring cleanup on all exit paths (normal return, early return, panic).
pub(super) struct CommitGuard {
    pub(super) committing_branches: Arc<Mutex<HashSet<BranchId>>>,
    pub(super) branch_id: BranchId,
}

impl Drop for CommitGuard {
    fn drop(&mut self) {
        let mut committing = unlock_poisoned(self.committing_branches.lock());
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

    /// Return owned list of loaded profile names.
    pub fn profile_names(&self) -> Vec<String> {
        self.profile_loader.list_names()
    }

    /// Return the number of loaded profiles.
    pub fn profile_count(&self) -> usize {
        self.profile_loader.count()
    }

    /// Return the number of active branches.
    pub fn branch_count(&self) -> usize {
        self.branches.len()
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
    pub(super) fn get_metrics(&self) -> Option<&crate::metrics::Metrics> {
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

    /// List all branches (returns owned snapshot — DashMap iteration is lock-free).
    pub fn list(&self) -> Vec<BranchInfo> {
        self.branches.iter().map(|r| r.value().clone()).collect()
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

    /// Discard the branch upper layer (zero residue).
    ///
    /// M19: `reason` is propagated through audit logging and D-Bus signals
    /// to provide context on why the rollback was initiated.
    /// BC2: Check if a branch is currently mid-commit.
    /// External callers (D-Bus rollback) should check this before proceeding.
    pub fn is_committing(&self, id: &BranchId) -> bool {
        let committing = unlock_poisoned(self.committing_branches.lock());
        committing.contains(id)
    }

    pub fn rollback(&self, reason: &str, id: &BranchId) -> Result<()> {
        // BC2: Prevent rollback/unregister while a commit is in progress for this branch.
        // The commit flow uses rollback_internal() for its own rollback needs.
        {
            let committing = unlock_poisoned(self.committing_branches.lock());
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
    pub(super) fn rollback_internal(&self, reason: &str, id: &BranchId) -> Result<()> {
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
    pub(super) fn transition(&self, id: &BranchId, new_state: BranchState) -> Result<()> {
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
    pub(super) fn wal_commit(
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

        // L1/M6: Collect base filesystem paths from WAL operations BEFORE
        // reverse_operations() removes the WAL files. These paths are where
        // `.puzzled_old` orphan files are actually created during commit
        // (via renameat2 RENAME_EXCHANGE), not in branch_root.
        let mut all_base_paths = HashSet::new();

        for branch_id in &incomplete {
            tracing::warn!(
                branch = %branch_id,
                "rolling back incomplete commit from previous run"
            );

            // Read the WAL to find which operations completed and need reversal
            let (operations, completed) = self.wal.read_operations_with_status(branch_id)?;

            // L1/M6: Extract base filesystem paths from CopyFile targets before
            // the WAL file is removed by reverse_operations().
            let branch_base_paths = WriteAheadLog::collect_base_paths_from_wal(&operations);
            all_base_paths.extend(branch_base_paths);

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
            let mut drop_branch_entry = !branch_dir.exists();
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
                drop_branch_entry = true;
            }
            // M15: Drop in-memory branch after WAL cleanup when state was loaded first.
            if drop_branch_entry {
                self.branches.remove(branch_id);
            }
        }

        // L1: Scan branch_root for orphaned .puzzled_old files (original behavior).
        WriteAheadLog::cleanup_orphan_puzzled_old(&self.config.branch_root);

        // L1/M6: Scan base filesystem paths extracted from WAL CopyFile targets.
        // This fixes the audit finding: previously only branch_root was scanned,
        // but .puzzled_old files are created in base filesystem commit target
        // directories (via renameat2 RENAME_EXCHANGE), not in branch_root.
        if !all_base_paths.is_empty() {
            tracing::info!(
                base_path_count = all_base_paths.len(),
                "L1/M6: scanning WAL-derived base filesystem paths for orphaned .puzzled_old files"
            );
            for base_path in &all_base_paths {
                tracing::debug!(
                    path = %base_path.display(),
                    "L1/M6: cleaning orphan .puzzled_old files in base path"
                );
                WriteAheadLog::cleanup_orphan_puzzled_old(base_path);
            }
        }

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

        // M15: Terminate surviving agents after restore — seccomp USER_NOTIF fds are not
        // recoverable; gated syscalls return ENOSYS permanently for pre-crash agents.
        #[cfg(target_os = "linux")]
        kill_surviving_agents_after_recovery(&self.branches);

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
    pub fn approve_branch(&self, id: &BranchId) -> Result<puzzled_types::CommitResult> {
        // H-1/H-2: Use committing_branches guard to prevent concurrent
        // approve+reject race. Only one thread can hold this for a given branch.
        {
            let mut committing = unlock_poisoned(self.committing_branches.lock());
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
            let mut committing = unlock_poisoned(self.committing_branches.lock());
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
        unlock_poisoned(self.conflict_detector.lock()).cancel_reservation(id);

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
    /// Restores Ready/Active branches whose upper_dir still exists on disk as
    /// `Degraded`: seccomp notify, cgroup, and overlay enforcement are not
    /// re-established after restart. Does NOT restore sandbox handles.
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
        for mut info in branches {
            if matches!(info.state, BranchState::Active | BranchState::Ready)
                && info.upper_dir.exists()
            {
                let previous_state = info.state;
                tracing::warn!(
                    branch = %info.id,
                    previous_state = %previous_state,
                    "restored branch was Ready/Active — kernel enforcement cannot survive daemon restart; marking Degraded"
                );
                info.state = BranchState::Degraded;
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
                self.thaw_cgroup(&id);
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

/// Enumerate `agent-*.scope` cgroup directories under `puzzle.slice` (and `user-*.slice` children).
#[cfg(target_os = "linux")]
fn collect_puzzle_agent_scope_dirs(slice: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(slice) else {
        return out;
    };
    for e in entries.flatten() {
        let p = e.path();
        if !p.is_dir() {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with("user-") && name.ends_with(".slice") {
            if let Ok(inner) = std::fs::read_dir(&p) {
                for e2 in inner.flatten() {
                    let p2 = e2.path();
                    if !p2.is_dir() {
                        continue;
                    }
                    let n2 = e2.file_name();
                    let n2s = n2.to_string_lossy();
                    if n2s.starts_with("agent-") && n2s.ends_with(".scope") {
                        out.push(p2);
                    }
                }
            }
        } else if name.starts_with("agent-") && name.ends_with(".scope") {
            out.push(p);
        }
    }
    out
}

/// M15: SIGKILL surviving agent PIDs after daemon restart; scan `puzzle.slice` scopes for stragglers.
#[cfg(target_os = "linux")]
fn kill_surviving_agents_after_recovery(branches: &DashMap<BranchId, BranchInfo>) {
    use nix::errno::Errno;
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    for entry in branches.iter() {
        let id = entry.key().clone();
        let info = entry.value();
        if info.state != BranchState::Degraded {
            continue;
        }
        let Some(pid) = info.pid else {
            continue;
        };
        if pid == 0 {
            continue;
        }
        let Ok(pid_i32) = i32::try_from(pid) else {
            continue;
        };
        match kill(Pid::from_raw(pid_i32), Signal::SIGKILL) {
            Ok(()) => {
                tracing::warn!(
                    pid,
                    branch = %id,
                    "killing surviving agent process {} from degraded branch {} — seccomp notif fd lost, agent cannot be re-governed",
                    pid,
                    id
                );
            }
            Err(Errno::ESRCH) => {}
            Err(e) => {
                tracing::warn!(
                    pid,
                    branch = %id,
                    error = ?e,
                    "could not SIGKILL surviving agent process (may have exited)"
                );
            }
        }
    }

    let slice = std::path::Path::new("/sys/fs/cgroup/puzzle.slice");
    if !slice.is_dir() {
        return;
    }
    for scope_path in collect_puzzle_agent_scope_dirs(slice) {
        let Some(scope_name) = scope_path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(rest) = scope_name
            .strip_prefix("agent-")
            .and_then(|s| s.strip_suffix(".scope"))
        else {
            continue;
        };
        let bid = match BranchId::validated(rest.to_string()) {
            Ok(id) => id,
            Err(_) => continue,
        };
        let orphan_scope = match branches.get(&bid) {
            None => true,
            Some(r) => r.state == BranchState::Degraded,
        };
        if !orphan_scope {
            continue;
        }
        let procs_path = scope_path.join("cgroup.procs");
        let contents = match std::fs::read_to_string(&procs_path) {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(
                    path = %procs_path.display(),
                    error = %e,
                    "M15: could not read cgroup.procs"
                );
                continue;
            }
        };
        for token in contents.split_whitespace() {
            let Ok(pid_u) = token.parse::<u32>() else {
                continue;
            };
            if pid_u == 0 {
                continue;
            }
            let Ok(pid_i32) = i32::try_from(pid_u) else {
                continue;
            };
            match kill(Pid::from_raw(pid_i32), Signal::SIGKILL) {
                Ok(()) => {
                    tracing::warn!(
                        pid = pid_u,
                        cgroup = %scope_path.display(),
                        branch = %bid,
                        "killing surviving agent process {} from orphaned puzzle.slice scope — seccomp notif fd lost, agent cannot be re-governed",
                        pid_u
                    );
                }
                Err(Errno::ESRCH) => {}
                Err(e) => {
                    tracing::debug!(
                        pid = pid_u,
                        error = ?e,
                        "M15: SIGKILL for cgroup.procs pid failed"
                    );
                }
            }
        }
    }
}
