// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zbus::zvariant::Type;

use crate::credential::{CredentialConfig, DataResidencyConfig};

// ---------------------------------------------------------------------------
// Agent profiles
// ---------------------------------------------------------------------------

/// An agent profile defines the sandbox constraints for a class of agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentProfile {
    pub name: String,
    pub description: String,
    pub filesystem: FilesystemRules,
    pub exec_allowlist: Vec<String>,
    /// H12: Executables explicitly denied (e.g., "curl", "wget", "nc").
    #[serde(default)]
    pub exec_denylist: Vec<String>,
    pub resource_limits: ResourceLimits,
    pub network: NetworkConfig,
    pub behavioral: BehavioralConfig,
    /// Fail mode for safety-critical deployments.
    #[serde(default)]
    pub fail_mode: FailMode,
    /// Linux capabilities to retain (empty = drop all).
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Which enforcement mechanisms are required vs best-effort.
    #[serde(default)]
    pub enforcement: EnforcementRequirements,
    /// seccomp filter mode: `Permissive` (default-allow + denylist) or
    /// `Strict` (default-deny + allowlist). Default: `Permissive`.
    #[serde(default)]
    pub seccomp_mode: SeccompMode,
    /// H10: Whether symlinks are allowed in changesets. Default: false (reject).
    /// Set to true for profiles that legitimately need to create symlinks.
    #[serde(default)]
    pub allow_symlinks: bool,
    /// Whether to allow exec from the OverlayFS mount. Default: false (MS_NOEXEC applied).
    #[serde(default)]
    pub allow_exec_overlay: bool,
    /// Credential injection configuration (§3.4). If None, no credentials injected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<CredentialConfig>,
    /// Optional parent profile name for inheritance.
    /// When set, the profile inherits all settings from the parent,
    /// with this profile's explicit settings taking precedence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extends: Option<String>,
}

/// seccomp filter strategy for sandboxed agent processes.
///
/// `Permissive` (default-allow): all syscalls are allowed except those in
/// the KillProcess deny list and the USER_NOTIF-gated list. Unknown or
/// missing syscalls do not cause silent failures in agent workloads.
///
/// `Strict` (default-deny): only explicitly allowlisted syscalls are
/// permitted. Anything not in the allowlist, USER_NOTIF list, or
/// KillProcess deny list returns EPERM. More secure but requires the
/// allowlist to cover every syscall the agent workload needs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Type)]
pub enum SeccompMode {
    /// Default-allow with aggressive denylist. Safe for production — unknown
    /// syscalls succeed, deny list blocks escape vectors, USER_NOTIF gates
    /// high-impact calls. Avoids silent workload failures from incomplete
    /// allowlists.
    #[default]
    Permissive,
    /// Default-deny with curated allowlist (~120 syscalls). Maximum security
    /// posture — novel/unknown syscalls return EPERM. Requires validation
    /// that the allowlist covers the target workload's syscall surface.
    Strict,
}

impl std::fmt::Display for SeccompMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Permissive => f.write_str("permissive"),
            Self::Strict => f.write_str("strict"),
        }
    }
}

/// Configures which enforcement mechanisms must succeed during sandbox setup.
///
/// When a mechanism marked `true` fails, sandbox creation is aborted instead
/// of silently continuing. Default: all best-effort (false) for backwards
/// compatibility and development on non-XFS/non-BPF systems.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnforcementRequirements {
    /// XFS project quota setup must succeed.
    #[serde(default)]
    pub require_quota: bool,
    /// BPF LSM attachment must succeed.
    #[serde(default)]
    pub require_bpf_lsm: bool,
    /// Landlock ruleset application must succeed.
    #[serde(default)]
    pub require_landlock: bool,
    /// seccomp-BPF filter must be loaded.
    #[serde(default)]
    pub require_seccomp: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemRules {
    /// Paths the agent may read.
    /// m8: Accepts PRD-canonical "read_allow" as alias.
    #[serde(alias = "read_allow")]
    pub read_allowlist: Vec<PathBuf>,
    /// Paths the agent may write.
    /// m8: Accepts PRD-canonical "write_allow" as alias.
    #[serde(alias = "write_allow")]
    pub write_allowlist: Vec<PathBuf>,
    /// Paths explicitly denied (override allowlists).
    pub denylist: Vec<PathBuf>,
    /// H11: Paths explicitly denied for reading (e.g., /etc/shadow, /proc/kcore).
    #[serde(default)]
    pub read_denylist: Vec<PathBuf>,
    /// H11: Paths explicitly denied for writing (e.g., /boot, /usr/bin).
    #[serde(default)]
    pub write_denylist: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub memory_bytes: u64,
    pub cpu_shares: u32,
    pub io_weight: u32,
    pub max_pids: u32,
    pub storage_quota_mb: u64,
    pub inode_quota: u64,
    /// L11: Maximum threads allowed (via clone3 thread counting).
    #[serde(default)]
    pub max_threads: Option<u32>,
    /// L11: Prevent gaining new privileges (PR_SET_NO_NEW_PRIVS).
    #[serde(default)]
    pub no_new_privileges: Option<bool>,
    /// L11: Maximum total files read during branch lifetime.
    #[serde(default)]
    pub max_files_read: Option<u64>,
    /// L11: Maximum total files written during branch lifetime.
    #[serde(default)]
    pub max_files_written: Option<u64>,
    /// L11: Maximum single file size in MB.
    #[serde(default)]
    pub max_single_file_size_mb: Option<u32>,
    /// L6: CPU quota in microseconds per period (e.g., 50000 = 50% of one CPU).
    #[serde(default)]
    pub cpu_quota_us: Option<u64>,
    /// memory.high — soft limit for throttling before OOM kill.
    #[serde(default)]
    pub memory_high: Option<u64>,
    /// io.max — per-device I/O bandwidth limit string (e.g., "MAJ:MIN rbps=VALUE wbps=VALUE").
    #[serde(default)]
    pub io_max: Option<String>,
    /// M2: Maximum exec calls allowed per branch lifetime (default: max_pids * 10).
    #[serde(default)]
    pub max_exec_calls: Option<u32>,
    /// M2: Maximum open file descriptors (default 1024, range 64-65536).
    #[serde(default)]
    pub max_open_fds: Option<u32>,
    /// M2: Maximum files deleted per branch lifetime.
    #[serde(default)]
    pub max_files_deleted: Option<u64>,
    /// M2: Maximum total write volume in MB.
    #[serde(default)]
    pub max_total_write_mb: Option<u32>,
    /// M4: Branch lifetime in minutes (default 60, range 1-1440).
    #[serde(default)]
    pub lifetime_minutes: Option<u32>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_bytes: 512 * 1024 * 1024, // 512 MiB
            cpu_shares: 100,
            io_weight: 100,
            max_pids: 64,
            storage_quota_mb: 1024,
            inode_quota: 10_000,
            max_threads: None,
            no_new_privileges: None,
            max_files_read: None,
            max_files_written: None,
            max_single_file_size_mb: None,
            cpu_quota_us: None,
            memory_high: None,
            io_max: None,
            max_exec_calls: None,
            max_open_fds: None,
            max_files_deleted: None,
            max_total_write_mb: None,
            lifetime_minutes: None,
        }
    }
}

impl ResourceLimits {
    /// M-typ2: Validate resource limit ranges.
    ///
    /// Returns a list of validation errors. Empty list means valid.
    ///
    /// H97: Callers MUST call `validate()` after deserialization (e.g., after
    /// `serde_yaml::from_str`). Serde does not invoke this method automatically;
    /// failing to call it allows invalid limits (zero memory, zero storage) to
    /// reach the sandbox setup code unchecked.
    // J69: Upper bound for memory_bytes: 64 TiB (largest practical server memory)
    // V52: Explicit _u64 suffix to prevent silent overflow on 32-bit targets
    pub const MAX_MEMORY_BYTES: u64 = 64_u64 * 1024 * 1024 * 1024 * 1024; // 64 TiB
                                                                          // J69: Upper bound for storage_quota_mb: 1 PiB
    pub const MAX_STORAGE_QUOTA_MB: u64 = 1024 * 1024 * 1024; // 1 PiB in MB

    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        // H89: memory_bytes must be > 0
        if self.memory_bytes == 0 {
            errors.push("memory_bytes must be > 0".to_string());
        }
        // J69: memory_bytes upper bound
        if self.memory_bytes > Self::MAX_MEMORY_BYTES {
            errors.push(format!(
                "J69: memory_bytes {} exceeds maximum {} (64 TiB)",
                self.memory_bytes,
                Self::MAX_MEMORY_BYTES
            ));
        }
        if self.cpu_shares == 0 || self.cpu_shares > 10000 {
            errors.push(format!(
                "cpu_shares must be 1-10000, got {}",
                self.cpu_shares
            ));
        }
        if self.io_weight == 0 || self.io_weight > 10000 {
            errors.push(format!("io_weight must be 1-10000, got {}", self.io_weight));
        }
        if self.inode_quota == 0 {
            errors.push("inode_quota must be > 0".to_string());
        }
        if self.max_pids == 0 || self.max_pids > 4_194_304 {
            errors.push(format!("max_pids must be 1-4194304, got {}", self.max_pids));
        }
        // H89: storage_quota_mb must be > 0
        if self.storage_quota_mb == 0 {
            errors.push("storage_quota_mb must be > 0".to_string());
        }
        // J69: storage_quota_mb upper bound
        if self.storage_quota_mb > Self::MAX_STORAGE_QUOTA_MB {
            errors.push(format!(
                "J69: storage_quota_mb {} exceeds maximum {} (1 PiB)",
                self.storage_quota_mb,
                Self::MAX_STORAGE_QUOTA_MB
            ));
        }
        errors
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub mode: NetworkMode,
    /// Allowed domains (only for Gated mode).
    pub allowed_domains: Vec<String>,
    /// Data residency configuration (§3.3). If None, no geographic enforcement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_residency: Option<DataResidencyConfig>,
    /// DLP content inspection rules file path (§3.3). If None, no content inspection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dlp_rules_path: Option<String>,
}

/// Network access mode for an agent sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
pub enum NetworkMode {
    /// No network access (isolated network namespace with no interfaces).
    Blocked,
    /// Network access gated through puzzled proxy with domain allowlist.
    Gated,
    /// Full network access with logging.
    Monitored,
    /// Unrestricted network access.
    Unrestricted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralConfig {
    /// Maximum number of files deleted in a single branch session.
    pub max_deletions: u32,
    /// Maximum number of files read per minute.
    pub max_reads_per_minute: u32,
    /// Trigger on access to credential-like paths.
    pub credential_access_alert: bool,
    /// §3.4 G28: Phantom token prefixes to detect in file writes.
    /// When a file write contains any of these prefixes, a
    /// `PhantomTokenLeakage` behavioral trigger is fired.
    #[serde(default)]
    pub phantom_token_prefixes: Vec<String>,
}

impl Default for BehavioralConfig {
    fn default() -> Self {
        Self {
            max_deletions: 50,
            max_reads_per_minute: 1000,
            credential_access_alert: true,
            phantom_token_prefixes: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Fail modes (safety-critical deployments)
// ---------------------------------------------------------------------------

/// Fail mode for safety-critical deployments (IEC 61508 / ISO 26262).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Type)]
pub enum FailMode {
    /// Default: reject commit, rollback branch.
    #[default]
    FailClosed,
    /// Hold last safe state (do not commit, do not rollback).
    FailSilent,
    /// Continue with reduced capability (apply subset of changes).
    FailOperational,
    /// Controlled stop / return to base.
    FailSafeState,
}
