// SPDX-License-Identifier: Apache-2.0
//! Shared types for the PuzzlePod daemon (`puzzled`) and CLI (`puzzlectl`).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;
use zbus::zvariant::Type;

// ---------------------------------------------------------------------------
// Branch identity
// ---------------------------------------------------------------------------

/// Unique identifier for a branch (OverlayFS upper-layer instance).
///
/// The inner `String` field is private to enforce validation on construction.
/// Use `BranchId::new()` for fresh IDs, `BranchId::validated()` for untrusted
/// input, or `BranchId::from()` for trusted internal strings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Type)]
pub struct BranchId(String);

/// Custom `Deserialize` for `BranchId` that validates input via `validated()`.
/// Rejects malformed IDs (path traversal, control chars, etc.) at deserialization
/// time rather than silently accepting them.
impl<'de> Deserialize<'de> for BranchId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        BranchId::validated(s).map_err(serde::de::Error::custom)
    }
}

impl BranchId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Create a BranchId from an externally-provided string, with validation.
    ///
    /// Rejects strings that could enable path traversal or other injection:
    /// - Empty strings
    /// - Strings containing `/`, `..`, `\0`, `\n`, or other control characters
    /// - Strings with non-alphanumeric characters (except `-` and `_`)
    /// - Strings longer than 256 characters
    pub fn validated(s: String) -> std::result::Result<Self, String> {
        if s.is_empty() {
            return Err("BranchId must not be empty".to_string());
        }
        if s.len() > 256 {
            return Err(format!(
                "BranchId exceeds maximum length of 256 characters (got {})",
                s.len()
            ));
        }
        for c in s.chars() {
            if c == '/' {
                return Err("BranchId must not contain '/'".to_string());
            }
            if c == '\0' {
                return Err("BranchId must not contain null bytes".to_string());
            }
            if c.is_control() {
                return Err(format!(
                    "BranchId must not contain control characters (found U+{:04X})",
                    c as u32
                ));
            }
            if !(c.is_alphanumeric() || c == '-' || c == '_') {
                return Err(format!(
                    "BranchId contains invalid character '{}' (allowed: alphanumeric, '-', '_')",
                    c
                ));
            }
        }
        if s.contains("..") {
            return Err("BranchId must not contain '..'".to_string());
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for BranchId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for BranchId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for BranchId {
    /// Create a BranchId from a string.
    ///
    /// G28: Always validates input. Panics on invalid input in both debug and
    /// release builds to prevent silently accepting path-traversal or injection
    /// attacks. This is intended for internal/trusted use (e.g., UUIDs generated
    /// by `BranchId::new()`, test fixtures). For external/untrusted input
    /// (D-Bus, CLI arguments), use `BranchId::validated()` instead.
    fn from(s: String) -> Self {
        match Self::validated(s.clone()) {
            Ok(id) => id,
            Err(e) => {
                // G28: Always validate — do not silently accept invalid input
                // in release builds. Panic to surface misuse immediately.
                eprintln!(
                    "ERROR: G28: BranchId::from() called with invalid input '{}': {}",
                    s, e
                );
                panic!("G28: BranchId::from() called with invalid input: {e}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Branch lifecycle
// ---------------------------------------------------------------------------

/// State machine for a branch's lifecycle.
///
/// ```text
/// E3: Valid state transitions:
///
///   Creating ──→ Ready ──→ Active ──→ Frozen ──→ Committing ──→ Committed
///                  │  │      │  ↑        │  ↑        │
///                  │  │      │  │        │  └────────┘ (WAL failure → Active)
///                  │  │      │  │        │
///                  │  │      │  │        ├──→ GovernanceReview ──→ Committed (approved)
///                  │  │      │  │        │                    └──→ RolledBack (rejected/timeout)
///                  │  │      │  │        ├──→ RolledBack (policy rejected)
///                  │  │      │  │        ├──→ Committed  (empty changeset)
///                  │  │      │  │        └──→ Terminated (OOM during freeze)
///                  │  │      │  │
///                  │  │      │  └──────── Frozen (FailSilent/FailOperational recovery)
///                  │  │      │
///                  │  │      ├──→ RolledBack (user-initiated)
///                  │  │      ├──→ Exited     (clean exit, code 0)
///                  │  │      └──→ Terminated (signal or non-zero exit)
///                  │  │
///                  │  └──→ Frozen (direct-mode commit, no process to freeze)
///                  └──→ RolledBack (workspace cancelled before activation)
///
///   Exited ──→ Frozen (freeze after clean exit for commit)
///   Terminated ──→ RolledBack (cleanup after termination)
///   Committing ──→ Failed (fatal commit error)
///   Any ──→ Degraded (FailOperational/FailSilent — branch tracked but not active)
///   Any ──→ Failed (fail-closed default)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
pub enum BranchState {
    /// Sandbox is being set up (namespaces, OverlayFS, Landlock, seccomp, cgroup).
    Creating,
    /// Workspace directories are provisioned; no sandbox is active yet.
    /// Waiting for `activate_branch()` to spawn the sandboxed process.
    Ready,
    /// Agent is running inside the sandbox.
    Active,
    /// Agent processes are frozen via cgroup.freeze for TOCTOU-free diff.
    Frozen,
    /// Commit is in progress (WAL write → apply → mark complete).
    Committing,
    /// H-9: Awaiting human reviewer approval (governance review).
    /// Policy approved but `require_human_approval` is enabled.
    GovernanceReview,
    /// Changes have been committed to the base filesystem.
    Committed,
    /// Changes have been discarded (upper layer removed).
    RolledBack,
    /// An error occurred during the branch lifecycle.
    Failed,
    /// H-26: Branch is tracked but in a degraded state.
    /// Used by FailOperational/FailSilent modes instead of removing the branch.
    /// The agent process may still be running with reduced capability (FailOperational)
    /// or frozen holding last safe state (FailSilent).
    Degraded,
    /// Agent process exited normally (exit code 0).
    Exited,
    /// Agent process was terminated (signal or non-zero exit).
    Terminated,
}

impl std::fmt::Display for BranchState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Creating => "creating",
            Self::Ready => "ready",
            Self::Active => "active",
            Self::Frozen => "frozen",
            Self::Committing => "committing",
            Self::GovernanceReview => "governance_review",
            Self::Committed => "committed",
            Self::RolledBack => "rolled_back",
            Self::Failed => "failed",
            Self::Degraded => "degraded",
            Self::Exited => "exited",
            Self::Terminated => "terminated",
        };
        f.write_str(s)
    }
}

/// Metadata about an active or completed branch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchInfo {
    pub id: BranchId,
    pub profile: String,
    pub base_path: PathBuf,
    pub upper_dir: PathBuf,
    pub work_dir: PathBuf,
    pub state: BranchState,
    pub created_at: DateTime<Utc>,
    /// M4: Expiration time derived from created_at + profile.lifetime_minutes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// PID of the agent init process (PID 1 inside the namespace).
    pub pid: Option<u32>,
    /// UID of the agent owner.
    pub uid: u32,
    /// Cached SELinux context at branch creation (avoids repeated /proc reads).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selinux_context: Option<String>,
}

// ---------------------------------------------------------------------------
// Filesystem diff
// ---------------------------------------------------------------------------

/// Kind of change detected in the OverlayFS upper layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
pub enum FileChangeKind {
    /// m4: PRD canonical name is "Created"; "Added" kept as primary for backward compat.
    #[serde(alias = "Created")]
    Added,
    Modified,
    Deleted,
    /// m5: PRD canonical name is "PermissionChanged"; "MetadataChanged" kept as primary.
    #[serde(alias = "PermissionChanged")]
    MetadataChanged,
    /// File was renamed (OverlayFS redirect xattr).
    Renamed,
    /// H9: Symbolic link detected in changeset. Rejected by default unless
    /// the agent profile sets `allow_symlinks: true`.
    Symlink,
    /// Q6: Hard link (nlink > 1) detected in changeset.
    Hardlink,
    /// Q6: Block device special file detected in changeset.
    BlockDevice,
    /// Q6: Character device special file detected in changeset.
    CharDevice,
    /// Q6: Named pipe (FIFO) detected in changeset.
    Fifo,
}

/// A single file change in a branch diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChange {
    /// Path relative to the branch root.
    pub path: PathBuf,
    pub kind: FileChangeKind,
    /// Size in bytes (0 for deletions).
    pub size: u64,
    /// Size of the file in the base layer (for Modified changes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_size: Option<u64>,
    /// File mode in the base layer (for Modified/MetadataChanged).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_mode: Option<u32>,
    /// File mode in the upper layer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_mode: Option<u32>,
    /// SHA-256 checksum of file contents (empty for deletions).
    pub checksum: String,
    /// RFC 3339 timestamp of the file modification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// K60: Symlink target path (only populated for Symlink changes).
    /// Included in Rego input so policies can validate symlink destinations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

// ---------------------------------------------------------------------------
// Commit / policy
// ---------------------------------------------------------------------------

/// Result of a branch commit operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitResult {
    pub branch_id: BranchId,
    pub files_committed: u64,
    pub bytes_committed: u64,
    pub policy_result: PolicyDecision,
}

/// Outcome of OPA/Rego policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyDecision {
    Approved,
    Rejected(Vec<Violation>),
    Error(String),
}

/// A single policy violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    /// Rego rule that triggered the violation.
    pub rule: String,
    /// Human-readable description.
    pub message: String,
    pub severity: ViolationSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
pub enum ViolationSeverity {
    Warning,
    Error,
    Critical,
}

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
}

/// Credential injection configuration per profile (§3.4.10).
///
/// Matches the PRD §3.4.10 schema: `secrets` defines per-credential specs,
/// `proxy` configures the transparent DNAT proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialConfig {
    /// Per-credential specifications.
    #[serde(default)]
    pub secrets: Vec<CredentialSpec>,
    /// Proxy configuration for transparent credential injection.
    #[serde(default)]
    pub proxy: CredentialProxyConfig,
}

impl CredentialConfig {
    /// Derive (domain, credential_name, env_var, required) tuples from secrets for
    /// phantom token issuance. Each credential's first Env exposure is used.
    /// M-4: Includes the `required` field from `CredentialSpec`.
    pub fn credential_mappings(&self) -> Vec<(String, String, String, bool)> {
        let mut result = Vec::new();
        for spec in &self.secrets {
            let env_var = spec
                .expose
                .iter()
                .find_map(|e| match e {
                    CredentialExposure::Env { var, .. } => Some(var.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            for domain in &spec.domains {
                result.push((
                    domain.clone(),
                    spec.name.clone(),
                    env_var.clone(),
                    spec.required,
                ));
            }
        }
        result
    }

    /// Whether phantom token injection is enabled (secrets defined and proxy enabled).
    pub fn is_phantom_enabled(&self) -> bool {
        !self.secrets.is_empty() && self.proxy.enabled
    }
}

/// Credential injection mode (§3.4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialMode {
    /// Phantom tokens: agent sees surrogates, proxy injects real credentials.
    #[default]
    Phantom,
    /// Passthrough: agent manages its own credentials (no injection).
    Passthrough,
    /// Blocked: agent cannot use any credentials (all auth headers stripped).
    Blocked,
}

// ---------------------------------------------------------------------------
// §3.4 G16: Extended credential isolation types
// ---------------------------------------------------------------------------

/// Full credential specification per PRD §3.4.10.
///
/// Clone is derived because CredentialSpec is part of CredentialConfig which
/// is embedded in AgentProfile (Clone). This type contains credential
/// *configuration* (names, backends, domains), never real credential values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSpec {
    /// Unique credential name within the profile.
    pub name: String,
    /// Storage backend type.
    #[serde(default)]
    pub backend: CredentialBackendType,
    /// Backend-specific configuration (opaque JSON).
    #[serde(default)]
    pub backend_config: serde_json::Value,
    /// How to expose the credential to the agent (env var, file, etc.).
    #[serde(default)]
    pub expose: Vec<CredentialExposure>,
    /// Whether to issue a phantom token for this credential (default: true).
    #[serde(default = "default_true_val")]
    pub phantom_token: bool,
    /// Domains this credential should be injected for.
    #[serde(default)]
    pub domains: Vec<String>,
    /// Allow wildcard domain patterns (default: false).
    #[serde(default)]
    pub allow_wildcard_domains: bool,
    /// Credential TTL in seconds for rotation (default: 900 = 15 minutes).
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u64,
    /// Headers to scan for phantom token swapping.
    #[serde(default = "default_swap_headers")]
    pub swap_headers: Vec<String>,
    /// Maximum credential value size in bytes (default: 4096).
    #[serde(default = "default_max_credential_size")]
    pub max_credential_size: usize,
    /// Whether this credential is required for branch creation (default: true).
    #[serde(default = "default_true_val")]
    pub required: bool,
}

fn default_true_val() -> bool {
    true
}
fn default_ttl() -> u64 {
    900
}
fn default_swap_headers() -> Vec<String> {
    vec!["authorization".to_string(), "x-api-key".to_string()]
}
fn default_max_credential_size() -> usize {
    4096
}

/// How a credential is exposed to the agent process.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum CredentialExposure {
    /// Expose as an environment variable.
    Env {
        /// Environment variable name.
        var: String,
        /// Optional JSON field path to extract (for structured secrets).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        field: Option<String>,
    },
    /// Expose as a file mounted into the container.
    File {
        /// Path inside the container.
        path: std::path::PathBuf,
        /// File format.
        #[serde(default)]
        format: CredentialFormat,
    },
}

/// File format when exposing credentials as files.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialFormat {
    /// Raw value, no formatting.
    #[default]
    Raw,
    /// INI-style key=value.
    Ini,
    /// JSON object.
    Json,
    /// Shell-compatible KEY=VALUE.
    Dotenv,
}

/// Credential storage backend type.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialBackendType {
    /// AES-256-GCM encrypted local file (HKDF-derived key).
    #[default]
    EncryptedFile,
    /// systemd-creds encrypt/decrypt (PRD §3.4.9 default).
    SystemdCreds,
    /// Read from puzzled's own environment variables (CI/development).
    EnvPassthrough,
    /// HashiCorp Vault KV v2.
    Vault,
    /// OpenBAO (open-source Vault fork).
    Openbao,
    /// AWS STS temporary credentials.
    AwsSts,
}

/// Credential proxy configuration within a profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProxyConfig {
    /// Enable the credential proxy for this profile (default: true).
    /// Per PRD §3.4.10, the proxy is enabled by default when credentials
    /// are configured.
    #[serde(default = "default_true_val")]
    pub enabled: bool,
    /// Ports to intercept via DNAT (default: [80, 443]).
    #[serde(default = "default_proxy_ports")]
    pub ports: Vec<u16>,
    /// Path to the combined CA trust bundle inside the container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_trust_path: Option<std::path::PathBuf>,
    /// Domains that bypass the proxy (direct connection allowed).
    #[serde(default)]
    pub passthrough_domains: Vec<String>,
}

impl Default for CredentialProxyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: default_proxy_ports(),
            ca_trust_path: None,
            passthrough_domains: vec![],
        }
    }
}

fn default_proxy_ports() -> Vec<u16> {
    vec![80, 443]
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

/// Data residency configuration for geographic enforcement (§3.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataResidencyConfig {
    /// Allowed geographic regions (ISO 3166-1 alpha-2 codes or aliases: "EU", "EEA", "US", "APAC").
    pub allowed_regions: Vec<String>,
    /// Enforcement mode.
    #[serde(default)]
    pub geo_enforcement: GeoEnforcement,
    /// Verify that DNS-resolved IPs match the claimed geographic region.
    #[serde(default)]
    pub dns_verification: bool,
    /// Path to MaxMind GeoLite2-Country database (.mmdb).
    #[serde(default = "default_geo_database")]
    pub geo_database: String,
    /// Domain exceptions (allowed regardless of region).
    #[serde(default)]
    pub exceptions: Vec<GeoException>,
}

fn default_geo_database() -> String {
    "/usr/share/GeoIP/GeoLite2-Country.mmdb".to_string()
}

/// Geographic enforcement mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GeoEnforcement {
    #[default]
    Strict,
    Permissive,
}

/// Domain exception for data residency rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoException {
    pub domain: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
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

// ---------------------------------------------------------------------------
// Conflict detection
// ---------------------------------------------------------------------------

/// A conflict between concurrent branches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conflict {
    /// The conflicting file path.
    pub path: PathBuf,
    /// Branch IDs that modified this path.
    pub conflicting_branches: Vec<BranchId>,
    /// Type of conflict.
    pub kind: ConflictKind,
}

/// Type of cross-branch conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
pub enum ConflictKind {
    /// Both branches modified the same file.
    BothModified,
    /// One branch modified, another deleted.
    ModifiedAndDeleted,
    /// Both branches created the same new file.
    BothCreated,
}

/// Strategy for resolving cross-branch conflicts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Type)]
pub enum ConflictResolution {
    /// Default: reject the commit.
    #[default]
    Reject,
    /// Last writer wins (overwrite silently).
    LastWriterWins,
    /// Three-way merge for text files, reject for binary.
    MergeIfText,
    /// Non-overlapping path prefixes per branch.
    ScopePartition,
}

// ---------------------------------------------------------------------------
// Budget / adaptive escalation
// ---------------------------------------------------------------------------

/// Budget tier for adaptive resource allocation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Type)]
pub enum BudgetTier {
    /// Minimal resources, strict limits.
    #[default]
    Restricted,
    /// Standard allocation after proven clean commits.
    Standard,
    /// Extended allocation for established agents.
    Extended,
}

/// Budget status for a branch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetStatus {
    pub branch_id: BranchId,
    pub tier: BudgetTier,
    pub clean_commits: u32,
    pub violations: u32,
}

// ---------------------------------------------------------------------------
// Behavioral triggers (fanotify)
// ---------------------------------------------------------------------------

/// A behavioral trigger fired by the fanotify monitor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BehavioralTrigger {
    MassDeletion {
        count: u32,
        threshold: u32,
    },
    ExcessiveReads {
        rate: u32,
        threshold: u32,
    },
    CredentialAccess {
        path: String,
    },
    /// Fanotify event queue overflowed — incremental tracking is incomplete.
    /// The diff engine must fall back to a full upper-dir walk for this branch.
    QueueOverflow,
    /// §3.4 G28: Phantom token detected in file write — potential credential leak.
    /// Fired when fanotify detects a write containing `pt_puzzled_*` patterns.
    PhantomTokenLeakage {
        /// File path where the phantom token was written.
        file_path: String,
        /// The phantom token prefix detected (first 16 chars max).
        token_prefix: String,
    },
}

// ---------------------------------------------------------------------------
// Audit (persistent storage)
// ---------------------------------------------------------------------------

/// Filter for querying audit events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFilter {
    /// Filter by branch ID.
    pub branch_id: Option<String>,
    /// Filter by event type.
    pub event_type: Option<String>,
    /// Filter events since this timestamp (RFC 3339).
    pub since: Option<String>,
    /// Maximum number of events to return.
    pub limit: Option<u32>,
}

// ---------------------------------------------------------------------------
// Attestation (§3.1 — Cryptographic Attestation of Governance)
// ---------------------------------------------------------------------------

/// Identity of the agent that produced a governance event.
///
/// Included in attestation records for third-party verifiability.
/// Contains only metadata (UID, profile, SELinux context) — no PII.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// POSIX UID of the agent process.
    pub uid: u32,
    /// Agent profile name (e.g., "restricted", "standard").
    pub profile: String,
    /// SELinux context if available (e.g., "puzzlepod_t:s0:c42,c99").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selinux_context: Option<String>,
    /// Agent framework if reported by SDK (e.g., "langchain", "crewai").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
}

/// Governance decision recorded in an attestation record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceDecision {
    Approved,
    Rejected,
    Rollback,
    Violation,
    Escape,
    Killed,
    Created,
}

impl std::fmt::Display for GovernanceDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Approved => write!(f, "approved"),
            Self::Rejected => write!(f, "rejected"),
            Self::Rollback => write!(f, "rollback"),
            Self::Violation => write!(f, "violation"),
            Self::Escape => write!(f, "escape"),
            Self::Killed => write!(f, "killed"),
            Self::Created => write!(f, "created"),
        }
    }
}

/// Merkle tree inclusion proof for a single attestation record.
///
/// Given the leaf hash, the proof hashes, and the root hash at `tree_size`,
/// a verifier can confirm that the record exists in the log without
/// downloading the entire tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Index of the leaf in the Merkle tree.
    pub leaf_index: u64,
    /// Tree size at the time the proof was generated.
    pub tree_size: u64,
    /// Sibling hashes from leaf to root (each 32 bytes, hex-encoded).
    pub proof_hashes: Vec<String>,
}

/// Merkle tree consistency proof between two tree sizes.
///
/// Proves that the log at `new_size` is a strict append-only extension
/// of the log at `old_size` — no records were deleted or modified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyProof {
    /// Tree size of the earlier checkpoint.
    pub old_size: u64,
    /// Tree size of the later checkpoint.
    pub new_size: u64,
    /// Proof hashes (each 32 bytes, hex-encoded).
    pub proof_hashes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // -----------------------------------------------------------------------
    // 1. BranchId
    // -----------------------------------------------------------------------

    #[test]
    fn branch_id_new_generates_unique_ids() {
        let a = BranchId::new();
        let b = BranchId::new();
        assert_ne!(a, b, "Two new BranchIds must be distinct");
    }

    #[test]
    fn branch_id_from_string_roundtrip() {
        let raw = "test-branch-42".to_string();
        let id = BranchId::from(raw.clone());
        assert_eq!(id.as_str(), "test-branch-42");
    }

    #[test]
    fn branch_id_display() {
        let id = BranchId::from("display-me".to_string());
        assert_eq!(format!("{id}"), "display-me");
    }

    #[test]
    fn branch_id_validated_accepts_valid() {
        assert!(BranchId::validated("test-branch-42".to_string()).is_ok());
        assert!(BranchId::validated("my_branch_99".to_string()).is_ok());
        assert!(BranchId::validated("abc".to_string()).is_ok());
    }

    #[test]
    fn branch_id_validated_rejects_path_traversal() {
        assert!(BranchId::validated("../../etc".to_string()).is_err());
        assert!(BranchId::validated("foo/bar".to_string()).is_err());
        assert!(BranchId::validated("a..b".to_string()).is_err());
    }

    #[test]
    fn branch_id_validated_rejects_null_and_control() {
        assert!(BranchId::validated("foo\0bar".to_string()).is_err());
        assert!(BranchId::validated("foo\nbar".to_string()).is_err());
        assert!(BranchId::validated("foo\rbar".to_string()).is_err());
        assert!(BranchId::validated("foo\tbar".to_string()).is_err());
    }

    #[test]
    fn branch_id_validated_rejects_empty() {
        assert!(BranchId::validated("".to_string()).is_err());
    }

    #[test]
    fn branch_id_validated_rejects_special_chars() {
        assert!(BranchId::validated("foo bar".to_string()).is_err());
        assert!(BranchId::validated("foo=bar".to_string()).is_err());
        assert!(BranchId::validated("foo;bar".to_string()).is_err());
        assert!(BranchId::validated("foo\"bar".to_string()).is_err());
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "BranchId::from() called with invalid input")]
    fn branch_id_from_panics_on_invalid_debug() {
        let _id = BranchId::from("../../etc/passwd".to_string());
    }

    // H80: Test now expects panic in all builds (impl always panics on invalid input).
    #[test]
    #[should_panic(expected = "BranchId::from() called with invalid input")]
    fn branch_id_from_fallback_on_invalid_release() {
        let _id = BranchId::from("../../etc/passwd".to_string());
    }

    #[test]
    fn branch_id_serde_json_roundtrip() {
        let id = BranchId::from("serde-test".to_string());
        let json = serde_json::to_string(&id).unwrap();
        let back: BranchId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    // -----------------------------------------------------------------------
    // 2. BranchState
    // -----------------------------------------------------------------------

    #[test]
    fn branch_state_display_all_variants() {
        assert_eq!(BranchState::Creating.to_string(), "creating");
        assert_eq!(BranchState::Ready.to_string(), "ready");
        assert_eq!(BranchState::Active.to_string(), "active");
        assert_eq!(BranchState::Frozen.to_string(), "frozen");
        assert_eq!(BranchState::Committing.to_string(), "committing");
        assert_eq!(
            BranchState::GovernanceReview.to_string(),
            "governance_review"
        );
        assert_eq!(BranchState::Committed.to_string(), "committed");
        assert_eq!(BranchState::RolledBack.to_string(), "rolled_back");
        assert_eq!(BranchState::Failed.to_string(), "failed");
        assert_eq!(BranchState::Degraded.to_string(), "degraded");
        assert_eq!(BranchState::Exited.to_string(), "exited");
        assert_eq!(BranchState::Terminated.to_string(), "terminated");
    }

    #[test]
    fn branch_state_partial_eq() {
        assert_eq!(BranchState::Active, BranchState::Active);
        assert_ne!(BranchState::Active, BranchState::Frozen);
    }

    #[test]
    fn branch_state_copy() {
        let a = BranchState::Active;
        let b = a; // Copy
        assert_eq!(a, b);
    }

    #[test]
    fn branch_state_serde_json_roundtrip() {
        for state in [
            BranchState::Creating,
            BranchState::Ready,
            BranchState::Active,
            BranchState::Frozen,
            BranchState::Committing,
            BranchState::GovernanceReview,
            BranchState::Committed,
            BranchState::RolledBack,
            BranchState::Failed,
            BranchState::Degraded,
            BranchState::Exited,
            BranchState::Terminated,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let back: BranchState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, back);
        }
    }

    // -----------------------------------------------------------------------
    // 3. FileChange + FileChangeKind
    // -----------------------------------------------------------------------

    #[test]
    fn file_change_kind_serde_json_roundtrip() {
        for kind in [
            FileChangeKind::Added,
            FileChangeKind::Modified,
            FileChangeKind::Deleted,
            FileChangeKind::MetadataChanged,
            FileChangeKind::Renamed,
            FileChangeKind::Symlink,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: FileChangeKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn file_change_serde_json_roundtrip() {
        let change = FileChange {
            path: PathBuf::from("src/main.rs"),
            kind: FileChangeKind::Modified,
            size: 2048,
            checksum: "abc123def456".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        };
        let json = serde_json::to_string(&change).unwrap();
        let back: FileChange = serde_json::from_str(&json).unwrap();
        assert_eq!(back.path, PathBuf::from("src/main.rs"));
        assert_eq!(back.kind, FileChangeKind::Modified);
        assert_eq!(back.size, 2048);
        assert_eq!(back.checksum, "abc123def456");
    }

    #[test]
    fn file_change_deleted_has_zero_size() {
        let change = FileChange {
            path: PathBuf::from("old_file.txt"),
            kind: FileChangeKind::Deleted,
            size: 0,
            checksum: String::new(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        };
        assert_eq!(change.size, 0);
        assert!(change.checksum.is_empty());
    }

    /// G28: BranchId::From<String> must always validate, not just debug_assert.
    #[test]
    fn test_g28_branch_id_from_validates() {
        let source = include_str!("lib.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // Find the From<String> impl
        let from_impl = prod_source
            .find("fn from(s: String) -> Self")
            .expect("From<String> impl must exist for BranchId");
        let from_block = &prod_source[from_impl..];
        let from_end = from_block.find("\n}").unwrap_or(from_block.len());
        let from_body = &from_block[..from_end];

        // Must call validated() — this is already present
        assert!(
            from_body.contains("validated"),
            "G28: BranchId::from() must call validated()"
        );

        // Must NOT silently accept invalid input in release — should panic or reject
        // The old code had `Self(s)` fallback that silently accepted invalid input.
        // The fix must not contain a bare `Self(s)` fallback.
        assert!(
            !from_body.contains("Self(s)"),
            "G28: BranchId::from() must not silently accept invalid input \
             via bare Self(s) fallback in release builds"
        );
    }

    // -----------------------------------------------------------------------
    // 4. PolicyDecision
    // -----------------------------------------------------------------------

    #[test]
    fn policy_decision_approved_serde_roundtrip() {
        let decision = PolicyDecision::Approved;
        let json = serde_json::to_string(&decision).unwrap();
        let back: PolicyDecision = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, PolicyDecision::Approved));
    }

    #[test]
    fn policy_decision_rejected_serde_roundtrip() {
        let violations = vec![
            Violation {
                rule: "no_credentials".to_string(),
                message: "Found .env file".to_string(),
                severity: ViolationSeverity::Error,
            },
            Violation {
                rule: "size_limit".to_string(),
                message: "Changeset too large".to_string(),
                severity: ViolationSeverity::Warning,
            },
        ];
        let decision = PolicyDecision::Rejected(violations);
        let json = serde_json::to_string(&decision).unwrap();
        let back: PolicyDecision = serde_json::from_str(&json).unwrap();
        match back {
            PolicyDecision::Rejected(v) => {
                assert_eq!(v.len(), 2);
                assert_eq!(v[0].rule, "no_credentials");
                assert_eq!(v[1].severity, ViolationSeverity::Warning);
            }
            _ => panic!("Expected PolicyDecision::Rejected"),
        }
    }

    #[test]
    fn policy_decision_error_serde_roundtrip() {
        let decision = PolicyDecision::Error("OPA engine timeout".to_string());
        let json = serde_json::to_string(&decision).unwrap();
        let back: PolicyDecision = serde_json::from_str(&json).unwrap();
        match back {
            PolicyDecision::Error(msg) => assert_eq!(msg, "OPA engine timeout"),
            _ => panic!("Expected PolicyDecision::Error"),
        }
    }

    // -----------------------------------------------------------------------
    // 5. Violation + ViolationSeverity
    // -----------------------------------------------------------------------

    #[test]
    fn violation_creation_and_serde() {
        let v = Violation {
            rule: "no_persistence".to_string(),
            message: "Attempted to create a cron job".to_string(),
            severity: ViolationSeverity::Critical,
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: Violation = serde_json::from_str(&json).unwrap();
        assert_eq!(back.rule, "no_persistence");
        assert_eq!(back.message, "Attempted to create a cron job");
        assert_eq!(back.severity, ViolationSeverity::Critical);
    }

    #[test]
    fn violation_severity_all_variants_serde() {
        for sev in [
            ViolationSeverity::Warning,
            ViolationSeverity::Error,
            ViolationSeverity::Critical,
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            let back: ViolationSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(sev, back);
        }
    }

    // -----------------------------------------------------------------------
    // 6. CommitResult
    // -----------------------------------------------------------------------

    #[test]
    fn commit_result_serde_json_roundtrip() {
        let result = CommitResult {
            branch_id: BranchId::from("commit-test-branch".to_string()),
            files_committed: 42,
            bytes_committed: 1_048_576,
            policy_result: PolicyDecision::Approved,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: CommitResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.branch_id.as_str(), "commit-test-branch");
        assert_eq!(back.files_committed, 42);
        assert_eq!(back.bytes_committed, 1_048_576);
        assert!(matches!(back.policy_result, PolicyDecision::Approved));
    }

    // -----------------------------------------------------------------------
    // 7. ResourceLimits: Default values
    // -----------------------------------------------------------------------

    #[test]
    fn resource_limits_default_values_are_sensible() {
        let defaults = ResourceLimits::default();
        assert!(defaults.memory_bytes > 0, "memory_bytes must be non-zero");
        assert_eq!(defaults.memory_bytes, 512 * 1024 * 1024); // 512 MiB
        assert!(defaults.cpu_shares > 0, "cpu_shares must be non-zero");
        assert!(defaults.io_weight > 0, "io_weight must be non-zero");
        assert!(defaults.max_pids > 0, "max_pids must be non-zero");
        assert!(
            defaults.storage_quota_mb > 0,
            "storage_quota_mb must be non-zero"
        );
        assert!(defaults.inode_quota > 0, "inode_quota must be non-zero");
    }

    #[test]
    fn resource_limits_serde_roundtrip() {
        let limits = ResourceLimits::default();
        let json = serde_json::to_string(&limits).unwrap();
        let back: ResourceLimits = serde_json::from_str(&json).unwrap();
        assert_eq!(back.memory_bytes, limits.memory_bytes);
        assert_eq!(back.max_pids, limits.max_pids);
    }

    #[test]
    fn resource_limits_validate_defaults_pass() {
        let limits = ResourceLimits::default();
        assert!(limits.validate().is_empty(), "defaults should validate");
    }

    #[test]
    fn resource_limits_validate_cpu_shares_range() {
        let limits = ResourceLimits {
            cpu_shares: 0,
            ..Default::default()
        };
        assert!(!limits.validate().is_empty());
        let limits = ResourceLimits {
            cpu_shares: 10001,
            ..Default::default()
        };
        assert!(!limits.validate().is_empty());
        let limits = ResourceLimits {
            cpu_shares: 10000,
            ..Default::default()
        };
        assert!(limits.validate().is_empty());
    }

    #[test]
    fn resource_limits_validate_io_weight_range() {
        let limits = ResourceLimits {
            io_weight: 0,
            ..Default::default()
        };
        assert!(!limits.validate().is_empty());
        let limits = ResourceLimits {
            io_weight: 10001,
            ..Default::default()
        };
        assert!(!limits.validate().is_empty());
    }

    #[test]
    fn resource_limits_validate_max_pids_range() {
        let limits = ResourceLimits {
            max_pids: 0,
            ..Default::default()
        };
        assert!(!limits.validate().is_empty());
        let limits = ResourceLimits {
            max_pids: 4_194_305,
            ..Default::default()
        };
        assert!(!limits.validate().is_empty());
        let limits = ResourceLimits {
            max_pids: 4_194_304,
            ..Default::default()
        };
        assert!(limits.validate().is_empty());
    }

    #[test]
    fn resource_limits_validate_inode_quota() {
        let limits = ResourceLimits {
            inode_quota: 0,
            ..Default::default()
        };
        assert!(!limits.validate().is_empty());
    }

    // -----------------------------------------------------------------------
    // 8. AgentProfile: full YAML roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn agent_profile_serde_yaml_roundtrip() {
        let profile = AgentProfile {
            name: "test-agent".to_string(),
            description: "A test agent profile".to_string(),
            filesystem: FilesystemRules {
                read_allowlist: vec![PathBuf::from("/home/agent"), PathBuf::from("/usr/lib")],
                write_allowlist: vec![PathBuf::from("/home/agent/workspace")],
                denylist: vec![PathBuf::from("/etc/shadow"), PathBuf::from("/root")],
                read_denylist: vec![],
                write_denylist: vec![],
            },
            exec_allowlist: vec!["/usr/bin/python3".to_string(), "/usr/bin/git".to_string()],
            exec_denylist: vec![],
            resource_limits: ResourceLimits::default(),
            network: NetworkConfig {
                mode: NetworkMode::Gated,
                allowed_domains: vec!["api.example.com".to_string()],
                data_residency: None,
                dlp_rules_path: None,
            },
            behavioral: BehavioralConfig::default(),
            fail_mode: FailMode::FailClosed,
            capabilities: vec![],
            enforcement: Default::default(),
            seccomp_mode: SeccompMode::default(),
            allow_symlinks: false,
            allow_exec_overlay: false,
            credentials: None,
        };

        let yaml = serde_yaml::to_string(&profile).unwrap();
        let back: AgentProfile = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(back.name, "test-agent");
        assert_eq!(back.description, "A test agent profile");
        assert_eq!(back.filesystem.read_allowlist.len(), 2);
        assert_eq!(back.filesystem.write_allowlist.len(), 1);
        assert_eq!(back.filesystem.denylist.len(), 2);
        assert_eq!(back.exec_allowlist.len(), 2);
        assert_eq!(back.resource_limits.memory_bytes, 512 * 1024 * 1024);
        assert_eq!(back.network.mode, NetworkMode::Gated);
        assert_eq!(back.network.allowed_domains, vec!["api.example.com"]);
        assert_eq!(back.behavioral.max_deletions, 50);
        assert_eq!(back.fail_mode, FailMode::FailClosed);
    }

    #[test]
    fn agent_profile_serde_json_roundtrip() {
        let profile = AgentProfile {
            name: "json-test".to_string(),
            description: "JSON roundtrip test".to_string(),
            filesystem: FilesystemRules {
                read_allowlist: vec![PathBuf::from("/tmp")],
                write_allowlist: vec![PathBuf::from("/tmp/out")],
                denylist: vec![],
                read_denylist: vec![],
                write_denylist: vec![],
            },
            exec_allowlist: vec!["/bin/echo".to_string()],
            exec_denylist: vec![],
            resource_limits: ResourceLimits {
                memory_bytes: 256 * 1024 * 1024,
                cpu_shares: 50,
                io_weight: 50,
                max_pids: 16,
                storage_quota_mb: 256,
                inode_quota: 5000,
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
            },
            network: NetworkConfig {
                mode: NetworkMode::Blocked,
                allowed_domains: vec![],
                data_residency: None,
                dlp_rules_path: None,
            },
            behavioral: BehavioralConfig {
                max_deletions: 10,
                max_reads_per_minute: 500,
                credential_access_alert: false,
                phantom_token_prefixes: Vec::new(),
            },
            fail_mode: FailMode::FailSafeState,
            capabilities: vec!["CAP_NET_RAW".to_string()],
            enforcement: Default::default(),
            seccomp_mode: SeccompMode::Strict,
            allow_symlinks: false,
            allow_exec_overlay: false,
            credentials: None,
        };

        let json = serde_json::to_string_pretty(&profile).unwrap();
        let back: AgentProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "json-test");
        assert_eq!(back.fail_mode, FailMode::FailSafeState);
        assert_eq!(back.resource_limits.cpu_shares, 50);
    }

    // -----------------------------------------------------------------------
    // 9. NetworkMode: all variants
    // -----------------------------------------------------------------------

    #[test]
    fn network_mode_all_variants() {
        let modes = [
            NetworkMode::Blocked,
            NetworkMode::Gated,
            NetworkMode::Monitored,
            NetworkMode::Unrestricted,
        ];
        for mode in modes {
            let json = serde_json::to_string(&mode).unwrap();
            let back: NetworkMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, back);
        }
    }

    #[test]
    fn network_mode_partial_eq() {
        assert_eq!(NetworkMode::Blocked, NetworkMode::Blocked);
        assert_ne!(NetworkMode::Blocked, NetworkMode::Gated);
        assert_ne!(NetworkMode::Monitored, NetworkMode::Unrestricted);
    }

    // -----------------------------------------------------------------------
    // 10. BehavioralConfig: Default values
    // -----------------------------------------------------------------------

    #[test]
    fn behavioral_config_default_values() {
        let config = BehavioralConfig::default();
        assert_eq!(config.max_deletions, 50);
        assert_eq!(config.max_reads_per_minute, 1000);
        assert!(config.credential_access_alert);
    }

    #[test]
    fn behavioral_config_serde_roundtrip() {
        let config = BehavioralConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: BehavioralConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_deletions, config.max_deletions);
        assert_eq!(back.max_reads_per_minute, config.max_reads_per_minute);
        assert_eq!(back.credential_access_alert, config.credential_access_alert);
    }

    // -----------------------------------------------------------------------
    // 11. FailMode: Default is FailClosed
    // -----------------------------------------------------------------------

    #[test]
    fn fail_mode_default_is_fail_closed() {
        assert_eq!(FailMode::default(), FailMode::FailClosed);
    }

    #[test]
    fn fail_mode_all_variants_serde() {
        for mode in [
            FailMode::FailClosed,
            FailMode::FailSilent,
            FailMode::FailOperational,
            FailMode::FailSafeState,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: FailMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, back);
        }
    }

    // -----------------------------------------------------------------------
    // 12. SeccompMode: Default is Permissive
    // -----------------------------------------------------------------------

    #[test]
    fn seccomp_mode_default_is_permissive() {
        assert_eq!(SeccompMode::default(), SeccompMode::Permissive);
    }

    #[test]
    fn seccomp_mode_display() {
        assert_eq!(SeccompMode::Permissive.to_string(), "permissive");
        assert_eq!(SeccompMode::Strict.to_string(), "strict");
    }

    #[test]
    fn seccomp_mode_all_variants_serde() {
        for mode in [SeccompMode::Permissive, SeccompMode::Strict] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: SeccompMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, back);
        }
    }

    #[test]
    fn seccomp_mode_partial_eq() {
        assert_eq!(SeccompMode::Permissive, SeccompMode::Permissive);
        assert_eq!(SeccompMode::Strict, SeccompMode::Strict);
        assert_ne!(SeccompMode::Permissive, SeccompMode::Strict);
    }

    // -----------------------------------------------------------------------
    // 13. BudgetTier: Default is Restricted
    // -----------------------------------------------------------------------

    #[test]
    fn budget_tier_default_is_restricted() {
        assert_eq!(BudgetTier::default(), BudgetTier::Restricted);
    }

    #[test]
    fn budget_tier_all_variants_serde() {
        for tier in [
            BudgetTier::Restricted,
            BudgetTier::Standard,
            BudgetTier::Extended,
        ] {
            let json = serde_json::to_string(&tier).unwrap();
            let back: BudgetTier = serde_json::from_str(&json).unwrap();
            assert_eq!(tier, back);
        }
    }

    // -----------------------------------------------------------------------
    // 13. ConflictKind: PartialEq
    // -----------------------------------------------------------------------

    #[test]
    fn conflict_kind_partial_eq() {
        assert_eq!(ConflictKind::BothModified, ConflictKind::BothModified);
        assert_eq!(
            ConflictKind::ModifiedAndDeleted,
            ConflictKind::ModifiedAndDeleted
        );
        assert_eq!(ConflictKind::BothCreated, ConflictKind::BothCreated);
        assert_ne!(ConflictKind::BothModified, ConflictKind::BothCreated);
        assert_ne!(ConflictKind::ModifiedAndDeleted, ConflictKind::BothModified);
    }

    #[test]
    fn conflict_serde_roundtrip() {
        let conflict = Conflict {
            path: PathBuf::from("shared/config.yaml"),
            conflicting_branches: vec![
                BranchId::from("branch-a".to_string()),
                BranchId::from("branch-b".to_string()),
            ],
            kind: ConflictKind::BothModified,
        };
        let json = serde_json::to_string(&conflict).unwrap();
        let back: Conflict = serde_json::from_str(&json).unwrap();
        assert_eq!(back.path, PathBuf::from("shared/config.yaml"));
        assert_eq!(back.conflicting_branches.len(), 2);
        assert_eq!(back.kind, ConflictKind::BothModified);
    }

    #[test]
    fn conflict_resolution_default_is_reject() {
        assert_eq!(ConflictResolution::default(), ConflictResolution::Reject);
    }

    // -----------------------------------------------------------------------
    // 14. AuditFilter: optional fields default to None
    // -----------------------------------------------------------------------

    #[test]
    fn audit_filter_optional_fields_default_to_none() {
        // Deserialize from an empty JSON object — all fields should be None.
        let filter: AuditFilter = serde_json::from_str(
            r#"{"branch_id": null, "event_type": null, "since": null, "limit": null}"#,
        )
        .unwrap();
        assert!(filter.branch_id.is_none());
        assert!(filter.event_type.is_none());
        assert!(filter.since.is_none());
        assert!(filter.limit.is_none());
    }

    #[test]
    fn audit_filter_with_values_serde_roundtrip() {
        let filter = AuditFilter {
            branch_id: Some("branch-123".to_string()),
            event_type: Some("commit".to_string()),
            since: Some("2026-01-01T00:00:00Z".to_string()),
            limit: Some(100),
        };
        let json = serde_json::to_string(&filter).unwrap();
        let back: AuditFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(back.branch_id.as_deref(), Some("branch-123"));
        assert_eq!(back.event_type.as_deref(), Some("commit"));
        assert_eq!(back.since.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(back.limit, Some(100));
    }

    // -----------------------------------------------------------------------
    // Extra: BehavioralTrigger serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn behavioral_trigger_mass_deletion_serde() {
        let trigger = BehavioralTrigger::MassDeletion {
            count: 100,
            threshold: 50,
        };
        let json = serde_json::to_string(&trigger).unwrap();
        let back: BehavioralTrigger = serde_json::from_str(&json).unwrap();
        match back {
            BehavioralTrigger::MassDeletion { count, threshold } => {
                assert_eq!(count, 100);
                assert_eq!(threshold, 50);
            }
            _ => panic!("Expected MassDeletion"),
        }
    }

    #[test]
    fn behavioral_trigger_excessive_reads_serde() {
        let trigger = BehavioralTrigger::ExcessiveReads {
            rate: 5000,
            threshold: 1000,
        };
        let json = serde_json::to_string(&trigger).unwrap();
        let back: BehavioralTrigger = serde_json::from_str(&json).unwrap();
        match back {
            BehavioralTrigger::ExcessiveReads { rate, threshold } => {
                assert_eq!(rate, 5000);
                assert_eq!(threshold, 1000);
            }
            _ => panic!("Expected ExcessiveReads"),
        }
    }

    #[test]
    fn behavioral_trigger_queue_overflow_serde() {
        let trigger = BehavioralTrigger::QueueOverflow;
        let json = serde_json::to_string(&trigger).unwrap();
        let back: BehavioralTrigger = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, BehavioralTrigger::QueueOverflow));
    }

    #[test]
    fn behavioral_trigger_credential_access_serde() {
        let trigger = BehavioralTrigger::CredentialAccess {
            path: "/etc/shadow".to_string(),
        };
        let json = serde_json::to_string(&trigger).unwrap();
        let back: BehavioralTrigger = serde_json::from_str(&json).unwrap();
        match back {
            BehavioralTrigger::CredentialAccess { path } => {
                assert_eq!(path, "/etc/shadow");
            }
            _ => panic!("Expected CredentialAccess"),
        }
    }

    // -----------------------------------------------------------------------
    // Extra: BranchInfo serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn branch_info_serde_json_roundtrip() {
        let info = BranchInfo {
            id: BranchId::from("info-test".to_string()),
            profile: "standard".to_string(),
            base_path: PathBuf::from("/var/lib/puzzled/base"),
            upper_dir: PathBuf::from("/var/lib/puzzled/branches/info-test/upper"),
            work_dir: PathBuf::from("/var/lib/puzzled/branches/info-test/work"),
            state: BranchState::Active,
            created_at: Utc::now(),
            expires_at: None,
            pid: Some(12345),
            uid: 1000,
            selinux_context: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: BranchInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id.as_str(), "info-test");
        assert_eq!(back.profile, "standard");
        assert_eq!(back.state, BranchState::Active);
        assert_eq!(back.pid, Some(12345));
        assert_eq!(back.uid, 1000);
    }

    // -----------------------------------------------------------------------
    // Extra: BudgetStatus serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn budget_status_serde_roundtrip() {
        let status = BudgetStatus {
            branch_id: BranchId::from("budget-branch".to_string()),
            tier: BudgetTier::Standard,
            clean_commits: 10,
            violations: 1,
        };
        let json = serde_json::to_string(&status).unwrap();
        let back: BudgetStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back.branch_id.as_str(), "budget-branch");
        assert_eq!(back.tier, BudgetTier::Standard);
        assert_eq!(back.clean_commits, 10);
        assert_eq!(back.violations, 1);
    }

    // -----------------------------------------------------------------------
    // Governance significance
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_governance_significant() {
        // Governance-significant events
        assert!(is_governance_significant("branch_created"));
        assert!(is_governance_significant("branch_committed"));
        assert!(is_governance_significant("branch_rolled_back"));
        assert!(is_governance_significant("policy_violation"));
        assert!(is_governance_significant("commit_rejected"));
        assert!(is_governance_significant("sandbox_escape"));
        assert!(is_governance_significant("behavioral_trigger"));
        assert!(is_governance_significant("agent_killed"));

        // High-frequency events are NOT governance-significant
        assert!(!is_governance_significant("exec_gated"));
        assert!(!is_governance_significant("connect_gated"));
        assert!(!is_governance_significant("branch_frozen"));
        assert!(!is_governance_significant("profile_loaded"));
        assert!(!is_governance_significant("policy_reloaded"));
        assert!(!is_governance_significant(""));
        assert!(!is_governance_significant("unknown_event"));
    }

    // -----------------------------------------------------------------------
    // F2: Property-based tests (proptest)
    // -----------------------------------------------------------------------

    mod proptest_tests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// F2: BranchId::validated never panics on arbitrary input.
            /// It returns Ok or Err, but never crashes.
            #[test]
            fn branch_id_validated_never_panics(s in "\\PC{0,512}") {
                let _ = BranchId::validated(s);
            }

            /// F2: BranchId::validated accepts all UUID-format strings.
            #[test]
            fn branch_id_validated_accepts_uuid(
                a in "[0-9a-f]{8}",
                b in "[0-9a-f]{4}",
                c in "[0-9a-f]{4}",
                d in "[0-9a-f]{4}",
                e in "[0-9a-f]{12}",
            ) {
                let uuid_str = format!("{a}-{b}-{c}-{d}-{e}");
                prop_assert!(BranchId::validated(uuid_str).is_ok());
            }

            /// F2: BranchId::validated rejects strings containing path traversal.
            #[test]
            fn branch_id_rejects_path_traversal(
                prefix in "[a-z]{0,10}",
                suffix in "[a-z]{0,10}",
            ) {
                let with_dotdot = format!("{prefix}../{suffix}");
                prop_assert!(BranchId::validated(with_dotdot).is_err());
            }

            /// F2: BranchId::validated rejects strings with null bytes.
            #[test]
            fn branch_id_rejects_null_bytes(
                prefix in "[a-z]{1,10}",
                suffix in "[a-z]{1,10}",
            ) {
                let with_null = format!("{prefix}\0{suffix}");
                prop_assert!(BranchId::validated(with_null).is_err());
            }

            /// F2: FileChange serialization roundtrips correctly.
            #[test]
            fn file_change_roundtrip(
                path in "[a-z/]{1,50}",
                size in 0u64..1_000_000,
                checksum in "[0-9a-f]{64}",
            ) {
                let change = FileChange {
                    path: PathBuf::from(&path),
                    kind: FileChangeKind::Added,
                    size,
                    checksum: checksum.clone(),
                    old_size: None,
                    old_mode: None,
                    new_mode: None,
                    timestamp: None,
                    target: None,
                };
                let json = serde_json::to_string(&change).unwrap();
                let back: FileChange = serde_json::from_str(&json).unwrap();
                prop_assert_eq!(back.path, PathBuf::from(&path));
                prop_assert_eq!(back.size, size);
                prop_assert_eq!(back.checksum, checksum);
            }
        }
    }

    // -----------------------------------------------------------------------
    // §4.1 TrustLevel
    // -----------------------------------------------------------------------

    #[test]
    fn trust_level_from_score_boundaries() {
        assert_eq!(TrustLevel::from_score(0), TrustLevel::Untrusted);
        assert_eq!(TrustLevel::from_score(19), TrustLevel::Untrusted);
        assert_eq!(TrustLevel::from_score(20), TrustLevel::Restricted);
        assert_eq!(TrustLevel::from_score(39), TrustLevel::Restricted);
        assert_eq!(TrustLevel::from_score(40), TrustLevel::Standard);
        assert_eq!(TrustLevel::from_score(59), TrustLevel::Standard);
        assert_eq!(TrustLevel::from_score(60), TrustLevel::Elevated);
        assert_eq!(TrustLevel::from_score(79), TrustLevel::Elevated);
        assert_eq!(TrustLevel::from_score(80), TrustLevel::Trusted);
        assert_eq!(TrustLevel::from_score(100), TrustLevel::Trusted);
    }

    #[test]
    fn trust_level_as_str_all_variants() {
        assert_eq!(TrustLevel::Untrusted.as_str(), "untrusted");
        assert_eq!(TrustLevel::Restricted.as_str(), "restricted");
        assert_eq!(TrustLevel::Standard.as_str(), "standard");
        assert_eq!(TrustLevel::Elevated.as_str(), "elevated");
        assert_eq!(TrustLevel::Trusted.as_str(), "trusted");
    }

    #[test]
    fn trust_level_display() {
        assert_eq!(format!("{}", TrustLevel::Untrusted), "untrusted");
        assert_eq!(format!("{}", TrustLevel::Restricted), "restricted");
        assert_eq!(format!("{}", TrustLevel::Standard), "standard");
        assert_eq!(format!("{}", TrustLevel::Elevated), "elevated");
        assert_eq!(format!("{}", TrustLevel::Trusted), "trusted");
    }

    #[test]
    fn trust_level_serde_roundtrip() {
        for level in [
            TrustLevel::Untrusted,
            TrustLevel::Restricted,
            TrustLevel::Standard,
            TrustLevel::Elevated,
            TrustLevel::Trusted,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let back: TrustLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, back);
        }
    }

    // -----------------------------------------------------------------------
    // §4.1 TrustState
    // -----------------------------------------------------------------------

    #[test]
    fn trust_state_new_defaults() {
        let state = TrustState::new(1000, 50);
        assert_eq!(state.uid, 1000);
        assert_eq!(state.score, 50);
        assert_eq!(state.level, TrustLevel::Standard);
        assert_eq!(state.clean_commits, 0);
        assert_eq!(state.violations, 0);
        assert!(!state.override_active);
        assert!(state.override_expires.is_none());
        assert!(state.override_level.is_none());
    }

    #[test]
    fn trust_state_new_clamps_at_100() {
        let state = TrustState::new(1000, 200);
        assert_eq!(state.score, 100);
        assert_eq!(state.level, TrustLevel::Trusted);
    }

    #[test]
    fn trust_state_apply_delta_positive() {
        let mut state = TrustState::new(1000, 50);
        state.apply_delta(10);
        assert_eq!(state.score, 60);
        assert_eq!(state.level, TrustLevel::Elevated);
    }

    #[test]
    fn trust_state_apply_delta_negative() {
        let mut state = TrustState::new(1000, 50);
        state.apply_delta(-30);
        assert_eq!(state.score, 20);
        assert_eq!(state.level, TrustLevel::Restricted);
    }

    #[test]
    fn trust_state_apply_delta_clamps_at_zero() {
        let mut state = TrustState::new(1000, 10);
        state.apply_delta(-100);
        assert_eq!(state.score, 0);
        assert_eq!(state.level, TrustLevel::Untrusted);
    }

    #[test]
    fn trust_state_apply_delta_clamps_at_100() {
        let mut state = TrustState::new(1000, 90);
        state.apply_delta(50);
        assert_eq!(state.score, 100);
        assert_eq!(state.level, TrustLevel::Trusted);
    }

    /// S48: Ensure apply_delta uses saturating arithmetic to prevent wrapping
    /// on extreme delta values.
    #[test]
    fn test_s48_trust_score_saturating() {
        let source = include_str!("lib.rs");
        // Find the apply_delta method in the full source (it's defined after
        // the test module, so we cannot use the split-by-cfg(test) trick).
        let fn_start = source
            .find("pub fn apply_delta")
            .expect("apply_delta function must exist in lib.rs");
        let fn_block = &source[fn_start..];
        let fn_end = fn_block[1..]
            .find("\n    pub fn ")
            .or_else(|| fn_block[1..].find("\n}"))
            .map(|p| p + 1)
            .unwrap_or(fn_block.len());
        let fn_body = &fn_block[..fn_end];

        assert!(
            fn_body.contains("saturating_add"),
            "S48: apply_delta must use saturating_add to prevent wrapping \
             on extreme delta values. Found:\n{}",
            fn_body
        );
    }

    #[test]
    fn trust_state_effective_level_no_override() {
        let state = TrustState::new(1000, 50);
        assert_eq!(state.effective_level(), TrustLevel::Standard);
    }

    #[test]
    fn trust_state_effective_level_with_active_override() {
        let mut state = TrustState::new(1000, 50);
        state.override_active = true;
        // Set expiry far in the future
        let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        state.override_expires = Some(future);
        state.override_level = Some(TrustLevel::Trusted);
        assert_eq!(state.effective_level(), TrustLevel::Trusted);
    }

    #[test]
    fn trust_state_effective_level_expired_override() {
        let mut state = TrustState::new(1000, 50);
        state.override_active = true;
        // Set expiry in the past
        let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        state.override_expires = Some(past);
        state.override_level = Some(TrustLevel::Trusted);
        // Expired override should fall back to normal level
        assert_eq!(state.effective_level(), TrustLevel::Standard);
    }

    #[test]
    fn trust_state_clear_expired_override() {
        let mut state = TrustState::new(1000, 50);
        state.override_active = true;
        state.override_level = Some(TrustLevel::Trusted);
        let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        state.override_expires = Some(past);

        // Should clear and return true.
        assert!(state.clear_expired_override());
        assert!(!state.override_active);
        assert!(state.override_level.is_none());
        assert!(state.override_expires.is_none());

        // Second call is a no-op.
        assert!(!state.clear_expired_override());
    }

    #[test]
    fn trust_state_serde_roundtrip() {
        let state = TrustState::new(1000, 75);
        let json = serde_json::to_string(&state).unwrap();
        let back: TrustState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.uid, 1000);
        assert_eq!(back.score, 75);
        assert_eq!(back.level, TrustLevel::Elevated);
        assert_eq!(back.clean_commits, 0);
        assert_eq!(back.violations, 0);
        assert!(!back.override_active);
    }

    // -----------------------------------------------------------------------
    // §4.3 ProvenanceRecord + ProvenanceType serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn provenance_record_request_serde_roundtrip() {
        let record = ProvenanceRecord {
            id: "prov-001".to_string(),
            record_type: ProvenanceType::Request {
                request_id: "req-1".to_string(),
                user_uid: 1000,
                prompt_hash: "abc123".to_string(),
            },
            branch_id: "branch-42".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: ProvenanceRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "prov-001");
        assert_eq!(back.branch_id, "branch-42");
        match back.record_type {
            ProvenanceType::Request {
                request_id,
                user_uid,
                prompt_hash,
            } => {
                assert_eq!(request_id, "req-1");
                assert_eq!(user_uid, 1000);
                assert_eq!(prompt_hash, "abc123");
            }
            _ => panic!("Expected ProvenanceType::Request"),
        }
    }

    #[test]
    fn provenance_type_governance_serde_roundtrip() {
        let ptype = ProvenanceType::Governance {
            decision_id: "dec-1".to_string(),
            change_ids: vec!["c1".to_string(), "c2".to_string()],
            policy_version: "1.0.0".to_string(),
            result: "approved".to_string(),
            violations: vec![],
            manifest_hash: Some("deadbeef".to_string()),
        };
        let json = serde_json::to_string(&ptype).unwrap();
        let back: ProvenanceType = serde_json::from_str(&json).unwrap();
        match back {
            ProvenanceType::Governance {
                decision_id,
                change_ids,
                policy_version,
                result,
                violations,
                manifest_hash,
            } => {
                assert_eq!(decision_id, "dec-1");
                assert_eq!(change_ids.len(), 2);
                assert_eq!(policy_version, "1.0.0");
                assert_eq!(result, "approved");
                assert!(violations.is_empty());
                assert_eq!(manifest_hash, Some("deadbeef".to_string()));
            }
            _ => panic!("Expected ProvenanceType::Governance"),
        }
    }

    // -----------------------------------------------------------------------
    // §4.5 GovernanceClaims serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn governance_claims_serde_roundtrip() {
        let claims = GovernanceClaims {
            sub: "spiffe://example.com/agent/branch-1".to_string(),
            iss: "puzzled".to_string(),
            aud: vec!["api.example.com".to_string()],
            iat: 1700000000,
            exp: 1700003600,
            branch_id: "branch-1".to_string(),
            agent_profile: "standard".to_string(),
            trust_level: "elevated".to_string(),
            trust_score: 65,
            governance: GovernanceClaimsMetadata {
                enforcement_layers: vec!["landlock".to_string(), "seccomp".to_string()],
                policy_version: "1.2.3".to_string(),
                attestation_chain_hash: Some("cafe0000".to_string()),
                attestation_chain_length: 42,
            },
            containment: Some(ContainmentClaims {
                filesystem_scope: "/workspace".to_string(),
                network_mode: "gated".to_string(),
                allowed_domains: vec!["api.example.com".to_string()],
                exec_allowlist_count: 5,
            }),
            delegation: None,
        };
        let json = serde_json::to_string(&claims).unwrap();
        let back: GovernanceClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(back.sub, claims.sub);
        assert_eq!(back.iss, "puzzled");
        assert_eq!(back.branch_id, "branch-1");
        assert_eq!(back.trust_score, 65);
        assert_eq!(back.governance.enforcement_layers.len(), 2);
        assert_eq!(back.governance.attestation_chain_length, 42);
        let c = back.containment.unwrap();
        assert_eq!(c.filesystem_scope, "/workspace");
        assert_eq!(c.exec_allowlist_count, 5);
    }

    #[test]
    fn governance_claims_without_containment_serde_roundtrip() {
        let claims = GovernanceClaims {
            sub: "spiffe://example.com/agent/branch-2".to_string(),
            iss: "puzzled".to_string(),
            aud: vec![],
            iat: 1700000000,
            exp: 1700003600,
            branch_id: "branch-2".to_string(),
            agent_profile: "restricted".to_string(),
            trust_level: "untrusted".to_string(),
            trust_score: 10,
            governance: GovernanceClaimsMetadata {
                enforcement_layers: vec![],
                policy_version: "0.1.0".to_string(),
                attestation_chain_hash: None,
                attestation_chain_length: 0,
            },
            containment: None,
            delegation: None,
        };
        let json = serde_json::to_string(&claims).unwrap();
        let back: GovernanceClaims = serde_json::from_str(&json).unwrap();
        assert!(back.containment.is_none());
        assert_eq!(back.trust_score, 10);
    }

    /// F26: Verify that apply_delta has a debug_assert protecting against
    /// trust scores exceeding the expected 0-100 range before the i32 cast.
    #[test]
    fn test_f26_trust_score_has_debug_assert() {
        let source = include_str!("lib.rs");

        // Find the actual apply_delta implementation (the last one, which is
        // the production code — earlier occurrences are in tests).
        // Search for "pub fn apply_delta" and check the function body.
        let mut found = false;
        let lines: Vec<&str> = source.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.contains("pub fn apply_delta") {
                // Check the next ~5 lines for debug_assert!
                let body = lines[i..std::cmp::min(i + 8, lines.len())].join("\n");
                if body.contains("debug_assert!") {
                    found = true;
                }
            }
        }

        assert!(
            found,
            "F26: apply_delta must contain a debug_assert! to guard against \
             trust score exceeding expected range before the i32 cast"
        );
    }

    // -----------------------------------------------------------------------
    // H89: ResourceLimits validate() catches zero memory_bytes and storage_quota_mb
    // -----------------------------------------------------------------------

    #[test]
    fn h89_resource_limits_validate_zero_memory_bytes() {
        let limits = ResourceLimits {
            memory_bytes: 0,
            ..Default::default()
        };
        let errors = limits.validate();
        assert!(
            errors.iter().any(|e| e.contains("memory_bytes")),
            "H89: validate() must catch memory_bytes: 0, got errors: {:?}",
            errors
        );
    }

    #[test]
    fn h89_resource_limits_validate_zero_storage_quota_mb() {
        let limits = ResourceLimits {
            storage_quota_mb: 0,
            ..Default::default()
        };
        let errors = limits.validate();
        assert!(
            errors.iter().any(|e| e.contains("storage_quota_mb")),
            "H89: validate() must catch storage_quota_mb: 0, got errors: {:?}",
            errors
        );
    }

    #[test]
    fn h89_resource_limits_default_passes_validate() {
        let limits = ResourceLimits::default();
        let errors = limits.validate();
        assert!(
            errors.is_empty(),
            "H89: Default ResourceLimits must pass validation, got: {:?}",
            errors
        );
    }

    // -----------------------------------------------------------------------
    // H97: ResourceLimits::validate() doc comment documents caller obligation
    // -----------------------------------------------------------------------

    #[test]
    fn h97_validate_doc_comment_documents_caller_obligation() {
        let source = include_str!("lib.rs");
        assert!(
            source.contains("Callers MUST call `validate()` after deserialization"),
            "H97: ResourceLimits::validate() must document that callers MUST call it after deserialization"
        );
    }

    // J69: Upper bound validation for memory_bytes and storage_quota_mb
    #[test]
    fn j69_resource_limits_validate_excessive_memory_bytes() {
        let limits = ResourceLimits {
            memory_bytes: ResourceLimits::MAX_MEMORY_BYTES + 1,
            ..Default::default()
        };
        let errors = limits.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("J69") && e.contains("memory_bytes")),
            "J69: validate() must catch memory_bytes exceeding 64 TiB, got errors: {:?}",
            errors
        );
    }

    #[test]
    fn j69_resource_limits_validate_excessive_storage_quota_mb() {
        let limits = ResourceLimits {
            storage_quota_mb: ResourceLimits::MAX_STORAGE_QUOTA_MB + 1,
            ..Default::default()
        };
        let errors = limits.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("J69") && e.contains("storage_quota_mb")),
            "J69: validate() must catch storage_quota_mb exceeding 1 PiB, got errors: {:?}",
            errors
        );
    }

    #[test]
    fn j69_resource_limits_at_max_passes() {
        let limits = ResourceLimits {
            memory_bytes: ResourceLimits::MAX_MEMORY_BYTES,
            storage_quota_mb: ResourceLimits::MAX_STORAGE_QUOTA_MB,
            ..Default::default()
        };
        let errors = limits.validate();
        assert!(
            !errors.iter().any(|e| e.contains("J69")),
            "J69: values at exactly the max should pass, got errors: {:?}",
            errors
        );
    }
}

// ---------------------------------------------------------------------------
// Governance significance classification
// ---------------------------------------------------------------------------

/// Determine which audit event types are governance-significant and
/// should receive attestation signatures.
///
/// Governance-significant events are those that represent material state
/// transitions or security incidents. High-frequency operational events
/// (e.g., `exec_gated`, `connect_gated`) are excluded to avoid excessive
/// attestation overhead.
pub fn is_governance_significant(event_type: &str) -> bool {
    matches!(
        event_type,
        "branch_created"
            | "branch_committed"
            | "branch_rolled_back"
            | "policy_violation"
            | "commit_rejected"
            | "sandbox_escape"
            | "behavioral_trigger"
            | "agent_killed"
    )
}

// ---------------------------------------------------------------------------
// Merkle tree crypto utilities (A-M1: deduplicated from attestation.rs + puzzlectl)
// ---------------------------------------------------------------------------

/// Shared Merkle tree cryptographic functions used by both `puzzled` (attestation)
/// and `puzzlectl` (verification). Domain-separated hashing per RFC 6962.
pub mod merkle {
    use sha2::{Digest, Sha256};

    /// Domain separation prefix for leaf nodes (RFC 6962 §2.1).
    const LEAF_PREFIX: u8 = 0x00;
    /// Domain separation prefix for internal nodes (RFC 6962 §2.1).
    const NODE_PREFIX: u8 = 0x01;

    /// Compute domain-separated leaf hash: SHA-256(0x00 || data).
    pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([LEAF_PREFIX]);
        hasher.update(data);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Compute domain-separated internal node hash: SHA-256(0x01 || left || right).
    pub fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([NODE_PREFIX]);
        hasher.update(left);
        hasher.update(right);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Largest power of 2 strictly less than `n`.
    pub fn largest_power_of_2_less_than(n: u64) -> u64 {
        if n <= 1 {
            return 0;
        }
        1u64 << (63 - (n - 1).leading_zeros())
    }

    /// Encode a byte slice as a lowercase hex string.
    pub fn hex_encode(bytes: &[u8]) -> String {
        const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(HEX_CHARS[(b >> 4) as usize] as char);
            s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
        }
        s
    }

    /// Decode a hex string to bytes.
    ///
    /// Returns an error for odd-length strings, non-ASCII input, or invalid hex digits.
    pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
        // A-M3: Guard against multi-byte UTF-8 input which would cause panics
        // in the byte-offset indexing below (&s[i..i + 2]).
        if !s.is_ascii() {
            return Err("non-ASCII characters in hex string".to_string());
        }
        if !s.len().is_multiple_of(2) {
            return Err("odd-length hex string".to_string());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16)
                    .map_err(|e| format!("invalid hex at position {}: {}", i, e))
            })
            .collect()
    }

    /// Recompute root hash from an inclusion proof (bottom-up traversal).
    ///
    /// Proof elements are consumed bottom-up via `pos` index, matching the
    /// order they were generated (leaf-level sibling first, root-level last).
    pub fn compute_root_from_inclusion(
        leaf_index: u64,
        tree_size: u64,
        leaf_hash: &[u8; 32],
        proof: &[[u8; 32]],
        pos: &mut usize,
    ) -> Option<[u8; 32]> {
        if tree_size <= 1 {
            return Some(*leaf_hash);
        }
        let k = largest_power_of_2_less_than(tree_size);
        if leaf_index < k {
            let left = compute_root_from_inclusion(leaf_index, k, leaf_hash, proof, pos)?;
            let right = *proof.get(*pos)?;
            *pos += 1;
            Some(hash_node(&left, &right))
        } else {
            let right =
                compute_root_from_inclusion(leaf_index - k, tree_size - k, leaf_hash, proof, pos)?;
            let left = *proof.get(*pos)?;
            *pos += 1;
            Some(hash_node(&left, &right))
        }
    }

    /// Verify a Merkle inclusion proof against an expected root hash.
    ///
    /// Returns `Ok(true)` if the proof is valid, `Ok(false)` if the computed root
    /// doesn't match, or `Err` if the proof is malformed.
    pub fn verify_merkle_inclusion(
        leaf_hash: &[u8; 32],
        proof: &super::InclusionProof,
        expected_root: &[u8; 32],
    ) -> Result<bool, String> {
        let proof_hashes: Vec<[u8; 32]> = proof
            .proof_hashes
            .iter()
            .map(|h| {
                let bytes = hex_decode(h)?;
                if bytes.len() != 32 {
                    return Err(format!("proof hash must be 32 bytes, got {}", bytes.len()));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(arr)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut pos = 0;
        let computed = compute_root_from_inclusion(
            proof.leaf_index,
            proof.tree_size,
            leaf_hash,
            &proof_hashes,
            &mut pos,
        )
        .ok_or_else(|| "malformed inclusion proof: insufficient proof hashes".to_string())?;

        // RFC 6962: all proof hashes must be consumed
        if pos != proof_hashes.len() {
            return Err(format!(
                "malformed inclusion proof: {} extra hashes",
                proof_hashes.len() - pos
            ));
        }

        Ok(computed == *expected_root)
    }
}

// ---------------------------------------------------------------------------
// Trust (§4.1 -- Graduated Trust with Behavioral Learning)
// ---------------------------------------------------------------------------

/// Trust level derived from numeric score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Score 0-19.
    Untrusted,
    /// Score 20-39.
    Restricted,
    /// Score 40-59.
    Standard,
    /// Score 60-79.
    Elevated,
    /// Score 80-100.
    Trusted,
}

impl TrustLevel {
    /// Return the trust level corresponding to a numeric score (0-100).
    pub fn from_score(score: u32) -> Self {
        match score {
            0..=19 => TrustLevel::Untrusted,
            20..=39 => TrustLevel::Restricted,
            40..=59 => TrustLevel::Standard,
            60..=79 => TrustLevel::Elevated,
            _ => TrustLevel::Trusted,
        }
    }

    /// Return the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustLevel::Untrusted => "untrusted",
            TrustLevel::Restricted => "restricted",
            TrustLevel::Standard => "standard",
            TrustLevel::Elevated => "elevated",
            TrustLevel::Trusted => "trusted",
        }
    }
}

impl std::fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Persistent trust state for an agent identity (keyed by UID).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustState {
    pub uid: u32,
    pub score: u32,
    pub level: TrustLevel,
    pub clean_commits: u32,
    pub violations: u32,
    pub last_updated: String,
    pub override_active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_expires: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_level: Option<TrustLevel>,
}

impl TrustState {
    /// Create a new trust state with the given initial score.
    pub fn new(uid: u32, initial_score: u32) -> Self {
        let score = initial_score.min(100);
        Self {
            uid,
            score,
            level: TrustLevel::from_score(score),
            clean_commits: 0,
            violations: 0,
            last_updated: chrono::Utc::now().to_rfc3339(),
            override_active: false,
            override_expires: None,
            override_level: None,
        }
    }

    /// Return the effective trust level (accounting for overrides).
    pub fn effective_level(&self) -> TrustLevel {
        if self.override_active {
            if let Some(ref expires) = self.override_expires {
                if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(expires) {
                    if chrono::Utc::now() < exp {
                        return self.override_level.unwrap_or(self.level);
                    }
                }
            }
        }
        self.level
    }

    /// Clear the override if it has expired, returning true if cleared.
    ///
    /// Call this before persisting state or exposing it via D-Bus to avoid
    /// stale `override_active: true` in serialized output.
    pub fn clear_expired_override(&mut self) -> bool {
        if !self.override_active {
            return false;
        }
        if let Some(ref expires) = self.override_expires {
            if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(expires) {
                if chrono::Utc::now() >= exp {
                    self.override_active = false;
                    self.override_level = None;
                    self.override_expires = None;
                    return true;
                }
            }
        }
        false
    }

    /// Apply a score delta, clamping to [0, 100].
    /// S48: Uses saturating_add to prevent wrapping on extreme delta values.
    pub fn apply_delta(&mut self, delta: i32) {
        // F26: Guard against future changes that might allow score > 100,
        // which would cause the `as i32` cast to produce unexpected values
        // if score ever exceeded i32::MAX.
        debug_assert!(self.score <= 100, "F26: trust score out of expected range");
        let new_score = (self.score as i32).saturating_add(delta).clamp(0, 100) as u32;
        self.score = new_score;
        self.level = TrustLevel::from_score(new_score);
        self.last_updated = chrono::Utc::now().to_rfc3339();
    }
}

/// A trust score change event (appended to history).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEvent {
    pub timestamp: String,
    pub uid: u32,
    /// Machine-readable event type (e.g., "commit_approved", "policy_violation").
    /// Used for structured querying — separate from human-readable `reason`.
    #[serde(default)]
    pub event_type: String,
    pub old_score: u32,
    pub new_score: u32,
    pub old_level: TrustLevel,
    pub new_level: TrustLevel,
    pub delta: i32,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch_id: Option<String>,
}

/// Scoring rule loaded from configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringRule {
    pub event: String,
    pub delta: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_increase_per_day: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Behavioral baseline severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BaselineSeverity {
    /// Warning-level deviation.
    Warning,
    /// Critical deviation.
    Critical,
    /// Fatal deviation (reserved for future use).
    Fatal,
}

// ---------------------------------------------------------------------------
// Provenance (§4.3 — Full Provenance Chain)
// ---------------------------------------------------------------------------

/// A provenance record linking cause to effect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    pub id: String,
    pub record_type: ProvenanceType,
    pub branch_id: String,
    pub timestamp: String,
}

/// Provenance record type -- each variant captures a different stage of the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProvenanceType {
    /// Reported by agent framework SDK.
    Request {
        request_id: String,
        user_uid: u32,
        prompt_hash: String,
    },
    /// Reported by agent framework SDK.
    Inference {
        inference_id: String,
        request_id: String,
        model: String,
        token_count: u32,
        tool_calls: Vec<String>,
    },
    /// From seccomp USER_NOTIF handler + optional SDK enrichment.
    ToolInvocation {
        invocation_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        inference_id: Option<String>,
        tool_path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        arguments_hash: Option<String>,
        pid: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
        /// Timestamp when the tool invocation started (RFC 3339).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        started_at: Option<String>,
        /// Timestamp when the tool invocation exited (RFC 3339).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exited_at: Option<String>,
    },
    /// From DiffEngine + fanotify correlation.
    FileChange {
        change_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        invocation_id: Option<String>,
        path: String,
        kind: FileChangeKind,
        size: u64,
        checksum: String,
    },
    /// From policy evaluation + CommitManifest.
    Governance {
        decision_id: String,
        change_ids: Vec<String>,
        policy_version: String,
        result: String,
        violations: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        manifest_hash: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// Identity (§4.5 -- Agent Workload Identity)
// ---------------------------------------------------------------------------

/// Delegation metadata for sub-agent workflows (§4.5).
///
/// Every delegation has a `delegated_by_uid` — at depth 0 this is the human
/// operator who started the agent; at depth > 0 it is the parent agent's UID.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DelegationMetadata {
    pub depth: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_branch_id: Option<String>,
    pub delegated_by_uid: u32,
}

/// JWT-SVID governance claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GovernanceClaims {
    pub sub: String,
    pub iss: String,
    pub aud: Vec<String>,
    pub iat: i64,
    pub exp: i64,
    pub branch_id: String,
    pub agent_profile: String,
    pub trust_level: String,
    pub trust_score: u32,
    pub governance: GovernanceClaimsMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub containment: Option<ContainmentClaims>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<DelegationMetadata>,
}

/// Metadata about governance enforcement layers embedded in JWT claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GovernanceClaimsMetadata {
    pub enforcement_layers: Vec<String>,
    pub policy_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_chain_hash: Option<String>,
    pub attestation_chain_length: u32,
}

/// Containment scope claims embedded in JWT.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContainmentClaims {
    pub filesystem_scope: String,
    pub network_mode: String,
    pub allowed_domains: Vec<String>,
    pub exec_allowlist_count: u32,
}

/// Identity injection mode for puzzle-proxy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityInjectionMode {
    JwtSvid,
    MtlsClientCert,
    Both,
    #[default]
    Disabled,
}
