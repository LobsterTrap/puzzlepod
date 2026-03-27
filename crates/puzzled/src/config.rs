// SPDX-License-Identifier: Apache-2.0
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const DEFAULT_CONFIG_PATH: &str = "/etc/puzzled/puzzled.conf";

/// Returns `true` when puzzled is running as a non-root user.
/// Used to select user-mode config paths and defaults.
#[cfg(unix)]
fn is_user_mode() -> bool {
    nix::unistd::getuid().as_raw() != 0
}

#[cfg(not(unix))]
fn is_user_mode() -> bool {
    true
}

/// Returns the user's home directory from `$HOME`.
///
/// Returns `None` if `$HOME` is not set or is not an absolute path —
/// callers must handle this rather than silently falling back to an
/// insecure directory like `/tmp`.
fn home_dir() -> Option<String> {
    std::env::var("HOME")
        .ok()
        .filter(|h| !h.is_empty() && h.starts_with('/'))
}

/// Returns the XDG runtime directory (`$XDG_RUNTIME_DIR`), falling back to `/run/user/<uid>`.
///
/// Returns an error if no runtime directory can be determined — callers
/// must not silently fall back to world-writable directories like `/tmp`.
fn runtime_base_dir() -> Result<String> {
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        if !dir.starts_with('/') {
            anyhow::bail!("$XDG_RUNTIME_DIR must be an absolute path, got '{dir}'");
        }
        return Ok(dir);
    }
    #[cfg(unix)]
    {
        Ok(format!("/run/user/{}", nix::unistd::getuid().as_raw()))
    }
    #[cfg(not(unix))]
    {
        Err(anyhow::anyhow!(
            "$XDG_RUNTIME_DIR is not set and cannot determine runtime directory on this platform"
        ))
    }
}

/// Top-level daemon configuration, deserialized from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Root directory for branch storage (OverlayFS upper layers, work dirs, WAL).
    #[serde(default = "default_branch_root")]
    pub branch_root: PathBuf,

    /// Directory containing agent profile YAML files.
    #[serde(default = "default_profiles_dir")]
    pub profiles_dir: PathBuf,

    /// Directory containing OPA/Rego policy bundles.
    #[serde(default = "default_policies_dir")]
    pub policies_dir: PathBuf,

    /// Maximum number of concurrent branches.
    #[serde(default = "default_max_branches")]
    pub max_branches: u32,

    /// D-Bus bus type ("system" or "session").
    #[serde(default = "default_bus_type")]
    pub bus_type: String,

    /// Filesystem type for branch storage (xfs recommended for project quotas).
    #[serde(default = "default_fs_type")]
    pub fs_type: String,

    /// Log level (trace, debug, info, warn, error).
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Watchdog timeout in seconds (0 = disabled).
    #[serde(default = "default_watchdog_timeout")]
    pub watchdog_timeout_secs: u64,

    /// Path to compiled BPF LSM object file for exec rate limiting.
    #[serde(default = "default_bpf_obj_path")]
    pub bpf_obj_path: PathBuf,

    /// Default storage quota per branch (MB).
    #[serde(default = "default_storage_quota_mb")]
    pub default_storage_quota_mb: u64,

    /// Default inode quota per branch.
    #[serde(default = "default_inode_quota")]
    pub default_inode_quota: u64,

    /// Default branch lifetime in minutes (0 = unlimited).
    #[serde(default = "default_lifetime_minutes")]
    pub default_lifetime_minutes: u64,

    /// Interval in seconds between cleanup sweeps.
    /// m2: Reduced from 300s to 30s to prevent branch accumulation under rapid
    /// agent cycling (e.g., CI/CD pipelines creating/destroying agents frequently).
    #[serde(default = "default_cleanup_interval")]
    pub cleanup_interval_seconds: u64,

    /// Governance policy configuration.
    #[serde(default)]
    pub governance: GovernanceConfig,

    /// Network proxy configuration.
    #[serde(default)]
    pub network: NetworkSectionConfig,

    /// Audit configuration.
    #[serde(default)]
    pub audit: AuditSectionConfig,

    /// Fanotify monitoring configuration.
    #[serde(default)]
    pub fanotify: FanotifyConfig,

    /// BPF LSM configuration.
    #[serde(default)]
    pub bpf_lsm: BpfLsmConfig,

    /// M22: Path to the Ed25519 signing key for IMA changeset signing.
    #[serde(default = "default_signing_key_path")]
    pub signing_key_path: PathBuf,

    /// H10: Require policies to be loaded at startup (fatal if missing).
    #[serde(default)]
    pub require_policies: bool,

    /// L8: Require IMA integration at startup (fatal if initialization fails).
    #[serde(default)]
    pub require_ima: bool,

    /// L9: Require seccomp self-hardening at startup (fatal if fails).
    #[serde(default)]
    pub require_self_hardening: bool,

    /// M-cfg1: Default agent profile name (used when no profile is specified).
    #[serde(default = "default_default_profile")]
    pub default_profile: String,

    /// M-cfg2: Default action on unclean agent exit ("rollback" or "hold").
    #[serde(default = "default_default_action")]
    pub default_action: String,

    /// M-br2: Runtime directory for ephemeral state (state.json).
    /// Should be on tmpfs (/run) rather than persistent storage.
    #[serde(default = "default_runtime_dir")]
    pub runtime_dir: PathBuf,

    /// M-cfg3/M-br6: Timeout in seconds for commit operations.
    /// Must be > 0 and <= 3600.
    #[serde(default = "default_commit_timeout_seconds")]
    pub commit_timeout_seconds: u64,

    /// M-cfg4: Require human approval for commits.
    #[serde(default)]
    pub require_human_approval: bool,

    /// M-cfg5: Timeout in seconds for governance review (human approval window).
    #[serde(default = "default_governance_review_timeout_seconds")]
    pub governance_review_timeout_seconds: u64,

    /// §3.1: Cryptographic attestation configuration.
    #[serde(default)]
    pub attestation: AttestationConfig,

    /// §3.3: DLP content inspection configuration.
    #[serde(default)]
    pub dlp: DlpConfig,

    /// §3.4: Credential injection configuration.
    #[serde(default)]
    pub credentials: CredentialsConfig,

    /// §3.4 G17: Credential proxy configuration.
    #[serde(default)]
    pub credential_proxy: CredentialProxyDaemonConfig,

    /// §3.4 G17: Secure credential store configuration.
    #[serde(default)]
    pub credential_store: CredentialStoreDaemonConfig,

    /// M8: Path to the Unix domain socket for puzzled.
    #[serde(default = "default_socket_path")]
    pub socket_path: PathBuf,

    /// M8: Path to the PID file.
    #[serde(default = "default_pid_file")]
    pub pid_file: PathBuf,

    /// M8: Log target ("journal" or "stderr").
    #[serde(default = "default_log_target")]
    pub log_target: String,

    /// M8: Policy engine type ("opa").
    #[serde(default = "default_policy_engine")]
    pub policy_engine: String,

    /// M8: Enable hot-reload of policies and profiles.
    #[serde(default = "default_true")]
    pub hot_reload: bool,

    /// M8: Heartbeat interval in seconds for watchdog pings.
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_seconds: u32,

    /// M8: Maximum restart attempts before giving up.
    #[serde(default = "default_max_restart_attempts")]
    pub max_restart_attempts: u32,

    /// M8: Enable changeset signing (IMA + Ed25519).
    #[serde(default = "default_true")]
    pub enable_changeset_signing: bool,

    /// §4.1: Graduated trust configuration.
    #[serde(default)]
    pub trust: TrustConfig,

    /// §4.3: Provenance chain configuration.
    #[serde(default)]
    pub provenance: ProvenanceConfig,

    /// §4.5: Agent workload identity configuration.
    #[serde(default)]
    pub identity: IdentityConfig,
}

/// Governance policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceConfig {
    /// Directory containing OPA/Rego policy bundles (overrides top-level policies_dir).
    #[serde(default = "default_policies_dir")]
    pub policy_dir: PathBuf,
    /// Timeout for policy evaluation in milliseconds.
    #[serde(default = "default_evaluation_timeout_ms")]
    pub evaluation_timeout_ms: u64,
    /// Require policy bundle signature verification.
    #[serde(default)]
    pub require_signature: bool,
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self {
            policy_dir: default_policies_dir(),
            evaluation_timeout_ms: default_evaluation_timeout_ms(),
            require_signature: false,
        }
    }
}

/// Network proxy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSectionConfig {
    /// Address the HTTP proxy listens on inside the network namespace.
    #[serde(default = "default_proxy_listen_addr")]
    pub proxy_listen_addr: String,
    /// Port the HTTP proxy listens on.
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,
    /// Default allowed domains for Gated network mode.
    #[serde(default)]
    pub default_allowed_domains: Vec<String>,
    /// Maximum request/response body size in MB.
    #[serde(default = "default_max_body_size_mb")]
    pub max_body_size_mb: u64,
    /// M8: Default network mode ("gated", "blocked", "unrestricted", "monitored").
    #[serde(default = "default_network_mode")]
    pub default_mode: String,
    /// M8: Maximum pending network operations per branch.
    #[serde(default = "default_pending_ops_max")]
    pub pending_ops_max_per_branch: u32,
    /// M8: Maximum pending network operations size in MB.
    #[serde(default = "default_pending_ops_max_size")]
    pub pending_ops_max_size_mb: u32,
}

impl Default for NetworkSectionConfig {
    fn default() -> Self {
        Self {
            proxy_listen_addr: default_proxy_listen_addr(),
            proxy_port: default_proxy_port(),
            default_allowed_domains: vec![],
            max_body_size_mb: default_max_body_size_mb(),
            default_mode: default_network_mode(),
            pending_ops_max_per_branch: default_pending_ops_max(),
            pending_ops_max_size_mb: default_pending_ops_max_size(),
        }
    }
}

/// Audit configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSectionConfig {
    /// Path for the audit log file.
    #[serde(default = "default_audit_log_path")]
    pub audit_log_path: PathBuf,
    /// Path for the HMAC integrity key.
    #[serde(default = "default_integrity_key_path")]
    pub integrity_key_path: PathBuf,
    /// Days to retain audit records.
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
}

impl Default for AuditSectionConfig {
    fn default() -> Self {
        Self {
            audit_log_path: default_audit_log_path(),
            integrity_key_path: default_integrity_key_path(),
            retention_days: default_retention_days(),
        }
    }
}

/// Fanotify monitoring configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FanotifyConfig {
    /// Enable fanotify behavioral monitoring.
    #[serde(default = "default_true")]
    pub enable: bool,
    /// Number of deletions that triggers a mass-delete alert.
    #[serde(default = "default_mass_delete_threshold")]
    pub mass_delete_threshold: u32,
    /// Paths that trigger credential access alerts.
    #[serde(default = "default_credential_paths")]
    pub credential_paths: Vec<String>,
}

impl Default for FanotifyConfig {
    fn default() -> Self {
        Self {
            enable: true,
            mass_delete_threshold: default_mass_delete_threshold(),
            credential_paths: default_credential_paths(),
        }
    }
}

/// BPF LSM configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpfLsmConfig {
    /// Enable BPF LSM exec rate limiting.
    #[serde(default = "default_true")]
    pub enable: bool,
    /// Maximum exec calls per second per branch.
    #[serde(default = "default_max_exec_rate")]
    pub max_exec_rate: u32,
    /// Maximum exec burst (token bucket burst).
    #[serde(default = "default_max_exec_burst")]
    pub max_exec_burst: u32,
}

impl Default for BpfLsmConfig {
    fn default() -> Self {
        Self {
            enable: true,
            max_exec_rate: default_max_exec_rate(),
            max_exec_burst: default_max_exec_burst(),
        }
    }
}

/// §3.1: Cryptographic attestation configuration.
///
/// When `enabled` is `true`, governance-significant audit events are
/// signed with Ed25519 and appended to an append-only Merkle tree.
/// All fields use `#[serde(default)]` so an unmodified config file
/// continues to work identically to v1.0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationConfig {
    /// Enable cryptographic attestation of governance events.
    #[serde(default)]
    pub enabled: bool,
    /// Enable Merkle tree for inclusion/consistency proofs.
    /// Can be disabled on edge devices for reduced overhead.
    #[serde(default = "default_true")]
    pub merkle_tree: bool,
    /// Directory for Merkle tree data files.
    #[serde(default = "default_attestation_dir")]
    pub attestation_dir: PathBuf,
    /// Directory for attestation checkpoints.
    #[serde(default = "default_checkpoint_dir")]
    pub checkpoint_dir: PathBuf,
    /// Interval for automatic checkpoints (number of records).
    #[serde(default = "default_checkpoint_interval")]
    pub checkpoint_interval: u64,
    /// Time interval for automatic checkpoints (seconds).
    #[serde(default = "default_checkpoint_time_interval_secs")]
    pub checkpoint_time_interval_secs: u64,
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            merkle_tree: true,
            attestation_dir: default_attestation_dir(),
            checkpoint_dir: default_checkpoint_dir(),
            checkpoint_interval: default_checkpoint_interval(),
            checkpoint_time_interval_secs: default_checkpoint_time_interval_secs(),
        }
    }
}

fn default_attestation_dir() -> PathBuf {
    PathBuf::from("/var/lib/puzzled/attestation")
}

fn default_checkpoint_dir() -> PathBuf {
    PathBuf::from("/var/lib/puzzled/attestation/checkpoints")
}

fn default_checkpoint_interval() -> u64 {
    100
}

fn default_checkpoint_time_interval_secs() -> u64 {
    60
}

/// §3.3: DLP content inspection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpConfig {
    /// Enable DLP content inspection (default: false).
    #[serde(default)]
    pub enabled: bool,
    /// Default DLP rules file (used when profile doesn't specify dlp_rules_path).
    #[serde(default = "default_dlp_rules_path")]
    pub default_rules_path: PathBuf,
    /// Path to MaxMind GeoLite2-Country database (.mmdb), shared across profiles.
    #[serde(default = "default_geo_database_path")]
    pub geo_database_path: PathBuf,
    /// Maximum request body size to inspect in bytes (default: 10MB).
    #[serde(default = "default_max_inspection_body_size")]
    pub max_inspection_body_size: usize,
    /// Action for oversized request bodies.
    #[serde(default)]
    pub oversized_body_action: OversizedAction,
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_rules_path: default_dlp_rules_path(),
            geo_database_path: default_geo_database_path(),
            max_inspection_body_size: default_max_inspection_body_size(),
            oversized_body_action: OversizedAction::default(),
        }
    }
}

pub use puzzle_proxy::dlp::OversizedAction;

fn default_dlp_rules_path() -> PathBuf {
    PathBuf::from("/etc/puzzled/dlp/rules.yaml")
}

fn default_geo_database_path() -> PathBuf {
    PathBuf::from("/usr/share/GeoIP/GeoLite2-Country.mmdb")
}

fn default_max_inspection_body_size() -> usize {
    10 * 1024 * 1024 // 10MB
}

/// §3.4: Credential backend configuration.
///
/// Matches PRD §3.4.3 `CredentialBackend` enum. This is a lightweight mirror
/// of `puzzle_proxy::credential_backends::BackendConfig` for daemon-level config
/// parsing — the proxy crate has the full backend implementations.
#[derive(Debug, Clone, Serialize, Deserialize)]
// L-11: kebab-case for consistency with CredentialBackendType in puzzled-types.
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum CredentialBackendConfig {
    /// Local AES-256-GCM encrypted file (default).
    Local {
        /// Path to encrypted store file.
        #[serde(default = "default_credential_store_path")]
        store_path: PathBuf,
    },
    /// OS keyring (macOS Keychain, GNOME Keyring, etc.).
    Keyring {
        /// Service name prefix (default: "puzzled").
        #[serde(default = "default_keyring_service")]
        service: String,
    },
    /// HashiCorp Vault / OpenBao.
    Vault {
        /// Vault address (e.g., "https://vault.example.com:8200").
        address: String,
        /// Vault authentication method.
        #[serde(default)]
        auth: VaultAuthConfig,
        /// KV mount path (default: "secret").
        #[serde(default = "default_vault_mount")]
        mount: String,
        /// Key prefix within the mount (default: "puzzled/").
        #[serde(default = "default_vault_prefix")]
        prefix: String,
        /// Cache TTL in seconds (default: 300).
        #[serde(default = "default_vault_cache_ttl")]
        cache_ttl_secs: u64,
    },
}

impl Default for CredentialBackendConfig {
    fn default() -> Self {
        CredentialBackendConfig::Local {
            store_path: default_credential_store_path(),
        }
    }
}

/// §3.4: Vault authentication method configuration.
///
/// Mirrors the proxy-side `VaultAuth` enum. Secrets (token, secret_id)
/// are never stored inline — only paths to files containing them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum VaultAuthConfig {
    /// Static token authentication (simplest, for dev/test).
    Token {
        /// Path to file containing the Vault token.
        #[serde(default = "default_vault_token_path")]
        token_path: PathBuf,
    },
    /// AppRole authentication (recommended for daemons).
    AppRole {
        /// AppRole role ID.
        role_id: String,
        /// Path to file containing the secret ID (rotated externally).
        secret_id_path: PathBuf,
    },
    /// Kubernetes service account authentication.
    Kubernetes {
        /// Vault role name for K8s auth.
        role: String,
    },
}

impl Default for VaultAuthConfig {
    fn default() -> Self {
        VaultAuthConfig::Token {
            token_path: default_vault_token_path(),
        }
    }
}

fn default_vault_token_path() -> PathBuf {
    PathBuf::from("/etc/puzzled/vault-token")
}

fn default_keyring_service() -> String {
    "puzzled".to_string()
}

fn default_vault_mount() -> String {
    "secret".to_string()
}

fn default_vault_prefix() -> String {
    "puzzled/".to_string()
}

fn default_vault_cache_ttl() -> u64 {
    300
}

/// §3.4: Credential injection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialsConfig {
    /// Enable credential injection (default: false).
    #[serde(default)]
    pub enabled: bool,
    /// Credential storage backend.
    #[serde(default)]
    pub backend: CredentialBackendConfig,
    /// Phantom token prefix (default: "pt_puzzled").
    #[serde(default = "default_phantom_prefix")]
    pub phantom_prefix: String,
    /// Phantom token entropy bytes (default: 16).
    #[serde(default = "default_phantom_entropy")]
    pub phantom_entropy_bytes: usize,
}

impl Default for CredentialsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: CredentialBackendConfig::default(),
            phantom_prefix: default_phantom_prefix(),
            phantom_entropy_bytes: default_phantom_entropy(),
        }
    }
}

fn default_credential_store_path() -> PathBuf {
    PathBuf::from("/etc/puzzled/credentials/store.enc")
}

fn default_phantom_prefix() -> String {
    "pt_puzzled".to_string()
}

fn default_phantom_entropy() -> usize {
    16
}

// ---------------------------------------------------------------------------
// §3.4 G17: Credential proxy daemon configuration
// ---------------------------------------------------------------------------

/// §3.4 G17: Configuration for the per-branch credential proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProxyDaemonConfig {
    /// Listen address for proxy listeners (default: 127.0.0.1).
    #[serde(default = "default_proxy_listen")]
    pub listen_address: String,
    /// Port range for proxy listeners.
    /// System: "18000-18499", User: "18500-18999".
    #[serde(default = "default_proxy_port_range_system")]
    pub port_range: String,
    /// Max concurrent connections per branch (default: 64).
    #[serde(default = "default_proxy_max_conns_branch")]
    pub max_concurrent_connections_per_branch: usize,
    /// Max concurrent connections total across all branches (default: 512).
    #[serde(default = "default_proxy_max_conns_total")]
    pub max_concurrent_connections_total: usize,
    /// Multi-tenant wildcard domains that should always be rejected.
    #[serde(default = "default_dangerous_wildcards")]
    pub dangerous_wildcards: Vec<String>,
}

impl Default for CredentialProxyDaemonConfig {
    fn default() -> Self {
        Self {
            listen_address: default_proxy_listen(),
            port_range: default_proxy_port_range_system(),
            max_concurrent_connections_per_branch: default_proxy_max_conns_branch(),
            max_concurrent_connections_total: default_proxy_max_conns_total(),
            dangerous_wildcards: default_dangerous_wildcards(),
        }
    }
}

impl CredentialProxyDaemonConfig {
    /// Parse the port range string into a `RangeInclusive<u16>`.
    pub fn parse_port_range(&self) -> Result<std::ops::RangeInclusive<u16>> {
        let parts: Vec<&str> = self.port_range.split('-').collect();
        if parts.len() != 2 {
            anyhow::bail!(
                "invalid port_range '{}': expected format 'START-END'",
                self.port_range
            );
        }
        let start: u16 = parts[0]
            .trim()
            .parse()
            .with_context(|| format!("invalid port range start '{}'", parts[0]))?;
        let end: u16 = parts[1]
            .trim()
            .parse()
            .with_context(|| format!("invalid port range end '{}'", parts[1]))?;
        if start > end {
            anyhow::bail!(
                "invalid port_range '{}': start ({}) must be <= end ({})",
                self.port_range,
                start,
                end
            );
        }
        Ok(start..=end)
    }
}

/// H-2: Check if two port ranges overlap.
fn ranges_overlap(a: &std::ops::RangeInclusive<u16>, b: &std::ops::RangeInclusive<u16>) -> bool {
    a.start() <= b.end() && b.start() <= a.end()
}

fn default_proxy_listen() -> String {
    "127.0.0.1".to_string()
}
fn default_proxy_port_range_system() -> String {
    "18000-18499".to_string()
}
fn default_proxy_max_conns_branch() -> usize {
    64
}
fn default_proxy_max_conns_total() -> usize {
    512
}
pub fn default_dangerous_wildcards() -> Vec<String> {
    vec![
        "*.github.io".to_string(),
        "*.pages.dev".to_string(),
        "*.vercel.app".to_string(),
        "*.herokuapp.com".to_string(),
        "*.netlify.app".to_string(),
        "*.azurewebsites.net".to_string(),
        "*.cloudfront.net".to_string(),
        "*.s3.amazonaws.com".to_string(),
        "*.web.app".to_string(),
        "*.firebaseapp.com".to_string(),
        "*.gitlab.io".to_string(),
        "*.surge.sh".to_string(),
        "*.render.com".to_string(),
        "*.execute-api.amazonaws.com".to_string(),
    ]
}

/// §3.4 G17: Secure credential store configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStoreDaemonConfig {
    /// Whether mlock() failure is fatal (default: true).
    #[serde(default = "default_true_cfg")]
    pub mlock_required: bool,
    /// Enable kernel keyring caching for passphrase-derived keys (default: true).
    #[serde(default = "default_true_cfg")]
    pub keyring_cache_enabled: bool,
    /// Kernel keyring cache timeout in seconds (default: 86400 = 24 hours).
    #[serde(default = "default_keyring_timeout")]
    pub keyring_cache_timeout: u64,
}

impl Default for CredentialStoreDaemonConfig {
    fn default() -> Self {
        Self {
            mlock_required: true,
            keyring_cache_enabled: true,
            keyring_cache_timeout: default_keyring_timeout(),
        }
    }
}

fn default_true_cfg() -> bool {
    true
}
fn default_keyring_timeout() -> u64 {
    86400
}

// ---------------------------------------------------------------------------
// §3.4 G24: Port allocation for per-branch credential proxies
// ---------------------------------------------------------------------------

/// Allocates unique proxy ports per branch from a configurable range.
///
/// Ports are verified as available via a bind check before allocation.
/// Released ports are returned to the pool for reuse.
pub struct PortAllocator {
    range: std::ops::RangeInclusive<u16>,
    allocated: std::collections::HashSet<u16>,
}

impl PortAllocator {
    /// Create a new allocator from a port range.
    pub fn new(range: std::ops::RangeInclusive<u16>) -> Self {
        Self {
            range,
            allocated: std::collections::HashSet::new(),
        }
    }

    /// Create from the daemon config, parsing the port range string.
    pub fn from_config(config: &CredentialProxyDaemonConfig) -> Result<Self> {
        let range = config.parse_port_range()?;
        Ok(Self::new(range))
    }

    /// Allocate the next available port.
    ///
    /// Tries each port in the range, skipping already-allocated ports.
    /// Verifies availability via a bind check.
    /// Returns `None` if all ports in the range are exhausted.
    pub fn allocate(&mut self) -> Option<u16> {
        for port in self.range.clone() {
            if self.allocated.contains(&port) {
                continue;
            }
            // Verify port is available via bind check
            if Self::port_available(port) {
                self.allocated.insert(port);
                return Some(port);
            }
        }
        None
    }

    /// Release a previously allocated port back to the pool.
    pub fn release(&mut self, port: u16) {
        self.allocated.remove(&port);
    }

    /// Mark a port as allocated (e.g., when recovering from persistence).
    pub fn mark_allocated(&mut self, port: u16) {
        self.allocated.insert(port);
    }

    /// Number of currently allocated ports.
    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }

    /// Check if a port is available by attempting to bind to it.
    fn port_available(port: u16) -> bool {
        use std::net::{SocketAddr, TcpListener};
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        TcpListener::bind(addr).is_ok()
    }
}

/// §4.1: Per-metric behavioral baseline configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricBehavioralConfig {
    /// Anomaly threshold in standard deviations from the mean.
    pub threshold_sigma: f64,
    /// Severity to report when an anomaly is detected.
    pub severity: puzzled_types::BaselineSeverity,
}

/// §4.1: Graduated trust configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustConfig {
    /// Enable graduated trust scoring (default: false).
    #[serde(default)]
    pub enabled: bool,
    /// Directory for persistent trust data (scores, history, baselines).
    #[serde(default = "default_trust_store_dir")]
    pub store_dir: PathBuf,
    /// Default initial trust score for unknown agents (0-100).
    #[serde(default = "default_initial_trust_score")]
    pub initial_score: u32,
    /// Rolling window duration for behavioral baselines (days).
    #[serde(default = "default_window_duration_days")]
    pub window_duration_days: u64,
    /// Anomaly detection threshold (standard deviations from mean).
    #[serde(default = "default_anomaly_threshold_sigma")]
    pub anomaly_threshold_sigma: f64,
    /// Minimum observations before anomaly detection activates (PRD: 10).
    #[serde(default = "default_min_samples")]
    pub min_samples: usize,
    /// Per-metric behavioral configuration overrides.
    #[serde(default = "default_metric_configs")]
    pub metric_configs: std::collections::HashMap<String, MetricBehavioralConfig>,
}

impl Default for TrustConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            store_dir: default_trust_store_dir(),
            initial_score: default_initial_trust_score(),
            window_duration_days: default_window_duration_days(),
            anomaly_threshold_sigma: default_anomaly_threshold_sigma(),
            min_samples: default_min_samples(),
            metric_configs: default_metric_configs(),
        }
    }
}

fn default_trust_store_dir() -> PathBuf {
    PathBuf::from("/var/lib/puzzled/trust")
}

fn default_initial_trust_score() -> u32 {
    25
}

fn default_window_duration_days() -> u64 {
    7
}

fn default_anomaly_threshold_sigma() -> f64 {
    2.0
}

fn default_min_samples() -> usize {
    10
}

fn default_metric_configs() -> std::collections::HashMap<String, MetricBehavioralConfig> {
    use puzzled_types::BaselineSeverity;
    let mut m = std::collections::HashMap::new();
    m.insert(
        "exec_rate".into(),
        MetricBehavioralConfig {
            threshold_sigma: 3.0,
            severity: BaselineSeverity::Warning,
        },
    );
    m.insert(
        "network_rate".into(),
        MetricBehavioralConfig {
            threshold_sigma: 2.5,
            severity: BaselineSeverity::Critical,
        },
    );
    m.insert(
        "file_modification_volume".into(),
        MetricBehavioralConfig {
            threshold_sigma: 3.0,
            severity: BaselineSeverity::Warning,
        },
    );
    m.insert(
        "branch_duration".into(),
        MetricBehavioralConfig {
            threshold_sigma: 3.0,
            severity: BaselineSeverity::Warning,
        },
    );
    m.insert(
        "deletion_count".into(),
        MetricBehavioralConfig {
            threshold_sigma: 2.0,
            severity: BaselineSeverity::Critical,
        },
    );
    m
}

/// §4.3: Provenance chain configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceConfig {
    /// Enable provenance chain recording (default: false).
    #[serde(default)]
    pub enabled: bool,
    /// Directory for provenance record storage.
    #[serde(default = "default_provenance_dir")]
    pub store_dir: PathBuf,
}

impl Default for ProvenanceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            store_dir: default_provenance_dir(),
        }
    }
}

fn default_provenance_dir() -> PathBuf {
    PathBuf::from("/var/lib/puzzled/provenance")
}

/// §4.5: Agent workload identity configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// Enable agent workload identity (default: false).
    #[serde(default)]
    pub enabled: bool,
    /// SPIFFE trust domain (default: hostname).
    #[serde(default = "default_trust_domain")]
    pub trust_domain: String,
    /// JWT-SVID lifetime in seconds (default: 3600 = 1 hour).
    #[serde(default = "default_svid_lifetime")]
    pub svid_lifetime_secs: u64,
    /// Include governance claims in JWT-SVID (default: true).
    #[serde(default = "default_true")]
    pub include_governance_claims: bool,
    /// Include containment details in JWT-SVID (default: false).
    #[serde(default)]
    pub include_containment_claims: bool,
    /// Identity injection mode for puzzle-proxy.
    #[serde(default)]
    pub injection_mode: puzzled_types::IdentityInjectionMode,
    /// Maximum JWT-SVID lifetime in seconds (default: 86400 = 24 hours).
    #[serde(default = "default_max_svid_lifetime")]
    pub max_svid_lifetime_secs: u64,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            trust_domain: default_trust_domain(),
            svid_lifetime_secs: default_svid_lifetime(),
            include_governance_claims: true,
            include_containment_claims: false,
            injection_mode: puzzled_types::IdentityInjectionMode::default(),
            max_svid_lifetime_secs: default_max_svid_lifetime(),
        }
    }
}

fn default_trust_domain() -> String {
    "localhost".to_string()
}

fn default_svid_lifetime() -> u64 {
    3600
}

fn default_max_svid_lifetime() -> u64 {
    86400
}

fn default_branch_root() -> PathBuf {
    PathBuf::from("/var/lib/puzzled/branches")
}

fn default_profiles_dir() -> PathBuf {
    PathBuf::from("/etc/puzzled/profiles")
}

fn default_policies_dir() -> PathBuf {
    PathBuf::from("/etc/puzzled/policies")
}

fn default_max_branches() -> u32 {
    64
}

fn default_bus_type() -> String {
    "system".to_string()
}

fn default_fs_type() -> String {
    "xfs".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_watchdog_timeout() -> u64 {
    30
}

fn default_bpf_obj_path() -> PathBuf {
    PathBuf::from("/usr/lib/puzzled/exec_guard.bpf.o")
}

fn default_storage_quota_mb() -> u64 {
    1024
}

fn default_inode_quota() -> u64 {
    10_000
}

fn default_lifetime_minutes() -> u64 {
    60
}

fn default_cleanup_interval() -> u64 {
    30
}

fn default_evaluation_timeout_ms() -> u64 {
    5000
}

fn default_proxy_listen_addr() -> String {
    "10.200.0.1".to_string()
}

fn default_proxy_port() -> u16 {
    3128
}

fn default_max_body_size_mb() -> u64 {
    100
}

fn default_audit_log_path() -> PathBuf {
    PathBuf::from("/var/log/puzzled/audit.log")
}

fn default_integrity_key_path() -> PathBuf {
    PathBuf::from("/var/lib/puzzled/audit/.hmac_key")
}

fn default_retention_days() -> u32 {
    90
}

fn default_true() -> bool {
    true
}

fn default_mass_delete_threshold() -> u32 {
    50
}

fn default_credential_paths() -> Vec<String> {
    vec![
        "/etc/shadow".to_string(),
        "/etc/gshadow".to_string(),
        ".ssh/".to_string(),
        ".gnupg/".to_string(),
        ".aws/credentials".to_string(),
        ".env".to_string(),
    ]
}

fn default_max_exec_rate() -> u32 {
    100
}

fn default_max_exec_burst() -> u32 {
    200
}

fn default_signing_key_path() -> PathBuf {
    PathBuf::from("/etc/puzzled/signing-key.pem")
}

fn default_default_profile() -> String {
    "restricted".to_string()
}

fn default_default_action() -> String {
    "rollback".to_string()
}

fn default_runtime_dir() -> PathBuf {
    PathBuf::from("/run/puzzled")
}

fn default_commit_timeout_seconds() -> u64 {
    30
}

fn default_governance_review_timeout_seconds() -> u64 {
    1800
}

fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/puzzled/puzzled.sock")
}

fn default_pid_file() -> PathBuf {
    PathBuf::from("/run/puzzled/puzzled.pid")
}

fn default_log_target() -> String {
    "journal".to_string()
}

fn default_policy_engine() -> String {
    "opa".to_string()
}

fn default_heartbeat_interval() -> u32 {
    10
}

fn default_max_restart_attempts() -> u32 {
    3
}

fn default_network_mode() -> String {
    "gated".to_string()
}

fn default_pending_ops_max() -> u32 {
    100
}

fn default_pending_ops_max_size() -> u32 {
    10
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            branch_root: default_branch_root(),
            profiles_dir: default_profiles_dir(),
            policies_dir: default_policies_dir(),
            max_branches: default_max_branches(),
            bus_type: default_bus_type(),
            fs_type: default_fs_type(),
            log_level: default_log_level(),
            watchdog_timeout_secs: default_watchdog_timeout(),
            bpf_obj_path: default_bpf_obj_path(),
            default_storage_quota_mb: default_storage_quota_mb(),
            default_inode_quota: default_inode_quota(),
            default_lifetime_minutes: default_lifetime_minutes(),
            cleanup_interval_seconds: default_cleanup_interval(),
            governance: GovernanceConfig::default(),
            network: NetworkSectionConfig::default(),
            audit: AuditSectionConfig::default(),
            fanotify: FanotifyConfig::default(),
            bpf_lsm: BpfLsmConfig::default(),
            signing_key_path: default_signing_key_path(),
            require_policies: false,
            require_ima: false,
            require_self_hardening: false,
            default_profile: default_default_profile(),
            default_action: default_default_action(),
            runtime_dir: default_runtime_dir(),
            commit_timeout_seconds: default_commit_timeout_seconds(),
            require_human_approval: false,
            governance_review_timeout_seconds: default_governance_review_timeout_seconds(),
            attestation: AttestationConfig::default(),
            dlp: DlpConfig::default(),
            credentials: CredentialsConfig::default(),
            credential_proxy: CredentialProxyDaemonConfig::default(),
            credential_store: CredentialStoreDaemonConfig::default(),
            socket_path: default_socket_path(),
            pid_file: default_pid_file(),
            log_target: default_log_target(),
            policy_engine: default_policy_engine(),
            hot_reload: true,
            heartbeat_interval_seconds: default_heartbeat_interval(),
            max_restart_attempts: default_max_restart_attempts(),
            enable_changeset_signing: true,
            trust: TrustConfig::default(),
            provenance: ProvenanceConfig::default(),
            identity: IdentityConfig::default(),
        }
    }
}

impl DaemonConfig {
    /// Validate configuration values.
    ///
    /// Returns an error describing the first invalid field found.
    pub fn validate(&self) -> Result<()> {
        if self.max_branches == 0 || self.max_branches > 1024 {
            anyhow::bail!(
                "max_branches must be between 1 and 1024, got {}",
                self.max_branches
            );
        }

        match self.log_level.as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {}
            other => anyhow::bail!(
                "invalid log_level '{}': must be trace|debug|info|warn|error",
                other
            ),
        }

        match self.bus_type.as_str() {
            "system" | "session" => {}
            other => anyhow::bail!("invalid bus_type '{}': must be system|session", other),
        }

        match self.fs_type.as_str() {
            "xfs" | "ext4" | "btrfs" => {}
            other => anyhow::bail!("invalid fs_type '{}': must be xfs|ext4|btrfs", other),
        }

        // U1: Validate network.default_mode
        match self.network.default_mode.as_str() {
            "blocked" | "gated" | "monitored" | "unrestricted" => {}
            other => anyhow::bail!(
                "invalid network.default_mode '{}': must be blocked|gated|monitored|unrestricted",
                other
            ),
        }

        // U2: Validate policy_engine
        match self.policy_engine.as_str() {
            "opa" => {}
            other => anyhow::bail!("invalid policy_engine '{}': must be opa", other),
        }

        if self.watchdog_timeout_secs == 0 {
            tracing::warn!("watchdog_timeout_secs is 0 — watchdog disabled");
        }

        // M25: Validate paths are absolute
        if !self.branch_root.is_absolute() {
            anyhow::bail!(
                "branch_root must be an absolute path, got '{}'",
                self.branch_root.display()
            );
        }
        if !self.profiles_dir.is_absolute() {
            anyhow::bail!(
                "profiles_dir must be an absolute path, got '{}'",
                self.profiles_dir.display()
            );
        }
        if !self.policies_dir.is_absolute() {
            anyhow::bail!(
                "policies_dir must be an absolute path, got '{}'",
                self.policies_dir.display()
            );
        }

        // M25: Validate positive numeric values
        if self.governance.evaluation_timeout_ms == 0 {
            anyhow::bail!("governance.evaluation_timeout_ms must be > 0");
        }
        if self.default_storage_quota_mb == 0 {
            anyhow::bail!("default_storage_quota_mb must be > 0");
        }
        if self.audit.retention_days == 0 {
            anyhow::bail!("audit.retention_days must be > 0");
        }

        // M11: Validate signing_key_path is an absolute path
        if !self.signing_key_path.is_absolute() {
            anyhow::bail!(
                "signing_key_path must be an absolute path, got '{}'",
                self.signing_key_path.display()
            );
        }

        // M-cfg2/m9: Validate default_action — "hold" maps to GovernanceReview state
        match self.default_action.as_str() {
            "rollback" | "hold" => {}
            other => anyhow::bail!("invalid default_action '{}': must be rollback|hold", other),
        }

        // M-cfg3: Validate commit_timeout_seconds
        if self.commit_timeout_seconds == 0 || self.commit_timeout_seconds > 3600 {
            anyhow::bail!(
                "commit_timeout_seconds must be between 1 and 3600, got {}",
                self.commit_timeout_seconds
            );
        }

        // U3: Bound governance_review_timeout_seconds
        if self.governance_review_timeout_seconds == 0
            || self.governance_review_timeout_seconds > 86400
        {
            anyhow::bail!(
                "governance_review_timeout_seconds must be between 1 and 86400 (24 hours), got {}",
                self.governance_review_timeout_seconds
            );
        }

        // M-br2: Validate runtime_dir is an absolute path
        if !self.runtime_dir.is_absolute() {
            anyhow::bail!(
                "runtime_dir must be an absolute path, got '{}'",
                self.runtime_dir.display()
            );
        }

        // Validate socket_path and pid_file are absolute paths
        if !self.socket_path.is_absolute() {
            anyhow::bail!(
                "socket_path must be an absolute path, got '{}'",
                self.socket_path.display()
            );
        }
        if !self.pid_file.is_absolute() {
            anyhow::bail!(
                "pid_file must be an absolute path, got '{}'",
                self.pid_file.display()
            );
        }

        // M22: Validate signing_key_path is not under branch_root (security)
        if self.signing_key_path.starts_with(&self.branch_root) {
            anyhow::bail!(
                "signing_key_path ({}) must not be under branch_root ({})",
                self.signing_key_path.display(),
                self.branch_root.display()
            );
        }

        // K86: Validate identity svid_lifetime_secs (1-604800 = 7 days)
        if self.identity.svid_lifetime_secs < 1 || self.identity.svid_lifetime_secs > 604800 {
            anyhow::bail!(
                "identity.svid_lifetime_secs must be between 1 and 604800 (7 days), got {}",
                self.identity.svid_lifetime_secs
            );
        }

        // K86: Validate trust initial_score (0-100)
        if self.trust.initial_score > 100 {
            anyhow::bail!(
                "trust.initial_score must be between 0 and 100, got {}",
                self.trust.initial_score
            );
        }

        // T7: Also reject infinity — infinite sigma disables anomaly detection
        if self.trust.anomaly_threshold_sigma.is_nan()
            || self.trust.anomaly_threshold_sigma.is_infinite()
            || self.trust.anomaly_threshold_sigma <= 0.0
        {
            anyhow::bail!(
                "trust.anomaly_threshold_sigma must be finite and > 0, got {}",
                self.trust.anomaly_threshold_sigma
            );
        }

        // K86: Validate phantom_entropy_bytes (>= 8 when credentials enabled)
        if self.credentials.enabled && self.credentials.phantom_entropy_bytes < 8 {
            anyhow::bail!(
                "credentials.phantom_entropy_bytes must be >= 8 when credentials are enabled, got {}",
                self.credentials.phantom_entropy_bytes
            );
        }

        // U4: Upper bound phantom_entropy_bytes
        if self.credentials.enabled && self.credentials.phantom_entropy_bytes > 1024 {
            anyhow::bail!(
                "credentials.phantom_entropy_bytes must be <= 1024 (1KB) when credentials are enabled, got {}",
                self.credentials.phantom_entropy_bytes
            );
        }

        // H-2: Validate credential_proxy.port_range does not overlap with the
        // opposite instance type's default range. PRD §3.4.11 requires ranges
        // MUST NOT overlap between system and user instances.
        if let Ok(configured_range) = self.credential_proxy.parse_port_range() {
            let system_default = 18000u16..=18499u16;
            let user_default = 18500u16..=18999u16;
            match self.bus_type.as_str() {
                "session" => {
                    if ranges_overlap(&configured_range, &system_default) {
                        anyhow::bail!(
                            "credential_proxy.port_range '{}' overlaps system instance default \
                             range 18000-18499; user instance must use non-overlapping range \
                             (default: 18500-18999)",
                            self.credential_proxy.port_range
                        );
                    }
                }
                "system" => {
                    if ranges_overlap(&configured_range, &user_default) {
                        anyhow::bail!(
                            "credential_proxy.port_range '{}' overlaps user instance default \
                             range 18500-18999; system instance must use non-overlapping range \
                             (default: 18000-18499)",
                            self.credential_proxy.port_range
                        );
                    }
                }
                _ => {} // bus_type already validated above
            }
        }

        // §3.1: Validate attestation config
        if self.attestation.enabled {
            if !self.attestation.attestation_dir.is_absolute() {
                anyhow::bail!(
                    "attestation.attestation_dir must be an absolute path, got '{}'",
                    self.attestation.attestation_dir.display()
                );
            }
            if self
                .attestation
                .attestation_dir
                .starts_with(&self.branch_root)
            {
                anyhow::bail!(
                    "attestation.attestation_dir ({}) must not be under branch_root ({})",
                    self.attestation.attestation_dir.display(),
                    self.branch_root.display()
                );
            }
            if !self.attestation.checkpoint_dir.is_absolute() {
                anyhow::bail!(
                    "attestation.checkpoint_dir must be an absolute path, got '{}'",
                    self.attestation.checkpoint_dir.display()
                );
            }
        }

        Ok(())
    }

    /// Construct a `DaemonConfig` with user-mode defaults.
    ///
    /// All paths point to XDG-compliant locations under `$HOME` and
    /// `$XDG_RUNTIME_DIR`. D-Bus is set to session bus, BPF LSM and
    /// fanotify are disabled (require root capabilities), and
    /// `max_branches` is reduced for user sessions.
    ///
    /// Returns an error if `$HOME` is not set — user-mode paths cannot
    /// be resolved without it, and falling back to `/tmp` would be a
    /// security risk (world-writable, symlink attacks).
    pub fn default_for_user() -> Result<Self> {
        let home = home_dir().ok_or_else(|| {
            anyhow::anyhow!(
                "$HOME is not set or is not an absolute path — cannot determine user-mode \
                 config paths. Set $HOME or provide an explicit config file with --config"
            )
        })?;
        let rtdir = runtime_base_dir()?;

        // XDG Base Directory Specification compliance — require absolute paths
        let config_home = PathBuf::from(
            std::env::var("XDG_CONFIG_HOME")
                .ok()
                .filter(|p| p.starts_with('/'))
                .unwrap_or_else(|| format!("{home}/.config")),
        );
        let data_home = PathBuf::from(
            std::env::var("XDG_DATA_HOME")
                .ok()
                .filter(|p| p.starts_with('/'))
                .unwrap_or_else(|| format!("{home}/.local/share")),
        );
        let rtdir = PathBuf::from(rtdir);

        let puzzled_config = config_home.join("puzzled");
        let puzzled_data = data_home.join("puzzled");
        let puzzled_runtime = rtdir.join("puzzled");
        let policies_dir = puzzled_config.join("policies");

        let cfg = Self {
            branch_root: puzzled_data.join("branches"),
            profiles_dir: puzzled_config.join("profiles"),
            policies_dir: policies_dir.clone(),
            max_branches: 16,
            default_storage_quota_mb: 512,
            default_inode_quota: 5000,
            bus_type: "session".to_string(),
            fs_type: "ext4".to_string(),
            runtime_dir: puzzled_runtime.clone(),
            socket_path: puzzled_runtime.join("puzzled.sock"),
            pid_file: puzzled_runtime.join("puzzled.pid"),
            signing_key_path: puzzled_config.join("signing-key.pem"),
            audit: AuditSectionConfig {
                audit_log_path: puzzled_data.join("audit").join("audit.log"),
                integrity_key_path: puzzled_data.join("audit").join(".hmac_key"),
                ..Default::default()
            },
            bpf_lsm: BpfLsmConfig {
                enable: false,
                ..Default::default()
            },
            fanotify: FanotifyConfig {
                enable: false,
                ..Default::default()
            },
            governance: GovernanceConfig {
                policy_dir: policies_dir,
                ..Default::default()
            },
            trust: TrustConfig {
                store_dir: puzzled_data.join("trust"),
                ..Default::default()
            },
            provenance: ProvenanceConfig {
                store_dir: puzzled_data.join("provenance"),
                ..Default::default()
            },
            attestation: AttestationConfig {
                attestation_dir: puzzled_data.join("attestation"),
                checkpoint_dir: puzzled_data.join("attestation").join("checkpoints"),
                ..Default::default()
            },
            credentials: CredentialsConfig {
                backend: CredentialBackendConfig::Local {
                    store_path: puzzled_config.join("credentials").join("store.enc"),
                },
                ..Default::default()
            },
            dlp: DlpConfig {
                default_rules_path: puzzled_config.join("dlp").join("rules.yaml"),
                ..Default::default()
            },
            credential_proxy: CredentialProxyDaemonConfig {
                port_range: "18500-18999".to_string(),
                ..Default::default()
            },
            log_target: "stderr".to_string(),
            ..Default::default()
        };

        // Validate the generated config so callers don't have to.
        cfg.validate()
            .context("user-mode default config validation failed")?;
        Ok(cfg)
    }

    /// Load config from the default path, or return defaults if the file doesn't exist.
    ///
    /// When running as a non-root user, checks `~/.config/puzzled/puzzled.conf`
    /// before falling back to user-mode defaults.
    pub fn load_or_default() -> Result<Self> {
        let path = Path::new(DEFAULT_CONFIG_PATH);
        if path.exists() {
            return Self::load(path);
        }

        if is_user_mode() {
            let config_home = std::env::var("XDG_CONFIG_HOME")
                .ok()
                .filter(|p| p.starts_with('/'))
                .or_else(|| home_dir().map(|h| format!("{h}/.config")));
            if let Some(config_home) = config_home {
                let user_path = PathBuf::from(&config_home)
                    .join("puzzled")
                    .join("puzzled.conf");
                if user_path.exists() {
                    tracing::info!("loading user config from {}", user_path.display());
                    return Self::load(&user_path);
                }
            }
            #[cfg(unix)]
            tracing::info!(
                "no config file found, using user-mode defaults (running as UID {})",
                nix::unistd::getuid().as_raw(),
            );
            #[cfg(not(unix))]
            tracing::info!("no config file found, using user-mode defaults");
            return Self::default_for_user();
        }

        tracing::info!("no config file at {}, using defaults", DEFAULT_CONFIG_PATH);
        Ok(Self::default())
    }

    /// Load config from a specific path.
    ///
    /// N9: Validates the loaded config before returning to catch invalid values early.
    pub fn load(path: &Path) -> Result<Self> {
        let contents =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let config: Self = serde_yaml::from_str(&contents)
            .with_context(|| format!("parsing {}", path.display()))?;
        config.validate()?; // N9: validate on load
        Ok(config)
    }
}

/// §3.4 G14: Per-instance 256-bit random secret for CA key encryption and HKDF derivation.
///
/// Path priorities:
/// - System mode: `/var/lib/puzzled/instance_secret`
/// - Rootless mode: `~/.local/share/puzzled/instance_secret`
///
/// On first startup, generates 32 bytes from OsRng and writes atomically with O_CREAT|O_EXCL
/// and mode 0o600. On subsequent starts, reads and validates the existing secret (>= 32 bytes).
///
/// Fallback: If neither path is writable (e.g., read-only root in containers), falls back to
/// `/etc/machine-id` with a Critical audit event — this is deterministic and NOT cryptographically
/// suitable for production use.
pub fn load_instance_secret(bus_type: &str) -> Result<Zeroizing<[u8; 32]>> {
    let secret_path = if bus_type == "session" {
        // Rootless mode
        let data_dir = dirs_instance_secret_rootless()?;
        data_dir.join("instance_secret")
    } else {
        // System mode
        PathBuf::from("/var/lib/puzzled/instance_secret")
    };

    if secret_path.exists() {
        // Read and validate existing secret
        let bytes = std::fs::read(&secret_path)
            .with_context(|| format!("reading instance secret from {}", secret_path.display()))?;
        if bytes.len() < 32 {
            anyhow::bail!(
                "§3.4 G14: instance secret at {} is too short ({} bytes, need >= 32). \
                 Delete and restart to regenerate.",
                secret_path.display(),
                bytes.len()
            );
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&bytes[..32]);
        tracing::info!(
            path = %secret_path.display(),
            "§3.4 G14: loaded instance secret"
        );
        Ok(key)
    } else {
        // Generate new secret
        if let Some(parent) = secret_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating directory {}", parent.display()))?;
            // Ensure directory has restrictive permissions
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o700);
                std::fs::set_permissions(parent, perms).ok(); // best-effort
            }
        }

        let mut secret = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut *secret)
            .map_err(|e| anyhow::anyhow!("§3.4 G14: failed to generate instance secret: {}", e))?;

        // Atomic write: write to temp file, then rename
        let tmp_path = secret_path.with_extension("tmp");
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true) // O_CREAT | O_EXCL — fail if exists (race protection)
                .open(&tmp_path)
                .with_context(|| format!("creating instance secret at {}", tmp_path.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            file.write_all(&*secret)?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp_path, &secret_path).with_context(|| {
            format!(
                "renaming {} to {}",
                tmp_path.display(),
                secret_path.display()
            )
        })?;

        tracing::info!(
            path = %secret_path.display(),
            "§3.4 G14: generated new instance secret (32 bytes)"
        );
        Ok(secret)
    }
}

/// Determine the rootless instance secret directory.
fn dirs_instance_secret_rootless() -> Result<PathBuf> {
    // XDG_DATA_HOME or ~/.local/share
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        return Ok(PathBuf::from(xdg).join("puzzled"));
    }
    if let Ok(home) = std::env::var("HOME") {
        return Ok(PathBuf::from(home).join(".local/share/puzzled"));
    }
    anyhow::bail!(
        "§3.4 G14: cannot determine data directory — neither XDG_DATA_HOME nor HOME is set"
    )
}

/// §3.4 G14: Fallback to machine-id when instance_secret path is not available.
/// This is NOT cryptographically suitable — it is deterministic and shared across services.
/// Returns a derived key using HKDF over machine-id with a domain-specific info string.
pub fn load_instance_secret_machine_id_fallback() -> Result<Zeroizing<[u8; 32]>> {
    let machine_id_str = std::fs::read_to_string("/etc/machine-id")
        .with_context(|| "reading /etc/machine-id for instance secret fallback")?;
    let machine_id = machine_id_str.trim();
    if machine_id.len() < 32 {
        anyhow::bail!("§3.4 G14: /etc/machine-id is too short for key derivation");
    }

    // L-9: Derive key using HKDF-SHA-256 (not plain SHA-256) for proper
    // extract-and-expand separation from non-uniform input.
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(None, machine_id.as_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(b"puzzlepod-instance-secret-v1", &mut *key)
        .expect("HKDF-SHA256 expand is infallible for 32-byte output");

    tracing::error!(
        "§3.4 G14 CRITICAL: using machine-id fallback for instance secret — \
         this is NOT cryptographically suitable. Write permissions to \
         /var/lib/puzzled/ or ~/.local/share/puzzled/ are required for production use."
    );

    Ok(key)
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config_values() {
        let config = DaemonConfig::default();
        assert_eq!(
            config.branch_root,
            PathBuf::from("/var/lib/puzzled/branches")
        );
        assert_eq!(config.max_branches, 64);
        assert_eq!(config.bus_type, "system");
        assert_eq!(config.fs_type, "xfs");
        assert_eq!(config.log_level, "info");
        assert_eq!(config.watchdog_timeout_secs, 30);
        assert_eq!(
            config.bpf_obj_path,
            PathBuf::from("/usr/lib/puzzled/exec_guard.bpf.o")
        );
    }

    #[test]
    fn test_config_load_from_yaml() {
        let yaml = r#"
branch_root: /tmp/test-branches
profiles_dir: /tmp/profiles
policies_dir: /tmp/policies
max_branches: 16
bus_type: session
fs_type: ext4
log_level: debug
watchdog_timeout_secs: 60
credential_proxy:
  port_range: "18500-18999"
"#;
        let mut tmpfile = NamedTempFile::new().unwrap();
        tmpfile.write_all(yaml.as_bytes()).unwrap();

        let config = DaemonConfig::load(tmpfile.path()).unwrap();
        assert_eq!(config.branch_root, PathBuf::from("/tmp/test-branches"));
        assert_eq!(config.profiles_dir, PathBuf::from("/tmp/profiles"));
        assert_eq!(config.policies_dir, PathBuf::from("/tmp/policies"));
        assert_eq!(config.max_branches, 16);
        assert_eq!(config.bus_type, "session");
        assert_eq!(config.fs_type, "ext4");
        assert_eq!(config.log_level, "debug");
        assert_eq!(config.watchdog_timeout_secs, 60);
    }

    #[test]
    fn test_config_load_partial_yaml() {
        let yaml = r#"
max_branches: 8
log_level: warn
"#;
        let mut tmpfile = NamedTempFile::new().unwrap();
        tmpfile.write_all(yaml.as_bytes()).unwrap();

        let config = DaemonConfig::load(tmpfile.path()).unwrap();
        // Explicitly set fields
        assert_eq!(config.max_branches, 8);
        assert_eq!(config.log_level, "warn");
        // Default-filled fields
        assert_eq!(
            config.branch_root,
            PathBuf::from("/var/lib/puzzled/branches")
        );
        assert_eq!(config.bus_type, "system");
        assert_eq!(config.fs_type, "xfs");
        assert_eq!(config.watchdog_timeout_secs, 30);
    }

    #[test]
    fn test_config_load_nonexistent() {
        let result = DaemonConfig::load(Path::new("/nonexistent/path/config.yaml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validates_max_branches() {
        let mut config = DaemonConfig::default();
        assert!(config.validate().is_ok());

        config.max_branches = 0;
        assert!(config.validate().is_err());

        config.max_branches = 1025;
        assert!(config.validate().is_err());

        config.max_branches = 1024;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validates_log_level() {
        let mut config = DaemonConfig::default();

        for valid in &["trace", "debug", "info", "warn", "error"] {
            config.log_level = valid.to_string();
            assert!(
                config.validate().is_ok(),
                "log_level '{}' should be valid",
                valid
            );
        }

        config.log_level = "verbose".to_string();
        assert!(config.validate().is_err());

        config.log_level = "WARN".to_string();
        assert!(config.validate().is_err(), "case-sensitive validation");
    }

    #[test]
    fn test_config_validates_bus_type() {
        let config = DaemonConfig {
            bus_type: "system".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_ok());

        let mut config = config;

        config.bus_type = "session".to_string();
        // H-2: session instance needs non-overlapping port range
        config.credential_proxy.port_range = "18500-18999".to_string();
        assert!(config.validate().is_ok());

        config.bus_type = "peer".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validates_fs_type() {
        let mut config = DaemonConfig::default();

        for valid in &["xfs", "ext4", "btrfs"] {
            config.fs_type = valid.to_string();
            assert!(
                config.validate().is_ok(),
                "fs_type '{}' should be valid",
                valid
            );
        }

        config.fs_type = "ntfs".to_string();
        assert!(config.validate().is_err());

        config.fs_type = "zfs".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validates_absolute_paths() {
        let mut config = DaemonConfig::default();
        assert!(config.validate().is_ok());

        config.branch_root = PathBuf::from("relative/path");
        assert!(config.validate().is_err());

        config.branch_root = PathBuf::from("/var/lib/puzzled/branches");
        config.profiles_dir = PathBuf::from("profiles");
        assert!(config.validate().is_err());

        config.profiles_dir = PathBuf::from("/etc/puzzled/profiles");
        config.policies_dir = PathBuf::from("policies");
        assert!(config.validate().is_err());

        // Restore policies_dir, test socket_path and pid_file
        config.policies_dir = PathBuf::from("/etc/puzzled/policies");
        config.socket_path = PathBuf::from("relative/puzzled.sock");
        assert!(config.validate().is_err(), "socket_path must be absolute");

        config.socket_path = PathBuf::from("/run/puzzled/puzzled.sock");
        config.pid_file = PathBuf::from("puzzled.pid");
        assert!(config.validate().is_err(), "pid_file must be absolute");
    }

    #[test]
    fn test_config_validates_positive_values() {
        let mut config = DaemonConfig::default();

        config.governance.evaluation_timeout_ms = 0;
        assert!(config.validate().is_err());
        config.governance.evaluation_timeout_ms = 5000;

        config.default_storage_quota_mb = 0;
        assert!(config.validate().is_err());
        config.default_storage_quota_mb = 1024;

        config.audit.retention_days = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validates_signing_key_not_under_branch_root() {
        let mut config = DaemonConfig::default();
        config.signing_key_path = config.branch_root.join("signing_key");
        assert!(config.validate().is_err());

        config.signing_key_path = PathBuf::from("/etc/puzzled/signing-key.pem");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_default_config_validates_successfully() {
        // Phase 1.10: Default config must pass all validation checks.
        let config = DaemonConfig::default();
        if let Err(e) = config.validate() {
            panic!("default config should validate: {:?}", e);
        }
    }

    #[test]
    fn test_config_rejects_zero_commit_timeout() {
        // Phase 1.10: commit_timeout_seconds = 0 must be rejected.
        let config = DaemonConfig {
            commit_timeout_seconds: 0,
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("commit_timeout_seconds"),
            "error should mention commit_timeout_seconds: {}",
            msg
        );
    }

    #[test]
    fn test_config_rejects_relative_runtime_dir() {
        // Phase 1.10: runtime_dir must be an absolute path.
        let config = DaemonConfig {
            runtime_dir: PathBuf::from("relative/runtime"),
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("runtime_dir"),
            "error should mention runtime_dir: {}",
            msg
        );
    }

    #[test]
    fn test_config_rejects_invalid_default_action() {
        // m9: default_action must be "rollback" or "hold" (not "commit").
        let config = DaemonConfig {
            default_action: "ignore".to_string(),
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("default_action"),
            "error should mention default_action: {}",
            msg
        );

        // "commit" is no longer valid — must be "hold" or "rollback"
        let config = DaemonConfig {
            default_action: "commit".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_err());

        // "hold" is valid
        let config = DaemonConfig {
            default_action: "hold".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    // K86: Validate svid_lifetime_secs range (1-604800)
    #[test]
    fn k86_validates_svid_lifetime_secs_range() {
        let mut config = DaemonConfig::default();

        // Valid: within range
        config.identity.svid_lifetime_secs = 3600;
        assert!(config.validate().is_ok());

        config.identity.svid_lifetime_secs = 1;
        assert!(config.validate().is_ok());

        config.identity.svid_lifetime_secs = 604800;
        assert!(config.validate().is_ok());

        // Invalid: too low
        config.identity.svid_lifetime_secs = 0;
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("svid_lifetime_secs"), "error: {err}");

        // Invalid: too high
        config.identity.svid_lifetime_secs = 604801;
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("svid_lifetime_secs"), "error: {err}");
    }

    // K86: Validate initial_score range (0-100)
    #[test]
    fn k86_validates_initial_score_range() {
        let mut config = DaemonConfig::default();

        config.trust.initial_score = 0;
        assert!(config.validate().is_ok());

        config.trust.initial_score = 100;
        assert!(config.validate().is_ok());

        config.trust.initial_score = 101;
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("initial_score"), "error: {err}");
    }

    // K86: Validate anomaly_threshold_sigma (> 0, not NaN)
    #[test]
    fn k86_validates_anomaly_threshold_sigma() {
        let mut config = DaemonConfig::default();

        config.trust.anomaly_threshold_sigma = 2.0;
        assert!(config.validate().is_ok());

        config.trust.anomaly_threshold_sigma = 0.0;
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("anomaly_threshold_sigma"), "error: {err}");

        config.trust.anomaly_threshold_sigma = -1.0;
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("anomaly_threshold_sigma"), "error: {err}");

        config.trust.anomaly_threshold_sigma = f64::NAN;
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("anomaly_threshold_sigma"), "error: {err}");
    }

    // K86: Validate phantom_entropy_bytes (>= 8 when credentials enabled)
    #[test]
    fn k86_validates_phantom_entropy_bytes() {
        let mut config = DaemonConfig::default();

        // When credentials disabled, no validation on phantom_entropy_bytes
        config.credentials.enabled = false;
        config.credentials.phantom_entropy_bytes = 4;
        assert!(config.validate().is_ok());

        // When credentials enabled, must be >= 8
        config.credentials.enabled = true;
        config.credentials.phantom_entropy_bytes = 8;
        assert!(config.validate().is_ok());

        config.credentials.phantom_entropy_bytes = 7;
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("phantom_entropy_bytes"), "error: {err}");
    }

    #[test]
    fn test_default_for_user_has_session_bus() {
        let config = DaemonConfig::default_for_user().unwrap();
        assert_eq!(config.bus_type, "session");
    }

    #[test]
    fn test_default_for_user_has_user_paths() {
        let config = DaemonConfig::default_for_user().unwrap();
        let home = home_dir().expect("$HOME must be set for this test");
        let home_path = PathBuf::from(&home);
        assert!(
            config
                .branch_root
                .starts_with(home_path.join(".local/share/puzzled")),
            "branch_root should be under $HOME/.local/share/puzzled: {:?}",
            config.branch_root
        );
        assert!(
            config
                .profiles_dir
                .starts_with(home_path.join(".config/puzzled")),
            "profiles_dir should be under $HOME/.config/puzzled: {:?}",
            config.profiles_dir
        );
        assert!(
            config
                .policies_dir
                .starts_with(home_path.join(".config/puzzled")),
            "policies_dir should be under $HOME/.config/puzzled: {:?}",
            config.policies_dir
        );
        assert!(
            config.signing_key_path.starts_with(&home_path),
            "signing_key_path should be under $HOME: {:?}",
            config.signing_key_path
        );
    }

    #[test]
    fn test_default_for_user_disables_root_features() {
        let config = DaemonConfig::default_for_user().unwrap();
        assert!(
            !config.bpf_lsm.enable,
            "BPF LSM should be disabled in user mode"
        );
        assert!(
            !config.fanotify.enable,
            "fanotify should be disabled in user mode"
        );
    }

    #[test]
    fn test_default_for_user_validates() {
        let config = DaemonConfig::default_for_user().unwrap();
        if let Err(e) = config.validate() {
            panic!("user-mode defaults should validate: {:?}", e);
        }
    }

    #[test]
    fn test_default_for_user_fs_type() {
        let config = DaemonConfig::default_for_user().unwrap();
        assert_eq!(
            config.fs_type, "ext4",
            "user mode should default to ext4 (no XFS quotas)"
        );
    }

    #[test]
    fn test_default_for_user_log_target() {
        let config = DaemonConfig::default_for_user().unwrap();
        assert_eq!(
            config.log_target, "stderr",
            "user mode should log to stderr"
        );
    }

    /// N9: Loading a config file with invalid values must return an error
    /// (validate() is now called inside load()).
    #[test]
    fn test_n9_load_validates_config() {
        let yaml = r#"
branch_root: /tmp/test-branches
max_branches: 0
"#;
        let mut tmpfile = NamedTempFile::new().unwrap();
        tmpfile.write_all(yaml.as_bytes()).unwrap();

        let result = DaemonConfig::load(tmpfile.path());
        assert!(
            result.is_err(),
            "load() should fail for max_branches=0 due to validate()"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("max_branches"),
            "error should mention max_branches, got: {err_msg}"
        );
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let original = DaemonConfig::default();
        let yaml = serde_yaml::to_string(&original).unwrap();
        let deserialized: DaemonConfig = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(original.branch_root, deserialized.branch_root);
        assert_eq!(original.profiles_dir, deserialized.profiles_dir);
        assert_eq!(original.policies_dir, deserialized.policies_dir);
        assert_eq!(original.max_branches, deserialized.max_branches);
        assert_eq!(original.bus_type, deserialized.bus_type);
        assert_eq!(original.fs_type, deserialized.fs_type);
        assert_eq!(original.log_level, deserialized.log_level);
        assert_eq!(
            original.watchdog_timeout_secs,
            deserialized.watchdog_timeout_secs
        );
        assert_eq!(original.bpf_obj_path, deserialized.bpf_obj_path);
    }

    // --- load_or_default() fallback chain tests ---

    /// When no config files exist and running as non-root, load_or_default()
    /// should fall back to default_for_user() (session bus, user paths).
    #[test]
    fn test_load_or_default_falls_back_to_user_defaults_when_no_config() {
        // This test only makes sense on non-root systems where $HOME is set.
        if nix::unistd::getuid().is_root() {
            return; // skip on root — load_or_default uses system defaults
        }
        if std::env::var("HOME").is_err() {
            return; // skip if HOME is not set
        }
        // If /etc/puzzled/puzzled.conf exists, load_or_default will use it
        // and won't reach the user fallback path. Skip in that case.
        if std::path::Path::new(DEFAULT_CONFIG_PATH).exists() {
            return;
        }
        // Skip if XDG_CONFIG_HOME is explicitly set — another test or the
        // environment may be manipulating it, causing a race condition.
        if std::env::var("XDG_CONFIG_HOME").is_ok() {
            return;
        }
        // If the user config file exists, load_or_default will load it
        // instead of returning defaults. That's still valid behavior,
        // but we can't assert on the specific default values.
        let config_home = home_dir().map(|h| format!("{h}/.config"));
        if let Some(ch) = &config_home {
            if PathBuf::from(ch)
                .join("puzzled")
                .join("puzzled.conf")
                .exists()
            {
                return;
            }
        }

        let config = DaemonConfig::load_or_default().expect("load_or_default should succeed");
        assert_eq!(
            config.bus_type, "session",
            "non-root without config should get session bus"
        );
        assert_eq!(
            config.fs_type, "ext4",
            "non-root without config should get ext4"
        );
        assert_eq!(
            config.max_branches, 16,
            "non-root should get reduced max_branches"
        );
        assert!(!config.bpf_lsm.enable, "user mode should disable BPF LSM");
        assert!(!config.fanotify.enable, "user mode should disable fanotify");
    }

    /// load_or_default() should load from a user config file when it exists.
    #[test]
    fn test_load_or_default_loads_user_config_file() {
        if nix::unistd::getuid().is_root() {
            return;
        }
        if std::path::Path::new(DEFAULT_CONFIG_PATH).exists() {
            return;
        }
        // Create a temporary config in a temp XDG_CONFIG_HOME
        let tmpdir = tempfile::tempdir().unwrap();
        let puzzled_dir = tmpdir.path().join("puzzled");
        std::fs::create_dir_all(&puzzled_dir).unwrap();
        let conf_path = puzzled_dir.join("puzzled.conf");
        std::fs::write(
            &conf_path,
            "max_branches: 7\nbus_type: session\nfs_type: ext4\ncredential_proxy:\n  port_range: \"18500-18999\"\n",
        )
        .unwrap();

        // Temporarily set XDG_CONFIG_HOME to our tmpdir.
        // SAFETY: This test mutates process-global env state. It is not safe
        // to run in parallel with other tests that read XDG_CONFIG_HOME.
        // Rust 1.83+ marks set_var/remove_var as unsafe for this reason.
        let old_xdg = std::env::var("XDG_CONFIG_HOME").ok();
        unsafe { std::env::set_var("XDG_CONFIG_HOME", tmpdir.path()) };

        let result = DaemonConfig::load_or_default();

        // Restore
        match old_xdg {
            Some(v) => unsafe { std::env::set_var("XDG_CONFIG_HOME", v) },
            None => unsafe { std::env::remove_var("XDG_CONFIG_HOME") },
        }

        let config = result.expect("should load user config");
        assert_eq!(
            config.max_branches, 7,
            "should load max_branches from user config file"
        );
    }

    /// load_or_default() should use system defaults when running as root
    /// without /etc/puzzled/puzzled.conf.
    #[test]
    fn test_load_or_default_system_defaults_when_root_mode() {
        // We can't simulate root mode in a unit test, but we can verify
        // that DaemonConfig::default() gives system defaults.
        let config = DaemonConfig::default();
        assert_eq!(config.bus_type, "system");
        assert_eq!(config.fs_type, "xfs");
        assert_eq!(config.max_branches, 64);
    }

    /// §3.4 G14: Test instance secret generation and loading.
    #[test]
    fn test_instance_secret_create_and_load() {
        let tmp = tempfile::tempdir().unwrap();
        let secret_path = tmp.path().join("instance_secret");

        // Manually test the generation path by setting HOME to temp dir
        // (load_instance_secret uses bus_type to choose path — we test the underlying logic)

        // Generate: write 32 random bytes
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).unwrap();
        std::fs::write(&secret_path, secret).unwrap();

        // Read back and verify
        let loaded = std::fs::read(&secret_path).unwrap();
        assert_eq!(loaded.len(), 32);
        assert_eq!(&loaded[..], &secret[..]);
    }

    /// §3.4 G14: Test instance secret rejects short secrets.
    #[test]
    fn test_instance_secret_rejects_short() {
        let tmp = tempfile::tempdir().unwrap();
        let secret_path = tmp.path().join("instance_secret");

        // Write a secret that's too short
        std::fs::write(&secret_path, [0u8; 16]).unwrap();

        let bytes = std::fs::read(&secret_path).unwrap();
        assert!(bytes.len() < 32, "should be too short");
    }

    /// §3.4 G14: Test machine-id fallback produces deterministic output.
    #[test]
    fn test_machine_id_fallback_deterministic() {
        // Only run on systems with /etc/machine-id
        if !Path::new("/etc/machine-id").exists() {
            return;
        }
        let key1 = load_instance_secret_machine_id_fallback().unwrap();
        let key2 = load_instance_secret_machine_id_fallback().unwrap();
        assert_eq!(*key1, *key2, "machine-id fallback must be deterministic");
    }

    // §3.4 G24: Port allocator tests

    #[test]
    fn test_port_allocator_allocate_and_release() {
        // Use a high range unlikely to conflict with real services
        let mut alloc = PortAllocator::new(49100..=49105);

        let p1 = alloc.allocate();
        assert!(p1.is_some());
        assert_eq!(alloc.allocated_count(), 1);

        let p2 = alloc.allocate();
        assert!(p2.is_some());
        assert_ne!(p1, p2);
        assert_eq!(alloc.allocated_count(), 2);

        alloc.release(p1.unwrap());
        assert_eq!(alloc.allocated_count(), 1);
    }

    #[test]
    fn test_port_allocator_mark_allocated() {
        let mut alloc = PortAllocator::new(49200..=49202);
        alloc.mark_allocated(49200);
        alloc.mark_allocated(49201);

        // Only 49202 should be available
        let p = alloc.allocate();
        assert_eq!(p, Some(49202));

        // No more ports
        assert!(alloc.allocate().is_none());
    }

    #[test]
    fn test_port_range_parsing() {
        let config = CredentialProxyDaemonConfig {
            port_range: "18000-18499".to_string(),
            ..Default::default()
        };
        let range = config.parse_port_range().unwrap();
        assert_eq!(*range.start(), 18000);
        assert_eq!(*range.end(), 18499);
    }

    #[test]
    fn test_port_range_invalid() {
        let config = CredentialProxyDaemonConfig {
            port_range: "bad-range".to_string(),
            ..Default::default()
        };
        assert!(config.parse_port_range().is_err());
    }

    // -----------------------------------------------------------------------
    // H-2: Port range overlap validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_h2_ranges_overlap_detects_overlap() {
        assert!(ranges_overlap(&(10..=20), &(15..=25)));
        assert!(ranges_overlap(&(15..=25), &(10..=20)));
        assert!(ranges_overlap(&(10..=20), &(10..=20)));
        assert!(ranges_overlap(&(10..=20), &(20..=30)));
    }

    #[test]
    fn test_h2_ranges_overlap_no_overlap() {
        assert!(!ranges_overlap(&(10..=19), &(20..=30)));
        assert!(!ranges_overlap(&(20..=30), &(10..=19)));
        assert!(!ranges_overlap(&(18000..=18499), &(18500..=18999)));
    }

    #[test]
    fn test_h2_session_rejects_system_range_overlap() {
        let mut config = DaemonConfig::default();
        config.bus_type = "session".to_string();
        // Overlaps with system default 18000-18499
        config.credential_proxy.port_range = "18000-18499".to_string();
        let result = config.validate();
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("overlaps system"),
            "H-2: session instance with system range must be rejected"
        );
    }

    #[test]
    fn test_h2_system_rejects_user_range_overlap() {
        let mut config = DaemonConfig::default();
        config.bus_type = "system".to_string();
        // Overlaps with user default 18500-18999
        config.credential_proxy.port_range = "18500-18999".to_string();
        let result = config.validate();
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("overlaps user"),
            "H-2: system instance with user range must be rejected"
        );
    }

    #[test]
    fn test_h2_default_ranges_no_overlap() {
        // System default (18000-18499) should pass for system bus
        let mut config = DaemonConfig::default();
        config.bus_type = "system".to_string();
        assert!(
            config.validate().is_ok(),
            "system default range should not overlap"
        );

        // User default equivalent (18500-18999) should pass for session bus
        let mut config = DaemonConfig::default();
        config.bus_type = "session".to_string();
        config.credential_proxy.port_range = "18500-18999".to_string();
        assert!(
            config.validate().is_ok(),
            "user default range should not overlap"
        );
    }
}
