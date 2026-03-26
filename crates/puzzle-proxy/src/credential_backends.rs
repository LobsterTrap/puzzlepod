// SPDX-License-Identifier: Apache-2.0
//! §3.4: Credential store backend abstraction.
//!
//! Provides a trait-based backend system for credential storage, allowing
//! the credential store to be backed by different secret management systems:
//! - `LocalEncrypted` (default): AES-256-GCM encrypted file on disk
//! - `Vault`: HashiCorp Vault KV v2 API (HTTP client)
//! - `Keyring`: OS-level keyring (Linux Secret Service, macOS Keychain)
//! - `KubernetesSecret`: Kubernetes Secrets mounted as files

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::credentials::{CredentialError, StoredCredential};

/// §3.4.9: Default timeout for caching Argon2id-derived keys in the Linux kernel
/// keyring (24 hours). After this timeout, passphrase-encrypted credentials require
/// manual unlock via `puzzlectl credential unlock` or the `UnlockCredential` D-Bus method.
pub const DEFAULT_KEYRING_CACHE_TIMEOUT_SECS: u64 = 86400;

/// §3.4: Vault authentication method.
///
/// Controls how puzzled authenticates to HashiCorp Vault. Supports static tokens,
/// AppRole (for daemons), and Kubernetes service account auth (for K8s pods).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum VaultAuth {
    /// Static token authentication (simplest, for dev/test).
    /// The token is read from a file at startup (never stored inline in config).
    Token {
        /// Path to file containing the Vault token (e.g., "/etc/puzzled/vault-token").
        token_path: PathBuf,
    },
    /// AppRole authentication (recommended for daemons).
    AppRole {
        /// AppRole role ID.
        role_id: String,
        /// Path to file containing the secret ID (rotated externally).
        secret_id_path: PathBuf,
    },
    /// Kubernetes service account authentication (for K8s deployments).
    /// Uses the default service account JWT at /var/run/secrets/kubernetes.io/serviceaccount/token.
    Kubernetes {
        /// Kubernetes auth role name configured in Vault.
        role: String,
    },
}

/// Backend configuration specifying which secret store to use.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BackendConfig {
    /// AES-256-GCM encrypted file on local disk (default).
    Local {
        /// Path to the encrypted store file (default: /etc/puzzled/credentials/store.enc).
        #[serde(default = "default_backend_store_path")]
        store_path: PathBuf,
    },
    /// HashiCorp Vault KV v2 backend.
    Vault {
        /// Vault address (e.g., "https://vault.example.com:8200").
        address: String,
        /// Authentication method for Vault.
        auth: VaultAuth,
        /// KV v2 mount path (default: "secret").
        #[serde(default = "default_vault_mount")]
        mount: String,
        /// Path prefix within KV mount (default: "puzzled/").
        #[serde(default = "default_vault_prefix")]
        prefix: String,
        /// Cache TTL in seconds (default: 300).
        #[serde(default = "default_vault_cache_ttl")]
        cache_ttl_secs: u64,
    },
    /// OS-level keyring (Linux Secret Service / macOS Keychain).
    Keyring {
        /// Service name prefix (default: "puzzled").
        #[serde(default = "default_keyring_service")]
        service: String,
    },
    /// Kubernetes Secrets mounted as files.
    KubernetesSecret {
        /// Directory where K8s secrets are mounted (e.g., "/var/run/secrets/puzzlepod").
        mount_path: PathBuf,
        /// Namespace (informational, secrets are pre-mounted by kubelet).
        namespace: Option<String>,
    },
    /// §3.4 G6: Read credentials from puzzled's own environment variables.
    /// For CI/development use only — not suitable for production.
    EnvPassthrough {
        /// Environment variable name to read.
        env_var: String,
    },
}

fn default_backend_store_path() -> PathBuf {
    PathBuf::from("/etc/puzzled/credentials/store.enc")
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

fn default_keyring_service() -> String {
    "puzzled".to_string()
}

impl Default for BackendConfig {
    fn default() -> Self {
        BackendConfig::Local {
            store_path: default_backend_store_path(),
        }
    }
}

/// Trait for credential storage backends.
///
/// Each backend must support the core CRUD operations. Backends that don't
/// support a particular operation (e.g., Kubernetes Secrets are read-only)
/// return `CredentialError::NotFound` or a descriptive error.
pub trait CredentialBackend: Send + Sync {
    /// Load all credentials from the backend.
    fn load_all(&self) -> Result<HashMap<String, StoredCredential>, CredentialError>;

    /// Store or update a single credential.
    fn store(&self, credential: &StoredCredential) -> Result<(), CredentialError>;

    /// Remove a credential by name. Returns true if it existed.
    fn remove(&self, name: &str) -> Result<bool, CredentialError>;

    /// Backend display name for logging.
    fn backend_name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// §3.4 T3.3: PRD-aligned SecretBackend trait for Phase 2 backends (Vault, AWS STS).
//
// The existing CredentialBackend trait uses synchronous CRUD operations suitable for
// Phase 1 local backends (encrypted-file, env-passthrough). The PRD §3.4.9 specifies
// an async `SecretBackend` with per-credential fetch and TTL-based expiry, needed for
// remote backends like Vault (lease renewal) and AWS STS (session credentials).
//
// Both traits coexist: CredentialBackend for disk-backed CRUD, SecretBackend for
// async fetch-with-expiry. Phase 2 backends implement SecretBackend.
// ---------------------------------------------------------------------------

/// A fetched secret value with optional expiry for cache TTL management.
/// Uses `Instant` (monotonic clock) for reliable expiry checking, unlike
/// string timestamps which require parsing.
pub struct SecretValue {
    /// The raw secret value, zeroized on drop.
    pub value: zeroize::Zeroizing<Vec<u8>>,
    /// When this value expires (if backend provides TTL/lease info).
    /// `None` means the value does not expire.
    pub expires_at: Option<std::time::Instant>,
}

/// Async backend trait for fetching individual secrets by configuration.
///
/// Unlike `CredentialBackend` (synchronous CRUD), this trait is designed for
/// remote secret stores (Vault, AWS STS) where:
/// - Fetching requires async I/O (HTTP requests)
/// - Secrets have TTLs/leases that need renewal
/// - Configuration is per-credential (Vault path, STS role ARN)
pub trait SecretBackend: Send + Sync {
    /// Fetch a secret value using backend-specific configuration.
    ///
    /// `config` contains backend-specific fields (e.g., Vault path + field,
    /// STS role ARN + session name). The format is defined per-backend.
    fn fetch(
        &self,
        config: &serde_json::Value,
    ) -> impl std::future::Future<Output = Result<SecretValue, CredentialError>> + Send;

    /// Backend identifier for logging and error messages.
    fn name(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// Local encrypted file backend (delegates to existing CredentialStore logic)
// ---------------------------------------------------------------------------

/// Local AES-256-GCM encrypted file backend.
///
/// This is the default backend, using the same encryption logic as the
/// existing `CredentialStore`. The store file format is:
/// `nonce (12 bytes) || AES-256-GCM ciphertext || tag (16 bytes)`.
///
/// D-I1: Stores the raw `signing_key` (not a derived key) so that
/// `CredentialStore::new()` performs the single correct HKDF derivation.
/// The previous code derived a key here AND `CredentialStore::new()` derived
/// again, producing a different key than a direct `CredentialStore::new()` call.
pub struct LocalEncryptedBackend {
    store_path: PathBuf,
    /// Raw signing key bytes — passed to `CredentialStore::new()` which derives
    /// the encryption key via HKDF. Zeroized on drop.
    signing_key: zeroize::Zeroizing<Vec<u8>>,
}

impl LocalEncryptedBackend {
    /// Create a new local encrypted backend.
    pub fn new(store_path: PathBuf, signing_key: &[u8]) -> Self {
        Self {
            store_path,
            signing_key: zeroize::Zeroizing::new(signing_key.to_vec()),
        }
    }
}

impl CredentialBackend for LocalEncryptedBackend {
    fn load_all(&self) -> Result<HashMap<String, StoredCredential>, CredentialError> {
        if !self.store_path.exists() {
            return Ok(HashMap::new());
        }
        // D-I1: Pass the raw signing_key to CredentialStore::new(), which performs
        // the single HKDF derivation. Previously we derived here AND CredentialStore
        // derived again (double derivation), producing a wrong key.
        let mut store =
            crate::credentials::CredentialStore::new(self.store_path.clone(), &self.signing_key)?;
        // Take ownership of the credentials map (avoids Clone requirement on StoredCredential).
        // The store is a local variable that will be dropped after this.
        Ok(std::mem::take(&mut store.credentials))
    }

    fn store(&self, _credential: &StoredCredential) -> Result<(), CredentialError> {
        // V20: No-op — CredentialStore handles persistence directly. Backend is read-only.
        tracing::debug!(
            backend = "local_encrypted",
            path = %self.store_path.display(),
            "credential stored via local encrypted backend"
        );
        Ok(())
    }

    fn remove(&self, name: &str) -> Result<bool, CredentialError> {
        // V20: No-op — CredentialStore handles persistence directly. Backend is read-only.
        tracing::debug!(
            backend = "local_encrypted",
            name = %name,
            "credential removed via local encrypted backend"
        );
        Ok(true)
    }

    fn backend_name(&self) -> &str {
        "local_encrypted"
    }
}

// ---------------------------------------------------------------------------
// HashiCorp Vault backend (KV v2)
// ---------------------------------------------------------------------------

/// HashiCorp Vault KV v2 backend.
///
/// Uses Vault's HTTP API to read/write secrets. Requires a valid Vault token.
/// The credential is stored at `<mount>/data/<prefix>/<credential_name>`.
///
/// This is a synchronous-compatible implementation that uses blocking HTTP
/// calls. For production use, consider an async Vault client.
pub struct VaultBackend {
    address: String,
    _auth: VaultAuth,
    mount: String,
    prefix: String,
    _cache_ttl_secs: u64,
}

impl VaultBackend {
    /// Create a new Vault backend.
    pub fn new(
        address: String,
        auth: VaultAuth,
        mount: String,
        prefix: String,
        cache_ttl_secs: u64,
    ) -> Self {
        Self {
            address: address.trim_end_matches('/').to_string(),
            _auth: auth,
            mount,
            prefix,
            _cache_ttl_secs: cache_ttl_secs,
        }
    }

    /// N11: Sanitize `name` to prevent path traversal in Vault URL construction.
    /// Rejects names containing `..`, `/`, `\`, or URL-encoded path components.
    fn secret_path(&self, name: &str) -> Result<String, crate::credentials::CredentialError> {
        if name.contains("..")
            || name.contains('/')
            || name.contains('\\')
            || name.contains("%2e")
            || name.contains("%2E")
            || name.contains("%2f")
            || name.contains("%2F")
            || name.contains("%5c")
            || name.contains("%5C")
        {
            return Err(crate::credentials::CredentialError::InvalidName(format!(
                "credential name '{}' contains path traversal characters",
                name
            )));
        }
        Ok(format!(
            "{}/v1/{}/data/{}/{}",
            self.address, self.mount, self.prefix, name
        ))
    }
}

impl CredentialBackend for VaultBackend {
    fn load_all(&self) -> Result<HashMap<String, StoredCredential>, CredentialError> {
        // D-I4: Error instead of silently returning empty — users configuring Vault
        // should be told it's not yet functional.
        Err(CredentialError::NotImplemented(
            "vault backend requires HTTP client (not yet implemented)".into(),
        ))
    }

    fn store(&self, credential: &StoredCredential) -> Result<(), CredentialError> {
        let _path = self.secret_path(&credential.name)?;
        Err(CredentialError::NotImplemented(
            "vault backend requires HTTP client (not yet implemented)".into(),
        ))
    }

    fn remove(&self, _name: &str) -> Result<bool, CredentialError> {
        Err(CredentialError::NotImplemented(
            "vault backend requires HTTP client (not yet implemented)".into(),
        ))
    }

    fn backend_name(&self) -> &str {
        "vault"
    }
}

// ---------------------------------------------------------------------------
// OS Keyring backend
// ---------------------------------------------------------------------------

/// OS-level keyring backend (Linux Secret Service / macOS Keychain).
///
/// Stores each credential as a keyring entry with:
/// - Service: `<service_name>` (default: "puzzlepod")
/// - Account: `<credential_name>`
/// - Password: JSON-serialized credential data
///
/// Requires the `keyring` crate for full implementation.
pub struct KeyringBackend {
    _service: String,
}

impl KeyringBackend {
    /// Create a new keyring backend.
    pub fn new(service: String) -> Self {
        Self { _service: service }
    }
}

impl CredentialBackend for KeyringBackend {
    fn load_all(&self) -> Result<HashMap<String, StoredCredential>, CredentialError> {
        // D-I4: Error instead of silently returning empty — users configuring Keyring
        // should be told it's not yet functional.
        Err(CredentialError::NotImplemented(
            "keyring backend requires keyring crate (not yet implemented)".into(),
        ))
    }

    fn store(&self, _credential: &StoredCredential) -> Result<(), CredentialError> {
        Err(CredentialError::NotImplemented(
            "keyring backend requires keyring crate (not yet implemented)".into(),
        ))
    }

    fn remove(&self, _name: &str) -> Result<bool, CredentialError> {
        Err(CredentialError::NotImplemented(
            "keyring backend requires keyring crate (not yet implemented)".into(),
        ))
    }

    fn backend_name(&self) -> &str {
        "keyring"
    }
}

// ---------------------------------------------------------------------------
// Kubernetes Secrets backend
// ---------------------------------------------------------------------------

/// Kubernetes Secrets backend (file mount).
///
/// Reads credentials from files mounted by the kubelet. Each secret key
/// becomes a file in the mount directory. The file content is the
/// JSON-serialized credential data.
///
/// This backend is **read-only** — credential creation/rotation must be
/// done via `kubectl` or the Kubernetes API. The proxy reads the mounted
/// files at startup and on rotation signals.
pub struct KubernetesSecretBackend {
    mount_path: PathBuf,
}

impl KubernetesSecretBackend {
    /// Create a new Kubernetes Secret backend.
    pub fn new(mount_path: PathBuf) -> Self {
        Self { mount_path }
    }
}

impl CredentialBackend for KubernetesSecretBackend {
    fn load_all(&self) -> Result<HashMap<String, StoredCredential>, CredentialError> {
        let mut credentials = HashMap::new();

        if !self.mount_path.exists() {
            tracing::warn!(
                backend = "kubernetes",
                path = %self.mount_path.display(),
                "K8s secret mount path does not exist"
            );
            return Ok(credentials);
        }

        let entries = std::fs::read_dir(&self.mount_path).map_err(CredentialError::Io)?;

        for entry in entries {
            let entry = entry.map_err(CredentialError::Io)?;
            let path = entry.path();

            // Skip hidden files (K8s uses ..data symlinks internally)
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with('.') {
                    continue;
                }
            }

            if path.is_file() {
                match std::fs::read_to_string(&path) {
                    Ok(content) => match serde_json::from_str::<StoredCredential>(&content) {
                        Ok(cred) => {
                            tracing::debug!(
                                backend = "kubernetes",
                                name = %cred.name,
                                "loaded credential from K8s secret mount"
                            );
                            credentials.insert(cred.name.clone(), cred);
                        }
                        Err(e) => {
                            tracing::warn!(
                                backend = "kubernetes",
                                path = %path.display(),
                                error = %e,
                                "failed to parse K8s secret as credential"
                            );
                        }
                    },
                    Err(e) => {
                        tracing::warn!(
                            backend = "kubernetes",
                            path = %path.display(),
                            error = %e,
                            "failed to read K8s secret file"
                        );
                    }
                }
            }
        }

        tracing::info!(
            backend = "kubernetes",
            count = credentials.len(),
            path = %self.mount_path.display(),
            "loaded credentials from K8s secret mount"
        );

        Ok(credentials)
    }

    fn store(&self, credential: &StoredCredential) -> Result<(), CredentialError> {
        // K8s secrets are read-only from the pod's perspective
        tracing::warn!(
            backend = "kubernetes",
            name = %credential.name,
            "cannot store credentials via K8s secret mount (read-only) — use kubectl or K8s API"
        );
        Err(CredentialError::NotImplemented(
            "T20: Kubernetes Secret backend is read-only; use kubectl or the Kubernetes API to manage secrets".to_string()
        ))
    }

    fn remove(&self, name: &str) -> Result<bool, CredentialError> {
        tracing::warn!(
            backend = "kubernetes",
            name = %name,
            "cannot remove credentials via K8s secret mount (read-only) — use kubectl or K8s API"
        );
        Err(CredentialError::NotImplemented(
            "T20: Kubernetes Secret backend is read-only; use kubectl or the Kubernetes API to manage secrets".to_string()
        ))
    }

    fn backend_name(&self) -> &str {
        "kubernetes"
    }
}

// ---------------------------------------------------------------------------
// L-3: AWS STS backend stub (Phase 2)
// ---------------------------------------------------------------------------

/// AWS STS backend for short-lived scoped session credentials via AssumeRole.
/// L-3: Stub implementation — returns NotImplemented for all operations.
#[derive(Default)]
pub struct AwsStsBackend;

impl AwsStsBackend {
    pub fn new() -> Self {
        Self
    }
}

impl CredentialBackend for AwsStsBackend {
    fn load_all(&self) -> Result<HashMap<String, StoredCredential>, CredentialError> {
        Err(CredentialError::NotImplemented(
            "AWS STS backend is not yet implemented (planned for Phase 2)".to_string(),
        ))
    }

    fn store(&self, _credential: &StoredCredential) -> Result<(), CredentialError> {
        Err(CredentialError::NotImplemented(
            "AWS STS backend is not yet implemented (planned for Phase 2)".to_string(),
        ))
    }

    fn remove(&self, _name: &str) -> Result<bool, CredentialError> {
        Err(CredentialError::NotImplemented(
            "AWS STS backend is not yet implemented (planned for Phase 2)".to_string(),
        ))
    }

    fn backend_name(&self) -> &str {
        "aws-sts"
    }
}

// ---------------------------------------------------------------------------
// §3.4 G6: Environment passthrough backend
// ---------------------------------------------------------------------------

/// Backend that reads credentials from puzzled's own environment variables.
///
/// **WARNING:** This backend is for CI/development use only. Credential values
/// exist in puzzled's process environment, which may be visible via /proc.
pub struct EnvPassthroughBackend {
    env_var: String,
}

impl EnvPassthroughBackend {
    pub fn new(env_var: String) -> Self {
        tracing::warn!(
            env_var = %env_var,
            "§3.4 G6: using env-passthrough backend — credential exists in host environment"
        );
        Self { env_var }
    }
}

impl CredentialBackend for EnvPassthroughBackend {
    fn load_all(&self) -> Result<HashMap<String, StoredCredential>, CredentialError> {
        match std::env::var(&self.env_var) {
            Ok(value) => {
                let credential = StoredCredential {
                    name: self.env_var.clone(),
                    credential_type: crate::credentials::CredentialType::ApiKey,
                    value: zeroize::Zeroizing::new(value),
                    allowed_profiles: vec!["*".to_string()],
                    target_domains: vec!["*".to_string()],
                    injection: crate::credentials::InjectionMethod::BearerHeader,
                    expires_at: None,
                    created_at: chrono::Utc::now().to_rfc3339(),
                    rotated_at: None,
                };
                let mut map = HashMap::new();
                map.insert(self.env_var.clone(), credential);
                Ok(map)
            }
            Err(std::env::VarError::NotPresent) => {
                tracing::warn!(
                    env_var = %self.env_var,
                    "§3.4 G6: environment variable not set"
                );
                Ok(HashMap::new())
            }
            Err(e) => Err(CredentialError::Crypto(format!(
                "failed to read env var '{}': {}",
                self.env_var, e
            ))),
        }
    }

    fn store(&self, _credential: &StoredCredential) -> Result<(), CredentialError> {
        Err(CredentialError::NotImplemented(
            "env-passthrough backend is read-only".to_string(),
        ))
    }

    fn remove(&self, _name: &str) -> Result<bool, CredentialError> {
        Err(CredentialError::NotImplemented(
            "env-passthrough backend is read-only".to_string(),
        ))
    }

    fn backend_name(&self) -> &str {
        "env-passthrough"
    }
}

/// Create a credential backend from configuration.
pub fn create_backend(config: &BackendConfig, signing_key: &[u8]) -> Box<dyn CredentialBackend> {
    match config {
        BackendConfig::Local { store_path } => {
            Box::new(LocalEncryptedBackend::new(store_path.clone(), signing_key))
        }
        BackendConfig::Vault {
            address,
            auth,
            mount,
            prefix,
            cache_ttl_secs,
        } => Box::new(VaultBackend::new(
            address.clone(),
            auth.clone(),
            mount.clone(),
            prefix.clone(),
            *cache_ttl_secs,
        )),
        BackendConfig::Keyring { service } => Box::new(KeyringBackend::new(service.clone())),
        BackendConfig::KubernetesSecret {
            mount_path,
            namespace: _,
        } => Box::new(KubernetesSecretBackend::new(mount_path.clone())),
        BackendConfig::EnvPassthrough { env_var } => {
            Box::new(EnvPassthroughBackend::new(env_var.clone()))
        }
    }
}

// ---------------------------------------------------------------------------
// §3.4 G33: Argon2id KDF for passphrase-mode credential encryption
// ---------------------------------------------------------------------------

/// AGCR file format magic bytes.
pub const AGCR_MAGIC: &[u8; 4] = b"AGCR";
/// AGCR file format version.
pub const AGCR_VERSION: u16 = 0x0001;
/// KDF type: Argon2id.
pub const KDF_ARGON2ID: u16 = 0x0001;
/// KDF type: systemd-creds.
pub const KDF_SYSTEMD_CREDS: u16 = 0x0002;

/// Default Argon2id parameters per PRD §3.4.9.
pub const ARGON2_MEMORY_COST: u32 = 65536; // 64 MiB
pub const ARGON2_TIME_COST: u32 = 3;
pub const ARGON2_PARALLELISM: u32 = 4;

/// Encrypt a credential with a passphrase using Argon2id KDF + AES-256-GCM.
///
/// Returns the AGCR-formatted ciphertext.
///
/// File format:
/// - Magic: "AGCR" (4 bytes)
/// - Version: 0x0001 (2 bytes, big-endian)
/// - KDF type: 0x0001 = Argon2id (2 bytes, big-endian)
/// - Salt: 16 bytes random
/// - Argon2id params: memory_cost (4B), time_cost (4B), parallelism (4B) — all big-endian
/// - Nonce: 12 bytes random
/// - Ciphertext + 16-byte GCM tag
///
/// AAD = header bytes (0..48) || credential name (UTF-8)
pub fn encrypt_with_passphrase(
    name: &str,
    plaintext: &[u8],
    passphrase: &[u8],
) -> Result<Vec<u8>, CredentialError> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    // Generate salt and nonce
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut salt)
        .map_err(|e| CredentialError::Crypto(format!("getrandom failed: {}", e)))?;
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| CredentialError::Crypto(format!("getrandom failed: {}", e)))?;

    // Derive AES key via Argon2id
    let params = argon2::Params::new(
        ARGON2_MEMORY_COST,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(32),
    )
    .map_err(|e| CredentialError::Crypto(format!("argon2 params: {}", e)))?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase, &salt, &mut *key)
        .map_err(|e| CredentialError::Crypto(format!("argon2 hash failed: {}", e)))?;

    // Build header
    let mut header = Vec::with_capacity(48);
    header.extend_from_slice(AGCR_MAGIC); // 4 bytes
    header.extend_from_slice(&AGCR_VERSION.to_be_bytes()); // 2 bytes
    header.extend_from_slice(&KDF_ARGON2ID.to_be_bytes()); // 2 bytes
    header.extend_from_slice(&salt); // 16 bytes
    header.extend_from_slice(&ARGON2_MEMORY_COST.to_be_bytes()); // 4 bytes
    header.extend_from_slice(&ARGON2_TIME_COST.to_be_bytes()); // 4 bytes
    header.extend_from_slice(&ARGON2_PARALLELISM.to_be_bytes()); // 4 bytes
    header.extend_from_slice(&nonce_bytes); // 12 bytes
                                            // Total header: 48 bytes

    // AAD = header || credential name
    let mut aad = header.clone();
    aad.extend_from_slice(name.as_bytes());

    // Encrypt
    let cipher = Aes256Gcm::new_from_slice(&*key)
        .map_err(|e| CredentialError::Crypto(format!("AES key init: {}", e)))?;
    // L-5: Explicitly drop derived key after cipher construction. The cipher's
    // internal key schedule is a separate copy; the source key should not linger.
    drop(key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| CredentialError::Crypto(format!("AES-GCM encrypt: {}", e)))?;

    // Build output: header + ciphertext (includes GCM tag)
    let mut output = header;
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt a credential encrypted with `encrypt_with_passphrase`.
///
/// Returns the plaintext wrapped in `Zeroizing`.
pub fn decrypt_with_passphrase(
    name: &str,
    data: &[u8],
    passphrase: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>, CredentialError> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    if data.len() < 48 {
        return Err(CredentialError::Crypto(
            "AGCR file too short (< 48 bytes)".to_string(),
        ));
    }

    // Parse header
    if &data[0..4] != AGCR_MAGIC {
        return Err(CredentialError::Crypto(
            "invalid AGCR magic bytes".to_string(),
        ));
    }
    let version = u16::from_be_bytes([data[4], data[5]]);
    if version != AGCR_VERSION {
        return Err(CredentialError::Crypto(format!(
            "unsupported AGCR version: {}",
            version
        )));
    }
    let kdf_type = u16::from_be_bytes([data[6], data[7]]);
    if kdf_type != KDF_ARGON2ID {
        // L-4: Improved error message directing users to the correct backend.
        let hint = if kdf_type == KDF_SYSTEMD_CREDS {
            " (KDF type 2 = systemd-creds: decrypt with SystemdCredsBackend instead)"
        } else {
            ""
        };
        return Err(CredentialError::Crypto(format!(
            "unsupported KDF type: {} (expected Argon2id=1){hint}",
            kdf_type
        )));
    }

    let salt = &data[8..24];
    let memory_cost = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);
    let time_cost = u32::from_be_bytes([data[28], data[29], data[30], data[31]]);
    let parallelism = u32::from_be_bytes([data[32], data[33], data[34], data[35]]);
    let nonce_bytes = &data[36..48];
    let ciphertext = &data[48..];

    // Derive key
    let params = argon2::Params::new(memory_cost, time_cost, parallelism, Some(32))
        .map_err(|e| CredentialError::Crypto(format!("argon2 params: {}", e)))?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase, salt, &mut *key)
        .map_err(|e| CredentialError::Crypto(format!("argon2 hash failed: {}", e)))?;

    // Reconstruct AAD
    let header = &data[0..48];
    let mut aad = header.to_vec();
    aad.extend_from_slice(name.as_bytes());

    // Decrypt
    let cipher = Aes256Gcm::new_from_slice(&*key)
        .map_err(|e| CredentialError::Crypto(format!("AES key init: {}", e)))?;
    // L-5: Explicitly drop derived key after cipher construction.
    drop(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|e| {
            CredentialError::Crypto(format!("AES-GCM decrypt failed (wrong passphrase?): {}", e))
        })?;

    Ok(zeroize::Zeroizing::new(plaintext))
}

// ---------------------------------------------------------------------------
// §3.4 G32: Kernel keyring caching for passphrase-derived AES keys
// ---------------------------------------------------------------------------
//
// Caches Argon2id-derived AES keys in the Linux kernel session keyring so
// that users do not need to re-enter passphrases after puzzled restart
// (within the configured timeout). The kernel manages key lifetime and
// zeroization on expiry.
//
// Security properties:
// - Keys are stored in the session keyring (KEY_SPEC_SESSION_KEYRING = -3),
//   scoped to the session and not readable by other sessions/UIDs.
// - Timeout is enforced by the kernel (`KEYCTL_SET_TIMEOUT`); expired keys
//   are automatically purged from kernel memory.
// - Key descriptions are namespaced with "puzzled:cred:" prefix to avoid
//   collisions with other keyring users.
// - Retrieved key material is immediately wrapped in `Zeroizing` to ensure
//   userspace copies are cleared on drop.

/// Cache a derived AES key in the Linux kernel session keyring.
///
/// The key is stored as a "user" type key with description `puzzled:cred:<name>`.
/// The kernel will automatically expire and purge the key after `timeout_secs`.
///
/// # Errors
///
/// Returns `Err` with a descriptive message if the `add_key` or `keyctl`
/// syscall fails. Callers should log the error and fall back to prompting
/// for the passphrase — keyring caching is an optimization, not a requirement.
#[cfg(target_os = "linux")]
pub fn cache_derived_key_in_keyring(
    name: &str,
    key: &[u8],
    timeout_secs: u64,
) -> Result<(), String> {
    use std::ffi::CString;

    /// Session keyring identifier (KEY_SPEC_SESSION_KEYRING).
    const KEY_SPEC_SESSION_KEYRING: i32 = -3;
    /// keyctl command: set key timeout.
    const KEYCTL_SET_TIMEOUT: i32 = 15;

    let desc = format!("puzzled:cred:{}", name);
    let desc_cstr =
        CString::new(desc.as_bytes()).map_err(|e| format!("invalid keyring description: {}", e))?;

    // add_key("user", description, payload, payload_len, KEY_SPEC_SESSION_KEYRING)
    let key_id = unsafe {
        libc::syscall(
            libc::SYS_add_key,
            c"user".as_ptr(),
            desc_cstr.as_ptr(),
            key.as_ptr(),
            key.len(),
            KEY_SPEC_SESSION_KEYRING,
        )
    };

    if key_id < 0 {
        let errno = std::io::Error::last_os_error();
        return Err(format!("add_key failed for '{}': {}", name, errno));
    }

    tracing::debug!(
        name = %name,
        key_id = key_id,
        timeout_secs = timeout_secs,
        "G32: cached derived key in kernel session keyring"
    );

    // keyctl(KEYCTL_SET_TIMEOUT, key_id, timeout_secs)
    let ret = unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_SET_TIMEOUT, key_id, timeout_secs) };

    if ret < 0 {
        let errno = std::io::Error::last_os_error();
        tracing::warn!(
            name = %name,
            key_id = key_id,
            error = %errno,
            "G32: keyctl SET_TIMEOUT failed — key cached but will not auto-expire"
        );
        // Non-fatal: the key is cached, just without a timeout.
        // This is acceptable because the key will be purged when the session ends.
    }

    Ok(())
}

/// Non-Linux stub: keyring caching is not available.
#[cfg(not(target_os = "linux"))]
pub fn cache_derived_key_in_keyring(
    _name: &str,
    _key: &[u8],
    _timeout_secs: u64,
) -> Result<(), String> {
    Err("kernel keyring caching is only available on Linux".to_string())
}

/// Look up a previously cached derived key in the Linux kernel session keyring.
///
/// Returns `Some(key_data)` if a valid, non-expired key with description
/// `puzzled:cred:<name>` is found, or `None` on any failure (key not found,
/// expired, permission denied, non-Linux platform).
///
/// The returned key material is wrapped in `Zeroizing` to ensure it is
/// cleared from memory when dropped.
#[cfg(target_os = "linux")]
pub fn lookup_derived_key_in_keyring(name: &str) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    use std::ffi::CString;

    /// Session keyring identifier (KEY_SPEC_SESSION_KEYRING).
    const KEY_SPEC_SESSION_KEYRING: i32 = -3;
    /// keyctl command: search for a key.
    const KEYCTL_SEARCH: i32 = 10;
    /// keyctl command: read key payload.
    const KEYCTL_READ: i32 = 11;

    let desc = format!("puzzled:cred:{}", name);
    let desc_cstr = CString::new(desc.as_bytes()).ok()?;

    // keyctl(KEYCTL_SEARCH, KEY_SPEC_SESSION_KEYRING, "user", description, 0)
    let key_id = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_SEARCH,
            KEY_SPEC_SESSION_KEYRING,
            c"user".as_ptr(),
            desc_cstr.as_ptr(),
            0i64,
        )
    };

    if key_id < 0 {
        tracing::debug!(
            name = %name,
            "G32: derived key not found in kernel keyring (expired or never cached)"
        );
        return None;
    }

    // First call with null buffer to get the key size
    let key_size = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_READ,
            key_id,
            std::ptr::null_mut::<u8>(),
            0usize,
        )
    };

    if !(0..=256).contains(&key_size) {
        // Sanity check: AES keys should be at most 32 bytes; 256 is a generous
        // upper bound. If the kernel reports a larger size, something is wrong.
        tracing::warn!(
            name = %name,
            key_size = key_size,
            "G32: keyring key has unexpected size — ignoring"
        );
        return None;
    }

    let mut buf = zeroize::Zeroizing::new(vec![0u8; key_size as usize]);

    let bytes_read = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_READ,
            key_id,
            buf.as_mut_ptr(),
            buf.len(),
        )
    };

    if bytes_read < 0 {
        let errno = std::io::Error::last_os_error();
        tracing::warn!(
            name = %name,
            error = %errno,
            "G32: failed to read key from kernel keyring"
        );
        return None;
    }

    buf.truncate(bytes_read as usize);

    tracing::debug!(
        name = %name,
        key_id = key_id,
        key_len = bytes_read,
        "G32: retrieved derived key from kernel keyring cache"
    );

    Some(buf)
}

/// Non-Linux stub: keyring lookup is not available.
#[cfg(not(target_os = "linux"))]
pub fn lookup_derived_key_in_keyring(_name: &str) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{CredentialType, InjectionMethod, StoredCredential};
    use chrono::Utc;

    fn test_credential(name: &str) -> StoredCredential {
        StoredCredential {
            name: name.to_string(),
            credential_type: CredentialType::ApiKey,
            value: zeroize::Zeroizing::new("test-secret".to_string()),
            allowed_profiles: vec!["*".to_string()],
            target_domains: vec!["example.com".to_string()],
            injection: InjectionMethod::BearerHeader,
            expires_at: None,
            created_at: Utc::now().to_rfc3339(),
            rotated_at: None,
        }
    }

    #[test]
    fn test_backend_config_default() {
        let config = BackendConfig::default();
        match config {
            BackendConfig::Local { store_path } => {
                assert_eq!(
                    store_path,
                    PathBuf::from("/etc/puzzled/credentials/store.enc")
                );
            }
            _ => panic!("expected Local default"),
        }
    }

    #[test]
    fn test_backend_config_serde() {
        let configs = vec![
            BackendConfig::Local {
                store_path: PathBuf::from("/tmp/test.enc"),
            },
            BackendConfig::Vault {
                address: "https://vault.example.com:8200".to_string(),
                auth: VaultAuth::Token {
                    token_path: PathBuf::from("/etc/puzzled/vault-token"),
                },
                mount: "secret".to_string(),
                prefix: "puzzlepod/creds".to_string(),
                cache_ttl_secs: 300,
            },
            BackendConfig::Keyring {
                service: "puzzlepod-test".to_string(),
            },
            BackendConfig::KubernetesSecret {
                mount_path: PathBuf::from("/var/run/secrets/puzzlepod"),
                namespace: Some("default".to_string()),
            },
        ];

        for config in &configs {
            let json = serde_json::to_string(config).unwrap();
            let parsed: BackendConfig = serde_json::from_str(&json).unwrap();
            let reparsed = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, reparsed);
        }
    }

    /// D-I4: Vault backend should return NotImplemented errors, not silently succeed.
    #[test]
    fn test_vault_backend_returns_not_implemented() {
        let backend = VaultBackend::new(
            "https://vault.example.com:8200".to_string(),
            VaultAuth::Token {
                token_path: PathBuf::from("/run/vault/token"),
            },
            "secret".to_string(),
            "puzzled/".to_string(),
            300,
        );
        assert_eq!(backend.backend_name(), "vault");
        assert!(backend.load_all().is_err());
        assert!(backend.store(&test_credential("test")).is_err());
        assert!(backend.remove("test").is_err());

        // Verify the error is NotImplemented
        match backend.load_all() {
            Err(CredentialError::NotImplemented(msg)) => {
                assert!(msg.contains("vault"), "error should mention vault: {msg}");
            }
            other => panic!("expected NotImplemented, got: {other:?}"),
        }
    }

    /// D-I4: Keyring backend should return NotImplemented errors, not silently succeed.
    #[test]
    fn test_keyring_backend_returns_not_implemented() {
        let backend = KeyringBackend::new("puzzled".to_string());
        assert_eq!(backend.backend_name(), "keyring");
        assert!(backend.load_all().is_err());
        assert!(backend.store(&test_credential("test")).is_err());
        assert!(backend.remove("test").is_err());

        match backend.load_all() {
            Err(CredentialError::NotImplemented(msg)) => {
                assert!(
                    msg.contains("keyring"),
                    "error should mention keyring: {msg}"
                );
            }
            other => panic!("expected NotImplemented, got: {other:?}"),
        }
    }

    #[test]
    fn test_k8s_backend_nonexistent_path() {
        let backend = KubernetesSecretBackend::new(PathBuf::from("/nonexistent/path"));
        assert_eq!(backend.backend_name(), "kubernetes");
        assert!(backend.load_all().unwrap().is_empty());
    }

    #[test]
    fn test_k8s_backend_read_only() {
        let backend = KubernetesSecretBackend::new(PathBuf::from("/tmp"));
        assert!(backend.store(&test_credential("test")).is_err());
        assert!(backend.remove("test").is_err());
    }

    #[test]
    fn test_k8s_backend_load_from_files() {
        let tmp = tempfile::tempdir().unwrap();
        let cred = test_credential("k8s-cred");
        // K8s backend reads full StoredCredential JSON, but value is skip_serializing.
        // We need to write the full JSON including value for the backend to load.
        let json = serde_json::json!({
            "name": "k8s-cred",
            "credential_type": "api_key",
            "value": "test-secret",
            "allowed_profiles": ["*"],
            "target_domains": ["example.com"],
            "injection": "bearer_header",
            "created_at": cred.created_at,
        });
        std::fs::write(
            tmp.path().join("k8s-cred"),
            serde_json::to_string(&json).unwrap(),
        )
        .unwrap();
        // Also write a hidden file that should be skipped
        std::fs::write(tmp.path().join(".hidden"), "ignored").unwrap();

        let backend = KubernetesSecretBackend::new(tmp.path().to_path_buf());
        let loaded = backend.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains_key("k8s-cred"));
    }

    #[test]
    fn test_create_backend_factory() {
        let configs = vec![
            BackendConfig::Local {
                store_path: PathBuf::from("/tmp/test.enc"),
            },
            BackendConfig::Vault {
                address: "https://vault:8200".to_string(),
                auth: VaultAuth::Token {
                    token_path: PathBuf::from("/run/vault/token"),
                },
                mount: "secret".to_string(),
                prefix: "puzzled/".to_string(),
                cache_ttl_secs: 300,
            },
            BackendConfig::Keyring {
                service: "puzzled".to_string(),
            },
            BackendConfig::KubernetesSecret {
                mount_path: PathBuf::from("/tmp"),
                namespace: None,
            },
        ];

        for config in &configs {
            let backend = create_backend(config, b"test-key");
            assert!(!backend.backend_name().is_empty());
        }
    }

    #[test]
    fn test_vault_auth_serde_roundtrip() {
        let variants: Vec<VaultAuth> = vec![
            VaultAuth::Token {
                token_path: PathBuf::from("/etc/puzzled/vault-token"),
            },
            VaultAuth::AppRole {
                role_id: "role-id-123".to_string(),
                secret_id_path: PathBuf::from("/run/vault/secret-id"),
            },
            VaultAuth::Kubernetes {
                role: "puzzlepod-role".to_string(),
            },
            VaultAuth::Kubernetes {
                role: "minimal".to_string(),
            },
        ];

        for auth in &variants {
            let json = serde_json::to_string(auth).unwrap();
            let parsed: VaultAuth = serde_json::from_str(&json).unwrap();
            let reparsed = serde_json::to_string(&parsed).unwrap();
            assert_eq!(
                json, reparsed,
                "VaultAuth serde roundtrip failed for: {json}"
            );
        }
    }

    #[test]
    fn test_vault_backend_with_approle_auth() {
        let backend = VaultBackend::new(
            "https://vault:8200".to_string(),
            VaultAuth::AppRole {
                role_id: "my-role".to_string(),
                secret_id_path: PathBuf::from("/run/vault/secret-id"),
            },
            "secret".to_string(),
            "puzzled/".to_string(),
            300,
        );
        assert_eq!(backend.backend_name(), "vault");
        assert!(
            backend.load_all().is_err(),
            "D-I4: vault backend should return NotImplemented"
        );
    }

    #[test]
    fn test_vault_backend_with_k8s_auth() {
        let backend = VaultBackend::new(
            "https://vault:8200".to_string(),
            VaultAuth::Kubernetes {
                role: "puzzlepod".to_string(),
            },
            "secret".to_string(),
            "puzzlepod/creds".to_string(),
            300,
        );
        assert_eq!(backend.backend_name(), "vault");
    }

    #[test]
    fn test_vault_secret_path() {
        let backend = VaultBackend::new(
            "https://vault.example.com:8200".to_string(),
            VaultAuth::Token {
                token_path: PathBuf::from("/run/vault/token"),
            },
            "kv".to_string(),
            "myapp/creds".to_string(),
            300,
        );
        let path = backend.secret_path("api-key").unwrap();
        assert_eq!(
            path,
            "https://vault.example.com:8200/v1/kv/data/myapp/creds/api-key"
        );
    }

    /// N11: Verify that Vault secret_path rejects path traversal attempts.
    #[test]
    fn test_vault_secret_path_traversal_rejected() {
        let backend = VaultBackend::new(
            "https://vault.example.com:8200".to_string(),
            VaultAuth::Token {
                token_path: PathBuf::from("/run/vault/token"),
            },
            "kv".to_string(),
            "myapp/creds".to_string(),
            300,
        );
        // Double-dot traversal
        assert!(backend.secret_path("../../../etc/passwd").is_err());
        // Forward slash
        assert!(backend.secret_path("foo/bar").is_err());
        // Backslash
        assert!(backend.secret_path("foo\\bar").is_err());
        // URL-encoded traversal
        assert!(backend.secret_path("%2e%2e").is_err());
        assert!(backend.secret_path("%2E%2E").is_err());
        assert!(backend.secret_path("foo%2fbar").is_err());
        assert!(backend.secret_path("foo%2Fbar").is_err());
        assert!(backend.secret_path("foo%5cbar").is_err());
        assert!(backend.secret_path("foo%5Cbar").is_err());
        // Valid name should work
        assert!(backend.secret_path("my-api-key").is_ok());
    }

    /// D-I1: Verify that LocalEncryptedBackend passes the raw signing key to
    /// CredentialStore::new, producing the same encryption key as a direct
    /// CredentialStore::new() call (no double derivation).
    #[test]
    fn test_local_backend_no_double_derivation() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join("creds.enc");
        let signing_key = b"test-signing-key-for-derivation";

        // Store a credential directly via CredentialStore
        let mut store =
            crate::credentials::CredentialStore::new(store_path.clone(), signing_key).unwrap();
        store.store(test_credential("my-key")).unwrap();
        store.save().unwrap();
        drop(store);

        // Load via LocalEncryptedBackend — should succeed because it uses the
        // same single HKDF derivation, not double derivation
        let backend = LocalEncryptedBackend::new(store_path.clone(), signing_key);
        let loaded = backend.load_all().expect(
            "D-I1: load_all should succeed — LocalEncryptedBackend must pass raw signing_key \
             to CredentialStore::new, not a pre-derived key (double derivation)",
        );
        assert_eq!(loaded.len(), 1, "should load 1 credential");
        assert!(loaded.contains_key("my-key"), "should contain 'my-key'");
    }

    // §3.4 G6: env-passthrough tests

    #[test]
    fn test_env_passthrough_reads_var() {
        // Set a test env var
        std::env::set_var("PUZZLED_TEST_CRED_G6", "test-secret-value");
        let backend = EnvPassthroughBackend::new("PUZZLED_TEST_CRED_G6".to_string());

        let creds = backend.load_all().unwrap();
        assert_eq!(creds.len(), 1);
        assert!(creds.contains_key("PUZZLED_TEST_CRED_G6"));

        // Cleanup
        std::env::remove_var("PUZZLED_TEST_CRED_G6");
    }

    #[test]
    fn test_env_passthrough_missing_var() {
        std::env::remove_var("PUZZLED_TEST_MISSING_VAR");
        let backend = EnvPassthroughBackend::new("PUZZLED_TEST_MISSING_VAR".to_string());

        let creds = backend.load_all().unwrap();
        assert!(creds.is_empty());
    }

    #[test]
    fn test_env_passthrough_is_read_only() {
        let backend = EnvPassthroughBackend::new("TEST".to_string());
        assert!(backend.store(&test_credential("x")).is_err());
        assert!(backend.remove("x").is_err());
    }

    #[test]
    fn test_env_passthrough_backend_name() {
        let backend = EnvPassthroughBackend::new("X".to_string());
        assert_eq!(backend.backend_name(), "env-passthrough");
    }

    // §3.4 G33: Argon2id KDF tests

    #[test]
    fn test_argon2id_encrypt_decrypt_roundtrip() {
        let plaintext = b"my-secret-api-key-12345";
        let passphrase = b"strong-passphrase";
        let name = "test-credential";

        let encrypted = encrypt_with_passphrase(name, plaintext, passphrase).unwrap();

        // Verify AGCR magic
        assert_eq!(&encrypted[0..4], AGCR_MAGIC);

        let decrypted = decrypt_with_passphrase(name, &encrypted, passphrase).unwrap();
        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn test_argon2id_wrong_passphrase_fails() {
        let encrypted = encrypt_with_passphrase("cred", b"secret", b"correct-passphrase").unwrap();

        let result = decrypt_with_passphrase("cred", &encrypted, b"wrong-passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn test_argon2id_aad_mismatch_fails() {
        let encrypted = encrypt_with_passphrase("original-name", b"secret", b"passphrase").unwrap();

        // Using wrong name as AAD should fail decryption
        let result = decrypt_with_passphrase("different-name", &encrypted, b"passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn test_argon2id_truncated_file_fails() {
        let result = decrypt_with_passphrase("x", &[0u8; 10], b"pass");
        assert!(result.is_err());
    }

    #[test]
    fn test_argon2id_bad_magic_fails() {
        let mut data = vec![0u8; 100];
        data[0..4].copy_from_slice(b"XXXX"); // wrong magic
        let result = decrypt_with_passphrase("x", &data, b"pass");
        assert!(result.is_err());
    }

    // §3.4 G32: Kernel keyring caching tests

    /// On non-Linux platforms, cache_derived_key_in_keyring returns Err.
    /// On Linux without keyring access, this also validates graceful error handling.
    #[test]
    fn test_keyring_cache_function_exists() {
        // Verify the functions are callable and have correct signatures.
        // On non-Linux, cache returns Err; on Linux without a session keyring
        // (e.g., some CI environments), it may also return Err — both are fine.
        let result = cache_derived_key_in_keyring("test-key", &[0u8; 32], 300);
        // We don't assert success because keyring may not be available in CI,
        // but we verify it doesn't panic.
        let _ = result;
    }

    #[test]
    fn test_keyring_lookup_returns_none_for_missing() {
        // Looking up a key that was never cached should return None (not panic).
        let result = lookup_derived_key_in_keyring("nonexistent-key-g32-test");
        assert!(
            result.is_none(),
            "lookup of non-existent key should return None"
        );
    }

    /// Round-trip test: cache a key, then look it up.
    /// Requires a Linux kernel with session keyring support.
    /// Skipped in CI environments without keyring access.
    #[test]
    #[ignore]
    fn test_keyring_cache_lookup_roundtrip() {
        let key_data = b"0123456789abcdef0123456789abcdef"; // 32-byte AES-256 key
        let name = "g32-roundtrip-test";
        let timeout_secs = 60;

        // Cache the key
        cache_derived_key_in_keyring(name, key_data, timeout_secs)
            .expect("cache_derived_key_in_keyring should succeed with session keyring");

        // Look it up
        let retrieved =
            lookup_derived_key_in_keyring(name).expect("lookup should find the key we just cached");

        assert_eq!(
            retrieved.as_slice(),
            key_data.as_slice(),
            "retrieved key should match cached key"
        );
    }

    /// Verify that non-Linux stubs return the expected values.
    #[test]
    #[cfg(not(target_os = "linux"))]
    fn test_keyring_non_linux_stubs() {
        let cache_result = cache_derived_key_in_keyring("x", &[0u8; 32], 60);
        assert!(cache_result.is_err(), "non-Linux cache should return Err");
        assert!(
            cache_result.unwrap_err().contains("Linux"),
            "error message should mention Linux"
        );

        let lookup_result = lookup_derived_key_in_keyring("x");
        assert!(
            lookup_result.is_none(),
            "non-Linux lookup should return None"
        );
    }
}
