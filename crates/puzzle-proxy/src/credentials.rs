// SPDX-License-Identifier: Apache-2.0
//! Credential store and phantom token manager for the agent proxy.
//!
//! Provides secure credential storage with AES-256-GCM encryption at rest,
//! domain-scoped credential injection, and phantom token issuance so that
//! agents never see real secrets — only surrogate tokens that the proxy
//! resolves at request time.
//!
//! PXH4: All credential operations are auditable via D-Bus signals.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use base64::Engine;
use chrono::Utc;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::RwLock;
use zeroize::{Zeroize, Zeroizing};

/// Errors returned by credential operations.
#[derive(Debug)]
pub enum CredentialError {
    /// Credential not found in store.
    NotFound(String),
    /// Encryption or decryption failure.
    Crypto(String),
    /// I/O error reading or writing the store file.
    Io(std::io::Error),
    /// Serialization error.
    Serialization(String),
    /// Backend or feature not yet implemented.
    NotImplemented(String),
    /// N11: Invalid credential name (e.g., path traversal attempt).
    InvalidName(String),
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CredentialError::NotFound(name) => write!(f, "credential not found: {name}"),
            CredentialError::Crypto(msg) => write!(f, "crypto error: {msg}"),
            CredentialError::Io(e) => write!(f, "I/O error: {e}"),
            CredentialError::Serialization(msg) => write!(f, "serialization error: {msg}"),
            CredentialError::NotImplemented(msg) => write!(f, "not implemented: {msg}"),
            CredentialError::InvalidName(msg) => write!(f, "invalid credential name: {msg}"),
        }
    }
}

impl std::error::Error for CredentialError {}

impl From<std::io::Error> for CredentialError {
    fn from(e: std::io::Error) -> Self {
        CredentialError::Io(e)
    }
}

/// Type of credential stored.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    /// Bearer token / API key.
    ApiKey,
    /// OAuth 2.0 bearer token.
    OAuthBearer,
    /// Username:password pair.
    BasicAuth,
    /// Custom header value.
    CustomHeader {
        /// Name of the header to set.
        header_name: String,
    },
    /// AWS Signature V4 (access_key_id + secret_access_key).
    AwsSigV4 {
        /// AWS region (e.g., "us-east-1").
        region: String,
        /// AWS service (e.g., "s3", "bedrock").
        service: String,
    },
}

/// How the credential is injected into outbound requests.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InjectionMethod {
    /// Set `Authorization: Bearer <value>`.
    BearerHeader,
    /// Set `Authorization: Basic <base64(value)>`.
    BasicHeader,
    /// Set a named header to the credential value.
    CustomHeader {
        /// Name of the header.
        header_name: String,
    },
    /// Inject the credential as a query parameter.
    QueryParameter {
        /// Name of the query parameter.
        param_name: String,
    },
    /// AWS SigV4 signing of the request.
    AwsSigV4,
}

/// A credential stored in the encrypted credential store.
/// §3.4: `value` is zeroized on drop to prevent credential leakage in memory.
/// D-M3: Custom Debug impl redacts `value` to prevent credential leakage in logs.
#[derive(Serialize, Deserialize)]
pub struct StoredCredential {
    /// Reference name (e.g., "anthropic-api-key").
    pub name: String,
    /// Type of credential.
    pub credential_type: CredentialType,
    /// The actual secret value. Skipped during serialization and deserialization of metadata.
    /// D-I7: Wrapped in `Zeroizing<String>` for structural zeroization on drop.
    /// N7: `skip` ensures a `value` field in JSON input is ignored during deserialization,
    /// preventing external JSON from injecting credential values into the struct.
    #[serde(skip)]
    pub value: Zeroizing<String>,
    /// Which agent profiles may use this credential.
    pub allowed_profiles: Vec<String>,
    /// Which domains to inject for (supports glob patterns like "*.anthropic.com").
    pub target_domains: Vec<String>,
    /// How to inject the credential into requests.
    pub injection: InjectionMethod,
    /// RFC 3339 expiration timestamp, if any.
    pub expires_at: Option<String>,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// RFC 3339 timestamp of last rotation, if any.
    pub rotated_at: Option<String>,
}

/// D-M3: Custom Debug impl that redacts the secret value to prevent credential
/// leakage in log output, debug assertions, or error messages.
impl fmt::Debug for StoredCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredCredential")
            .field("name", &self.name)
            .field("credential_type", &self.credential_type)
            .field("value", &"[REDACTED]")
            .field("allowed_profiles", &self.allowed_profiles)
            .field("target_domains", &self.target_domains)
            .field("injection", &self.injection)
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .field("rotated_at", &self.rotated_at)
            .finish()
    }
}

/// §3.4: Defense-in-depth zeroization on drop. The `Zeroizing<String>` wrapper
/// (D-I7) handles zeroization structurally, but we keep this manual impl as a
/// safety net.
impl Drop for StoredCredential {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl StoredCredential {
    /// Check whether this credential has expired.
    pub fn is_expired(&self) -> bool {
        match &self.expires_at {
            None => false,
            Some(ts) => match chrono::DateTime::parse_from_rfc3339(ts) {
                Ok(expiry) => Utc::now() > expiry,
                // H66: Fail-closed — treat unparseable expiry as expired
                Err(e) => {
                    tracing::warn!(
                        expires_at = %ts,
                        error = %e,
                        "H66: unparseable credential expiration — treating as expired (fail-closed)"
                    );
                    true
                }
            },
        }
    }

    /// Generate the HTTP header value based on the injection method.
    /// G4: Returns Zeroizing<String> so credential copies are zeroized on drop.
    pub fn to_auth_header_value(&self) -> Zeroizing<String> {
        match &self.injection {
            InjectionMethod::BearerHeader => Zeroizing::new(format!("Bearer {}", &*self.value)),
            InjectionMethod::BasicHeader => {
                // K46: Wrap intermediate base64 string in Zeroizing so it is
                // scrubbed from memory on drop, preventing credential leakage.
                let encoded =
                    Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(&*self.value));
                Zeroizing::new(format!("Basic {}", &*encoded))
            }
            InjectionMethod::CustomHeader { .. } => Zeroizing::new((*self.value).clone()),
            InjectionMethod::QueryParameter { .. } => Zeroizing::new((*self.value).clone()),
            InjectionMethod::AwsSigV4 => Zeroizing::new((*self.value).clone()), // SigV4 signing handled at request level
        }
    }

    /// Check if the given domain matches any of this credential's target domain patterns.
    pub fn matches_domain(&self, domain: &str) -> bool {
        self.target_domains
            .iter()
            .any(|pattern| domain_matches(domain, pattern))
    }

    /// Check if the given profile is allowed to use this credential.
    /// A profile entry of `"*"` matches all profiles.
    pub fn matches_profile(&self, profile: &str) -> bool {
        self.allowed_profiles
            .iter()
            .any(|p| p == "*" || p == profile)
    }
}

/// Credential metadata safe to expose via API/CLI — no secret value included.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CredentialMetadata {
    /// Reference name.
    pub name: String,
    /// Type of credential.
    pub credential_type: CredentialType,
    /// Which agent profiles may use this credential.
    pub allowed_profiles: Vec<String>,
    /// Which domains to inject for.
    pub target_domains: Vec<String>,
    /// How to inject the credential.
    pub injection: InjectionMethod,
    /// RFC 3339 expiration timestamp, if any.
    pub expires_at: Option<String>,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// RFC 3339 timestamp of last rotation, if any.
    pub rotated_at: Option<String>,
}

impl CredentialMetadata {
    /// Create metadata from a stored credential, stripping the secret value.
    pub fn from_credential(cred: &StoredCredential) -> Self {
        Self {
            name: cred.name.clone(),
            credential_type: cred.credential_type.clone(),
            allowed_profiles: cred.allowed_profiles.clone(),
            target_domains: cred.target_domains.clone(),
            injection: cred.injection.clone(),
            expires_at: cred.expires_at.clone(),
            created_at: cred.created_at.clone(),
            rotated_at: cred.rotated_at.clone(),
        }
    }
}

/// HKDF info string used when deriving the credential store encryption key.
const HKDF_INFO: &[u8] = b"puzzled-credential-store";

/// Encrypted credential store backed by AES-256-GCM.
pub struct CredentialStore {
    /// Credentials keyed by name.
    pub(crate) credentials: HashMap<String, StoredCredential>,
    /// Path to the encrypted store file on disk.
    store_path: PathBuf,
    /// D-M3: AES-256-GCM encryption key derived via HKDF from the signing key.
    /// Wrapped in `Zeroizing` for structural zeroization on drop.
    encryption_key: Zeroizing<[u8; 32]>,
}

/// §3.4: Defense-in-depth zeroization. `Zeroizing<[u8; 32]>` (D-M3) handles
/// this structurally, but we keep the manual impl as a safety net.
impl Drop for CredentialStore {
    fn drop(&mut self) {
        self.encryption_key.zeroize();
    }
}

impl CredentialStore {
    /// Look up a credential by name. Returns None if not found.
    pub fn get(&self, name: &str) -> Option<&StoredCredential> {
        self.credentials.get(name)
    }

    /// Create a new credential store.
    ///
    /// Derives the encryption key from `signing_key` via HKDF-SHA256. If the
    /// store file already exists on disk, its contents are decrypted and loaded.
    pub fn new(store_path: PathBuf, signing_key: &[u8]) -> Result<Self, CredentialError> {
        let encryption_key = Zeroizing::new(hkdf_sha256(signing_key, HKDF_INFO));
        let credentials = if store_path.exists() {
            Self::load(&store_path, &encryption_key)?
        } else {
            HashMap::new()
        };
        Ok(Self {
            credentials,
            store_path,
            encryption_key,
        })
    }

    /// §3.4 Gap 43: Load credentials from a pluggable backend into this store.
    /// Merges loaded credentials with any already present (backend wins on conflict).
    pub fn load_from_backend(
        &mut self,
        backend: &dyn crate::credential_backends::CredentialBackend,
    ) -> Result<usize, CredentialError> {
        let loaded = backend.load_all()?;
        let count = loaded.len();
        for (name, cred) in loaded {
            self.credentials.insert(name, cred);
        }
        if count > 0 {
            self.save()?;
        }
        Ok(count)
    }

    /// Add or update a credential and persist to disk.
    ///
    /// D-I3: Rejects credentials with `InjectionMethod::AwsSigV4` at store time
    /// rather than silently failing at request time.
    pub fn store(&mut self, credential: StoredCredential) -> Result<(), CredentialError> {
        if credential.injection == InjectionMethod::AwsSigV4 {
            return Err(CredentialError::Crypto(
                "AwsSigV4 injection is not yet implemented — use BearerHeader or CustomHeader"
                    .into(),
            ));
        }
        self.credentials.insert(credential.name.clone(), credential);
        self.save()
    }

    /// Remove a credential by name. Returns `true` if found and removed.
    pub fn remove(&mut self, name: &str) -> Result<bool, CredentialError> {
        let existed = self.credentials.remove(name).is_some();
        if existed {
            self.save()?;
        }
        Ok(existed)
    }

    /// Rotate a credential's value and update `rotated_at`.
    pub fn rotate(&mut self, name: &str, new_value: &str) -> Result<(), CredentialError> {
        let cred = self
            .credentials
            .get_mut(name)
            .ok_or_else(|| CredentialError::NotFound(name.to_string()))?;
        let old_value = std::mem::replace(&mut cred.value, Zeroizing::new(new_value.to_string()));
        drop(old_value); // §3.4: Zeroizing<String> zeroizes on drop
        cred.rotated_at = Some(Utc::now().to_rfc3339());
        self.save()
    }

    /// Look up a credential matching the given profile and domain.
    ///
    /// Returns the first non-expired credential whose `allowed_profiles`
    /// includes the profile (or `"*"`) and whose `target_domains` matches
    /// the domain.
    pub fn lookup(&self, profile: &str, domain: &str) -> Option<&StoredCredential> {
        self.credentials.values().find(|cred| {
            !cred.is_expired() && cred.matches_profile(profile) && cred.matches_domain(domain)
        })
    }

    /// List metadata for all stored credentials (no secret values).
    pub fn list(&self) -> Vec<CredentialMetadata> {
        self.credentials
            .values()
            .map(CredentialMetadata::from_credential)
            .collect()
    }

    /// Encrypt and write all credentials to disk.
    ///
    /// Format on disk: `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
    pub fn save(&self) -> Result<(), CredentialError> {
        // Serialize credentials with values included (skip_serializing is only
        // on the metadata path; we need a wrapper for the full serialization).
        let entries: Vec<CredentialEntry> = self
            .credentials
            .values()
            .map(|c| CredentialEntry {
                name: c.name.clone(),
                credential_type: c.credential_type.clone(),
                value: Zeroizing::new((*c.value).clone()),
                allowed_profiles: c.allowed_profiles.clone(),
                target_domains: c.target_domains.clone(),
                injection: c.injection.clone(),
                expires_at: c.expires_at.clone(),
                created_at: c.created_at.clone(),
                rotated_at: c.rotated_at.clone(),
            })
            .collect();

        let mut plaintext = serde_json::to_vec(&entries)
            .map_err(|e| CredentialError::Serialization(e.to_string()))?;

        let cipher = Aes256Gcm::new_from_slice(self.encryption_key.as_ref())
            .map_err(|e| CredentialError::Crypto(e.to_string()))?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| CredentialError::Crypto(e.to_string()))?;
        plaintext.zeroize(); // §3.4: Zeroize plaintext after encryption

        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);

        if let Some(parent) = self.store_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // §3.4: Atomic write via temp file + rename to prevent partial writes
        // G24: Use random suffix + create_new(true) (O_EXCL) to prevent symlink attacks
        let mut rand_bytes = [0u8; 4];
        getrandom::getrandom(&mut rand_bytes)
            .map_err(|e| CredentialError::Crypto(format!("G24: getrandom failed: {e}")))?;
        let rand_suffix = u32::from_le_bytes(rand_bytes);
        let tmp_path = self
            .store_path
            .with_extension(format!("tmp.{:08x}", rand_suffix));
        {
            use std::io::Write;
            #[cfg(unix)]
            use std::os::unix::fs::OpenOptionsExt;

            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            opts.mode(0o600);

            let mut file = opts.open(&tmp_path)?;
            file.write_all(&output)?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp_path, &self.store_path)?;
        Ok(())
    }

    /// Decrypt and load credentials from an encrypted store file.
    fn load(
        store_path: &Path,
        encryption_key: &[u8; 32],
    ) -> Result<HashMap<String, StoredCredential>, CredentialError> {
        let data = std::fs::read(store_path)?;
        if data.len() < 12 {
            return Err(CredentialError::Crypto(
                "store file too short for nonce".into(),
            ));
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(encryption_key)
            .map_err(|e| CredentialError::Crypto(e.to_string()))?;
        let mut plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| CredentialError::Crypto(e.to_string()))?;

        let entries: Vec<CredentialEntry> = serde_json::from_slice(&plaintext)
            .map_err(|e| CredentialError::Serialization(e.to_string()))?;
        plaintext.zeroize(); // §3.4: Zeroize decrypted plaintext after deserialization

        let mut map = HashMap::new();
        for entry in entries {
            let name = entry.name.clone();
            let cred = StoredCredential {
                name: entry.name.clone(),
                credential_type: entry.credential_type.clone(),
                value: Zeroizing::new((*entry.value).clone()),
                allowed_profiles: entry.allowed_profiles.clone(),
                target_domains: entry.target_domains.clone(),
                injection: entry.injection.clone(),
                expires_at: entry.expires_at.clone(),
                created_at: entry.created_at.clone(),
                rotated_at: entry.rotated_at.clone(),
            };
            map.insert(name, cred);
        }
        Ok(map)
    }
}

/// Internal serialization struct that includes the secret value.
/// `StoredCredential` has `skip_serializing` on `value`, so we use this
/// wrapper for the encrypted-at-rest format.
#[derive(Serialize, Deserialize)]
struct CredentialEntry {
    name: String,
    credential_type: CredentialType,
    /// D-I7: Wrapped in `Zeroizing<String>` for structural zeroization.
    value: Zeroizing<String>,
    allowed_profiles: Vec<String>,
    target_domains: Vec<String>,
    injection: InjectionMethod,
    expires_at: Option<String>,
    created_at: String,
    rotated_at: Option<String>,
}

/// §3.4: Defense-in-depth zeroization. `Zeroizing<String>` (D-I7) handles this
/// structurally, but we keep the manual impl as a safety net.
impl Drop for CredentialEntry {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// A phantom token issued to an agent in place of a real credential.
///
/// D-I7: All phantom tokens are revoked when the branch is destroyed (committed
/// or rolled back). The previous `expires_with_branch` field was dead code —
/// `revoke_branch()` always removed ALL tokens for the branch regardless of its
/// value, and `issue_for_branch()` always set it to `true`. Removing it
/// eliminates confusion and correctly reflects the security invariant: tokens
/// MUST NOT survive branch lifecycle.
#[derive(Debug, Clone)]
pub struct PhantomToken {
    /// The surrogate token the agent sees (e.g., "pt_puzzled_abcd1234_0a1b2c3d4e5f6789").
    pub surrogate: String,
    /// Name of the credential in the store that this token maps to.
    pub credential_ref: String,
    /// Branch this token is scoped to.
    pub branch_id: puzzled_types::BranchId,
}

/// Result of resolving a phantom token to real credential data.
pub struct ResolvedCredential {
    /// Name of the credential in the store.
    pub credential_name: String,
    /// Ready-to-use HTTP header value (e.g., "Bearer sk-...").
    /// G4: Uses Zeroizing<String> so credential copies are zeroized on drop.
    pub auth_header_value: Zeroizing<String>,
    /// How the credential should be injected.
    pub injection: InjectionMethod,
    /// Domains this credential targets.
    pub target_domains: Vec<String>,
    /// Profiles allowed to use this credential (for handler-side verification).
    pub allowed_profiles: Vec<String>,
}

/// §3.4: Zeroize the real credential value on drop.
/// G4: auth_header_value is Zeroizing<String> and self-zeroizes.
/// This Drop impl is retained for defense-in-depth.
impl Drop for ResolvedCredential {
    fn drop(&mut self) {
        self.auth_header_value.zeroize();
    }
}

/// §3.4: Custom Debug impl to prevent credential leakage in logs/debug output.
impl fmt::Debug for ResolvedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedCredential")
            .field("credential_name", &self.credential_name)
            .field("auth_header_value", &"[REDACTED]")
            .field("injection", &self.injection)
            .field("target_domains", &self.target_domains)
            .field("allowed_profiles", &self.allowed_profiles)
            .finish()
    }
}

/// M-4: Credential mapping with named fields for `issue_for_branch()`.
/// Replaces the raw `(String, String, String)` tuple for type safety.
#[derive(Debug, Clone)]
pub struct CredentialMapping {
    /// Target domain for this credential (e.g., "api.github.com").
    pub domain: String,
    /// Reference to the credential in the store (credential name).
    pub credential_ref: String,
    /// Environment variable to expose the phantom token (e.g., "GITHUB_TOKEN").
    pub env_var: String,
    /// Whether this credential is required for branch creation (default: true).
    /// When false, missing credentials are skipped with a warning.
    pub required: bool,
}

/// Manages phantom tokens — surrogate values issued to agents so that real
/// secrets never enter the sandbox.
pub struct PhantomTokenManager {
    /// Phantom tokens keyed by surrogate value.
    tokens: HashMap<String, PhantomToken>,
    /// Reference to the credential store for metadata and disk persistence.
    credential_store: Arc<RwLock<CredentialStore>>,
    /// §3.4 T3.2: mmap-backed secure store for runtime credential values.
    /// When present, real credential values are stored here (mlock'd, guard pages,
    /// MADV_DONTDUMP) rather than in the HashMap-based CredentialStore.
    secure_store: Option<crate::secure_memory::SecureCredentialStore>,
    /// Prefix for generated surrogate tokens.
    phantom_prefix: String,
    /// Number of random bytes for surrogate token entropy (default: 16 per PRD §3.4).
    phantom_entropy_bytes: usize,
}

impl fmt::Debug for PhantomTokenManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PhantomTokenManager")
            .field("token_count", &self.tokens.len())
            .field("phantom_prefix", &self.phantom_prefix)
            .field("phantom_entropy_bytes", &self.phantom_entropy_bytes)
            .finish()
    }
}

impl PhantomTokenManager {
    /// Create a new phantom token manager.
    pub fn new(
        credential_store: Arc<RwLock<CredentialStore>>,
        phantom_prefix: String,
        phantom_entropy_bytes: usize,
    ) -> Self {
        Self {
            tokens: HashMap::new(),
            credential_store,
            secure_store: None,
            phantom_prefix,
            phantom_entropy_bytes,
        }
    }

    /// §3.4 T3.2: Attach a secure memory store for runtime credential values.
    /// When set, `issue_for_branch()` copies credential values into this mmap-backed
    /// region (mlock'd, MADV_DONTDUMP, guard pages) and `resolve()` reads from it.
    pub fn set_secure_store(&mut self, store: crate::secure_memory::SecureCredentialStore) {
        self.secure_store = Some(store);
    }

    /// Issue phantom tokens for a branch.
    ///
    /// M-4: `mappings` is a slice of `CredentialMapping` structs with named fields
    /// including `required` (default true). When `required` is false and a credential
    /// is not found, it is skipped with a warning rather than failing branch creation.
    ///
    /// Returns a list of `(env_var, surrogate_value)` pairs to inject into
    /// the agent's environment.
    pub async fn issue_for_branch(
        &mut self,
        branch_id: &puzzled_types::BranchId,
        profile: &str,
        mappings: &[CredentialMapping],
    ) -> Result<Vec<(String, String)>, CredentialError> {
        let mut result = Vec::new();
        let mut errors: Vec<String> = Vec::new();
        let store = self.credential_store.read().await;
        for mapping in mappings {
            let credential_ref = &mapping.credential_ref;
            let env_var = &mapping.env_var;
            // §3.4 H4: Verify the credential exists in the store before issuing
            // a phantom token. Without this check, a phantom token would be
            // issued for a non-existent credential, causing confusing 401
            // failures at runtime when the proxy tries to resolve it.
            let cred = match store.credentials.get(credential_ref) {
                Some(cred) => cred,
                None => {
                    // M-4/§3.4.5: Check the `required` field to determine behavior.
                    if mapping.required {
                        tracing::error!(
                            branch = %branch_id,
                            credential = %credential_ref,
                            "M-4/§3.4 H4: required credential not found in store — failing branch creation. \
                             Ensure the credential is provisioned via `puzzlectl credential add`."
                        );
                        errors.push(format!(
                            "credential '{}' not found in store",
                            credential_ref
                        ));
                    } else {
                        tracing::warn!(
                            branch = %branch_id,
                            credential = %credential_ref,
                            "M-4/§3.4.5: optional credential not found in store — skipping. \
                             Proxy requests for this credential will return 503."
                        );
                    }
                    continue;
                }
            };

            // §3.4: Verify the credential's allowed_profiles includes this branch's profile
            if !cred.matches_profile(profile) {
                tracing::warn!(
                    branch = %branch_id,
                    credential = %credential_ref,
                    profile = %profile,
                    "§3.4: credential not authorized for profile — skipping phantom token issuance"
                );
                continue;
            }

            let surrogate = match generate_phantom_token(
                &self.phantom_prefix,
                self.phantom_entropy_bytes,
            ) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(branch = %branch_id, error = %e, "K48: failed to generate surrogate token");
                    errors.push(format!(
                        "failed to generate phantom token for '{}': {}",
                        credential_ref, e
                    ));
                    continue;
                }
            };
            let token = PhantomToken {
                surrogate: surrogate.clone(),
                credential_ref: credential_ref.clone(),
                branch_id: branch_id.clone(),
            };
            // §3.4 T3.2: Copy credential value into mmap-backed secure store
            // so the runtime resolution path reads from mlock'd memory.
            if let Some(ref mut secure) = self.secure_store {
                if let Err(e) = secure.store(&surrogate, cred.value.as_bytes()) {
                    tracing::error!(
                        branch = %branch_id,
                        credential = %credential_ref,
                        error = %e,
                        "§3.4 T3.2: failed to store credential in secure memory"
                    );
                    errors.push(format!(
                        "secure memory store failed for '{}': {}",
                        credential_ref, e
                    ));
                    continue;
                }
            }
            self.tokens.insert(surrogate.clone(), token);
            result.push((env_var.clone(), surrogate));
        }

        // M-1/§3.4.5: If any required credentials failed, return an error so
        // branch creation fails cleanly rather than starting an agent without
        // its required credentials.
        if !errors.is_empty() {
            return Err(CredentialError::Crypto(format!(
                "required credential(s) unavailable: {}",
                errors.join("; ")
            )));
        }

        Ok(result)
    }

    /// Resolve a surrogate token to the real credential data.
    ///
    /// Returns `None` if the surrogate is unknown, the token's branch doesn't
    /// match the requesting branch, or the referenced credential no longer
    /// exists / has expired.
    pub async fn resolve(
        &self,
        surrogate: &str,
        requesting_branch: Option<&puzzled_types::BranchId>,
    ) -> Option<ResolvedCredential> {
        let token = self.tokens.get(surrogate)?;
        // §3.4: Verify the token belongs to the requesting branch (cross-branch isolation)
        if let Some(req_branch) = requesting_branch {
            if token.branch_id != *req_branch {
                return None;
            }
        }
        let store = self.credential_store.read().await;
        let cred = store.credentials.get(&token.credential_ref)?;
        if cred.is_expired() {
            return None;
        }

        // §3.4 T3.2: Prefer the mmap-backed secure store for the credential value.
        // The secure store holds values in mlock'd memory with guard pages and
        // MADV_DONTDUMP, protecting against swap/core dump leakage. Fall back to
        // the CredentialStore's heap-based Zeroizing<String> if no secure store.
        let auth_header_value = if let Some(ref secure) = self.secure_store {
            if let Some(value_bytes) = secure.resolve(surrogate) {
                // Reconstruct the formatted header value from secure memory bytes
                let raw_value = Zeroizing::new(String::from_utf8_lossy(value_bytes).into_owned());
                match &cred.injection {
                    InjectionMethod::BearerHeader => {
                        Zeroizing::new(format!("Bearer {}", &*raw_value))
                    }
                    InjectionMethod::BasicHeader => {
                        let encoded = Zeroizing::new(
                            base64::engine::general_purpose::STANDARD.encode(&*raw_value),
                        );
                        Zeroizing::new(format!("Basic {}", &*encoded))
                    }
                    _ => raw_value,
                }
            } else {
                // Surrogate not in secure store — fall back to CredentialStore
                cred.to_auth_header_value()
            }
        } else {
            cred.to_auth_header_value()
        };

        Some(ResolvedCredential {
            credential_name: cred.name.clone(),
            auth_header_value,
            injection: cred.injection.clone(),
            target_domains: cred.target_domains.clone(),
            allowed_profiles: cred.allowed_profiles.clone(),
        })
    }

    /// Revoke all phantom tokens issued for a branch.
    /// §3.4: Called when a branch is committed or rolled back so that
    /// phantom tokens cannot be reused.
    pub fn revoke_branch(&mut self, branch_id: &puzzled_types::BranchId) {
        // §3.4 T3.2: Remove credential values from secure store (zeroizes slots)
        if let Some(ref mut secure) = self.secure_store {
            let surrogates_to_remove: Vec<String> = self
                .tokens
                .iter()
                .filter(|(_, t)| t.branch_id == *branch_id)
                .map(|(surrogate, _)| surrogate.clone())
                .collect();
            for surrogate in &surrogates_to_remove {
                let _ = secure.remove(surrogate);
            }
        }
        self.tokens.retain(|_, token| token.branch_id != *branch_id);
    }

    /// Check whether a value looks like a phantom token (starts with the prefix).
    // Q7: The phantom_prefix is a fixed string ("pt_puzzled"), not cryptographically
    // unpredictable. This is acceptable because a failed phantom token lookup (i.e., a
    // guessed token with the right prefix but no matching entry) returns 401 Unauthorized
    // (fail-closed). The prefix is only used for fast rejection of non-phantom values;
    // actual authentication requires an exact match in the token map.
    pub fn is_phantom_token(&self, value: &str) -> bool {
        value.starts_with(&self.phantom_prefix)
    }

    /// §3.4 G36: Get the phantom token prefix for scanning headers.
    pub fn phantom_prefix(&self) -> &str {
        &self.phantom_prefix
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Glob-style domain matching.
///
/// Supports patterns like `"*.anthropic.com"` (matches `"api.anthropic.com"`)
/// and exact matches. Only a leading `*.` wildcard is supported.
// V19: Intentional strictness — *.example.com does NOT match bare example.com for
// credential injection (defense-in-depth). The domain allowlist is more permissive.
pub fn domain_matches(domain: &str, pattern: &str) -> bool {
    let domain = domain.to_lowercase();
    let pattern = pattern.to_lowercase();

    if domain == pattern {
        return true;
    }

    if let Some(suffix) = pattern.strip_prefix("*.") {
        // "*.example.com" should match "sub.example.com" and "a.b.example.com"
        // but NOT "example.com" itself.
        domain.ends_with(&format!(".{suffix}"))
    } else {
        false
    }
}

/// Derive a 32-byte key from input keying material via HKDF-SHA256.
/// §3.4: Uses a fixed application-specific salt per NIST SP 800-56C Rev. 2.
pub fn hkdf_sha256(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    // Fixed salt for domain separation — ensures HKDF extract produces
    // a strong PRK even when the IKM has low entropy.
    let salt = b"puzzlepod-hkdf-v1-salt";
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    // K47: This expect is safe because HKDF-SHA256 expand can only fail when
    // the requested output length exceeds 255 * HashLen (= 255 * 32 = 8160 bytes).
    // We request exactly 32 bytes (== HashLen), so expand is infallible here.
    hk.expand(info, &mut okm)
        .expect("HKDF-SHA256 expand is infallible for 32-byte output (<= 255*HashLen)");
    okm
}

/// Generate a random phantom token string (PRD §3.4.5).
///
/// Format: `<prefix>_<2*entropy_bytes random hex chars>`.
/// M-5: Branch ID is NOT embedded in the token — tokens are opaque.
/// The branch association is tracked in the PhantomTokenManager's internal mapping.
/// `entropy_bytes` controls the number of random bytes (clamped to [8, 64]).
// K48: Returns Result instead of panicking on getrandom failure.
pub fn generate_phantom_token(
    prefix: &str,
    entropy_bytes: usize,
) -> Result<String, CredentialError> {
    // Clamp to reasonable range: at least 8 bytes (64 bits), at most 64 bytes (512 bits)
    let n = entropy_bytes.clamp(8, 64);
    let mut rand_bytes = vec![0u8; n];
    getrandom::getrandom(&mut rand_bytes)
        .map_err(|e| CredentialError::Crypto(format!("K48: getrandom failed: {e}")))?;
    let hex: String = rand_bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("{prefix}_{hex}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a test credential.
    fn test_credential(name: &str) -> StoredCredential {
        StoredCredential {
            name: name.to_string(),
            credential_type: CredentialType::ApiKey,
            value: Zeroizing::new("sk-test-secret-key-12345".to_string()),
            allowed_profiles: vec!["standard".to_string(), "privileged".to_string()],
            target_domains: vec!["api.anthropic.com".to_string(), "*.openai.com".to_string()],
            injection: InjectionMethod::BearerHeader,
            expires_at: None,
            created_at: Utc::now().to_rfc3339(),
            rotated_at: None,
        }
    }

    /// N7: Verify that deserializing JSON with a `value` field does NOT populate the value.
    #[test]
    fn test_stored_credential_skip_deserializing_value() {
        let json = r#"{
            "name": "test-key",
            "credential_type": "api_key",
            "value": "SHOULD-NOT-APPEAR",
            "allowed_profiles": ["standard"],
            "target_domains": ["api.example.com"],
            "injection": "bearer_header",
            "expires_at": null,
            "created_at": "2025-01-01T00:00:00Z",
            "rotated_at": null
        }"#;
        let cred: StoredCredential = serde_json::from_str(json).unwrap();
        assert!(
            cred.value.is_empty(),
            "value field should be empty after deserialization, got: '{}'",
            *cred.value
        );
    }

    #[test]
    fn test_credential_store_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join("credentials.enc");
        let signing_key = b"test-signing-key-for-hkdf";

        // Store a credential and save.
        {
            let mut store = CredentialStore::new(store_path.clone(), signing_key).unwrap();
            store.store(test_credential("anthropic-key")).unwrap();
        }

        // Reload from disk and verify.
        {
            let store = CredentialStore::new(store_path, signing_key).unwrap();
            let cred = store.lookup("standard", "api.anthropic.com");
            assert!(cred.is_some());
            let cred = cred.unwrap();
            assert_eq!(cred.name, "anthropic-key");
            assert_eq!(*cred.value, "sk-test-secret-key-12345");
        }
    }

    #[test]
    fn test_credential_lookup_by_profile_and_domain() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join("credentials.enc");
        let mut store = CredentialStore::new(store_path, b"key").unwrap();
        store.store(test_credential("key1")).unwrap();

        // Matching profile and domain.
        assert!(store.lookup("standard", "api.anthropic.com").is_some());

        // Non-matching profile.
        assert!(store.lookup("restricted", "api.anthropic.com").is_none());

        // Non-matching domain.
        assert!(store.lookup("standard", "example.com").is_none());
    }

    #[test]
    fn test_credential_domain_glob_matching() {
        let cred = test_credential("test");
        // Exact match.
        assert!(cred.matches_domain("api.anthropic.com"));
        // Glob match.
        assert!(cred.matches_domain("api.openai.com"));
        assert!(cred.matches_domain("beta.openai.com"));
        // No match.
        assert!(!cred.matches_domain("google.com"));
        // Glob should not match the bare domain.
        assert!(!cred.matches_domain("openai.com"));
    }

    #[test]
    fn test_credential_profile_wildcard() {
        let mut cred = test_credential("test");
        cred.allowed_profiles = vec!["*".to_string()];

        assert!(cred.matches_profile("standard"));
        assert!(cred.matches_profile("restricted"));
        assert!(cred.matches_profile("anything-at-all"));
    }

    #[test]
    fn test_credential_expiration() {
        let mut cred = test_credential("test");

        // No expiry — not expired.
        assert!(!cred.is_expired());

        // Future expiry — not expired.
        cred.expires_at = Some("2099-12-31T23:59:59Z".to_string());
        assert!(!cred.is_expired());

        // Past expiry — expired.
        cred.expires_at = Some("2020-01-01T00:00:00Z".to_string());
        assert!(cred.is_expired());
    }

    #[tokio::test]
    async fn test_phantom_token_issue_and_resolve() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join("credentials.enc");
        let mut store = CredentialStore::new(store_path, b"key").unwrap();
        store.store(test_credential("my-key")).unwrap();

        let store = Arc::new(RwLock::new(store));
        let mut mgr = PhantomTokenManager::new(store, "pt_puzzled".to_string(), 16);

        let mappings = vec![CredentialMapping {
            domain: "api.anthropic.com".to_string(),
            credential_ref: "my-key".to_string(),
            env_var: "ANTHROPIC_API_KEY".to_string(),
            required: true,
        }];

        let bid = puzzled_types::BranchId::from("branch-001".to_string());
        let issued = mgr
            .issue_for_branch(&bid, "standard", &mappings)
            .await
            .expect("issue_for_branch should succeed");
        assert_eq!(issued.len(), 1);
        assert_eq!(issued[0].0, "ANTHROPIC_API_KEY");
        assert!(issued[0].1.starts_with("pt_puzzled_"));

        let resolved = mgr.resolve(&issued[0].1, None).await;
        assert!(resolved.is_some());
        let resolved = resolved.unwrap();
        assert_eq!(resolved.credential_name, "my-key");
        assert!(resolved.auth_header_value.starts_with("Bearer "));
    }

    #[tokio::test]
    async fn test_phantom_token_revoke_branch() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join("credentials.enc");
        let mut store = CredentialStore::new(store_path, b"key").unwrap();
        store.store(test_credential("my-key")).unwrap();

        let store = Arc::new(RwLock::new(store));
        let mut mgr = PhantomTokenManager::new(store, "pt_puzzled".to_string(), 16);

        let mappings = vec![CredentialMapping {
            domain: "api.anthropic.com".to_string(),
            credential_ref: "my-key".to_string(),
            env_var: "KEY".to_string(),
            required: true,
        }];

        let bid = puzzled_types::BranchId::from("branch-002".to_string());
        let issued = mgr
            .issue_for_branch(&bid, "standard", &mappings)
            .await
            .expect("issue_for_branch should succeed");
        let surrogate = issued[0].1.clone();

        // Should resolve before revocation.
        assert!(mgr.resolve(&surrogate, None).await.is_some());

        // Revoke and verify gone.
        mgr.revoke_branch(&bid);
        assert!(mgr.resolve(&surrogate, None).await.is_none());
    }

    #[test]
    fn test_phantom_token_is_phantom() {
        let store = Arc::new(RwLock::new(
            CredentialStore::new(PathBuf::from("/tmp/nonexistent-cred-store-test"), b"key")
                .unwrap(),
        ));
        let mgr = PhantomTokenManager::new(store, "pt_puzzled".to_string(), 16);

        assert!(mgr.is_phantom_token("pt_puzzled_abc_1234"));
        assert!(mgr.is_phantom_token("pt_puzzled_"));
        assert!(!mgr.is_phantom_token("sk-real-key-123"));
        assert!(!mgr.is_phantom_token(""));
    }

    #[test]
    fn test_credential_metadata_no_value() {
        let cred = test_credential("secret-key");
        let meta = CredentialMetadata::from_credential(&cred);

        assert_eq!(meta.name, "secret-key");
        assert_eq!(meta.credential_type, CredentialType::ApiKey);
        assert_eq!(meta.allowed_profiles, cred.allowed_profiles);
        assert_eq!(meta.target_domains, cred.target_domains);

        // Metadata serialized to JSON should not contain the value.
        let json = serde_json::to_string(&meta).unwrap();
        assert!(!json.contains("sk-test-secret-key-12345"));
    }

    #[test]
    fn test_auth_header_bearer() {
        let cred = StoredCredential {
            name: "bearer-test".to_string(),
            credential_type: CredentialType::ApiKey,
            value: Zeroizing::new("sk-12345".to_string()),
            allowed_profiles: vec!["*".to_string()],
            target_domains: vec!["example.com".to_string()],
            injection: InjectionMethod::BearerHeader,
            expires_at: None,
            created_at: Utc::now().to_rfc3339(),
            rotated_at: None,
        };
        assert_eq!(&*cred.to_auth_header_value(), "Bearer sk-12345");
    }

    #[test]
    fn test_auth_header_basic() {
        let cred = StoredCredential {
            name: "basic-test".to_string(),
            credential_type: CredentialType::BasicAuth,
            value: Zeroizing::new("user:password".to_string()),
            allowed_profiles: vec!["*".to_string()],
            target_domains: vec!["example.com".to_string()],
            injection: InjectionMethod::BasicHeader,
            expires_at: None,
            created_at: Utc::now().to_rfc3339(),
            rotated_at: None,
        };
        let header = cred.to_auth_header_value();
        assert!(header.starts_with("Basic "));
        let decoded_bytes = base64::engine::general_purpose::STANDARD
            .decode(header.strip_prefix("Basic ").unwrap())
            .unwrap();
        assert_eq!(String::from_utf8(decoded_bytes).unwrap(), "user:password");
    }

    #[test]
    fn test_auth_header_custom() {
        let cred = StoredCredential {
            name: "custom-test".to_string(),
            credential_type: CredentialType::CustomHeader {
                header_name: "X-Api-Key".to_string(),
            },
            value: Zeroizing::new("my-raw-key".to_string()),
            allowed_profiles: vec!["*".to_string()],
            target_domains: vec!["example.com".to_string()],
            injection: InjectionMethod::CustomHeader {
                header_name: "X-Api-Key".to_string(),
            },
            expires_at: None,
            created_at: Utc::now().to_rfc3339(),
            rotated_at: None,
        };
        assert_eq!(&*cred.to_auth_header_value(), "my-raw-key");
    }

    #[test]
    fn test_domain_matches_exact() {
        assert!(domain_matches("api.anthropic.com", "api.anthropic.com"));
        assert!(domain_matches("API.Anthropic.COM", "api.anthropic.com"));
        assert!(!domain_matches("api.anthropic.com", "anthropic.com"));
    }

    #[test]
    fn test_domain_matches_wildcard() {
        assert!(domain_matches("api.openai.com", "*.openai.com"));
        assert!(domain_matches("beta.openai.com", "*.openai.com"));
        assert!(domain_matches("a.b.openai.com", "*.openai.com"));
        // Bare domain should NOT match a wildcard pattern.
        assert!(!domain_matches("openai.com", "*.openai.com"));
        // Different domain entirely.
        assert!(!domain_matches("api.anthropic.com", "*.openai.com"));
    }

    /// D-I7: `revoke_branch()` removes ALL tokens for the branch unconditionally.
    /// The previous `expires_with_branch` field was dead code and has been removed.
    #[tokio::test]
    async fn test_revoke_branch_removes_all_tokens() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join("credentials.enc");
        let mut store = CredentialStore::new(store_path, b"key").unwrap();
        store.store(test_credential("my-key")).unwrap();

        let store = Arc::new(RwLock::new(store));
        let mut mgr = PhantomTokenManager::new(store, "pt_puzzled".to_string(), 16);

        let mappings = vec![CredentialMapping {
            domain: "api.anthropic.com".to_string(),
            credential_ref: "my-key".to_string(),
            env_var: "KEY".to_string(),
            required: true,
        }];

        let bid = puzzled_types::BranchId::from("branch-x".to_string());
        let issued = mgr
            .issue_for_branch(&bid, "standard", &mappings)
            .await
            .expect("issue_for_branch should succeed");
        let surrogate_first = issued[0].1.clone();

        // Manually insert a second token for the same branch
        let second_surrogate = generate_phantom_token("pt_puzzled", 16).unwrap();
        mgr.tokens.insert(
            second_surrogate.clone(),
            PhantomToken {
                surrogate: second_surrogate.clone(),
                credential_ref: "my-key".to_string(),
                branch_id: bid.clone(),
            },
        );

        // Both should resolve before revocation
        assert!(mgr.resolve(&surrogate_first, None).await.is_some());
        assert!(mgr.resolve(&second_surrogate, None).await.is_some());

        // revoke_branch removes ALL tokens for the branch
        mgr.revoke_branch(&bid);
        assert!(mgr.resolve(&surrogate_first, None).await.is_none());
        assert!(mgr.resolve(&second_surrogate, None).await.is_none());
    }

    /// D-M3: StoredCredential Debug impl must redact the secret value.
    #[test]
    fn test_stored_credential_debug_redacts_value() {
        let cred = test_credential("secret-api-key");
        let debug_output = format!("{:?}", cred);

        // The real secret value must NOT appear in debug output
        assert!(
            !debug_output.contains("sk-test-secret-key-12345"),
            "D-M3: Debug output must not contain the real credential value, got: {debug_output}"
        );

        // The redaction marker should appear
        assert!(
            debug_output.contains("[REDACTED]"),
            "D-M3: Debug output should contain [REDACTED], got: {debug_output}"
        );

        // Other fields should still be present
        assert!(
            debug_output.contains("secret-api-key"),
            "D-M3: Debug output should contain the credential name"
        );
    }

    #[test]
    fn test_hkdf_deterministic() {
        let key1 = hkdf_sha256(b"same-input", b"same-info");
        let key2 = hkdf_sha256(b"same-input", b"same-info");
        assert_eq!(key1, key2);

        // Different input should produce different key.
        let key3 = hkdf_sha256(b"different-input", b"same-info");
        assert_ne!(key1, key3);

        // Different info should produce different key.
        let key4 = hkdf_sha256(b"same-input", b"different-info");
        assert_ne!(key1, key4);
    }

    /// D-I3: Storing a credential with AwsSigV4 injection should fail at store time.
    #[test]
    fn test_store_rejects_aws_sigv4_injection() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join("credentials.enc");
        let mut store = CredentialStore::new(store_path, b"key").unwrap();

        let cred = StoredCredential {
            name: "aws-cred".to_string(),
            credential_type: CredentialType::AwsSigV4 {
                region: "us-east-1".to_string(),
                service: "bedrock".to_string(),
            },
            value: Zeroizing::new("AKIAIOSFODNN7EXAMPLE:secret".to_string()),
            allowed_profiles: vec!["*".to_string()],
            target_domains: vec!["*.amazonaws.com".to_string()],
            injection: InjectionMethod::AwsSigV4,
            expires_at: None,
            created_at: Utc::now().to_rfc3339(),
            rotated_at: None,
        };

        let result = store.store(cred);
        assert!(
            result.is_err(),
            "D-I3: AwsSigV4 injection should be rejected at store time"
        );
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("AwsSigV4 injection is not yet implemented"),
            "D-I3: error message should mention AwsSigV4, got: {err_msg}"
        );
    }

    /// G4: ResolvedCredential.auth_header_value must use Zeroizing<String>
    /// so credential copies are zeroized on drop.
    #[test]
    fn test_g4_resolved_credential_zeroizing() {
        let source = include_str!("credentials.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        assert!(
            prod_source.contains("auth_header_value: Zeroizing<String>"),
            "G4: ResolvedCredential.auth_header_value must be Zeroizing<String>, \
             not bare String, so credential copies are zeroized on drop"
        );
    }

    /// H66: Unparseable credential expiration must be treated as expired (fail-closed).
    #[test]
    fn test_h66_unparseable_expiry_treated_as_expired() {
        let cred = StoredCredential {
            name: "test-cred".to_string(),
            credential_type: CredentialType::ApiKey,
            value: Zeroizing::new("secret".to_string()),
            injection: InjectionMethod::BearerHeader,
            target_domains: vec!["example.com".to_string()],
            allowed_profiles: vec!["*".to_string()],
            expires_at: Some("not-a-valid-date".to_string()),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            rotated_at: None,
        };
        assert!(
            cred.is_expired(),
            "H66: unparseable expiry string must be treated as expired (fail-closed)"
        );
    }

    /// H66: Valid RFC3339 expiry in the past should be expired.
    #[test]
    fn test_h66_past_expiry_is_expired() {
        let cred = StoredCredential {
            name: "test-cred".to_string(),
            credential_type: CredentialType::ApiKey,
            value: Zeroizing::new("secret".to_string()),
            injection: InjectionMethod::BearerHeader,
            target_domains: vec!["example.com".to_string()],
            allowed_profiles: vec!["*".to_string()],
            expires_at: Some("2020-01-01T00:00:00Z".to_string()),
            created_at: "2019-01-01T00:00:00Z".to_string(),
            rotated_at: None,
        };
        assert!(
            cred.is_expired(),
            "H66: credential with past expiry should be expired"
        );
    }

    /// H66: No expiry means not expired.
    #[test]
    fn test_h66_no_expiry_not_expired() {
        let cred = StoredCredential {
            name: "test-cred".to_string(),
            credential_type: CredentialType::ApiKey,
            value: Zeroizing::new("secret".to_string()),
            injection: InjectionMethod::BearerHeader,
            target_domains: vec!["example.com".to_string()],
            allowed_profiles: vec!["*".to_string()],
            expires_at: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
            rotated_at: None,
        };
        assert!(
            !cred.is_expired(),
            "H66: credential with no expiry should not be expired"
        );
    }

    /// G24: Credential temp file must use create_new(true) or random suffix
    /// to prevent symlink attacks on predictable .tmp paths.
    #[test]
    fn test_g24_credential_temp_file_unpredictable() {
        let source = include_str!("credentials.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        assert!(
            prod_source.contains("create_new(true)"),
            "G24: Credential temp file must use create_new(true) (O_EXCL) \
             to prevent symlink attacks on predictable temp file paths"
        );
    }

    // -----------------------------------------------------------------------
    // K46: Non-zeroized base64 intermediate in BasicHeader
    // -----------------------------------------------------------------------

    #[test]
    fn k46_basic_header_wraps_encoded_in_zeroizing() {
        let source = include_str!("credentials.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // Find the BasicHeader branch
        let basic_start = prod_source
            .find("InjectionMethod::BasicHeader =>")
            .expect("BasicHeader branch must exist");
        let basic_section = &prod_source[basic_start..basic_start + 400];

        assert!(
            basic_section.contains("Zeroizing::new(base64::"),
            "K46: BasicHeader must wrap base64-encoded intermediate in Zeroizing"
        );
    }

    // -----------------------------------------------------------------------
    // K47: HKDF expect is documented as safe
    // -----------------------------------------------------------------------

    #[test]
    fn k47_hkdf_expand_expect_documented() {
        let source = include_str!("credentials.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // Find the hkdf_sha256 function
        let hkdf_start = prod_source
            .find("fn hkdf_sha256")
            .expect("hkdf_sha256 function must exist");
        let hkdf_end = (hkdf_start + 900).min(prod_source.len());
        let hkdf_section = &prod_source[hkdf_start..hkdf_end];

        // K47: Must have a comment explaining why the expect is safe
        assert!(
            hkdf_section.contains("K47"),
            "K47: hkdf_sha256 must have a K47 comment documenting safety of expect"
        );
        assert!(
            hkdf_section.contains("infallible") || hkdf_section.contains("cannot fail"),
            "K47: hkdf_sha256 must document that expand is infallible for the requested length"
        );
    }

    // -----------------------------------------------------------------------
    // K48: getrandom must not use expect in generate_phantom_token
    // -----------------------------------------------------------------------

    #[test]
    fn k48_generate_phantom_token_no_expect_on_getrandom() {
        let source = include_str!("credentials.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // Find the generate_phantom_token function (L-1: renamed from generate_surrogate)
        let fn_start = prod_source
            .find("fn generate_phantom_token")
            .expect("generate_phantom_token function must exist");
        // Limit to next function boundary
        let fn_section = &prod_source[fn_start..fn_start + 500];

        assert!(
            !fn_section.contains(".expect("),
            "K48: generate_phantom_token must not use .expect() — use map_err instead"
        );
        assert!(
            fn_section.contains("Result<String"),
            "K48: generate_phantom_token must return Result"
        );
    }
}
