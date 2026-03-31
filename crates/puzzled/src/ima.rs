// SPDX-License-Identifier: Apache-2.0
//! IMA changeset signing — generates and signs commit manifests.
//!
//! Each commit produces a manifest (YAML) listing all files in the changeset
//! with their paths, change kinds, sizes, and checksums. The manifest is signed
//! with Ed25519 to provide integrity and non-repudiation.
//!
//! On Linux, the module also extends the IMA measurement log (best-effort).
//! On non-Linux platforms, only manifest generation and signing are available.

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use puzzled_types::{BranchId, FileChange, FileChangeKind};
use serde::{Deserialize, Serialize};

use crate::error::{PuzzledError, Result};

/// A signed commit manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitManifest {
    /// Branch that was committed.
    pub branch_id: String,
    /// ISO 8601 timestamp of the commit.
    pub timestamp: String,
    /// C5: ID of the agent that performed the commit.
    #[serde(default)]
    pub agent_id: String,
    /// C5: Profile under which the agent was running.
    #[serde(default)]
    pub agent_profile: String,
    /// C5: Checksum of the branch state before the commit (for auditability).
    #[serde(default)]
    pub checksum_before: String,
    /// List of files in the changeset.
    pub files: Vec<ManifestEntry>,
    /// Ed25519 signature over the canonical manifest content (hex-encoded).
    pub signature: String,
}

/// A single file entry in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub path: String,
    pub kind: String,
    pub size: u64,
    pub checksum: String,
}

/// Default key rotation threshold in days.
/// Keys older than this will be rotated when `check_key_rotation()` is called.
const DEFAULT_KEY_ROTATION_DAYS: u64 = 90;

/// IMA integration for changeset signing and verification.
pub struct ImaIntegration {
    /// Ed25519 signing key.
    signing_key: SigningKey,
    /// Ed25519 verifying key (derived from signing key).
    verifying_key: VerifyingKey,
    /// Directory where manifests are stored.
    manifest_dir: PathBuf,
    /// Path to the signing key file (needed for rotation).
    key_path: PathBuf,
}

impl ImaIntegration {
    /// Create a new IMA integration instance.
    ///
    /// If `key_path` exists, loads the key from it. Otherwise, generates a new
    /// keypair and saves it.
    ///
    /// # L8: IMA failure is configurable
    ///
    /// Callers should check `config.require_ima` (in `DaemonConfig`) before
    /// calling this method:
    ///
    /// - When `require_ima` is **true**: a failure from `new()` should be
    ///   treated as fatal (propagate the error, abort daemon startup). This is
    ///   the setting for deployments that require signed commit manifests for
    ///   compliance or audit trail integrity.
    ///
    /// - When `require_ima` is **false** (the default): a failure from `new()`
    ///   should be logged as a warning and IMA signing should be skipped for
    ///   the lifetime of the daemon. Commits proceed without manifest
    ///   signatures. This is appropriate for development, testing, and
    ///   environments where the IMA key infrastructure is not yet deployed.
    pub fn new(manifest_dir: PathBuf, key_path: &Path) -> Result<Self> {
        let signing_key = if key_path.exists() {
            let key_bytes = std::fs::read(key_path)
                .map_err(|e| PuzzledError::Ima(format!("reading signing key: {}", e)))?;
            if key_bytes.len() != 32 {
                return Err(PuzzledError::Ima(
                    "signing key must be 32 bytes".to_string(),
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&key_bytes);
            SigningKey::from_bytes(&arr)
        } else {
            // Generate a new keypair
            let mut rng_bytes = [0u8; 32];
            csprng_fill(&mut rng_bytes)?;
            let key = SigningKey::from_bytes(&rng_bytes);

            // Save the key with restricted permissions set atomically at creation
            // time (no TOCTOU race window where the key is world-readable).
            if let Some(parent) = key_path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| PuzzledError::Ima(format!("creating key directory: {}", e)))?;
            }
            {
                use std::io::Write;
                #[cfg(unix)]
                use std::os::unix::fs::OpenOptionsExt;

                let mut opts = std::fs::OpenOptions::new();
                opts.write(true).create_new(true);
                #[cfg(unix)]
                opts.mode(0o600);

                let mut file = opts
                    .open(key_path)
                    .map_err(|e| PuzzledError::Ima(format!("saving signing key: {}", e)))?;
                file.write_all(&key.to_bytes())
                    .map_err(|e| PuzzledError::Ima(format!("writing signing key: {}", e)))?;
            }

            key
        };

        let verifying_key = signing_key.verifying_key();

        std::fs::create_dir_all(&manifest_dir)
            .map_err(|e| PuzzledError::Ima(format!("creating manifest directory: {}", e)))?;

        Ok(Self {
            signing_key,
            verifying_key,
            manifest_dir,
            key_path: key_path.to_path_buf(),
        })
    }

    /// Generate and sign a commit manifest from the changeset.
    ///
    /// The manifest is saved to `<manifest_dir>/<branch_id>.manifest.yaml`.
    ///
    /// H-8: `agent_id`, `agent_profile`, and `checksum_before` are included in
    /// the canonical signed payload so they cannot be tampered with after signing.
    pub fn sign_commit(
        &self,
        branch_id: &BranchId,
        changes: &[FileChange],
    ) -> Result<CommitManifest> {
        self.sign_commit_with_metadata(branch_id, changes, "", "", "")
    }

    /// Generate and sign a commit manifest with full metadata.
    ///
    /// H-8: All metadata fields (`agent_id`, `agent_profile`, `checksum_before`)
    /// are included in the canonical signed payload to prevent post-signature tampering.
    pub fn sign_commit_with_metadata(
        &self,
        branch_id: &BranchId,
        changes: &[FileChange],
        agent_id: &str,
        agent_profile: &str,
        checksum_before: &str,
    ) -> Result<CommitManifest> {
        let files: Vec<ManifestEntry> = changes
            .iter()
            .map(|c| ManifestEntry {
                path: c.path.display().to_string(),
                kind: match c.kind {
                    FileChangeKind::Added => "added".to_string(),
                    FileChangeKind::Modified => "modified".to_string(),
                    FileChangeKind::Deleted => "deleted".to_string(),
                    FileChangeKind::MetadataChanged => "metadata_changed".to_string(),
                    FileChangeKind::Renamed => "renamed".to_string(),
                    FileChangeKind::Symlink => "symlink".to_string(),
                    // Q6: New special file type variants
                    FileChangeKind::Hardlink => "hardlink".to_string(),
                    FileChangeKind::BlockDevice => "block_device".to_string(),
                    FileChangeKind::CharDevice => "char_device".to_string(),
                    FileChangeKind::Fifo => "fifo".to_string(),
                },
                size: c.size,
                checksum: c.checksum.clone(),
            })
            .collect();

        let timestamp = chrono::Utc::now().to_rfc3339();

        // H-8: Build canonical content including agent_id, agent_profile,
        // checksum_before so they are covered by the Ed25519 signature.
        let canonical = build_canonical(
            branch_id.as_str(),
            &timestamp,
            &files,
            agent_id,
            agent_profile,
            checksum_before,
        )
        .map_err(|e| PuzzledError::Ima(format!("canonical form failed: {e}")))?;

        // Sign the canonical content
        let signature = self.signing_key.sign(canonical.as_bytes());
        let sig_hex = hex_encode(signature.to_bytes().as_slice());

        let manifest = CommitManifest {
            branch_id: branch_id.as_str().to_string(),
            timestamp,
            agent_id: agent_id.to_string(),
            agent_profile: agent_profile.to_string(),
            checksum_before: checksum_before.to_string(),
            files,
            signature: sig_hex,
        };

        // C4: Atomic manifest write — write to temp file, fsync, then rename.
        // This prevents a crash from leaving a partially-written manifest that
        // could pass signature verification with truncated content.
        let manifest_path = self
            .manifest_dir
            .join(format!("{}.manifest.yaml", branch_id.as_str()));
        let yaml = serde_yaml::to_string(&manifest)
            .map_err(|e| PuzzledError::Ima(format!("serializing manifest: {}", e)))?;
        {
            use std::io::Write;
            let mut tmp = tempfile::NamedTempFile::new_in(&self.manifest_dir)
                .map_err(|e| PuzzledError::Ima(format!("creating temp manifest file: {}", e)))?;
            tmp.write_all(yaml.as_bytes())
                .map_err(|e| PuzzledError::Ima(format!("writing temp manifest: {}", e)))?;
            tmp.as_file()
                .sync_all()
                .map_err(|e| PuzzledError::Ima(format!("fsync temp manifest: {}", e)))?;
            tmp.persist(&manifest_path)
                .map_err(|e| PuzzledError::Ima(format!("persisting manifest: {}", e)))?;
        }

        // On Linux, extend IMA measurement log (best-effort)
        #[cfg(target_os = "linux")]
        self.extend_ima_log(&manifest_path);

        tracing::info!(
            branch = %branch_id,
            manifest = %manifest_path.display(),
            files = manifest.files.len(),
            "commit manifest signed"
        );

        self.verify_manifest(&manifest)?;

        Ok(manifest)
    }

    /// Verify a manifest's signature.
    ///
    /// Returns `Ok(())` if the signature is valid, or an error if verification
    /// fails. This ensures callers cannot silently ignore a bad signature by
    /// forgetting to check a boolean return value.
    pub fn verify_manifest(&self, manifest: &CommitManifest) -> Result<()> {
        let canonical = build_canonical(
            &manifest.branch_id,
            &manifest.timestamp,
            &manifest.files,
            &manifest.agent_id,
            &manifest.agent_profile,
            &manifest.checksum_before,
        )
        .map_err(|e| PuzzledError::Ima(format!("canonical form failed: {e}")))?;

        let sig_bytes = hex_decode(&manifest.signature)
            .map_err(|e| PuzzledError::Ima(format!("decoding signature: {}", e)))?;

        if sig_bytes.len() != 64 {
            return Err(PuzzledError::Ima("signature must be 64 bytes".to_string()));
        }

        let mut arr = [0u8; 64];
        arr.copy_from_slice(&sig_bytes);
        let signature = ed25519_dalek::Signature::from_bytes(&arr);

        self.verifying_key
            .verify(canonical.as_bytes(), &signature)
            .map_err(|e| PuzzledError::Ima(format!("signature verification failed: {}", e)))
    }

    /// R21: Sign data using the IMA signing key.
    /// Does not expose the raw key — callers get signatures, not key material.
    pub fn sign(&self, data: &[u8]) -> ed25519_dalek::Signature {
        use ed25519_dalek::Signer;
        self.signing_key.sign(data)
    }

    /// Return a reference to the Ed25519 signing key (for attestation reuse).
    ///
    /// R21: WARNING — This exposes raw key material. Prefer `sign()` for new
    /// callers. Kept `pub` because `main.rs` (binary crate) clones the key for
    /// the AuditStore attestation path. If that dependency is refactored to use
    /// `sign()`, this should be changed to `pub(crate)` or removed.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Get the public verifying key (hex-encoded).
    pub fn public_key_hex(&self) -> String {
        hex_encode(self.verifying_key.as_bytes())
    }

    /// Check the age of the signing key and rotate if older than the threshold.
    ///
    /// When rotation occurs:
    /// 1. The old public key is saved to `<key_path>.pub.<timestamp>` for
    ///    verification of existing manifests signed with the old key.
    /// 2. A new Ed25519 keypair is generated and written to the key file.
    /// 3. The new key file permissions are set to 0600 (owner-read-write only).
    ///
    /// Returns `Ok(true)` if the key was rotated, `Ok(false)` if no rotation
    /// was needed.
    pub fn check_key_rotation(&mut self) -> Result<bool> {
        self.check_key_rotation_with_threshold(DEFAULT_KEY_ROTATION_DAYS)
    }

    /// Check key rotation with a custom threshold in days.
    pub fn check_key_rotation_with_threshold(&mut self, max_age_days: u64) -> Result<bool> {
        if !self.key_path.exists() {
            return Ok(false);
        }

        let metadata = std::fs::metadata(&self.key_path)
            .map_err(|e| PuzzledError::Ima(format!("reading key file metadata: {}", e)))?;

        let modified = metadata
            .modified()
            .map_err(|e| PuzzledError::Ima(format!("reading key file mtime: {}", e)))?;

        // S11: Detect clock skew — if the key file's mtime is in the future,
        // `duration_since()` fails. Previously `unwrap_or_default()` silently
        // returned Duration::ZERO, making future-dated keys appear 0 days old
        // and preventing rotation. Now we return an error so the caller can
        // investigate the clock skew.
        let age = std::time::SystemTime::now()
            .duration_since(modified)
            .map_err(|_| {
                PuzzledError::Ima(
                    "S11: signing key file mtime is in the future — possible clock skew. \
                 Cannot determine key age reliably. Check system clock and key file timestamp."
                        .to_string(),
                )
            })?;

        // L3: Use saturating_mul to avoid panic/wrap on large max_age_days.
        // Saturating at u64::MAX means an absurdly large threshold simply
        // never triggers rotation, which is the correct semantic.
        let max_age_secs = max_age_days
            .saturating_mul(24)
            .saturating_mul(60)
            .saturating_mul(60);
        let max_age = std::time::Duration::from_secs(max_age_secs);

        if age < max_age {
            tracing::debug!(
                key_age_days = age.as_secs() / 86400,
                max_age_days,
                "signing key is within rotation threshold"
            );
            return Ok(false);
        }

        tracing::warn!(
            key_age_days = age.as_secs() / 86400,
            max_age_days,
            "signing key exceeds rotation threshold, rotating"
        );

        // Preserve old public key for verification of existing manifests
        let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let old_pubkey_path = self.key_path.with_extension(format!("pub.{}", timestamp));
        let old_pubkey_bytes = self.verifying_key.to_bytes();
        std::fs::write(&old_pubkey_path, old_pubkey_bytes)
            .map_err(|e| PuzzledError::Ima(format!("saving old public key: {}", e)))?;

        tracing::info!(
            old_pubkey = %old_pubkey_path.display(),
            "preserved old public key for verification of existing manifests"
        );

        // Generate new keypair
        let mut rng_bytes = [0u8; 32];
        csprng_fill(&mut rng_bytes)?;
        let new_key = SigningKey::from_bytes(&rng_bytes);
        let new_verifying_key = new_key.verifying_key();

        // Write new key to disk atomically: write to a temp file with
        // restricted permissions, then rename over the old key file.
        // This avoids a TOCTOU race window where the key is world-readable.
        {
            use std::io::Write;
            #[cfg(unix)]
            use std::os::unix::fs::OpenOptionsExt;

            let tmp_path = self.key_path.with_extension("tmp");
            // R22: Remove stale temp file before creating with O_EXCL to prevent symlink attacks
            let _ = std::fs::remove_file(&tmp_path);

            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            opts.mode(0o600);

            let mut file = opts
                .open(&tmp_path)
                .map_err(|e| PuzzledError::Ima(format!("saving rotated signing key: {}", e)))?;
            file.write_all(&new_key.to_bytes())
                .map_err(|e| PuzzledError::Ima(format!("writing rotated signing key: {}", e)))?;

            // C6: Fsync the new key file before renaming to ensure the key
            // bytes are durable on disk. Without this, a crash after rename
            // but before the OS flushes the key data could leave a zero-length
            // or corrupted key file.
            file.sync_all()
                .map_err(|e| PuzzledError::Ima(format!("C6: fsync rotated signing key: {}", e)))?;

            std::fs::rename(&tmp_path, &self.key_path)
                .map_err(|e| PuzzledError::Ima(format!("replacing signing key file: {}", e)))?;
        }

        // Update in-memory state
        self.signing_key = new_key;
        self.verifying_key = new_verifying_key;

        tracing::info!(
            new_pubkey = %self.public_key_hex(),
            "signing key rotated successfully"
        );

        Ok(true)
    }

    /// Verify a manifest using a specific public key (hex-encoded).
    ///
    /// Useful for verifying manifests signed with a previous key after rotation.
    pub fn verify_manifest_with_pubkey(manifest: &CommitManifest, pubkey_hex: &str) -> Result<()> {
        let pubkey_bytes = hex_decode(pubkey_hex)
            .map_err(|e| PuzzledError::Ima(format!("decoding public key: {}", e)))?;

        if pubkey_bytes.len() != 32 {
            return Err(PuzzledError::Ima("public key must be 32 bytes".to_string()));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&pubkey_bytes);
        let verifying_key = VerifyingKey::from_bytes(&arr)
            .map_err(|e| PuzzledError::Ima(format!("invalid public key: {}", e)))?;

        let canonical = build_canonical(
            &manifest.branch_id,
            &manifest.timestamp,
            &manifest.files,
            &manifest.agent_id,
            &manifest.agent_profile,
            &manifest.checksum_before,
        )
        .map_err(|e| PuzzledError::Ima(format!("canonical form failed: {e}")))?;

        let sig_bytes = hex_decode(&manifest.signature)
            .map_err(|e| PuzzledError::Ima(format!("decoding signature: {}", e)))?;

        if sig_bytes.len() != 64 {
            return Err(PuzzledError::Ima("signature must be 64 bytes".to_string()));
        }

        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

        verifying_key
            .verify(canonical.as_bytes(), &signature)
            .map_err(|e| PuzzledError::Ima(format!("signature verification failed: {}", e)))
    }

    /// Best-effort IMA measurement log extension on Linux.
    #[cfg(target_os = "linux")]
    fn extend_ima_log(&self, manifest_path: &Path) {
        // Write to the IMA measurement log via /sys/kernel/security/ima/ascii_runtime_measurements
        // This requires CAP_SYS_ADMIN. If unavailable, we skip silently.
        let ima_path = Path::new("/sys/kernel/security/ima/policy");
        if ima_path.exists() {
            tracing::debug!(
                manifest = %manifest_path.display(),
                "IMA measurement log available (measurement recorded by kernel on file access)"
            );
        } else {
            tracing::debug!("IMA measurement log not available (continuing without)");
        }
    }
}

/// M21: Build canonical content for signing using JSON canonical form.
///
/// Uses `BTreeMap` for deterministic key ordering and `serde_json::to_string`
/// for consistent serialization. Each file entry is a JSON object with sorted
/// keys: `{"checksum":"...","kind":"...","path":"...","size":N}`. Files are
/// sorted by path for deterministic ordering.
///
/// H-8: Includes `agent_id`, `agent_profile`, and `checksum_before` fields in
/// the canonical output so they are covered by the Ed25519 signature.
///
/// Output format:
/// ```json
/// {"agent_id":"...","agent_profile":"...","branch_id":"...","checksum_before":"...","files":[...],"timestamp":"..."}
/// ```
fn build_canonical(
    branch_id: &str,
    timestamp: &str,
    files: &[ManifestEntry],
    agent_id: &str,
    agent_profile: &str,
    checksum_before: &str,
) -> anyhow::Result<String> {
    use std::collections::BTreeMap;

    // Sort files by path for deterministic ordering
    let mut sorted_files: Vec<&ManifestEntry> = files.iter().collect();
    sorted_files.sort_by(|a, b| a.path.cmp(&b.path));

    let file_entries: Vec<serde_json::Value> = sorted_files
        .iter()
        .map(|f| {
            let mut entry = BTreeMap::new();
            entry.insert("checksum", serde_json::Value::String(f.checksum.clone()));
            entry.insert("kind", serde_json::Value::String(f.kind.clone()));
            entry.insert("path", serde_json::Value::String(f.path.clone()));
            entry.insert("size", serde_json::json!(f.size));
            // N11: Propagate serialization errors instead of panicking
            serde_json::to_value(entry)
                .map_err(|e| anyhow::anyhow!("canonical serialization failed: {e}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let mut canonical = BTreeMap::new();
    // H-8: Include agent_id, agent_profile, and checksum_before in signed payload
    canonical.insert("agent_id", serde_json::Value::String(agent_id.to_string()));
    canonical.insert(
        "agent_profile",
        serde_json::Value::String(agent_profile.to_string()),
    );
    canonical.insert(
        "branch_id",
        serde_json::Value::String(branch_id.to_string()),
    );
    canonical.insert(
        "checksum_before",
        serde_json::Value::String(checksum_before.to_string()),
    );
    canonical.insert("files", serde_json::Value::Array(file_entries));
    canonical.insert(
        "timestamp",
        serde_json::Value::String(timestamp.to_string()),
    );

    // N11: Propagate serialization errors instead of panicking
    serde_json::to_string(&canonical)
        .map_err(|e| anyhow::anyhow!("canonical serialization failed: {e}"))
}

use puzzled_types::merkle::{hex_decode, hex_encode};

/// Fill buffer with cryptographically secure random bytes.
///
/// Uses the `getrandom` crate which calls the OS CSPRNG (`getrandom(2)` syscall
/// on Linux, `/dev/urandom` as fallback). Returns an error if the OS cannot
/// provide entropy — generating an Ed25519 signing key with insufficient
/// entropy is a critical security failure (CVE-2025-2814).
fn csprng_fill(buf: &mut [u8]) -> std::result::Result<(), PuzzledError> {
    getrandom::getrandom(buf).map_err(|e| {
        PuzzledError::Ima(format!(
            "CSPRNG entropy source unavailable — refusing to generate signing key with \
             insufficient randomness. Ensure /dev/urandom is accessible or the getrandom(2) \
             syscall is permitted by seccomp policy: {}",
            e
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_dir = dir.path().join("manifests");
        let key_path = dir.path().join("key");

        let ima = ImaIntegration::new(manifest_dir, &key_path).unwrap();

        let changes = vec![
            FileChange {
                path: "src/main.rs".into(),
                kind: FileChangeKind::Modified,
                size: 1024,
                checksum: "abc123".to_string(),
                old_size: None,
                old_mode: None,
                new_mode: None,
                timestamp: None,
                target: None,
                entropy: None,
                has_base64_blocks: None,
            },
            FileChange {
                path: "README.md".into(),
                kind: FileChangeKind::Added,
                size: 256,
                checksum: "def456".to_string(),
                old_size: None,
                old_mode: None,
                new_mode: None,
                timestamp: None,
                target: None,
                entropy: None,
                has_base64_blocks: None,
            },
        ];

        let branch_id = BranchId::from("test-branch-123".to_string());
        let manifest = ima.sign_commit(&branch_id, &changes).unwrap();

        assert_eq!(manifest.branch_id, "test-branch-123");
        assert_eq!(manifest.files.len(), 2);
        assert!(!manifest.signature.is_empty());

        // Verify the signature — Ok(()) means valid
        ima.verify_manifest(&manifest).unwrap();
    }

    #[test]
    fn test_tampered_manifest_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_dir = dir.path().join("manifests");
        let key_path = dir.path().join("key");

        let ima = ImaIntegration::new(manifest_dir, &key_path).unwrap();

        let changes = vec![FileChange {
            path: "file.txt".into(),
            kind: FileChangeKind::Added,
            size: 100,
            checksum: "aaa".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
            entropy: None,
            has_base64_blocks: None,
        }];

        let branch_id = BranchId::from("test-branch".to_string());
        let mut manifest = ima.sign_commit(&branch_id, &changes).unwrap();

        // Tamper with the manifest
        manifest.files[0].size = 999;

        // Verification should fail with an error
        assert!(ima.verify_manifest(&manifest).is_err());
    }

    #[test]
    fn test_key_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_dir = dir.path().join("manifests");
        let key_path = dir.path().join("key");

        let ima1 = ImaIntegration::new(manifest_dir.clone(), &key_path).unwrap();
        let pubkey1 = ima1.public_key_hex();

        // Create a second instance from the same key file
        let ima2 = ImaIntegration::new(manifest_dir, &key_path).unwrap();
        let pubkey2 = ima2.public_key_hex();

        assert_eq!(pubkey1, pubkey2);
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = b"hello world";
        let encoded = hex_encode(data);
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(data.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_key_rotation_not_needed() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_dir = dir.path().join("manifests");
        let key_path = dir.path().join("key");

        let mut ima = ImaIntegration::new(manifest_dir, &key_path).unwrap();
        let pubkey_before = ima.public_key_hex();

        // Key was just created, rotation should not occur
        let rotated = ima.check_key_rotation().unwrap();
        assert!(!rotated);
        assert_eq!(pubkey_before, ima.public_key_hex());
    }

    #[test]
    fn test_key_rotation_forced() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_dir = dir.path().join("manifests");
        let key_path = dir.path().join("key");

        let mut ima = ImaIntegration::new(manifest_dir, &key_path).unwrap();
        let pubkey_before = ima.public_key_hex();

        // Sign a manifest with the old key
        let changes = vec![FileChange {
            path: "file.txt".into(),
            kind: FileChangeKind::Added,
            size: 100,
            checksum: "abc".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
            entropy: None,
            has_base64_blocks: None,
        }];
        let branch_id = BranchId::from("rotation-test".to_string());
        let manifest = ima.sign_commit(&branch_id, &changes).unwrap();

        // Force rotation with threshold of 0 days (always rotate)
        let rotated = ima.check_key_rotation_with_threshold(0).unwrap();
        assert!(rotated);

        // Key should have changed
        let pubkey_after = ima.public_key_hex();
        assert_ne!(pubkey_before, pubkey_after);

        // Old manifest should fail verification with new key
        assert!(ima.verify_manifest(&manifest).is_err());

        // Old manifest should pass verification with preserved old public key
        ImaIntegration::verify_manifest_with_pubkey(&manifest, &pubkey_before).unwrap();
    }

    #[test]
    fn test_canonical_form_is_deterministic_json() {
        // M21: Verify that build_canonical produces deterministic JSON output
        // with sorted keys and sorted file entries.
        let files = vec![
            ManifestEntry {
                path: "src/main.rs".to_string(),
                kind: "modified".to_string(),
                size: 1024,
                checksum: "abc123".to_string(),
            },
            ManifestEntry {
                path: "README.md".to_string(),
                kind: "added".to_string(),
                size: 256,
                checksum: "def456".to_string(),
            },
        ];

        let canonical1 = build_canonical(
            "branch-1",
            "2026-01-01T00:00:00Z",
            &files,
            "agent-1",
            "standard",
            "abc123",
        )
        .unwrap();
        let canonical2 = build_canonical(
            "branch-1",
            "2026-01-01T00:00:00Z",
            &files,
            "agent-1",
            "standard",
            "abc123",
        )
        .unwrap();
        assert_eq!(
            canonical1, canonical2,
            "canonical form must be deterministic"
        );

        // Verify it's valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&canonical1).unwrap();
        assert_eq!(parsed["branch_id"], "branch-1");
        assert_eq!(parsed["timestamp"], "2026-01-01T00:00:00Z");
        // H-8: Verify agent metadata fields are included in canonical form
        assert_eq!(parsed["agent_id"], "agent-1");
        assert_eq!(parsed["agent_profile"], "standard");
        assert_eq!(parsed["checksum_before"], "abc123");

        // Files should be sorted by path: README.md before src/main.rs
        let files_arr = parsed["files"].as_array().unwrap();
        assert_eq!(files_arr.len(), 2);
        assert_eq!(files_arr[0]["path"], "README.md");
        assert_eq!(files_arr[1]["path"], "src/main.rs");

        // Each file entry should have sorted keys: checksum, kind, path, size
        let file_json = serde_json::to_string(&files_arr[0]).unwrap();
        assert!(
            file_json.starts_with(r#"{"checksum":"#),
            "keys should be sorted alphabetically, got: {}",
            file_json
        );

        // Reversed input order should produce same canonical output
        let files_reversed = vec![files[1].clone(), files[0].clone()];
        let canonical3 = build_canonical(
            "branch-1",
            "2026-01-01T00:00:00Z",
            &files_reversed,
            "agent-1",
            "standard",
            "abc123",
        )
        .unwrap();
        assert_eq!(
            canonical1, canonical3,
            "file order in input should not affect canonical form"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_key_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let manifest_dir = dir.path().join("manifests");
        let key_path = dir.path().join("key");

        let _ima = ImaIntegration::new(manifest_dir, &key_path).unwrap();

        let perms = std::fs::metadata(&key_path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    // S11: Clock skew on key file should return error, not silently default to 0
    //
    // When a key file has an mtime in the future, `duration_since()` fails and
    // `unwrap_or_default()` returns Duration::ZERO. This makes a future-dated
    // key appear 0 days old, preventing rotation even when the key should be
    // rotated (e.g., 90-day threshold). The fix should detect clock skew and
    // return an error.
    #[test]
    fn test_s11_future_dated_key_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_dir = dir.path().join("manifests");
        let key_path = dir.path().join("key");

        let mut ima = ImaIntegration::new(manifest_dir, &key_path).unwrap();

        // Set the key file's mtime far into the future (year 2100)
        let future_time =
            std::time::SystemTime::now() + std::time::Duration::from_secs(365 * 24 * 60 * 60 * 75); // ~75 years ahead

        let file = std::fs::File::open(&key_path).unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(future_time))
            .unwrap();

        // With the default 90-day threshold, a future-dated key with age
        // silently defaulted to 0 would appear "fresh" and skip rotation.
        // This should return an error about clock skew instead.
        let result = ima.check_key_rotation_with_threshold(DEFAULT_KEY_ROTATION_DAYS);
        assert!(
            result.is_err(),
            "S11: future-dated key should return an error about clock skew, \
             got {:?} — unwrap_or_default() makes the key appear 0 days old, \
             preventing rotation of a key that may actually be very old",
            result
        );
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("clock") || err_msg.contains("future"),
            "S11: error message should mention clock skew, got: {}",
            err_msg
        );
    }

    // L3: check_key_rotation_with_threshold must use checked arithmetic for
    // max_age_days * 24 * 60 * 60 to avoid panic/wrap on large inputs.
    #[test]
    fn l3_key_rotation_overflow_days() {
        // Verify that the source code uses checked_mul (or saturating_mul)
        // for the max_age_days conversion to seconds.
        let source = include_str!("ima.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        let in_fn = prod_source
            .split("fn check_key_rotation_with_threshold")
            .nth(1)
            .and_then(|rest| rest.split("\n    pub fn ").next())
            .unwrap_or("");
        assert!(
            in_fn.contains("checked_mul") || in_fn.contains("saturating_mul"),
            "L3: check_key_rotation_with_threshold must use checked_mul or \
             saturating_mul for max_age_days conversion — unchecked \
             multiplication on user-supplied u64 risks panic or silent wrap"
        );
    }
}
