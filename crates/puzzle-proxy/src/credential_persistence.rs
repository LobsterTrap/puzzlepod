// SPDX-License-Identifier: Apache-2.0
//! §3.4 G12: Credential mapping persistence for restart recovery.
//!
//! Persists phantom token → credential spec mappings to `credential_mappings.json`
//! in the branch state directory. This file contains phantom tokens and backend
//! references — **never** real credential values.
//!
//! File format:
//! ```json
//! {
//!   "version": 1,
//!   "proxy_port": 18443,
//!   "mappings": [
//!     { "phantom_token": "pt_abc123_...", "credential_name": "api-key", "domains": ["api.example.com"] }
//!   ]
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Version of the credential mapping file format.
const MAPPING_VERSION: u32 = 1;

/// Persisted credential mapping file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMappingFile {
    /// File format version.
    pub version: u32,
    /// Proxy port allocated for this branch.
    pub proxy_port: u16,
    /// Phantom token → credential mappings (no real values).
    pub mappings: Vec<PersistedMapping>,
}

/// A single persisted credential mapping.
/// M-6: Includes swap_headers, ttl_seconds, backend_config for full restart recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedMapping {
    /// The phantom token issued for this credential.
    pub phantom_token: String,
    /// Credential name (reference into the backend).
    pub credential_name: String,
    /// Domains this credential applies to.
    pub domains: Vec<String>,
    /// Backend type used for this credential.
    pub backend: String,
    /// Environment variable the phantom token was exposed as.
    pub env_var: String,
    /// M-6: Headers to scan for phantom token swapping (PRD §3.4.8).
    #[serde(default)]
    pub swap_headers: Vec<String>,
    /// M-6: TTL for credential rotation in seconds (PRD §3.4.5).
    #[serde(default)]
    pub ttl_seconds: u64,
    /// M-6: Backend-specific configuration for re-fetching on restart (PRD §3.4.8).
    #[serde(default)]
    pub backend_config: serde_json::Value,
}

impl CredentialMappingFile {
    /// Create a new mapping file.
    pub fn new(proxy_port: u16, mappings: Vec<PersistedMapping>) -> Self {
        Self {
            version: MAPPING_VERSION,
            proxy_port,
            mappings,
        }
    }

    /// Save the mapping file atomically to the branch state directory.
    ///
    /// Uses temp file + rename for crash safety.
    pub fn save(&self, branch_state_dir: &Path) -> std::io::Result<()> {
        let path = branch_state_dir.join("credential_mappings.json");
        // M-7: Use random suffix temp filename + O_EXCL (create_new) to prevent
        // symlink attacks on the temp file, matching the G24 pattern in credentials.rs.
        let rand_suffix: u64 = {
            let mut buf = [0u8; 8];
            getrandom::getrandom(&mut buf).map_err(|e| {
                std::io::Error::other(format!("M-7: getrandom failed for temp suffix: {e}"))
            })?;
            u64::from_ne_bytes(buf)
        };
        let tmp_name = format!("credential_mappings.{:016x}.tmp", rand_suffix);
        let tmp_path = branch_state_dir.join(&tmp_name);

        let json = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;

        // Write with O_EXCL, set permissions, and rename atomically. Clean up on error.
        let result = (|| -> std::io::Result<()> {
            use std::io::Write;
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true) // O_EXCL: fail if file already exists
                    .mode(0o600)
                    .open(&tmp_path)?;
                file.write_all(json.as_bytes())?;
            }
            #[cfg(not(unix))]
            {
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&tmp_path)?;
                file.write_all(json.as_bytes())?;
            }
            std::fs::rename(&tmp_path, &path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
        }
        result?;

        tracing::debug!(
            path = %path.display(),
            mappings = self.mappings.len(),
            "§3.4 G12: saved credential mappings"
        );

        Ok(())
    }

    /// Load the mapping file from the branch state directory.
    ///
    /// Returns `None` if the file doesn't exist (clean branch start).
    pub fn load(branch_state_dir: &Path) -> std::io::Result<Option<Self>> {
        let path = branch_state_dir.join("credential_mappings.json");

        if !path.exists() {
            return Ok(None);
        }

        let contents = std::fs::read_to_string(&path)?;
        let file: Self = serde_json::from_str(&contents)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        if file.version != MAPPING_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "unsupported credential_mappings.json version: {} (expected {})",
                    file.version, MAPPING_VERSION
                ),
            ));
        }

        tracing::debug!(
            path = %path.display(),
            mappings = file.mappings.len(),
            proxy_port = file.proxy_port,
            "§3.4 G12: loaded credential mappings for restart recovery"
        );

        Ok(Some(file))
    }

    /// Delete the mapping file (on branch commit or rollback).
    pub fn delete(branch_state_dir: &Path) -> std::io::Result<()> {
        let path = branch_state_dir.join("credential_mappings.json");
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_save_and_load_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();

        let file = CredentialMappingFile::new(
            18443,
            vec![
                PersistedMapping {
                    phantom_token: "pt_abc123_deadbeef".to_string(),
                    credential_name: "api-key".to_string(),
                    domains: vec!["api.example.com".to_string()],
                    backend: "encrypted_file".to_string(),
                    env_var: "API_KEY".to_string(),
                    swap_headers: vec!["authorization".to_string()],
                    ttl_seconds: 900,
                    backend_config: serde_json::Value::Null,
                },
                PersistedMapping {
                    phantom_token: "pt_abc123_cafebabe".to_string(),
                    credential_name: "db-password".to_string(),
                    domains: vec!["db.internal.com".to_string()],
                    backend: "systemd_creds".to_string(),
                    env_var: "DB_PASS".to_string(),
                    swap_headers: vec![],
                    ttl_seconds: 0,
                    backend_config: serde_json::Value::Null,
                },
            ],
        );

        file.save(tmp.path()).unwrap();
        let loaded = CredentialMappingFile::load(tmp.path()).unwrap().unwrap();

        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.proxy_port, 18443);
        assert_eq!(loaded.mappings.len(), 2);
        assert_eq!(loaded.mappings[0].phantom_token, "pt_abc123_deadbeef");
        assert_eq!(loaded.mappings[1].credential_name, "db-password");
    }

    #[test]
    fn test_load_nonexistent_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let loaded = CredentialMappingFile::load(tmp.path()).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_delete() {
        let tmp = tempfile::tempdir().unwrap();
        let file = CredentialMappingFile::new(18443, vec![]);
        file.save(tmp.path()).unwrap();

        assert!(tmp.path().join("credential_mappings.json").exists());
        CredentialMappingFile::delete(tmp.path()).unwrap();
        assert!(!tmp.path().join("credential_mappings.json").exists());
    }

    #[test]
    fn test_delete_nonexistent_is_ok() {
        let tmp = tempfile::tempdir().unwrap();
        CredentialMappingFile::delete(tmp.path()).unwrap();
    }

    #[test]
    fn test_file_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let file = CredentialMappingFile::new(18443, vec![]);
        file.save(tmp.path()).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(tmp.path().join("credential_mappings.json")).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "file should have 0o600 permissions");
        }
    }
}
