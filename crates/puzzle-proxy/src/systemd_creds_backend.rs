// SPDX-License-Identifier: Apache-2.0
//! §3.4 G5: `systemd-creds` credential encryption backend.
//!
//! Uses `systemd-creds encrypt`/`decrypt` subprocess calls for credential
//! encryption. This is the PRD-recommended default backend for production
//! deployments on systems with systemd >= 256.
//!
//! Encrypted blobs are stored at `~/.config/puzzled/secrets/<name>.enc` (rootless)
//! or `/etc/puzzled/secrets/<name>.enc` (system mode).

use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Errors from the systemd-creds backend.
#[derive(Debug, thiserror::Error)]
pub enum SystemdCredsError {
    #[error("systemd-creds binary not found")]
    NotFound,
    #[error("systemd-creds version {version} < 256 (minimum required)")]
    VersionTooOld { version: u32 },
    #[error("systemd-creds encrypt failed: {0}")]
    EncryptFailed(String),
    #[error("systemd-creds decrypt failed: {0}")]
    DecryptFailed(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("secrets directory {0} has insecure permissions (expected 0o700)")]
    InsecurePermissions(PathBuf),
}

/// systemd-creds credential encryption backend.
pub struct SystemdCredsBackend {
    /// Directory for storing encrypted credential files.
    secrets_dir: PathBuf,
    /// Whether to pass `--user` flag (rootless mode).
    user_mode: bool,
}

impl SystemdCredsBackend {
    /// Create a new backend.
    ///
    /// - `secrets_dir`: directory for `.enc` files
    /// - `user_mode`: pass `--user` to systemd-creds
    pub fn new(secrets_dir: PathBuf, user_mode: bool) -> Self {
        Self {
            secrets_dir,
            user_mode,
        }
    }

    /// Check if systemd-creds is available and has sufficient version.
    pub async fn is_available() -> bool {
        match tokio::process::Command::new("systemd-creds")
            .arg("--version")
            .output()
            .await
        {
            Ok(output) => {
                if !output.status.success() {
                    return false;
                }
                // Parse version from output (e.g., "systemd 256 (256-1.fc40)")
                let stdout = String::from_utf8_lossy(&output.stdout);
                parse_systemd_version(&stdout).is_some_and(|v| v >= 256)
            }
            Err(_) => false,
        }
    }

    /// Ensure the secrets directory exists with correct permissions.
    pub fn ensure_secrets_dir(&self) -> Result<(), SystemdCredsError> {
        if !self.secrets_dir.exists() {
            std::fs::create_dir_all(&self.secrets_dir)?;
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&self.secrets_dir)?;
            let mode = meta.permissions().mode() & 0o777;
            if mode != 0o700 {
                // Try to fix permissions
                std::fs::set_permissions(
                    &self.secrets_dir,
                    std::fs::Permissions::from_mode(0o700),
                )?;
            }
        }

        Ok(())
    }

    /// Encrypt a credential value using systemd-creds.
    ///
    /// Stores the encrypted blob at `{secrets_dir}/{name}.enc`.
    pub async fn encrypt(&self, name: &str, plaintext: &[u8]) -> Result<(), SystemdCredsError> {
        self.ensure_secrets_dir()?;

        let mut cmd = tokio::process::Command::new("systemd-creds");
        if self.user_mode {
            cmd.arg("--user");
        }
        cmd.args(["encrypt", &format!("--name={}", name), "-", "-"]);
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                SystemdCredsError::NotFound
            } else {
                SystemdCredsError::Io(e)
            }
        })?;

        // Write plaintext to stdin
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            stdin.write_all(plaintext).await?;
            // Drop stdin to close it, signaling EOF to systemd-creds
        }

        let output = child.wait_with_output().await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SystemdCredsError::EncryptFailed(stderr.to_string()));
        }

        // Write encrypted blob to file
        let enc_path = self.secrets_dir.join(format!("{}.enc", name));
        // Atomic write via temp + rename
        let tmp_path = enc_path.with_extension("enc.tmp");
        std::fs::write(&tmp_path, &output.stdout)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp_path, &enc_path)?;

        tracing::info!(
            name = name,
            path = %enc_path.display(),
            "§3.4 G5: credential encrypted with systemd-creds"
        );

        Ok(())
    }

    /// Decrypt a credential value using systemd-creds.
    ///
    /// Returns the plaintext wrapped in `Zeroizing` for automatic zeroization.
    pub async fn decrypt(&self, name: &str) -> Result<Zeroizing<Vec<u8>>, SystemdCredsError> {
        let enc_path = self.secrets_dir.join(format!("{}.enc", name));
        let ciphertext = std::fs::read(&enc_path)?;

        let mut cmd = tokio::process::Command::new("systemd-creds");
        if self.user_mode {
            cmd.arg("--user");
        }
        cmd.args([
            "decrypt",
            "--no-ask-password",
            &format!("--name={}", name),
            "-",
            "-",
        ]);
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                SystemdCredsError::NotFound
            } else {
                SystemdCredsError::Io(e)
            }
        })?;

        // Write ciphertext to stdin
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            stdin.write_all(&ciphertext).await?;
        }

        let output = child.wait_with_output().await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SystemdCredsError::DecryptFailed(stderr.to_string()));
        }

        // CRITICAL: Wrap stdout immediately in Zeroizing before any processing
        Ok(Zeroizing::new(output.stdout))
    }

    /// Check if an encrypted credential file exists.
    pub fn credential_exists(&self, name: &str) -> bool {
        self.secrets_dir.join(format!("{}.enc", name)).exists()
    }

    /// Remove an encrypted credential file.
    pub fn remove(&self, name: &str) -> Result<(), SystemdCredsError> {
        let enc_path = self.secrets_dir.join(format!("{}.enc", name));
        if enc_path.exists() {
            std::fs::remove_file(&enc_path)?;
        }
        Ok(())
    }

    /// Get the secrets directory path.
    pub fn secrets_dir(&self) -> &Path {
        &self.secrets_dir
    }
}

/// Parse systemd version from `systemd-creds --version` output.
fn parse_systemd_version(output: &str) -> Option<u32> {
    // Output format: "systemd 256 (256-1.fc40)" or similar
    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("systemd ") {
            let rest = line.strip_prefix("systemd ")?;
            let version_str = rest.split_whitespace().next()?;
            return version_str.parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_systemd_version() {
        assert_eq!(parse_systemd_version("systemd 256 (256-1.fc40)"), Some(256));
        assert_eq!(parse_systemd_version("systemd 255"), Some(255));
        assert_eq!(parse_systemd_version("systemd 257 (257~rc1-1)"), Some(257));
        assert_eq!(parse_systemd_version("not systemd output"), None);
        assert_eq!(parse_systemd_version(""), None);
    }

    #[test]
    fn test_ensure_secrets_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let secrets_dir = tmp.path().join("secrets");
        let backend = SystemdCredsBackend::new(secrets_dir.clone(), true);

        backend.ensure_secrets_dir().unwrap();
        assert!(secrets_dir.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&secrets_dir).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "secrets dir should have 0o700 permissions");
        }
    }

    #[test]
    fn test_credential_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let backend = SystemdCredsBackend::new(tmp.path().to_path_buf(), true);

        assert!(!backend.credential_exists("nonexistent"));

        std::fs::write(tmp.path().join("test.enc"), b"encrypted").unwrap();
        assert!(backend.credential_exists("test"));
    }

    #[test]
    fn test_remove_credential() {
        let tmp = tempfile::tempdir().unwrap();
        let backend = SystemdCredsBackend::new(tmp.path().to_path_buf(), true);

        let enc_path = tmp.path().join("removeme.enc");
        std::fs::write(&enc_path, b"encrypted").unwrap();
        assert!(enc_path.exists());

        backend.remove("removeme").unwrap();
        assert!(!enc_path.exists());
    }

    #[test]
    fn test_remove_nonexistent_is_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let backend = SystemdCredsBackend::new(tmp.path().to_path_buf(), true);
        // Should not error when file doesn't exist
        backend.remove("nonexistent").unwrap();
    }
}
