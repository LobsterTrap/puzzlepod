// SPDX-License-Identifier: Apache-2.0
//! SELinux integration for agent sandboxes.
//!
//! Validates that SELinux is available and in enforcing mode, verifies
//! that our policy module is loaded, and transitions agent processes
//! to the `puzzlepod_t` domain for mandatory access control.
//!
//! SELinux is optional — if not available, the sandbox proceeds without
//! it (with a warning). The other defense-in-depth layers (Landlock,
//! seccomp, namespaces, cgroups, capabilities) remain active.

use crate::error::{PuzzledError, Result};

pub struct SelinuxEnforcer;

impl SelinuxEnforcer {
    /// Check if SELinux is in enforcing mode.
    ///
    /// Reads `/sys/fs/selinux/enforce` — returns `true` if SELinux is
    /// enforcing, `false` if permissive or disabled.
    #[cfg(target_os = "linux")]
    pub fn verify_available() -> bool {
        match std::fs::read_to_string("/sys/fs/selinux/enforce") {
            Ok(content) => {
                let enforcing = content.trim() == "1";
                if enforcing {
                    tracing::info!("SELinux is in enforcing mode");
                } else {
                    tracing::warn!(
                        "SELinux is in permissive mode — puzzlepod_t domain will not enforce"
                    );
                }
                enforcing
            }
            Err(_) => {
                tracing::warn!("SELinux not available (cannot read /sys/fs/selinux/enforce)");
                false
            }
        }
    }

    /// Set the SELinux security context for an agent process.
    ///
    /// Writes the specified domain (e.g., `puzzlepod_t`) to
    /// `/proc/<pid>/attr/current` to transition the process into the
    /// agent SELinux domain. This enforces the type enforcement rules
    /// defined in `selinux/puzzled.te`.
    ///
    /// Must be called from a process with permission to set contexts
    /// (typically puzzled running as `puzzled_t`).
    #[cfg(target_os = "linux")]
    pub fn set_context(pid: u32, domain: &str) -> Result<()> {
        let attr_path = format!("/proc/{}/attr/current", pid);

        // Format: user:role:type:level (e.g., system_u:system_r:puzzlepod_t:s0)
        let context = format!("system_u:system_r:{}:s0", domain);

        std::fs::write(&attr_path, &context).map_err(|e| {
            PuzzledError::Sandbox(format!(
                "setting SELinux context '{}' on PID {} via {}: {}",
                context, pid, attr_path, e
            ))
        })?;

        tracing::info!(pid, domain, "SELinux context set for agent process");
        Ok(())
    }

    /// Verify that our SELinux policy module is loaded.
    ///
    /// Checks for the module name in `semodule -l` output.
    /// Returns true if the module is loaded, false otherwise.
    #[cfg(target_os = "linux")]
    pub fn verify_policy_loaded(module_name: &str) -> bool {
        match std::process::Command::new("semodule").args(["-l"]).output() {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let loaded = stdout
                    .lines()
                    .any(|line| line.split_whitespace().next() == Some(module_name));
                if loaded {
                    tracing::info!(module = module_name, "SELinux policy module loaded");
                } else {
                    tracing::warn!(
                        module = module_name,
                        "SELinux policy module not loaded — puzzlepod_t domain unavailable"
                    );
                }
                loaded
            }
            Err(e) => {
                tracing::warn!(error = %e, "semodule command not available");
                false
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn verify_available() -> bool {
        false
    }

    #[cfg(not(target_os = "linux"))]
    pub fn set_context(_pid: u32, _domain: &str) -> Result<()> {
        Err(PuzzledError::Sandbox("SELinux requires Linux".to_string()))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn verify_policy_loaded(_module_name: &str) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_available_returns_bool() {
        // On non-Linux or systems without SELinux, should return false
        let result = SelinuxEnforcer::verify_available();
        // Don't assert specific value — depends on test environment
        let _ = result;
    }

    #[test]
    fn test_verify_policy_loaded_nonexistent() {
        let result = SelinuxEnforcer::verify_policy_loaded("nonexistent_module_xyz");
        assert!(!result);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_set_context_non_linux() {
        let result = SelinuxEnforcer::set_context(1234, "puzzlepod_t");
        assert!(result.is_err());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_verify_available_non_linux() {
        assert!(!SelinuxEnforcer::verify_available());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_verify_policy_loaded_non_linux() {
        assert!(!SelinuxEnforcer::verify_policy_loaded("puzzled"));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_set_context_non_linux_error_message() {
        let result = SelinuxEnforcer::set_context(1234, "puzzlepod_t");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("SELinux requires Linux"),
            "expected error message to contain 'SELinux requires Linux', got: {}",
            err_msg
        );
    }
}
