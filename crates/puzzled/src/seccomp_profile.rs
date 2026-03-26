// SPDX-License-Identifier: Apache-2.0
//! OCI seccomp profile generation for Podman-native mode.
//!
//! Generates a JSON seccomp profile compatible with the OCI runtime spec.
//! The profile includes:
//! - `SCMP_ACT_NOTIFY` for execve/connect/bind (daemon-mediated gating)
//! - `SCMP_ACT_KILL_PROCESS` for 57+ escape-vector syscalls (static deny)
//! - `SCMP_ACT_ALLOW` as default action
//! - `listenerPath` for puzzled's seccomp notification socket
//! - `listenerMetadata` containing the branch_id

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::error::{PuzzledError, Result};

/// OCI seccomp profile structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciSeccompProfile {
    pub default_action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listener_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listener_metadata: Option<String>,
    pub architectures: Vec<String>,
    pub syscalls: Vec<SyscallRule>,
}

/// A single syscall rule in the OCI seccomp profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallRule {
    pub names: Vec<String>,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<SyscallArg>>,
    /// Optional errno return value (only used with SCMP_ACT_ERRNO).
    /// OCI spec field name is "errnoRet" (camelCase).
    #[serde(rename = "errnoRet", skip_serializing_if = "Option::is_none")]
    pub errno_ret: Option<u32>,
}

/// Argument filter for a syscall rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyscallArg {
    pub index: u32,
    pub value: u64,
    pub op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_two: Option<u64>,
}

/// Escape-vector syscalls that are statically denied (SCMP_ACT_KILL_PROCESS).
const DENY_SYSCALLS: &[&str] = &[
    "ptrace",
    "kexec_load",
    "kexec_file_load",
    "init_module",
    "finit_module",
    "delete_module",
    "mount",
    "umount2",
    "pivot_root",
    "setns",
    "unshare",
    "bpf",
    "userfaultfd",
    "perf_event_open",
    "mount_setattr",
    "move_mount",
    "open_tree",
    "fsopen",
    "fspick",
    "fsconfig",
    "fsmount",
    "reboot",
    "swapon",
    "swapoff",
    "acct",
    "iopl",
    "ioperm",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "process_vm_readv",
    "process_vm_writev",
    "kcmp",
    "add_key",
    "keyctl",
    "request_key",
    "personality",
    "syslog",
    "lookup_dcookie",
    "name_to_handle_at",
    "open_by_handle_at",
    "memfd_create",
    "memfd_secret",
    "chroot",
    "settimeofday",
    "clock_settime",
    "shmget",
    "shmat",
    "shmctl",
    "shmdt",
    "semget",
    "semop",
    "semctl",
    "semtimedop",
    "msgget",
    "msgsnd",
    "msgrcv",
    "msgctl",
    // modify_ldt — x86_64 only. Allows modifying the Local Descriptor Table,
    // which can be used for segmentation-based sandbox escapes.
    "modify_ldt",
];

/// Syscalls gated via SCMP_ACT_NOTIFY (daemon-mediated).
const NOTIFY_SYSCALLS: &[&str] = &["execve", "execveat", "connect", "bind"];

/// Landlock syscalls that must be allowed for puzzle-init shim.
const LANDLOCK_SYSCALLS: &[&str] = &[
    "landlock_create_ruleset",
    "landlock_add_rule",
    "landlock_restrict_self",
];

/// Generate an OCI seccomp profile for a branch.
///
/// The profile is written to `output_dir/<branch_id>/seccomp.json`.
///
/// # Arguments
/// * `branch_id` - Branch identifier for the `listenerMetadata` field
/// * `listener_socket` - Path to puzzled's seccomp notification socket
/// * `include_notify` - Whether to include SCMP_ACT_NOTIFY rules (false for static-only mode)
/// * `include_clone_guard` - Whether to include clone/clone3 in notify (when BPF guard inactive)
pub fn generate_seccomp_profile(
    branch_id: &str,
    listener_socket: &Path,
    include_notify: bool,
    include_clone_guard: bool,
) -> Result<OciSeccompProfile> {
    let mut syscalls = Vec::new();

    // Static deny rules for escape-vector syscalls — KILL_PROCESS, not ERRNO.
    // SCMP_ACT_KILL_PROCESS terminates the entire process on violation,
    // preventing agents from catching ERRNO and retrying or probing.
    syscalls.push(SyscallRule {
        names: DENY_SYSCALLS.iter().map(|s| s.to_string()).collect(),
        action: "SCMP_ACT_KILL_PROCESS".to_string(),
        args: None,
        errno_ret: None,
    });

    // Socket type filtering: block SOCK_RAW and SOCK_PACKET
    const SOCK_TYPE_MASK: u64 = 0x0F;
    const SOCK_RAW: u64 = 3;
    const SOCK_PACKET: u64 = 10;

    syscalls.push(SyscallRule {
        names: vec!["socket".to_string()],
        action: "SCMP_ACT_ERRNO".to_string(),
        args: Some(vec![SyscallArg {
            index: 1,
            value: SOCK_RAW,
            op: "SCMP_CMP_MASKED_EQ".to_string(),
            value_two: Some(SOCK_TYPE_MASK),
        }]),
        errno_ret: Some(1), // EPERM
    });

    syscalls.push(SyscallRule {
        names: vec!["socket".to_string()],
        action: "SCMP_ACT_ERRNO".to_string(),
        args: Some(vec![SyscallArg {
            index: 1,
            value: SOCK_PACKET,
            op: "SCMP_CMP_MASKED_EQ".to_string(),
            value_two: Some(SOCK_TYPE_MASK),
        }]),
        errno_ret: Some(1), // EPERM
    });

    // Allow Landlock syscalls (required for puzzle-init shim)
    syscalls.push(SyscallRule {
        names: LANDLOCK_SYSCALLS.iter().map(|s| s.to_string()).collect(),
        action: "SCMP_ACT_ALLOW".to_string(),
        args: None,
        errno_ret: None,
    });

    // NOTIFY rules for daemon-mediated gating
    if include_notify {
        let mut notify_names: Vec<String> = NOTIFY_SYSCALLS.iter().map(|s| s.to_string()).collect();

        if include_clone_guard {
            notify_names.push("clone".to_string());
            notify_names.push("clone3".to_string());
        }

        syscalls.push(SyscallRule {
            names: notify_names,
            action: "SCMP_ACT_NOTIFY".to_string(),
            args: None,
            errno_ret: None,
        });
    }

    let listener_path = if include_notify {
        Some(listener_socket.to_string_lossy().to_string())
    } else {
        None
    };

    let listener_metadata = if include_notify {
        Some(serde_json::json!({ "branch_id": branch_id }).to_string())
    } else {
        None
    };

    // M6: SCMP_ACT_ALLOW as default action is deliberate. Seccomp is one layer
    // in a defense-in-depth stack: Landlock enforces filesystem access (< 1μs),
    // BPF LSM provides exec counting/rate limiting, and 57+ escape-vector syscalls
    // are explicitly denied via SCMP_ACT_KILL_PROCESS above. The default-allow
    // approach avoids breaking legitimate syscalls while still blocking known
    // dangerous ones — the alternative (default-deny with explicit allow) would
    // require maintaining a complete syscall allowlist that varies by workload.
    Ok(OciSeccompProfile {
        default_action: "SCMP_ACT_ALLOW".to_string(),
        listener_path,
        listener_metadata,
        architectures: vec![
            "SCMP_ARCH_X86_64".to_string(),
            "SCMP_ARCH_AARCH64".to_string(),
        ],
        syscalls,
    })
}

/// Write the seccomp profile to a file.
pub fn write_seccomp_profile(profile: &OciSeccompProfile, output_path: &Path) -> Result<PathBuf> {
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            PuzzledError::Sandbox(format!(
                "creating seccomp profile directory {}: {}",
                parent.display(),
                e
            ))
        })?;
    }

    let json = serde_json::to_string_pretty(profile)
        .map_err(|e| PuzzledError::Sandbox(format!("serializing seccomp profile: {}", e)))?;

    std::fs::write(output_path, &json).map_err(|e| {
        PuzzledError::Sandbox(format!(
            "writing seccomp profile to {}: {}",
            output_path.display(),
            e
        ))
    })?;

    Ok(output_path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_profile_structure_valid() {
        let profile = generate_seccomp_profile(
            "test-branch-123",
            Path::new("/run/puzzled/seccomp-notify.sock"),
            true,
            false,
        )
        .unwrap();

        assert_eq!(profile.default_action, "SCMP_ACT_ALLOW");
        assert!(profile.listener_path.is_some());
        assert!(profile.listener_metadata.is_some());
        assert_eq!(profile.architectures.len(), 2);
    }

    #[test]
    fn test_profile_has_notify_actions() {
        let profile = generate_seccomp_profile(
            "test-branch",
            Path::new("/run/puzzled/seccomp-notify.sock"),
            true,
            false,
        )
        .unwrap();

        let notify_rules: Vec<_> = profile
            .syscalls
            .iter()
            .filter(|r| r.action == "SCMP_ACT_NOTIFY")
            .collect();
        assert!(!notify_rules.is_empty(), "should have NOTIFY rules");

        let notify_names: Vec<&str> = notify_rules
            .iter()
            .flat_map(|r| r.names.iter().map(|s| s.as_str()))
            .collect();
        assert!(notify_names.contains(&"execve"));
        assert!(notify_names.contains(&"connect"));
        assert!(notify_names.contains(&"bind"));
    }

    #[test]
    fn test_profile_deny_list_complete() {
        let profile = generate_seccomp_profile(
            "test-branch",
            Path::new("/run/puzzled/seccomp-notify.sock"),
            true,
            false,
        )
        .unwrap();

        let deny_rules: Vec<_> = profile
            .syscalls
            .iter()
            .filter(|r| r.action == "SCMP_ACT_KILL_PROCESS" && r.args.is_none())
            .collect();
        assert!(
            !deny_rules.is_empty(),
            "deny rules must use SCMP_ACT_KILL_PROCESS, not ERRNO"
        );

        let deny_names: Vec<&str> = deny_rules
            .iter()
            .flat_map(|r| r.names.iter().map(|s| s.as_str()))
            .collect();
        assert!(deny_names.contains(&"ptrace"));
        assert!(deny_names.contains(&"mount"));
        assert!(deny_names.contains(&"bpf"));
        assert!(deny_names.contains(&"io_uring_setup"));
        assert!(deny_names.contains(&"memfd_create"));
        assert!(deny_names.contains(&"memfd_secret"));
    }

    #[test]
    fn test_profile_listener_path_set() {
        let profile = generate_seccomp_profile(
            "my-branch",
            Path::new("/run/puzzled/seccomp-notify.sock"),
            true,
            false,
        )
        .unwrap();

        assert_eq!(
            profile.listener_path.unwrap(),
            "/run/puzzled/seccomp-notify.sock"
        );

        let metadata: serde_json::Value =
            serde_json::from_str(&profile.listener_metadata.unwrap()).unwrap();
        assert_eq!(metadata["branch_id"], "my-branch");
    }

    #[test]
    fn test_profile_socket_filter_included() {
        let profile = generate_seccomp_profile(
            "test",
            Path::new("/run/puzzled/seccomp-notify.sock"),
            true,
            false,
        )
        .unwrap();

        let socket_rules: Vec<_> = profile
            .syscalls
            .iter()
            .filter(|r| r.names.contains(&"socket".to_string()) && r.args.is_some())
            .collect();
        assert_eq!(
            socket_rules.len(),
            2,
            "should have SOCK_RAW and SOCK_PACKET rules"
        );
    }

    #[test]
    fn test_static_only_profile_no_notify() {
        let profile = generate_seccomp_profile(
            "test",
            Path::new("/run/puzzled/seccomp-notify.sock"),
            false,
            false,
        )
        .unwrap();

        let notify_rules: Vec<_> = profile
            .syscalls
            .iter()
            .filter(|r| r.action == "SCMP_ACT_NOTIFY")
            .collect();
        assert!(
            notify_rules.is_empty(),
            "static-only should have no NOTIFY rules"
        );
        assert!(profile.listener_path.is_none());
        assert!(profile.listener_metadata.is_none());
    }

    #[test]
    fn test_profile_with_clone_guard() {
        let profile = generate_seccomp_profile(
            "test",
            Path::new("/run/puzzled/seccomp-notify.sock"),
            true,
            true,
        )
        .unwrap();

        let notify_rules: Vec<_> = profile
            .syscalls
            .iter()
            .filter(|r| r.action == "SCMP_ACT_NOTIFY")
            .collect();
        let notify_names: Vec<&str> = notify_rules
            .iter()
            .flat_map(|r| r.names.iter().map(|s| s.as_str()))
            .collect();
        assert!(notify_names.contains(&"clone"));
        assert!(notify_names.contains(&"clone3"));
    }

    #[test]
    fn test_profile_serializes_to_valid_json() {
        let profile = generate_seccomp_profile(
            "test",
            Path::new("/run/puzzled/seccomp-notify.sock"),
            true,
            false,
        )
        .unwrap();

        let json = serde_json::to_string_pretty(&profile).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["defaultAction"], "SCMP_ACT_ALLOW");
        assert!(parsed["syscalls"].is_array());
    }

    #[test]
    fn test_write_seccomp_profile_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let output_path = dir.path().join("seccomp.json");

        let profile = generate_seccomp_profile(
            "test",
            Path::new("/run/puzzled/seccomp-notify.sock"),
            true,
            false,
        )
        .unwrap();

        let path = write_seccomp_profile(&profile, &output_path).unwrap();
        assert!(path.exists());

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: OciSeccompProfile = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed.default_action, "SCMP_ACT_ALLOW");
    }

    #[test]
    fn test_landlock_syscalls_allowed() {
        let profile = generate_seccomp_profile(
            "test",
            Path::new("/run/puzzled/seccomp-notify.sock"),
            true,
            false,
        )
        .unwrap();

        let allow_rules: Vec<_> = profile
            .syscalls
            .iter()
            .filter(|r| r.action == "SCMP_ACT_ALLOW")
            .collect();
        let allow_names: Vec<&str> = allow_rules
            .iter()
            .flat_map(|r| r.names.iter().map(|s| s.as_str()))
            .collect();
        assert!(allow_names.contains(&"landlock_create_ruleset"));
        assert!(allow_names.contains(&"landlock_add_rule"));
        assert!(allow_names.contains(&"landlock_restrict_self"));
    }
}
