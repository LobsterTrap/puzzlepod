// SPDX-License-Identifier: Apache-2.0
pub(crate) mod filter;
mod notif;
mod procmem;
mod validate;

use crate::error::Result;

/// seccomp-BPF filter builder with dual-mode support:
///
/// **Permissive** (default-allow):
///   - Default action: **ALLOW**
///   - **KILL_PROCESS**: Known escape vectors (ptrace, mount, bpf, io_uring, ...)
///   - **USER_NOTIF**: High-impact syscalls gated through puzzled
///   - Unknown syscalls pass through — avoids silent workload failures
///
/// **Strict** (default-deny):
///   - Default action: **EPERM**
///   - **ALLOW**: Safe syscalls from a curated allowlist (~120 entries)
///   - **USER_NOTIF**: High-impact syscalls gated through puzzled
///   - **KILL_PROCESS**: Known escape vectors
///   - Novel/unknown syscalls return EPERM
///
/// Both modes share the same KillProcess deny list (escape vectors) and
/// USER_NOTIF list (execve, connect, bind). The difference is what happens
/// to syscalls not in any list: Permissive allows them, Strict returns EPERM.
///
/// Once loaded via `seccomp()`, the filter is irrevocable.
pub struct SeccompBuilder {
    /// SC2: Whether the BPF LSM clone guard is active.
    /// When false, clone3 is added to the seccomp USER_NOTIF list so
    /// namespace escape flags can be checked by the notification handler.
    pub bpf_clone_guard_active: bool,
    /// Filter strategy: Permissive (default-allow) or Strict (default-deny).
    pub seccomp_mode: puzzled_types::SeccompMode,
}

/// Syscalls blocked in the daemon self-hardening filter.
///
/// Issue #2: Aligned with agent DENY_SYSCALLS. The daemon runs as root and is
/// the governance authority — its compromise is worse than agent compromise.
/// Intentionally excluded (daemon needs post-hardening):
///   - mount, umount2: OverlayFS branch setup
///   - setns: network namespace setup
#[cfg_attr(not(test), allow(dead_code))]
const DAEMON_DENY_SYSCALLS: &[&str] = &[
    "ptrace",
    "kexec_load",
    "kexec_file_load",
    "init_module",
    "finit_module",
    "delete_module",
    "pivot_root",
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
    // io_uring bypasses seccomp entirely.
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    // Cross-process memory access bypasses namespace isolation.
    "process_vm_readv",
    "process_vm_writev",
    "kcmp",
    "add_key",
    "keyctl",
    "request_key",
    "personality",
    "syslog",
    "lookup_dcookie",
    // Handle-based file access bypasses Landlock path-based checks.
    "name_to_handle_at",
    "open_by_handle_at",
    // Fileless execution — memfd_create + execve bypasses Landlock.
    "memfd_create",
    // §3.4 G2: memfd_secret (kernel 5.14+) — similar bypass vector.
    "memfd_secret",
    "chroot",
    // Hostname manipulation — no legitimate daemon use.
    "sethostname",
    "setdomainname",
    // Time manipulation attacks.
    "settimeofday",
    "clock_settime",
    // SysV IPC.
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
    // R17: deprecated module/kernel syscalls (Docker default blocks these)
    "create_module",
    "get_kernel_syms",
    "query_module",
    // S21+S23+S24: Aligned with agent DENY_SYSCALLS additions.
    "_sysctl",
    "sysfs",
    "quotactl",
    "nfsservctl",
    "clock_adjtime",
    "get_mempolicy",
    "set_mempolicy",
    "mbind",
    "migrate_pages",
    "move_pages",
];

/// Syscalls intentionally excluded from the daemon deny list because the
/// daemon needs them after hardening is applied.
/// modify_ldt is handled separately with #[cfg(target_arch)] in apply_daemon_hardening,
/// so it appears here as an "exclusion" from the const list but is still blocked.
#[cfg(test)]
const DAEMON_INTENTIONAL_EXCLUSIONS: &[&str] = {
    #[cfg(target_arch = "x86_64")]
    {
        &[
            "mount",      // OverlayFS branch setup
            "umount2",    // OverlayFS cleanup
            "setns",      // network namespace setup
            "modify_ldt", // blocked separately via #[cfg(target_arch)] block
        ]
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        &[
            "mount",   // OverlayFS branch setup
            "umount2", // OverlayFS cleanup
            "setns",   // network namespace setup
        ]
    }
};

/// Apply a minimal seccomp hardening filter to the puzzled daemon itself.
///
/// Blocks syscalls that puzzled should never need (see [`DAEMON_DENY_SYSCALLS`]).
/// Uses KillProcess action — a denied escape-vector syscall indicates compromise.
/// This is a defense-in-depth measure — even if puzzled is compromised, it cannot
/// load kernel modules, reboot the system, or escape its namespace.
#[cfg(target_os = "linux")]
pub fn apply_daemon_hardening() -> Result<()> {
    use libseccomp::*;

    let mut filter = ScmpFilterContext::new_filter(ScmpAction::Allow).map_err(|e| {
        crate::error::PuzzledError::Sandbox(format!("creating daemon seccomp filter: {}", e))
    })?;

    // Issue #3: Use KillProcess instead of EPERM. A denied escape-vector
    // syscall in the daemon indicates compromise — the daemon should crash
    // immediately (triggering systemd restart and audit logging) rather than
    // continue running in a potentially compromised state.
    //
    // Issue #4: Fail hard on add_rule errors. Partial hardening is dangerous
    // and undetectable. If a deny rule cannot be added, startup must fail.
    for name in DAEMON_DENY_SYSCALLS {
        match ScmpSyscall::from_name(name) {
            Ok(syscall) => {
                filter
                    .add_rule(ScmpAction::KillProcess, syscall)
                    .map_err(|e| {
                        crate::error::PuzzledError::Sandbox(format!(
                            "adding daemon hardening rule for {}: {}",
                            name, e
                        ))
                    })?;
            }
            Err(e) => {
                return Err(crate::error::PuzzledError::Sandbox(format!(
                    "daemon hardening: syscall '{}' not found: {} \
                     (libseccomp may be too old or syscall name invalid)",
                    name, e
                )));
            }
        }
    }

    // x86_64-only: block modify_ldt (segmentation-based sandbox escapes).
    #[cfg(target_arch = "x86_64")]
    {
        let name = "modify_ldt";
        match ScmpSyscall::from_name(name) {
            Ok(syscall) => {
                filter
                    .add_rule(ScmpAction::KillProcess, syscall)
                    .map_err(|e| {
                        crate::error::PuzzledError::Sandbox(format!(
                            "adding daemon hardening rule for {}: {}",
                            name, e
                        ))
                    })?;
            }
            Err(e) => {
                return Err(crate::error::PuzzledError::Sandbox(format!(
                    "daemon hardening: syscall '{}' not found: {}",
                    name, e
                )));
            }
        }
    }

    filter.load().map_err(|e| {
        crate::error::PuzzledError::Sandbox(format!("loading daemon seccomp filter: {}", e))
    })?;

    tracing::info!(
        blocked = DAEMON_DENY_SYSCALLS.len(),
        "puzzled self-hardening seccomp filter loaded (KillProcess)"
    );
    Ok(())
}

/// No-op stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn apply_daemon_hardening() -> Result<()> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Seccomp notification ID validation
// ---------------------------------------------------------------------------

/// Validate that a seccomp notification ID is still valid (TOCTOU protection).
///
/// Uses `ioctl(SECCOMP_IOCTL_NOTIF_ID_VALID)` directly rather than relying on
/// libseccomp bindings, which may not expose this ioctl. The kernel checks that
/// the notification identified by `id` has not been invalidated (e.g., because
/// the notifying process exited or was killed between our /proc/pid/mem read
/// and our response).
///
/// Returns Ok(()) if the notification is still valid, Err otherwise.
#[cfg(target_os = "linux")]
#[allow(dead_code)] // Will be called from seccomp notification handler once wired up
fn notify_id_valid(notify_fd: i32, id: u64) -> std::result::Result<(), String> {
    // SECCOMP_IOCTL_NOTIF_ID_VALID is defined as SECCOMP_IOW(2, __u64)
    // which expands to _IOW('!', 2, u64) = 0x40082102 on most architectures.
    //
    // The ioctl takes a pointer to the notification ID (u64) and returns 0
    // if valid, or -1 with errno=ENOENT if the notification has expired.
    const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = 0x40082102;

    let mut check_id = id;
    // SAFETY: We pass a valid fd (the seccomp notify fd) and a pointer to a
    // stack-allocated u64 with the correct ioctl number. The kernel will read
    // the u64 value and validate it against its internal notification table.
    let ret = unsafe {
        libc::ioctl(
            notify_fd,
            SECCOMP_IOCTL_NOTIF_ID_VALID as libc::c_ulong,
            &mut check_id as *mut u64,
        )
    };

    if ret == 0 {
        Ok(())
    } else {
        let errno = std::io::Error::last_os_error();
        Err(format!("notification id {} no longer valid: {}", id, errno))
    }
}

/// Non-Linux stub — always returns error since seccomp is Linux-only.
#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
fn notify_id_valid(_notify_fd: i32, _id: u64) -> std::result::Result<(), String> {
    Err("seccomp notification validation requires Linux".to_string())
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::SeccompBuilder;
    use puzzled_types::{AgentProfile, SeccompMode};

    #[test]
    fn test_validate_execve_empty_allowlist() {
        let profile = AgentProfile {
            name: "test".to_string(),
            description: "test".to_string(),
            filesystem: puzzled_types::FilesystemRules {
                read_allowlist: vec![],
                write_allowlist: vec![],
                denylist: vec![],
                read_denylist: vec![],
                write_denylist: vec![],
            },
            exec_allowlist: vec![],
            exec_denylist: vec![],
            resource_limits: Default::default(),
            network: puzzled_types::NetworkConfig {
                mode: puzzled_types::NetworkMode::Blocked,
                allowed_domains: vec![],
                data_residency: None,
                dlp_rules_path: None,
            },
            behavioral: Default::default(),
            fail_mode: puzzled_types::FailMode::FailClosed,
            capabilities: vec![],
            enforcement: Default::default(),
            seccomp_mode: SeccompMode::default(),
            allow_symlinks: false,
            allow_exec_overlay: false,
            credentials: None,
            extends: None,
        };

        // Can't actually test proc mem reading without a real process,
        // but we verify the allowlist logic
        assert!(profile.exec_allowlist.is_empty());
    }

    #[test]
    fn test_exec_allowlist_matching() {
        let patterns = [
            "/usr/bin/python3".to_string(),
            "/usr/bin/cat".to_string(),
            "/usr/local/bin/*".to_string(),
        ];

        // Exact match
        assert!(patterns.iter().any(|p| {
            if p.ends_with('*') {
                "/usr/bin/python3".starts_with(&p[..p.len() - 1])
            } else {
                "/usr/bin/python3" == *p
            }
        }));

        // Glob match
        assert!(patterns.iter().any(|p| {
            if p.ends_with('*') {
                "/usr/local/bin/myapp".starts_with(&p[..p.len() - 1])
            } else {
                "/usr/local/bin/myapp" == *p
            }
        }));

        // No match
        assert!(!patterns.iter().any(|p| {
            if p.ends_with('*') {
                "/usr/sbin/reboot".starts_with(&p[..p.len() - 1])
            } else {
                "/usr/sbin/reboot" == *p
            }
        }));
    }

    /// Helper to check if a path matches an allowlist (mirrors validate_execve logic).
    ///
    /// Note: In the real validate_execve, paths are canonicalized via
    /// /proc/<pid>/root before matching. This helper tests the post-
    /// canonicalization matching logic only.
    fn path_matches_allowlist(path: &str, allowlist: &[String]) -> bool {
        if allowlist.is_empty() {
            return false;
        }
        allowlist.iter().any(|pattern| {
            if pattern.ends_with('*') {
                let prefix = &pattern[..pattern.len() - 1];
                path.starts_with(prefix)
            } else {
                path == *pattern
            }
        })
    }

    #[test]
    fn test_exec_allowlist_empty_pattern() {
        // An empty allowlist should deny everything
        let allowlist: Vec<String> = vec![];
        assert!(!path_matches_allowlist("/usr/bin/cat", &allowlist));
        assert!(!path_matches_allowlist("", &allowlist));
    }

    #[test]
    fn test_exec_allowlist_root_path() {
        let allowlist = vec!["/usr/bin/*".to_string()];
        // Root path should not match /usr/bin/* prefix
        assert!(!path_matches_allowlist("/", &allowlist));
    }

    #[test]
    fn test_exec_allowlist_path_traversal() {
        let allowlist = vec!["/usr/bin/*".to_string()];
        // Relative path traversal attempt should not match /usr/bin/*
        assert!(!path_matches_allowlist("../../etc/passwd", &allowlist));
        // After canonicalization in validate_execve, /usr/bin/../../etc/passwd
        // resolves to /etc/passwd, which does NOT match /usr/bin/*.
        // This test verifies the post-canonicalization matching:
        assert!(
            !path_matches_allowlist("/etc/passwd", &allowlist),
            "canonicalized traversal path should not match /usr/bin/*"
        );
        // The raw string still matches the prefix, but validate_execve now
        // canonicalizes before matching, preventing this bypass.
        assert!(
            path_matches_allowlist("/usr/bin/../../etc/passwd", &allowlist),
            "raw string still matches prefix (validate_execve canonicalizes first)"
        );
    }

    /// Verify the deny list includes all known escape vectors.
    ///
    /// This test documents the minimum set of blocked syscalls. If a new
    /// escape vector is discovered, add it to the deny list AND to this test.
    #[test]
    fn test_deny_list_includes_critical_escape_vectors() {
        let critical_syscalls = [
            "ptrace",            // process tracing / debugging
            "mount",             // filesystem manipulation
            "umount2",           // filesystem manipulation
            "setns",             // namespace escape
            "unshare",           // namespace creation
            "bpf",               // BPF program loading
            "init_module",       // kernel module loading
            "finit_module",      // kernel module loading
            "kexec_load",        // kernel replacement
            "io_uring_setup",    // seccomp bypass via io_uring
            "process_vm_readv",  // cross-process memory read
            "process_vm_writev", // cross-process memory write
            "memfd_create",      // fileless execution
            "memfd_secret",      // §3.4 G2: sealed anonymous memory (kernel 5.14+)
            "open_by_handle_at", // Landlock bypass via handles
            "name_to_handle_at", // Landlock bypass via handles
            "chroot",            // container/namespace escape
            "settimeofday",      // time manipulation attack
            "clock_settime",     // time manipulation attack
                                 // NOTE: clone and clone3 are intentionally NOT blocked — they are
                                 // needed for thread creation. Namespace escape via clone flags is
                                 // handled by argument filtering / BPF LSM.
        ];

        // DENY_SYSCALLS is a module-level constant in filter.rs. Verify it
        // contains all critical escape vectors via source inspection.
        let source = include_str!("filter.rs");
        for syscall in &critical_syscalls {
            assert!(
                source.contains(&format!("\"{}\"", syscall)),
                "critical escape vector '{}' missing from seccomp deny list",
                syscall
            );
        }
    }

    /// Verify the deny list has at least 67 entries (S21+S23+S24).
    #[test]
    fn test_deny_list_minimum_size() {
        let source = include_str!("filter.rs");

        let start = source
            .find("const DENY_SYSCALLS: &[&str] = &[")
            .expect("DENY_SYSCALLS not found");
        let block = &source[start..];
        let end = block
            .find("];")
            .expect("DENY_SYSCALLS closing bracket not found");
        let array_text = &block[..end];

        // Count quoted syscall names
        let count = array_text.matches('"').count() / 2; // each name has open + close quote
                                                         // 67 on non-x86_64, 68 on x86_64 (includes modify_ldt)
        assert!(
            count >= 67,
            "expected at least 67 syscalls in deny list, found {}",
            count
        );
    }

    /// Verify the allowlist has at least 100 entries (the minimum safe set
    /// needed for agents to perform I/O, memory management, signals, etc.).
    #[test]
    fn test_allowlist_minimum_size() {
        let source = include_str!("filter.rs");

        let start = source
            .find("const ALLOW_SYSCALLS: &[&str] = &[")
            .expect("ALLOW_SYSCALLS not found");
        let block = &source[start..];
        let end = block
            .find("];")
            .expect("ALLOW_SYSCALLS closing bracket not found");
        let array_text = &block[..end];

        let count = array_text.matches('"').count() / 2;
        assert!(
            count >= 100,
            "expected at least 100 syscalls in allowlist, found {}",
            count
        );
    }

    /// Verify the allowlist does NOT contain syscalls that should be gated or denied.
    #[test]
    fn test_allowlist_excludes_gated_syscalls() {
        let source = include_str!("filter.rs");

        let start = source
            .find("const ALLOW_SYSCALLS: &[&str] = &[")
            .expect("ALLOW_SYSCALLS not found");
        let block = &source[start..];
        let end = block
            .find("];")
            .expect("ALLOW_SYSCALLS closing bracket not found");
        let allowlist_text = &block[..end];

        // These must NOT be in the allowlist — they are handled separately
        let forbidden_in_allowlist = [
            "execve",         // USER_NOTIF gated
            "execveat",       // USER_NOTIF gated
            "connect",        // USER_NOTIF gated
            "bind",           // USER_NOTIF gated
            "ptrace",         // KillProcess
            "mount",          // KillProcess
            "bpf",            // KillProcess
            "io_uring_setup", // KillProcess
            "memfd_create",   // KillProcess
        ];

        for name in &forbidden_in_allowlist {
            assert!(
                !allowlist_text.contains(&format!("\"{}\"", name)),
                "syscall '{}' must NOT be in ALLOW_SYSCALLS (handled by notify/deny tier)",
                name
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_seccomp_apply_non_linux() {
        let profile = AgentProfile {
            name: "test".to_string(),
            description: "test".to_string(),
            filesystem: puzzled_types::FilesystemRules {
                read_allowlist: vec![],
                write_allowlist: vec![],
                denylist: vec![],
                read_denylist: vec![],
                write_denylist: vec![],
            },
            exec_allowlist: vec![],
            exec_denylist: vec![],
            resource_limits: Default::default(),
            network: puzzled_types::NetworkConfig {
                mode: puzzled_types::NetworkMode::Blocked,
                allowed_domains: vec![],
                data_residency: None,
                dlp_rules_path: None,
            },
            behavioral: Default::default(),
            fail_mode: puzzled_types::FailMode::FailClosed,
            capabilities: vec![],
            enforcement: Default::default(),
            seccomp_mode: SeccompMode::default(),
            allow_symlinks: false,
            allow_exec_overlay: false,
            credentials: None,
            extends: None,
        };

        let builder = SeccompBuilder {
            bpf_clone_guard_active: true,
            seccomp_mode: SeccompMode::Strict,
        };
        let result = builder.apply(&profile);
        assert!(result.is_err(), "apply should return error on non-Linux");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_apply_daemon_hardening_non_linux() {
        // On non-Linux, apply_daemon_hardening is a no-op that returns Ok
        let result = super::apply_daemon_hardening();
        assert!(
            result.is_ok(),
            "daemon hardening should be no-op on non-Linux"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_notify_id_valid_non_linux() {
        // On non-Linux, notify_id_valid always returns Err
        let result = super::notify_id_valid(3, 42);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.contains("requires Linux"),
            "error should mention Linux, got: {}",
            msg
        );
    }

    #[test]
    fn test_seccomp_builder_fields() {
        let builder = SeccompBuilder {
            bpf_clone_guard_active: true,
            seccomp_mode: SeccompMode::Permissive,
        };
        assert!(builder.bpf_clone_guard_active);
        assert_eq!(builder.seccomp_mode, SeccompMode::Permissive);

        let builder = SeccompBuilder {
            bpf_clone_guard_active: false,
            seccomp_mode: SeccompMode::Strict,
        };
        assert!(!builder.bpf_clone_guard_active);
        assert_eq!(builder.seccomp_mode, SeccompMode::Strict);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_seccomp_apply_error_message() {
        let profile = AgentProfile {
            name: "test".to_string(),
            description: "test".to_string(),
            filesystem: puzzled_types::FilesystemRules {
                read_allowlist: vec![],
                write_allowlist: vec![],
                denylist: vec![],
                read_denylist: vec![],
                write_denylist: vec![],
            },
            exec_allowlist: vec![],
            exec_denylist: vec![],
            resource_limits: Default::default(),
            network: puzzled_types::NetworkConfig {
                mode: puzzled_types::NetworkMode::Blocked,
                allowed_domains: vec![],
                data_residency: None,
                dlp_rules_path: None,
            },
            behavioral: Default::default(),
            fail_mode: puzzled_types::FailMode::FailClosed,
            capabilities: vec![],
            enforcement: Default::default(),
            seccomp_mode: SeccompMode::default(),
            allow_symlinks: false,
            allow_exec_overlay: false,
            credentials: None,
            extends: None,
        };

        let builder = SeccompBuilder {
            bpf_clone_guard_active: false,
            seccomp_mode: SeccompMode::Permissive,
        };
        let err = builder.apply(&profile).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("seccomp requires Linux"),
            "error should mention Linux, got: {}",
            msg
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_seccomp_handle_notification_non_linux() {
        let profile = AgentProfile {
            name: "test".to_string(),
            description: "test".to_string(),
            filesystem: puzzled_types::FilesystemRules {
                read_allowlist: vec![],
                write_allowlist: vec![],
                denylist: vec![],
                read_denylist: vec![],
                write_denylist: vec![],
            },
            exec_allowlist: vec![],
            exec_denylist: vec![],
            resource_limits: Default::default(),
            network: puzzled_types::NetworkConfig {
                mode: puzzled_types::NetworkMode::Blocked,
                allowed_domains: vec![],
                data_residency: None,
                dlp_rules_path: None,
            },
            behavioral: Default::default(),
            fail_mode: puzzled_types::FailMode::FailClosed,
            capabilities: vec![],
            enforcement: Default::default(),
            seccomp_mode: SeccompMode::default(),
            allow_symlinks: false,
            allow_exec_overlay: false,
            credentials: None,
            extends: None,
        };

        let exec_count = std::sync::atomic::AtomicU64::new(0);
        let result = SeccompBuilder::handle_notification_counted(
            3,
            &profile,
            &exec_count,
            100,
            None,
            std::time::Instant::now(),
        );
        assert!(
            result.is_err(),
            "handle_notification_counted should return error on non-Linux"
        );
    }

    /// S8: Verify all USER_NOTIF syscall paths have H-23 timeout enforcement.
    /// Legacy clone was missing timeout — this test ensures it's present
    /// for all syscall handlers that read from process memory or validate args.
    #[test]
    fn test_s8_all_notif_syscalls_have_h23_timeout() {
        let source = include_str!("notif.rs");
        // Each syscall branch that validates arguments should check timeout.
        // The timeout pattern is "entry_time.elapsed() > NOTIFICATION_TIMEOUT"
        let timeout_checks = source
            .matches("entry_time.elapsed() > NOTIFICATION_TIMEOUT")
            .count();
        // Expected: execve (3 checks), execveat (3 checks), connect (1), clone3 (1),
        // clone (1), bind (1) = 10 total
        assert!(
            timeout_checks >= 10,
            "S8: expected at least 10 H-23 timeout checks across all syscall handlers, \
             found {} — legacy clone or other paths may be missing timeout enforcement",
            timeout_checks
        );
    }

    // ── Daemon hardening deny list validation tests ──────────────────────
    // These tests validate the DAEMON_DENY_SYSCALLS list against the agent
    // DENY_SYSCALLS list to prevent drift between the two.

    #[test]
    fn test_daemon_deny_list_is_subset_of_agent_deny_list() {
        // Every syscall in the daemon deny list must also be in the agent
        // deny list. If something is dangerous enough to block for the
        // daemon, it should also be blocked for agents.
        let agent_set: std::collections::HashSet<&str> =
            super::filter::DENY_SYSCALLS.iter().copied().collect();
        for syscall in super::DAEMON_DENY_SYSCALLS {
            assert!(
                agent_set.contains(syscall),
                "daemon deny list contains '{}' which is not in agent DENY_SYSCALLS — \
                 either add it to filter.rs DENY_SYSCALLS or remove it from DAEMON_DENY_SYSCALLS",
                syscall
            );
        }
    }

    #[test]
    fn test_daemon_deny_list_exclusions_are_intentional() {
        // The daemon intentionally excludes mount, umount2, setns because it
        // needs them for OverlayFS and network namespace setup. Verify that
        // every agent deny syscall NOT in the daemon list is in the
        // intentional exclusion list.
        let daemon_set: std::collections::HashSet<&str> =
            super::DAEMON_DENY_SYSCALLS.iter().copied().collect();
        let exclusion_set: std::collections::HashSet<&str> = super::DAEMON_INTENTIONAL_EXCLUSIONS
            .iter()
            .copied()
            .collect();

        for syscall in super::filter::DENY_SYSCALLS {
            if !daemon_set.contains(syscall) {
                assert!(
                    exclusion_set.contains(syscall),
                    "agent DENY_SYSCALLS contains '{}' which is missing from both \
                     DAEMON_DENY_SYSCALLS and DAEMON_INTENTIONAL_EXCLUSIONS — \
                     either add it to the daemon deny list or document why it's excluded",
                    syscall
                );
            }
        }
    }

    #[test]
    fn test_daemon_deny_list_minimum_count() {
        // Guard against accidental truncation. The daemon list should have
        // at least 40 entries (currently 48).
        assert!(
            super::DAEMON_DENY_SYSCALLS.len() >= 40,
            "daemon deny list has only {} entries (expected >= 40) — \
             was the list accidentally truncated?",
            super::DAEMON_DENY_SYSCALLS.len()
        );
    }

    #[test]
    fn test_daemon_deny_list_has_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for syscall in super::DAEMON_DENY_SYSCALLS {
            assert!(
                seen.insert(syscall),
                "duplicate entry '{}' in DAEMON_DENY_SYSCALLS",
                syscall
            );
        }
    }

    #[test]
    fn test_daemon_intentional_exclusions_are_in_agent_list() {
        // Every intentional exclusion must actually exist in the agent deny
        // list — otherwise the exclusion is stale.
        let agent_set: std::collections::HashSet<&str> =
            super::filter::DENY_SYSCALLS.iter().copied().collect();
        for syscall in super::DAEMON_INTENTIONAL_EXCLUSIONS {
            assert!(
                agent_set.contains(syscall),
                "DAEMON_INTENTIONAL_EXCLUSIONS contains '{}' which is not in agent \
                 DENY_SYSCALLS — remove the stale exclusion",
                syscall
            );
        }
    }

    // ── Issue #5: USER_NOTIF syscall name validation ────────────────────

    #[test]
    fn test_notif_syscall_names_are_complete() {
        // Verify that all 6 expected syscall names are in the constant.
        let names: std::collections::HashSet<&str> =
            super::notif::NOTIF_SYSCALL_NAMES.iter().copied().collect();
        for expected in &["execve", "execveat", "connect", "bind", "clone3", "clone"] {
            assert!(
                names.contains(expected),
                "NOTIF_SYSCALL_NAMES is missing '{}' — the handler won't match it",
                expected
            );
        }
    }

    #[test]
    fn test_notif_syscall_names_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for name in super::notif::NOTIF_SYSCALL_NAMES {
            assert!(
                seen.insert(name),
                "duplicate '{}' in NOTIF_SYSCALL_NAMES",
                name
            );
        }
    }

    #[test]
    fn test_notif_syscall_names_match_filter_notify_list() {
        // The USER_NOTIF syscalls in filter.rs should be a subset of
        // NOTIF_SYSCALL_NAMES — ensures the handler can process everything
        // the filter sends via USER_NOTIF.
        let notif_names: std::collections::HashSet<&str> =
            super::notif::NOTIF_SYSCALL_NAMES.iter().copied().collect();
        // The filter always adds execve, execveat, connect, bind to USER_NOTIF.
        // clone3 and clone are added conditionally (when BPF clone guard inactive).
        for expected in &["execve", "execveat", "connect", "bind"] {
            assert!(
                notif_names.contains(expected),
                "filter.rs adds '{}' to USER_NOTIF but NOTIF_SYSCALL_NAMES doesn't include it",
                expected
            );
        }
    }

    // ── R17: Verify deprecated module syscalls are in DENY_SYSCALLS ──

    #[test]
    fn test_r17_deny_list_includes_deprecated_module_syscalls() {
        for syscall in &["create_module", "get_kernel_syms", "query_module"] {
            assert!(
                super::filter::DENY_SYSCALLS.contains(syscall),
                "DENY_SYSCALLS must include {} (deprecated module syscall, Docker blocks it)",
                syscall
            );
        }
    }

    // ── Issue #15: Verify critical escape vectors are in DENY_SYSCALLS ──

    #[test]
    fn test_deny_list_includes_pivot_root() {
        assert!(
            super::filter::DENY_SYSCALLS.contains(&"pivot_root"),
            "DENY_SYSCALLS must include pivot_root (container/namespace escape)"
        );
    }

    #[test]
    fn test_deny_list_includes_chroot() {
        assert!(
            super::filter::DENY_SYSCALLS.contains(&"chroot"),
            "DENY_SYSCALLS must include chroot (container/namespace escape)"
        );
    }

    #[test]
    fn test_deny_list_includes_memfd_create() {
        assert!(
            super::filter::DENY_SYSCALLS.contains(&"memfd_create"),
            "DENY_SYSCALLS must include memfd_create (fileless execution bypasses Landlock)"
        );
    }

    /// §3.4 G2: memfd_secret (kernel 5.14+) creates sealed anonymous memory regions.
    /// Similar bypass vector to memfd_create for credential exfiltration.
    #[test]
    fn test_deny_list_includes_memfd_secret() {
        assert!(
            super::filter::DENY_SYSCALLS.contains(&"memfd_secret"),
            "DENY_SYSCALLS must include memfd_secret (sealed anonymous memory, kernel 5.14+)"
        );
    }

    #[test]
    fn test_deny_list_includes_io_uring() {
        // io_uring bypasses seccomp entirely — all three syscalls must be blocked
        for syscall in &["io_uring_setup", "io_uring_enter", "io_uring_register"] {
            assert!(
                super::filter::DENY_SYSCALLS.contains(syscall),
                "DENY_SYSCALLS must include {} (seccomp bypass vector)",
                syscall
            );
        }
    }

    #[test]
    fn test_deny_list_includes_process_vm_access() {
        for syscall in &["process_vm_readv", "process_vm_writev"] {
            assert!(
                super::filter::DENY_SYSCALLS.contains(syscall),
                "DENY_SYSCALLS must include {} (cross-process memory access)",
                syscall
            );
        }
    }

    // ── S21+S23+S24: Verify newly added deny syscalls ──────────────────

    #[test]
    fn test_deny_list_includes_sysctl_and_sysfs() {
        for syscall in &["_sysctl", "sysfs"] {
            assert!(
                super::filter::DENY_SYSCALLS.contains(syscall),
                "DENY_SYSCALLS must include {} (kernel parameter/structure access)",
                syscall
            );
        }
    }

    #[test]
    fn test_deny_list_includes_quotactl() {
        assert!(
            super::filter::DENY_SYSCALLS.contains(&"quotactl"),
            "DENY_SYSCALLS must include quotactl (DoS via quota exhaustion)"
        );
    }

    #[test]
    fn test_deny_list_includes_nfsservctl() {
        assert!(
            super::filter::DENY_SYSCALLS.contains(&"nfsservctl"),
            "DENY_SYSCALLS must include nfsservctl (deprecated NFS server ops)"
        );
    }

    #[test]
    fn test_deny_list_includes_clock_adjtime() {
        assert!(
            super::filter::DENY_SYSCALLS.contains(&"clock_adjtime"),
            "DENY_SYSCALLS must include clock_adjtime (timing attacks)"
        );
    }

    #[test]
    fn test_deny_list_includes_numa_memory_policy() {
        for syscall in &[
            "get_mempolicy",
            "set_mempolicy",
            "mbind",
            "migrate_pages",
            "move_pages",
        ] {
            assert!(
                super::filter::DENY_SYSCALLS.contains(syscall),
                "DENY_SYSCALLS must include {} (NUMA memory policy — info leak / resource exhaustion)",
                syscall
            );
        }
    }
}
