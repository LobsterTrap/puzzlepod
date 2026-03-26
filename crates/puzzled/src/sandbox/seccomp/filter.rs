// SPDX-License-Identifier: Apache-2.0
use puzzled_types::AgentProfile;
#[cfg(target_os = "linux")]
use puzzled_types::SeccompMode;

use crate::error::Result;

/// Safe syscalls allowed for sandboxed agent processes (used in Strict mode).
///
/// This allowlist defines the minimum set of syscalls needed for agents to
/// perform file I/O, memory management, process lifecycle, signals, networking
/// (gated at other layers), and threading. In Strict mode, anything not in
/// this list, the USER_NOTIF list, or the KillProcess deny list returns EPERM.
///
/// In Permissive mode this list is ignored — all non-denied, non-notified
/// syscalls are allowed by default.
#[cfg(target_os = "linux")]
const ALLOW_SYSCALLS: &[&str] = &[
    // Core I/O
    "read",
    "write",
    "open",
    "close",
    "openat",
    "creat",
    "pread64",
    "pwrite64",
    "readv",
    "writev",
    "lseek",
    "sendfile",
    // File metadata
    "stat",
    "fstat",
    "lstat",
    "newfstatat",
    "statx",
    "statfs",
    "fstatfs",
    "access",
    "faccessat",
    "faccessat2",
    // File operations
    "truncate",
    "ftruncate",
    "rename",
    "renameat",
    "renameat2",
    "mkdir",
    "mkdirat",
    "rmdir",
    "link",
    "linkat",
    "unlink",
    "unlinkat",
    "symlinkat",
    "readlink",
    "readlinkat",
    "chmod",
    "fchmod",
    "fchmodat",
    "chown",
    "fchown",
    "fchownat",
    "mknodat",
    "umask",
    "utimensat",
    // Directory
    "getdents",
    "getdents64",
    "getcwd",
    "chdir",
    // File locking and sync
    "flock",
    "fsync",
    "fdatasync",
    // File descriptors and multiplexing
    "dup",
    "dup2",
    "dup3",
    "fcntl",
    "pipe",
    "pipe2",
    "epoll_create1",
    "epoll_ctl",
    "epoll_wait",
    "epoll_pwait",
    "eventfd",
    "eventfd2",
    "select",
    "pselect6",
    "poll",
    "ppoll",
    "close_range",
    "copy_file_range",
    // Memory management
    "mmap",
    "mprotect",
    "munmap",
    "brk",
    "mremap",
    "madvise",
    "mlock",
    "munlock",
    "mincore",
    // Signals
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "rt_sigsuspend",
    "rt_sigpending",
    "rt_sigtimedwait",
    "sigaltstack",
    "kill",
    "tgkill",
    "alarm",
    // Process lifecycle (fork/vfork always allowed; clone/clone3 handled
    // separately — allowed when BPF clone guard is active, USER_NOTIF otherwise)
    "fork",
    "vfork",
    "exit",
    "exit_group",
    "wait4",
    "waitid",
    "getpid",
    "gettid",
    "getppid",
    "getpgrp",
    "setpgid",
    "setsid",
    "getsid",
    // Scheduling and time
    "sched_yield",
    "sched_getaffinity",
    "nanosleep",
    "clock_gettime",
    "clock_getres",
    "clock_nanosleep",
    "gettimeofday",
    "rseq",
    // System info
    "uname",
    "sysinfo",
    "getrlimit",
    "prlimit64",
    "getrandom",
    // Credentials (setuid/setgid for privilege drop; escalation prevented by
    // no_new_privs which is set before the seccomp filter is loaded)
    "getuid",
    "geteuid",
    "getgid",
    "getegid",
    "setuid",
    "setgid",
    "getresuid",
    "getresgid",
    "setresuid",
    "setresgid",
    // Threading primitives
    "set_tid_address",
    "futex",
    "arch_prctl",
    "prctl",
    "set_robust_list",
    "get_robust_list",
    "membarrier",
    // Network I/O — connect/bind are NOT here (gated via USER_NOTIF).
    // Network namespace blocks all traffic in Blocked mode; these syscalls
    // are needed for Gated/Monitored/Unrestricted modes.
    "socket",
    "socketpair",
    "listen",
    "accept4",
    "shutdown",
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "getsockopt",
    "setsockopt",
    "getsockname",
    "getpeername",
    // I/O control (operates on fds already constrained by Landlock)
    "ioctl",
    // POSIX timers
    "timer_create",
    "timer_settime",
    "timer_gettime",
    "timer_getoverrun",
    "timer_delete",
];

/// Escape-vector syscalls killed unconditionally in both Permissive and Strict
/// modes. KillProcess is used instead of EPERM because a denied escape-vector
/// syscall indicates a compromised or malicious agent.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) const DENY_SYSCALLS: &[&str] = &[
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
    // io_uring bypasses seccomp entirely — operations submitted via
    // submission queues are executed by the kernel asynchronously.
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    // Cross-process memory access bypasses namespace and Landlock isolation.
    "process_vm_readv",
    "process_vm_writev",
    // Process comparison info leak — can reveal PID namespace mappings.
    "kcmp",
    // Keyring manipulation.
    "add_key",
    "keyctl",
    "request_key",
    // Execution domain change — can alter syscall behavior.
    "personality",
    // Kernel log access — information leak vector.
    "syslog",
    // Kernel profiling info leak.
    "lookup_dcookie",
    // Handle-based file access bypasses Landlock path-based checks.
    "name_to_handle_at",
    "open_by_handle_at",
    // Fileless execution — memfd_create + execve bypasses Landlock write controls.
    "memfd_create",
    // §3.4 G2: memfd_secret creates sealed anonymous memory regions (kernel 5.14+),
    // similar bypass vector to memfd_create for credential exfiltration.
    "memfd_secret",
    // Container/namespace escape.
    "chroot",
    // Time manipulation attacks (Kerberos replay, log tampering, cert bypass).
    "settimeofday",
    "clock_settime",
    // SysV IPC — defense-in-depth alongside CLONE_NEWIPC.
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
    // S21+S23+S24: Syscalls that Docker blocks but were missing from our list.
    // Kernel parameter manipulation — direct sysctl read/write.
    "_sysctl",
    // Kernel internal structure access — bypasses /proc restrictions.
    "sysfs",
    // Disk quota manipulation — potential DoS via quota exhaustion.
    "quotactl",
    // NFS server operations — deprecated, no legitimate agent use.
    "nfsservctl",
    // NTP clock adjustment — timing attacks (defense-in-depth with clock_settime).
    "clock_adjtime",
    // NUMA memory policy — information leak + potential resource exhaustion.
    "get_mempolicy",
    "set_mempolicy",
    "mbind",
    "migrate_pages",
    "move_pages",
    // modify_ldt — x86_64 only. Allows modifying the Local Descriptor Table,
    // which can be used for segmentation-based sandbox escapes.
    #[cfg(target_arch = "x86_64")]
    "modify_ldt",
    // R17: deprecated module/kernel syscalls (Docker default blocks these)
    "create_module",
    "get_kernel_syms",
    "query_module",
];

impl super::SeccompBuilder {
    /// Build and load a seccomp-BPF filter.
    ///
    /// The filter strategy depends on `self.seccomp_mode`:
    ///
    /// **Permissive** (default-allow):
    ///   - Default: ALLOW
    ///   - KILL_PROCESS for escape vectors ([`DENY_SYSCALLS`])
    ///   - USER_NOTIF for execve/connect/bind (+ clone when BPF guard inactive)
    ///   - Raw socket blocking via argument filtering
    ///
    /// **Strict** (default-deny):
    ///   - Default: EPERM
    ///   - ALLOW for curated allowlist ([`ALLOW_SYSCALLS`])
    ///   - KILL_PROCESS for escape vectors ([`DENY_SYSCALLS`])
    ///   - USER_NOTIF for execve/connect/bind (+ clone when BPF guard inactive)
    ///   - Raw socket blocking via argument filtering
    ///
    /// Returns the USER_NOTIF file descriptor for puzzled to poll.
    /// Requires libseccomp >= 2.5.0 for USER_NOTIF support (get_notify_fd).
    #[cfg(target_os = "linux")]
    pub fn apply(&self, _profile: &AgentProfile) -> Result<Option<i32>> {
        use libseccomp::*;

        let default_action = match self.seccomp_mode {
            SeccompMode::Permissive => ScmpAction::Allow,
            SeccompMode::Strict => ScmpAction::Errno(libc::EPERM),
        };

        let mut filter = ScmpFilterContext::new_filter(default_action).map_err(|e| {
            crate::error::PuzzledError::Sandbox(format!("creating seccomp filter: {}", e))
        })?;

        // ── Tier 1: Allowlist (Strict mode only) ──────────────────────────
        // In Permissive mode the default action is ALLOW, so we skip this.
        let mut allow_count = 0usize;
        if self.seccomp_mode == SeccompMode::Strict {
            for syscall_name in ALLOW_SYSCALLS {
                match ScmpSyscall::from_name(syscall_name) {
                    Ok(syscall) => {
                        filter.add_rule(ScmpAction::Allow, syscall).map_err(|e| {
                            crate::error::PuzzledError::Sandbox(format!(
                                "adding seccomp allow rule for {}: {}",
                                syscall_name, e
                            ))
                        })?;
                        allow_count += 1;
                    }
                    Err(e) => {
                        tracing::debug!(
                            syscall = syscall_name,
                            error = %e,
                            "skipping syscall not available on this architecture"
                        );
                    }
                }
            }
        }

        // clone/clone3: when BPF clone guard is active, allow directly (BPF
        // LSM filters flags). In Permissive mode they're already allowed by
        // default; in Strict mode we need an explicit rule.
        // NOTE: clone and clone3 are intentionally NOT in the deny list.
        // Agents need clone/clone3 for thread creation (CLONE_VM|CLONE_FS).
        // Namespace escape via clone flags (CLONE_NEWNS, CLONE_NEWPID, etc.)
        // is prevented by the seccomp USER_NOTIF handler or BPF LSM argument
        // filtering — blocking clone entirely would prevent any multi-threaded
        // workload from functioning. The unshare and setns syscalls remain
        // blocked to cover the other namespace escape vectors.
        if self.bpf_clone_guard_active && self.seccomp_mode == SeccompMode::Strict {
            for name in &["clone", "clone3"] {
                if let Ok(syscall) = ScmpSyscall::from_name(name) {
                    filter.add_rule(ScmpAction::Allow, syscall).map_err(|e| {
                        crate::error::PuzzledError::Sandbox(format!(
                            "adding seccomp allow rule for {}: {}",
                            name, e
                        ))
                    })?;
                    allow_count += 1;
                }
            }
        }

        // ── Tier 3: KillProcess deny list (both modes) ───────────────────
        for syscall_name in DENY_SYSCALLS {
            match ScmpSyscall::from_name(syscall_name) {
                Ok(syscall) => {
                    filter
                        .add_rule(ScmpAction::KillProcess, syscall)
                        .map_err(|e| {
                            crate::error::PuzzledError::Sandbox(format!(
                                "adding seccomp deny rule for {}: {}",
                                syscall_name, e
                            ))
                        })?;
                }
                Err(e) => {
                    return Err(crate::error::PuzzledError::Sandbox(format!(
                        "seccomp deny rule for '{}' failed: {} \
                         (libseccomp may be too old or syscall name invalid)",
                        syscall_name, e
                    )));
                }
            }
        }

        // ── Raw socket blocking (both modes) ──────────────────────────────
        // socket(domain, type, protocol) — arg1 (type) is checked for
        // SOCK_RAW and SOCK_PACKET. MaskedEqual ignores SOCK_NONBLOCK and
        // SOCK_CLOEXEC flags.
        // Issue #6: Fail hard if socket syscall cannot be resolved. SOCK_RAW
        // allows packet injection, ARP spoofing, and kernel exploit delivery.
        // The socket syscall exists on every supported Linux system.
        let socket_syscall = ScmpSyscall::from_name("socket").map_err(|e| {
            crate::error::PuzzledError::Sandbox(format!(
                "socket syscall not found — cannot block SOCK_RAW/SOCK_PACKET: {}",
                e
            ))
        })?;
        {
            use libseccomp::{ScmpArgCompare, ScmpCompareOp};
            const SOCK_TYPE_MASK: u64 = 0x0F;
            const SOCK_RAW: u64 = 3;
            const SOCK_PACKET: u64 = 10;

            let raw_cmp =
                ScmpArgCompare::new(1, ScmpCompareOp::MaskedEqual(SOCK_TYPE_MASK), SOCK_RAW);
            filter
                .add_rule_conditional(ScmpAction::KillProcess, socket_syscall, &[raw_cmp])
                .map_err(|e| {
                    crate::error::PuzzledError::Sandbox(format!(
                        "adding seccomp rule to block SOCK_RAW: {}",
                        e
                    ))
                })?;

            let packet_cmp =
                ScmpArgCompare::new(1, ScmpCompareOp::MaskedEqual(SOCK_TYPE_MASK), SOCK_PACKET);
            filter
                .add_rule_conditional(ScmpAction::KillProcess, socket_syscall, &[packet_cmp])
                .map_err(|e| {
                    crate::error::PuzzledError::Sandbox(format!(
                        "adding seccomp rule to block SOCK_PACKET: {}",
                        e
                    ))
                })?;

            tracing::debug!("seccomp: SOCK_RAW and SOCK_PACKET blocked via argument filtering");
        }

        // ── Tier 2: USER_NOTIF (both modes) ──────────────────────────────
        let mut notify_syscalls: Vec<&str> = vec!["execve", "execveat", "connect", "bind"];
        if !self.bpf_clone_guard_active {
            tracing::warn!(
                "BPF clone guard not active — adding clone3/clone to seccomp USER_NOTIF \
                 for namespace escape prevention"
            );
            notify_syscalls.push("clone3");
            notify_syscalls.push("clone");
        }

        for syscall_name in &notify_syscalls {
            match ScmpSyscall::from_name(syscall_name) {
                Ok(syscall) => {
                    filter.add_rule(ScmpAction::Notify, syscall).map_err(|e| {
                        crate::error::PuzzledError::Sandbox(format!(
                            "adding seccomp notify rule for {}: {}",
                            syscall_name, e
                        ))
                    })?;
                }
                Err(e) => {
                    tracing::warn!(
                        syscall = syscall_name,
                        error = %e,
                        "skipping unknown syscall in seccomp notify list"
                    );
                }
            }
        }

        // Load the filter — irrevocable once loaded
        filter.load().map_err(|e| {
            crate::error::PuzzledError::Sandbox(format!("loading seccomp filter: {}", e))
        })?;

        let notify_fd = filter.get_notify_fd().map_err(|e| {
            crate::error::PuzzledError::Sandbox(format!("getting seccomp notify fd: {}", e))
        })?;

        let mode_label = match self.seccomp_mode {
            SeccompMode::Permissive => "permissive (default-allow)",
            SeccompMode::Strict => "strict (default-deny)",
        };

        tracing::info!(
            notify_fd,
            mode = mode_label,
            allow_count,
            deny_count = DENY_SYSCALLS.len(),
            notify_count = notify_syscalls.len(),
            "seccomp-BPF filter loaded [{}]: {} allowed, {} kill-on-use, \
             {} USER_NOTIF-gated; Landlock enforces filesystem ACL",
            mode_label,
            allow_count,
            DENY_SYSCALLS.len(),
            notify_syscalls.len()
        );

        Ok(if notify_fd >= 0 {
            Some(notify_fd)
        } else {
            None
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn apply(&self, _profile: &AgentProfile) -> Result<Option<i32>> {
        Err(crate::error::PuzzledError::Sandbox(
            "seccomp requires Linux".to_string(),
        ))
    }
}
