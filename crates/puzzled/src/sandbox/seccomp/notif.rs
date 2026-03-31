// SPDX-License-Identifier: Apache-2.0
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

use puzzled_types::AgentProfile;

use crate::error::Result;
#[cfg(target_os = "linux")]
use crate::seccomp_handler;

/// Issue #5: Syscall names used in the USER_NOTIF handler. Extracted as a
/// constant so they can be validated at startup (or in tests) rather than
/// silently returning None via `.ok()` at notification time.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) const NOTIF_SYSCALL_NAMES: &[&str] =
    &["execve", "execveat", "connect", "bind", "clone3", "clone"];

#[cfg(target_os = "linux")]
use super::procmem::{read_string_from_proc_mem, read_u64_from_proc_mem};
#[cfg(target_os = "linux")]
use super::validate::{validate_bind, validate_connect, validate_execve_with_path};

/// H-23: Handler-side deadline for expensive steps within one notification.
/// If elapsed time exceeds this threshold before an expensive operation
/// (reading process memory, policy check, ADDFD injection), the syscall
/// is denied and the handler returns early.
///
/// This is **only** a userspace handler budget: it does **not** unblock the
/// agent's syscall from the kernel's perspective. The notifying thread stays
/// blocked in the kernel until puzzled sends an allow/deny response.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const NOTIFICATION_TIMEOUT: Duration = Duration::from_secs(5);

impl super::SeccompBuilder {
    /// C2: Deny a pending seccomp notification (exec budget exceeded).
    /// Receives the notification and responds with EPERM without evaluating policy.
    #[cfg(target_os = "linux")]
    pub fn deny_notification(notify_fd: i32) -> Result<()> {
        use libseccomp::*;

        let req = ScmpNotifReq::receive(notify_fd).map_err(|e| {
            crate::error::PuzzledError::SeccompNotif(format!(
                "receiving seccomp notification for denial: {}",
                e
            ))
        })?;

        let resp = ScmpNotifResp::new_error(req.id, -(libc::EPERM), ScmpNotifRespFlags::empty());

        if super::notify_id_valid(notify_fd, req.id).is_ok() {
            resp.respond(notify_fd).map_err(|e| {
                crate::error::PuzzledError::SeccompNotif(format!(
                    "responding with denial to seccomp notification: {}",
                    e
                ))
            })?;
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn deny_notification(_notify_fd: i32) -> Result<()> {
        Err(crate::error::PuzzledError::Sandbox(
            "seccomp requires Linux".to_string(),
        ))
    }

    /// C7: Handle a seccomp notification, incrementing exec_count only for
    /// execve/execveat syscalls (not connect/bind/clone).
    ///
    /// Reads the notification, inspects the syscall arguments (execve path,
    /// connect address, bind port) via /proc/<pid>/mem, evaluates against the
    /// agent profile, and responds with ALLOW or DENY.
    ///
    /// H-23: Enforces a 5-second timeout. Before each expensive operation,
    /// checks elapsed time and denies the syscall if the timeout is exceeded.
    ///
    /// TOCTOU protection: uses SECCOMP_IOCTL_NOTIF_ID_VALID to check the
    /// notification is still valid before responding.
    ///
    /// DC: H-6 connect/bind sockaddr TOCTOU — fundamental USER_NOTIF limitation.
    /// Agent threads could modify sockaddr between our /proc/pid/mem read and the
    /// kernel's response. Mitigated by seccomp blocking `process_vm_writev`.
    ///
    /// DC: clone_args memory TOCTOU — clone_args lives in agent memory and could
    /// be modified between seccomp read and kernel processing. Mitigated by
    /// `notify_id_valid` check before responding.
    ///
    /// DC: H-4 execve canonicalize→open TOCTOU — fundamental race between path
    /// canonicalization and fd injection. ADDFD with O_PATH is the mitigation.
    /// Opening the canonicalized path is unavoidable.
    ///
    /// C1: Budget enforcement uses increment-then-check (atomic fetch_add followed
    /// by comparison) to eliminate the TOCTOU race in the previous check-then-increment
    /// pattern. Ordering::Relaxed is sufficient because exec_count is a monotonically
    /// increasing counter on a single atomic — no other memory operations depend on
    /// its ordering relative to other variables.
    ///
    /// WS9: `handler_wall_start` must be `Instant::now()` from the poll loop immediately
    /// before calling this function so the wall-clock deadline includes `receive`.
    #[cfg(target_os = "linux")]
    pub fn handle_notification_counted(
        notify_fd: i32,
        profile: &AgentProfile,
        exec_count: &std::sync::atomic::AtomicU64,
        exec_budget: u64,
        credential_proxy: Option<&seccomp_handler::CredentialProxyContext>,
        handler_wall_start: Instant,
    ) -> Result<()> {
        use libseccomp::*;
        use std::sync::atomic::Ordering;

        // H-23: Record entry time for timeout enforcement
        let entry_time = Instant::now();
        let req = ScmpNotifReq::receive(notify_fd).map_err(|e| {
            crate::error::PuzzledError::SeccompNotif(format!(
                "receiving seccomp notification: {}",
                e
            ))
        })?;

        let syscall = req.data.syscall;
        let pid = req.pid;

        // Issue #5: Resolve syscall names with explicit error handling rather
        // than .ok() which silently returns None. If resolution fails, the
        // handler logs a clear error and denies the syscall (fail-closed).
        let resolve = |name: &str| -> Option<ScmpSyscall> {
            match ScmpSyscall::from_name(name) {
                Ok(nr) => Some(nr),
                Err(e) => {
                    tracing::error!(
                        syscall = name,
                        error = %e,
                        "failed to resolve syscall name for USER_NOTIF handler — \
                         notifications for this syscall will be denied (fail-closed)"
                    );
                    None
                }
            }
        };

        // C7: Only increment exec counter for execve/execveat
        let execve_nr = resolve("execve");
        let execveat_nr = resolve("execveat");
        if execve_nr == Some(syscall) || execveat_nr == Some(syscall) {
            // C1: Increment-then-check eliminates TOCTOU race. fetch_add returns
            // the previous value atomically, so concurrent notifications cannot
            // both pass the budget check.
            let prev = exec_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if exec_budget > 0 && prev >= exec_budget {
                tracing::error!(
                    pid,
                    exec_count = prev + 1,
                    budget = exec_budget,
                    "exec budget exceeded — denying notification (C1)"
                );
                return Self::respond_deny(notify_fd, req.id);
            }
        }

        tracing::debug!(
            pid,
            syscall = ?syscall,
            notify_id = req.id,
            "seccomp USER_NOTIF received (counted)"
        );

        // Match syscall number to determine validation logic
        let connect_nr = resolve("connect");
        let bind_nr = resolve("bind");
        let clone3_nr = resolve("clone3");
        let clone_nr = resolve("clone");

        let allow = if execve_nr == Some(syscall) {
            // execve: arg0 = pointer to path string
            let path_addr = req.data.args[0] as usize;
            // H-23: Check timeout before reading process memory
            if entry_time.elapsed() > NOTIFICATION_TIMEOUT {
                tracing::warn!(
                    pid,
                    "seccomp notification timeout before reading execve path (H-23), denying"
                );
                false
            } else {
                // H6: Read the path ONCE from /proc/<pid>/mem and pass the same string
                // to both validate_execve and inject_fd_for_execve. This eliminates the
                // TOCTOU window where an attacker could swap the file between two reads.
                match read_string_from_proc_mem(pid, path_addr) {
                    Ok(execve_path) => {
                        // H-23: Check timeout before policy check
                        if entry_time.elapsed() > NOTIFICATION_TIMEOUT {
                            tracing::warn!(pid, "seccomp notification timeout before execve policy check (H-23), denying");
                            false
                        } else if validate_execve_with_path(pid, &execve_path, profile) {
                            // H-23: Check timeout before ADDFD injection
                            if entry_time.elapsed() > NOTIFICATION_TIMEOUT {
                                tracing::warn!(pid, "seccomp notification timeout before ADDFD injection (H-23), denying");
                                false
                            } else {
                                // SC1: Use SECCOMP_ADDFD for TOCTOU-safe execve when available.
                                // inject_fd_for_execve_with_path uses the already-read path
                                // instead of re-reading from /proc/<pid>/mem.
                                match seccomp_handler::inject_fd_for_execve_with_path(
                                    notify_fd,
                                    req.id,
                                    pid,
                                    &execve_path,
                                    profile,
                                ) {
                                    Ok(Some(_fd)) => true,
                                    Ok(None) => {
                                        tracing::warn!(pid, "ADDFD unavailable (kernel too old), allowing execve via CONTINUE (path validated)");
                                        true
                                    }
                                    Err(e) => {
                                        // ADDFD is a TOCTOU mitigation (H-4), not the primary
                                        // control. The path was validated by validate_execve_with_path
                                        // and Landlock enforces filesystem access independently.
                                        tracing::warn!(pid, error = %e, "SECCOMP_ADDFD inject failed for execve, allowing via CONTINUE (path validated)");
                                        true
                                    }
                                }
                            }
                        } else {
                            false
                        }
                    }
                    Err(e) => {
                        tracing::warn!(pid, error = %e, "failed to read execve path, denying");
                        false
                    }
                }
            }
        } else if execveat_nr == Some(syscall) {
            // execveat: arg1 = pointer to path string (arg0 = dirfd)
            let path_addr = req.data.args[1] as usize;
            // H-23: Check timeout before reading process memory
            if entry_time.elapsed() > NOTIFICATION_TIMEOUT {
                tracing::warn!(
                    pid,
                    "seccomp notification timeout before reading execveat path (H-23), denying"
                );
                false
            } else {
                // H6: Read the path ONCE — same TOCTOU fix as execve above.
                match read_string_from_proc_mem(pid, path_addr) {
                    Ok(execve_path) => {
                        // H-23: Check timeout before policy check
                        if entry_time.elapsed() > NOTIFICATION_TIMEOUT {
                            tracing::warn!(pid, "seccomp notification timeout before execveat policy check (H-23), denying");
                            false
                        } else if validate_execve_with_path(pid, &execve_path, profile) {
                            // H-23: Check timeout before ADDFD injection
                            if entry_time.elapsed() > NOTIFICATION_TIMEOUT {
                                tracing::warn!(pid, "seccomp notification timeout before execveat ADDFD injection (H-23), denying");
                                false
                            } else {
                                match seccomp_handler::inject_fd_for_execve_with_path(
                                    notify_fd,
                                    req.id,
                                    pid,
                                    &execve_path,
                                    profile,
                                ) {
                                    Ok(Some(_fd)) => true,
                                    Ok(None) => {
                                        tracing::warn!(pid, "ADDFD unavailable (kernel too old), allowing execveat via CONTINUE (path validated)");
                                        true
                                    }
                                    Err(e) => {
                                        // ADDFD is a TOCTOU mitigation (H-4), not the primary
                                        // control. The path was validated by validate_execve_with_path
                                        // and Landlock enforces filesystem access independently.
                                        tracing::warn!(
                                            pid,
                                            error = %e,
                                            "SECCOMP_ADDFD inject failed for execveat, allowing via CONTINUE (path validated)"
                                        );
                                        true
                                    }
                                }
                            }
                        } else {
                            false
                        }
                    }
                    Err(e) => {
                        tracing::warn!(pid, error = %e, "failed to read execveat path, denying");
                        false
                    }
                }
            }
        } else if connect_nr == Some(syscall) {
            // H-23: Check timeout before reading connect sockaddr
            if entry_time.elapsed() > NOTIFICATION_TIMEOUT {
                tracing::warn!(
                    pid,
                    "seccomp notification timeout before connect validation (H-23), denying"
                );
                false
            } else {
                validate_connect(
                    pid,
                    req.data.args[1] as usize,
                    req.data.args[2] as usize,
                    profile,
                    credential_proxy,
                )
            }
        } else if clone3_nr == Some(syscall) {
            // H-23: Check timeout before reading clone3 flags from process memory
            if entry_time.elapsed() > NOTIFICATION_TIMEOUT {
                tracing::warn!(
                    pid,
                    "seccomp notification timeout before reading clone3 flags (H-23), denying"
                );
                false
            } else {
                // SC2: clone3 USER_NOTIF handler — check clone flags for namespace escape.
                // When BPF clone guard is not active, clone3 is gated through USER_NOTIF.
                //
                // CRITICAL: For clone3, args[0] is a POINTER to struct clone_args, NOT
                // the flags directly. The flags field is at offset 0 of the struct.
                // V33: clone_args.flags is at offset 0 — stable kernel ABI since 5.3
                // We must read the flags from the agent's memory via /proc/<pid>/mem.
                let clone_flags = match read_u64_from_proc_mem(pid, req.data.args[0] as usize) {
                    Ok(flags) => flags,
                    Err(e) => {
                        tracing::warn!(
                            pid,
                            error = %e,
                            "failed to read clone3 flags from process memory, denying (fail-closed)"
                        );
                        return Self::respond_deny(notify_fd, req.id);
                    }
                };
                // H8: Block all namespace isolation flags — agents must not create
                // new IPC, UTS, or cgroup namespaces in addition to the original set.
                let forbidden_flags: u64 = libc::CLONE_NEWNS as u64
                    | libc::CLONE_NEWPID as u64
                    | libc::CLONE_NEWNET as u64
                    | libc::CLONE_NEWUSER as u64
                    | libc::CLONE_NEWIPC as u64
                    | libc::CLONE_NEWUTS as u64
                    | libc::CLONE_NEWCGROUP as u64;
                if clone_flags & forbidden_flags != 0 {
                    tracing::warn!(
                        pid,
                        clone_flags = format!("0x{:x}", clone_flags),
                        "clone3 denied: namespace escape flags detected (no BPF clone guard)"
                    );
                    false
                } else {
                    true
                }
            }
        } else if clone_nr == Some(syscall) {
            // H-23: Check timeout before validating clone flags
            if entry_time.elapsed() > NOTIFICATION_TIMEOUT {
                tracing::warn!(
                    pid,
                    "seccomp notification timeout before clone flag validation (H-23), denying"
                );
                false
            } else {
                // Legacy clone: args[0] IS the flags directly (unlike clone3 which uses a pointer).
                let clone_flags = req.data.args[0];
                // H8: Block all namespace isolation flags — same set as clone3 above.
                let forbidden_flags: u64 = libc::CLONE_NEWNS as u64
                    | libc::CLONE_NEWPID as u64
                    | libc::CLONE_NEWNET as u64
                    | libc::CLONE_NEWUSER as u64
                    | libc::CLONE_NEWIPC as u64
                    | libc::CLONE_NEWUTS as u64
                    | libc::CLONE_NEWCGROUP as u64;
                if clone_flags & forbidden_flags != 0 {
                    tracing::warn!(
                        pid,
                        clone_flags = format!("0x{:x}", clone_flags),
                        "legacy clone denied: namespace escape flags detected (no BPF clone guard)"
                    );
                    false
                } else {
                    true
                }
            }
        } else if bind_nr == Some(syscall) {
            // H-23: Check timeout before reading bind sockaddr
            if entry_time.elapsed() > NOTIFICATION_TIMEOUT {
                tracing::warn!(
                    pid,
                    "seccomp notification timeout before bind validation (H-23), denying"
                );
                false
            } else {
                validate_bind(
                    pid,
                    req.data.args[1] as usize,
                    req.data.args[2] as usize,
                    profile,
                )
            }
        } else {
            tracing::error!(pid, syscall = ?syscall, "unknown seccomp notify syscall, denying (fail-closed)");
            false
        };

        // TOCTOU mitigation: After reading from /proc/<pid>/mem and before
        // acting on the result, re-check that the notification is still valid.
        // This narrows the TOCTOU window where the agent process could have
        // been replaced or the memory contents changed between our read and
        // the response. The kernel's own notify_id_valid check in respond()
        // provides the final guarantee, but this belt-and-suspenders check
        // catches stale data earlier.
        if super::notify_id_valid(notify_fd, req.id).is_err() {
            tracing::debug!(
                pid,
                notify_id = req.id,
                "seccomp notification expired after validation (TOCTOU window)"
            );
            return Ok(());
        }

        // WS9: Hard wall-clock deadline from poll-loop start. If we would allow but took
        // too long, deny with EPERM so the poll loop can eventually serve other agents.
        let allow = if allow
            && handler_wall_start.elapsed() > seccomp_handler::SECCOMP_NOTIF_HANDLER_WALL_DEADLINE
        {
            seccomp_handler::SECCOMP_NOTIF_HANDLER_WALL_DEADLINE_DENIES
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                pid,
                notify_id = req.id,
                elapsed_ms = handler_wall_start.elapsed().as_millis() as u64,
                "WS9: seccomp notification wall-clock deadline exceeded — denying with EPERM \
                 (single-threaded handler; other agents' gated syscalls were blocked)"
            );
            false
        } else {
            allow
        };

        // Build the response
        // For allowed syscalls, use CONTINUE to let the kernel execute the original
        // syscall (critical for execve — new_val(0) would fake-succeed without loading
        // the binary). For denied syscalls, return EPERM.
        let resp = if allow {
            ScmpNotifResp::new_continue(req.id, ScmpNotifRespFlags::empty())
        } else {
            ScmpNotifResp::new_error(req.id, -(libc::EPERM), ScmpNotifRespFlags::empty())
        };

        // Verify the notification is still valid (final TOCTOU protection)
        if super::notify_id_valid(notify_fd, req.id).is_ok() {
            resp.respond(notify_fd).map_err(|e| {
                crate::error::PuzzledError::SeccompNotif(format!(
                    "responding to seccomp notification: {}",
                    e
                ))
            })?;
        }

        Ok(())
    }

    /// Helper to respond with denial.
    #[cfg(target_os = "linux")]
    fn respond_deny(notify_fd: i32, notify_id: u64) -> Result<()> {
        use libseccomp::*;
        let resp = ScmpNotifResp::new_error(notify_id, -(libc::EPERM), ScmpNotifRespFlags::empty());
        if super::notify_id_valid(notify_fd, notify_id).is_ok() {
            resp.respond(notify_fd).map_err(|e| {
                crate::error::PuzzledError::SeccompNotif(format!("responding with denial: {}", e))
            })?;
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn handle_notification_counted(
        _notify_fd: i32,
        _profile: &AgentProfile,
        _exec_count: &std::sync::atomic::AtomicU64,
        _exec_budget: u64,
        _credential_proxy: Option<&seccomp_handler::CredentialProxyContext>,
        _handler_wall_start: std::time::Instant,
    ) -> Result<()> {
        Err(crate::error::PuzzledError::Sandbox(
            "seccomp requires Linux".to_string(),
        ))
    }
}
