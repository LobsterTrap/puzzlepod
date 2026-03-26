// SPDX-License-Identifier: Apache-2.0
// DC: Single-threaded seccomp notification handling is sufficient for typical
// workloads (<100 execve/s). For higher throughput, consider per-branch handler threads.

//! Centralized seccomp USER_NOTIF polling thread.
//!
//! Manages an epoll set of seccomp notification file descriptors (one per
//! active branch). When a notification arrives, reads the syscall arguments
//! via `/proc/<pid>/mem` and evaluates against the agent's profile.
//!
//! Runs in `tokio::task::spawn_blocking` since epoll_wait is a blocking call.

#[cfg(target_os = "linux")]
use std::collections::{HashMap, HashSet};

use puzzled_types::{AgentProfile, BranchId};

use crate::error::{PuzzledError, Result};
#[cfg(target_os = "linux")]
use crate::sandbox::seccomp::SeccompBuilder;

/// M7: epoll_wait timeout in milliseconds for seccomp notification polling.
#[cfg(target_os = "linux")]
const EPOLL_TIMEOUT_MS: i32 = 100;

/// §3.4 G23: Credential proxy context for seccomp-aware gateway blocking.
///
/// When a credential proxy is active for a branch, the seccomp handler
/// blocks direct connections to the gateway IP on the proxy port range
/// to prevent agents from bypassing the transparent proxy.
#[derive(Debug, Clone)]
pub struct CredentialProxyContext {
    /// Whether the credential proxy is active for this branch.
    pub enabled: bool,
    /// Gateway IP address (container → host).
    pub proxy_gateway_ip: std::net::IpAddr,
    /// Proxy port for this specific branch.
    pub proxy_port: u16,
    /// Ports being intercepted by DNAT.
    pub proxied_ports: Vec<u16>,
    /// Global proxy port range (all branches).
    pub global_port_range: std::ops::RangeInclusive<u16>,
}

/// Commands sent to the polling thread via channel.
pub enum SeccompCommand {
    /// Register a new seccomp notify fd for a branch.
    Register {
        notify_fd: i32,
        branch_id: BranchId,
        profile: Box<AgentProfile>,
        /// §3.4 G23: Optional credential proxy context for gateway blocking.
        credential_proxy: Option<CredentialProxyContext>,
    },
    /// Unregister a branch's notify fd (branch terminated).
    Unregister { branch_id: BranchId },
    /// H9: Register a cgroup memory.events file for OOM kill monitoring.
    #[cfg(target_os = "linux")]
    RegisterOomMonitor {
        branch_id: BranchId,
        /// Path to the cgroup's memory.events file (e.g., /sys/fs/cgroup/puzzled/<branch>/memory.events)
        memory_events_path: std::path::PathBuf,
    },
    /// Shut down the polling thread.
    Shutdown,
}

/// Handle returned when the polling thread is spawned.
// Q2: wake_fd is a raw eventfd shared across clones (via #[derive(Clone)]).
// It is closed in poll_loop when a Shutdown command is received. Known limitation:
// if the handler is dropped without sending Shutdown, the fd is leaked.
#[derive(Clone)]
pub struct SeccompNotifHandler {
    sender: tokio::sync::mpsc::Sender<SeccompCommand>,
    /// File descriptor for the eventfd used to wake the epoll loop immediately
    /// after sending a command, rather than waiting for the 100ms timeout.
    #[cfg(target_os = "linux")]
    wake_fd: std::os::unix::io::RawFd,
}

impl SeccompNotifHandler {
    /// Create and spawn the seccomp notification handler thread.
    ///
    /// Returns a handle for sending register/unregister commands.
    pub fn spawn() -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(64);

        // H4: Create eventfd before spawning the thread so the handler can
        // write to it after each send to wake the epoll loop immediately.
        // S1: Check eventfd() return — -1 indicates failure (e.g., fd exhaustion)
        #[cfg(target_os = "linux")]
        let wake_fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        #[cfg(target_os = "linux")]
        if wake_fd < 0 {
            tracing::error!(
                error = %std::io::Error::last_os_error(),
                "S1: failed to create eventfd for seccomp wake — poll loop will rely on timeout"
            );
        }
        #[cfg(not(target_os = "linux"))]
        let _wake_fd: i32 = -1;

        #[cfg(target_os = "linux")]
        let wake_fd_for_thread = wake_fd;

        // Use tokio::task::spawn_blocking if a runtime is available,
        // otherwise fall back to std::thread::spawn (for sync tests).
        let poll_fn = move || {
            #[cfg(target_os = "linux")]
            {
                if let Err(e) = poll_loop(rx, wake_fd_for_thread) {
                    tracing::error!(error = %e, "seccomp polling thread exited with error");
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                if let Err(e) = poll_loop(rx) {
                    tracing::error!(error = %e, "seccomp polling thread exited with error");
                }
            }
        };

        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::task::spawn_blocking(poll_fn);
        } else {
            std::thread::spawn(poll_fn);
        }

        Self {
            sender: tx,
            #[cfg(target_os = "linux")]
            wake_fd,
        }
    }

    /// H4: Write to the wake_fd eventfd to wake the epoll loop immediately
    /// after sending a command via the channel.
    #[cfg(target_os = "linux")]
    fn wake_poll_loop(&self) {
        // S7: Check write() return to detect wake failures
        let val: u64 = 1;
        let ret = unsafe {
            libc::write(
                self.wake_fd,
                &val as *const u64 as *const libc::c_void,
                std::mem::size_of::<u64>(),
            )
        };
        if ret < 0 {
            tracing::warn!(
                error = %std::io::Error::last_os_error(),
                "S7: failed to write to wake eventfd — poll loop will wake on next timeout"
            );
        }
    }

    /// No-op on non-Linux platforms.
    #[cfg(not(target_os = "linux"))]
    fn wake_poll_loop(&self) {}

    /// Register a seccomp notify fd for a branch (async).
    pub async fn register_async(
        &self,
        notify_fd: i32,
        branch_id: BranchId,
        profile: AgentProfile,
        credential_proxy: Option<CredentialProxyContext>,
    ) -> Result<()> {
        self.sender
            .send(SeccompCommand::Register {
                notify_fd,
                branch_id,
                profile: Box::new(profile),
                credential_proxy,
            })
            .await
            .map_err(|_| PuzzledError::SeccompNotif("handler channel closed".to_string()))?;
        // H4: Wake the epoll loop immediately so the new fd is registered without delay
        self.wake_poll_loop();
        Ok(())
    }

    /// Register a seccomp notify fd for a branch (non-blocking).
    ///
    /// H4: Returns an error if the channel is full, so the caller can fail
    /// branch creation instead of silently running without seccomp mediation.
    pub fn register(
        &self,
        notify_fd: i32,
        branch_id: BranchId,
        profile: AgentProfile,
        credential_proxy: Option<CredentialProxyContext>,
    ) -> Result<()> {
        self.sender
            .try_send(SeccompCommand::Register {
                notify_fd,
                branch_id,
                profile: Box::new(profile),
                credential_proxy,
            })
            .map_err(|e| {
                PuzzledError::SeccompNotif(format!("registering seccomp notify fd: {}", e))
            })?;
        // H4: Wake the epoll loop immediately so the new fd is registered without delay
        self.wake_poll_loop();
        Ok(())
    }

    /// Unregister a branch's seccomp notify fd (non-blocking, fire-and-forget).
    pub fn unregister(&self, branch_id: BranchId) {
        if self
            .sender
            .try_send(SeccompCommand::Unregister { branch_id })
            .is_ok()
        {
            // H4: Wake the epoll loop immediately to process the unregister
            self.wake_poll_loop();
        }
    }

    /// Unregister by notify fd — convenience for rollback paths.
    pub fn unregister_by_fd(&self, _notify_fd: i32) {
        // The polling thread tracks fd->branch mapping; sending Unregister by BranchId
        // is the canonical path. This is a no-op placeholder.
    }

    /// H9: Register OOM kill monitoring for a branch's cgroup.
    /// Watches the cgroup's memory.events file via inotify and logs a warning
    /// when an OOM kill is detected.
    #[cfg(target_os = "linux")]
    pub fn register_oom_monitor(
        &self,
        branch_id: BranchId,
        memory_events_path: std::path::PathBuf,
    ) -> Result<()> {
        self.sender
            .try_send(SeccompCommand::RegisterOomMonitor {
                branch_id,
                memory_events_path,
            })
            .map_err(|e| PuzzledError::SeccompNotif(format!("registering OOM monitor: {}", e)))?;
        // H4: Wake the epoll loop immediately to register the OOM monitor
        self.wake_poll_loop();
        Ok(())
    }

    /// Shut down the polling thread.
    pub async fn shutdown(&self) {
        if self.sender.send(SeccompCommand::Shutdown).await.is_ok() {
            // H4: Wake the epoll loop immediately to process shutdown
            self.wake_poll_loop();
        }
    }
}

/// Entry for a registered branch in the polling thread.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct BranchEntry {
    notify_fd: i32,
    profile: AgentProfile,
    /// Per-branch exec counter — tracks total execve/execveat calls.
    /// Compared against the profile's exec budget to enforce limits.
    exec_count: std::sync::atomic::AtomicU64,
    /// §3.4 G23: Credential proxy context for gateway blocking.
    credential_proxy: Option<CredentialProxyContext>,
}

/// Main polling loop — runs in a blocking thread.
///
/// Uses epoll to wait on multiple seccomp notification fds simultaneously.
/// Processes commands from the channel between epoll waits.
#[cfg(target_os = "linux")]
fn poll_loop(
    mut rx: tokio::sync::mpsc::Receiver<SeccompCommand>,
    wake_fd: std::os::unix::io::RawFd,
) -> Result<()> {
    // Create epoll instance
    let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epoll_fd < 0 {
        return Err(PuzzledError::SeccompNotif(format!(
            "epoll_create1 failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // H4: wake_fd is created by SeccompNotifHandler::spawn() and shared with
    // the handler struct, so that callers can write to it after sending commands
    // to wake the epoll loop immediately instead of waiting for the 100ms timeout.
    if wake_fd < 0 {
        unsafe { libc::close(epoll_fd) };
        return Err(PuzzledError::SeccompNotif(
            "invalid wake_fd passed to poll_loop".to_string(),
        ));
    }

    // Add wake_fd to epoll
    let mut wake_event = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: wake_fd as u64,
    };
    unsafe {
        libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, wake_fd, &mut wake_event);
    }

    let mut active_fds: HashMap<i32, (BranchId, usize)> = HashMap::new(); // notify_fd -> (branch_id, index)
    let mut branches: HashMap<BranchId, BranchEntry> = HashMap::new();
    let mut events = vec![libc::epoll_event { events: 0, u64: 0 }; 64];
    // M-sc2: Track fds that are being closed to avoid processing in-flight
    // notifications for fds that are in the process of being unregistered.
    // The fd is added here before epoll_del to prevent a race where a
    // notification arrives between the epoll_del and the fd being removed
    // from active_fds.
    let mut closing_fds: HashSet<i32> = HashSet::new();

    // H9: inotify instance for monitoring cgroup memory.events files for OOM kills
    let inotify_fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    if inotify_fd < 0 {
        tracing::warn!(
            error = %std::io::Error::last_os_error(),
            "failed to create inotify instance for OOM monitoring, continuing without it"
        );
    } else {
        // Add inotify_fd to epoll
        let mut ino_event = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: inotify_fd as u64,
        };
        unsafe {
            libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, inotify_fd, &mut ino_event);
        }
    }
    // Maps inotify watch descriptor -> branch_id for OOM monitoring
    let mut oom_watches: HashMap<i32, BranchId> = HashMap::new();
    // Maps branch_id -> inotify watch descriptor for cleanup
    let mut oom_branch_to_wd: HashMap<BranchId, i32> = HashMap::new();

    tracing::info!("seccomp polling thread started");

    loop {
        // Process any pending commands (non-blocking)
        while let Ok(cmd) = rx.try_recv() {
            match cmd {
                SeccompCommand::Register {
                    notify_fd,
                    branch_id,
                    profile,
                    credential_proxy,
                } => {
                    tracing::debug!(
                        branch = %branch_id,
                        notify_fd,
                        "registering seccomp notify fd"
                    );

                    // Add to epoll
                    let mut event = libc::epoll_event {
                        events: libc::EPOLLIN as u32,
                        u64: notify_fd as u64,
                    };
                    let ret = unsafe {
                        libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, notify_fd, &mut event)
                    };
                    if ret < 0 {
                        tracing::error!(
                            notify_fd,
                            error = %std::io::Error::last_os_error(),
                            "failed to add notify fd to epoll"
                        );
                        continue;
                    }

                    active_fds.insert(notify_fd, (branch_id.clone(), 0));
                    branches.insert(
                        branch_id,
                        BranchEntry {
                            notify_fd,
                            profile: *profile,
                            exec_count: std::sync::atomic::AtomicU64::new(0),
                            credential_proxy,
                        },
                    );
                }
                SeccompCommand::Unregister { branch_id } => {
                    tracing::debug!(branch = %branch_id, "unregistering seccomp notify fd");

                    if let Some(entry) = branches.remove(&branch_id) {
                        // M-sc2: Mark fd as closing BEFORE epoll_del to prevent
                        // processing in-flight notifications for this fd.
                        closing_fds.insert(entry.notify_fd);
                        unsafe {
                            libc::epoll_ctl(
                                epoll_fd,
                                libc::EPOLL_CTL_DEL,
                                entry.notify_fd,
                                std::ptr::null_mut(),
                            );
                        }
                        active_fds.remove(&entry.notify_fd);
                        closing_fds.remove(&entry.notify_fd);
                    }

                    // H9: Remove OOM watch for this branch if present
                    if let Some(wd) = oom_branch_to_wd.remove(&branch_id) {
                        if inotify_fd >= 0 {
                            unsafe {
                                libc::inotify_rm_watch(inotify_fd, wd);
                            }
                        }
                        oom_watches.remove(&wd);
                    }
                }
                // H9: Register OOM monitoring for a branch's cgroup memory.events
                SeccompCommand::RegisterOomMonitor {
                    branch_id,
                    memory_events_path,
                } => {
                    if inotify_fd < 0 {
                        tracing::warn!(
                            branch = %branch_id,
                            "cannot register OOM monitor: inotify not available"
                        );
                    } else {
                        use std::ffi::CString;
                        use std::os::unix::ffi::OsStrExt;

                        if let Ok(c_path) = CString::new(memory_events_path.as_os_str().as_bytes())
                        {
                            let wd = unsafe {
                                libc::inotify_add_watch(
                                    inotify_fd,
                                    c_path.as_ptr(),
                                    libc::IN_MODIFY,
                                )
                            };
                            if wd < 0 {
                                tracing::warn!(
                                    branch = %branch_id,
                                    path = %memory_events_path.display(),
                                    error = %std::io::Error::last_os_error(),
                                    "failed to add inotify watch for OOM monitoring"
                                );
                            } else {
                                tracing::debug!(
                                    branch = %branch_id,
                                    path = %memory_events_path.display(),
                                    "registered OOM kill monitor"
                                );
                                oom_watches.insert(wd, branch_id.clone());
                                oom_branch_to_wd.insert(branch_id, wd);
                            }
                        }
                    }
                }
                SeccompCommand::Shutdown => {
                    tracing::info!("seccomp polling thread shutting down");
                    unsafe {
                        libc::close(wake_fd);
                        if inotify_fd >= 0 {
                            libc::close(inotify_fd);
                        }
                        libc::close(epoll_fd);
                    }
                    return Ok(());
                }
            }
        }

        // M7: Wait for events (EPOLL_TIMEOUT_MS timeout to check for commands)
        let n = unsafe {
            libc::epoll_wait(
                epoll_fd,
                events.as_mut_ptr(),
                events.len() as i32,
                EPOLL_TIMEOUT_MS,
            )
        };

        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            tracing::error!(error = %err, "epoll_wait failed");
            continue;
        }

        // T5: Use try_from for consistency with fanotify epoll loops
        for event in events.iter().take(usize::try_from(n).unwrap_or(0)) {
            // T6: Use try_from for consistency with fanotify J6 pattern
            // Copy from packed struct field to avoid misaligned reference (UB)
            let event_data = event.u64;
            let fd = match i32::try_from(event_data) {
                Ok(v) => v,
                Err(_) => {
                    tracing::warn!(raw = event_data, "T6: epoll event data exceeds i32 range");
                    continue;
                }
            };

            // Skip wake_fd events — just drain the eventfd
            if fd == wake_fd {
                let mut buf = [0u8; 8];
                unsafe {
                    libc::read(wake_fd, buf.as_mut_ptr() as *mut libc::c_void, 8);
                }
                continue;
            }

            // H9: Handle inotify events for OOM kill monitoring
            if fd == inotify_fd && inotify_fd >= 0 {
                let mut ino_buf = [0u8; 4096];
                let n_read = unsafe {
                    libc::read(
                        inotify_fd,
                        ino_buf.as_mut_ptr() as *mut libc::c_void,
                        ino_buf.len(),
                    )
                };
                if n_read > 0 {
                    // K3: Clamp n_read to buffer size to prevent out-of-bounds access
                    let n_read_clamped = std::cmp::min(n_read as usize, ino_buf.len());
                    // Parse inotify events to find which watch descriptor fired
                    let mut offset = 0usize;
                    while offset + std::mem::size_of::<libc::inotify_event>() <= n_read_clamped {
                        let event = unsafe {
                            &*(ino_buf.as_ptr().add(offset) as *const libc::inotify_event)
                        };
                        if let Some(branch_id) = oom_watches.get(&event.wd) {
                            tracing::warn!(
                                branch = %branch_id,
                                "cgroup memory.events modified — possible OOM kill detected for branch"
                            );
                        }
                        // Advance to next event: sizeof(inotify_event) + name_len
                        offset += std::mem::size_of::<libc::inotify_event>() + event.len as usize;
                    }
                }
                continue;
            }

            // M-sc2: Skip in-flight handling for fds that are being closed
            if closing_fds.contains(&fd) {
                tracing::debug!(fd, "skipping notification for closing fd (M-sc2)");
                continue;
            }

            // Find the branch for this notify fd
            if let Some((branch_id, _)) = active_fds.get(&fd) {
                if let Some(entry) = branches.get(branch_id) {
                    // C1: Budget enforcement is now inside handle_notification_counted
                    // using atomic increment-then-check (no TOCTOU race).
                    let exec_budget =
                        entry
                            .profile
                            .resource_limits
                            .max_exec_calls
                            .unwrap_or_else(|| {
                                entry.profile.resource_limits.max_pids.saturating_mul(10)
                            }) as u64; // S4: safe widening u32 → u64
                    if let Err(e) = SeccompBuilder::handle_notification_counted(
                        fd,
                        &entry.profile,
                        &entry.exec_count,
                        exec_budget,
                        entry.credential_proxy.as_ref(),
                    ) {
                        tracing::debug!(
                            branch = %branch_id,
                            error = %e,
                            "seccomp notification handling error"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn poll_loop(mut rx: tokio::sync::mpsc::Receiver<SeccompCommand>) -> Result<()> {
    // On non-Linux, just drain commands until shutdown
    loop {
        match rx.blocking_recv() {
            Some(SeccompCommand::Shutdown) | None => return Ok(()),
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// M6: SECCOMP_IOCTL_NOTIF_ADDFD for TOCTOU-safe execve handling
// ---------------------------------------------------------------------------

/// ioctl number for SECCOMP_IOCTL_NOTIF_ADDFD (kernel 5.9+).
///
/// This ioctl injects a file descriptor into the notifying (agent) process's
/// fd table, eliminating the TOCTOU window in execve handling:
///
/// Without ADDFD (current approach):
///   1. Agent calls execve("/usr/bin/python3")
///   2. seccomp USER_NOTIF fires; puzzled reads path from /proc/<pid>/mem
///   3. Agent could modify the memory between steps 2 and 4 (TOCTOU window)
///   4. puzzled validates path and responds with ALLOW
///   5. Kernel resumes agent's execve with potentially modified path
///
/// With ADDFD (TOCTOU-safe approach):
///   1. Agent calls execve("/usr/bin/python3")
///   2. seccomp USER_NOTIF fires; puzzled reads path from /proc/<pid>/mem
///   3. puzzled opens the binary file ITSELF (O_PATH)
///   4. puzzled uses SECCOMP_IOCTL_NOTIF_ADDFD to inject the fd into agent
///   5. puzzled responds with SECCOMP_USER_NOTIF_FLAG_CONTINUE, pointing
///      the execve at the injected fd via /proc/<pid>/fd/<N>
///   6. Kernel resumes agent's execve using the fd puzzled verified
///
/// The TOCTOU window is eliminated because puzzled opens the file itself
/// and injects a reference to the exact file it validated.
///
/// Requires kernel 5.9+ (SECCOMP_IOCTL_NOTIF_ADDFD was added in v5.9).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const SECCOMP_IOCTL_NOTIF_ADDFD: u64 = 0x40182103;

/// Kernel struct for SECCOMP_IOCTL_NOTIF_ADDFD (kernel 5.9+).
///
/// Mirrors `struct seccomp_notif_addfd` from `<linux/seccomp.h>`.
/// Used to inject a file descriptor from puzzled's fd table into the
/// notifying (agent) process's fd table.
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug)]
struct SeccompNotifAddfd {
    /// The notification ID (must match the pending notification).
    id: u64,
    /// Flags: 0 or SECCOMP_ADDFD_FLAG_SETFD.
    flags: u32,
    /// File descriptor in puzzled's fd table to inject.
    srcfd: u32,
    /// Desired fd number in agent (0 = kernel picks the next available).
    newfd: u32,
    /// Flags for the new fd (e.g., O_CLOEXEC).
    newfd_flags: u32,
}

/// Inject a validated file descriptor into the agent process for TOCTOU-safe execve.
///
/// Reads the execve path from `/proc/<pid>/mem`, validates it against the
/// agent's exec_allowlist, opens the binary with `O_PATH`, and uses
/// `SECCOMP_IOCTL_NOTIF_ADDFD` to inject the fd into the agent process.
///
/// Returns:
/// - `Ok(Some(fd))` — the fd number in the agent's process (ADDFD succeeded)
/// - `Ok(None)` — kernel too old for ADDFD; caller should fall back to standard approach
/// - `Err(msg)` — validation failed or unrecoverable error
///
/// Kernel version requirement: 5.9+ (the ioctl was added in commit 7cf97b12).
/// On older kernels, fall back to the standard TOCTOU-mitigated approach
/// H6: TOCTOU-safe variant that accepts a pre-read path string.
///
/// This function uses a path that has already been read from `/proc/<pid>/mem`
/// by the caller, instead of re-reading it. This eliminates the TOCTOU window
/// where an attacker could swap the file between the two reads.
///
/// The caller (handle_notification) reads the path ONCE and passes the same
/// string to both `validate_execve_with_path()` and this function.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub fn inject_fd_for_execve_with_path(
    notify_fd: i32,
    notify_id: u64,
    _pid: u32,
    path_str: &str,
    profile: &AgentProfile,
) -> std::result::Result<Option<i32>, String> {
    use std::ffi::CString;

    if path_str.is_empty() {
        return Err("execve path is empty".to_string());
    }

    // Step 1: Validate the path against exec_allowlist (using the pre-read path)
    // H-5: Use the same glob-style matching logic as validate_execve_with_path
    // to prevent allowlist mismatch between validation and fd injection.
    let allowed = profile.exec_allowlist.iter().any(|pattern| {
        if pattern.ends_with('*') {
            // Prefix glob: /usr/bin/* matches /usr/bin/anything
            let prefix = &pattern[..pattern.len() - 1];
            path_str.starts_with(prefix)
        } else {
            // Exact match
            path_str == *pattern
        }
    });

    if !allowed {
        return Err(format!(
            "execve path '{}' not in exec_allowlist (pid {})",
            path_str, _pid
        ));
    }

    // P2-N1: Check exec_denylist — deny overrides allow (mirrors validate.rs logic)
    if !profile.exec_denylist.is_empty() {
        let matches_denylist = |p: &str| -> bool {
            profile.exec_denylist.iter().any(|pattern| {
                if pattern.ends_with('*') {
                    let prefix = &pattern[..pattern.len() - 1];
                    p.starts_with(prefix)
                } else {
                    p == *pattern
                }
            })
        };
        if matches_denylist(path_str) {
            return Err(format!(
                "execve path '{}' denied by exec_denylist (pid {})",
                path_str, _pid
            ));
        }
    }

    // Step 2: Canonicalize and open the binary with O_PATH
    let canonical = std::fs::canonicalize(path_str)
        .map_err(|e| format!("failed to canonicalize '{}': {}", path_str, e))?;

    let c_path = CString::new(canonical.as_os_str().as_encoded_bytes())
        .map_err(|e| format!("path contains interior null byte: {}", e))?;

    let binary_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if binary_fd < 0 {
        return Err(format!(
            "failed to open '{}' with O_PATH: {}",
            canonical.display(),
            std::io::Error::last_os_error()
        ));
    }

    // Step 3: Use SECCOMP_IOCTL_NOTIF_ADDFD to inject fd into the agent process
    let addfd_req = SeccompNotifAddfd {
        id: notify_id,
        flags: 0,
        srcfd: binary_fd as u32, // S3: safe — binary_fd >= 0 guaranteed by check above
        newfd: 0,
        newfd_flags: 0,
    };

    let ret = unsafe {
        libc::ioctl(
            notify_fd,
            SECCOMP_IOCTL_NOTIF_ADDFD as libc::c_ulong,
            &addfd_req as *const SeccompNotifAddfd,
        )
    };

    // Close our copy of the O_PATH fd
    unsafe { libc::close(binary_fd) };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        let errno = err.raw_os_error().unwrap_or(0);

        if errno == libc::ENOTTY || errno == libc::EINVAL {
            return Ok(None);
        }

        return Err(format!(
            "SECCOMP_IOCTL_NOTIF_ADDFD failed for pid {}: {}",
            _pid, err
        ));
    }

    Ok(Some(ret))
}

/// Non-Linux stub for inject_fd_for_execve_with_path.
#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn inject_fd_for_execve_with_path(
    _notify_fd: i32,
    _notify_id: u64,
    _pid: u32,
    _path_str: &str,
    _profile: &AgentProfile,
) -> std::result::Result<Option<i32>, String> {
    Err("SECCOMP_IOCTL_NOTIF_ADDFD requires Linux 5.9+".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_spawn_and_shutdown() {
        let handler = SeccompNotifHandler::spawn();
        handler.shutdown().await;
    }

    #[tokio::test]
    async fn test_register_and_unregister() {
        let handler = SeccompNotifHandler::spawn();

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
            seccomp_mode: Default::default(),
            allow_symlinks: false,
            allow_exec_overlay: false,
            credentials: None,
        };

        let branch_id = BranchId::from("test-branch".to_string());

        // Register with a fake fd (won't actually be polled on non-Linux)
        handler
            .register(99, branch_id.clone(), profile, None)
            .unwrap();

        // Give the handler time to process the command
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Unregister
        handler.unregister(branch_id);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        handler.shutdown().await;
    }

    #[tokio::test]
    async fn test_clone_handler() {
        let handler = SeccompNotifHandler::spawn();
        let handler2 = handler.clone();

        // Both handles can send commands
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
            seccomp_mode: Default::default(),
            allow_symlinks: false,
            allow_exec_overlay: false,
            credentials: None,
        };

        handler
            .register(100, BranchId::from("b1".to_string()), profile.clone(), None)
            .unwrap();
        handler2
            .register(101, BranchId::from("b2".to_string()), profile, None)
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        handler.shutdown().await;
    }

    /// M6: Verify SECCOMP_IOCTL_NOTIF_ADDFD constant value.
    #[test]
    fn test_seccomp_addfd_ioctl_constant() {
        // The ioctl number is SECCOMP_IOW(3, struct seccomp_notif_addfd)
        // = _IOW('!', 3, 24_bytes) = 0x40182103
        assert_eq!(SECCOMP_IOCTL_NOTIF_ADDFD, 0x40182103);
    }

    /// M6: Verify inject_fd_for_execve_with_path returns Err with empty
    /// allowlist (path not allowed).
    #[test]
    fn test_inject_fd_for_execve_with_path_not_in_allowlist() {
        let profile = make_test_profile(vec![]);

        let result = inject_fd_for_execve_with_path(-1, 0, 1, "/usr/bin/ls", &profile);
        assert!(
            result.is_err(),
            "inject_fd_for_execve_with_path should return Err when path not in allowlist"
        );
    }

    /// M6: Verify SeccompNotifAddfd struct size matches the kernel definition (24 bytes).
    #[cfg(target_os = "linux")]
    #[test]
    fn test_seccomp_notif_addfd_struct_size() {
        assert_eq!(
            std::mem::size_of::<SeccompNotifAddfd>(),
            24,
            "SeccompNotifAddfd must be 24 bytes to match kernel struct seccomp_notif_addfd"
        );
    }

    /// Helper to create a minimal AgentProfile for tests.
    fn make_test_profile(exec_allowlist: Vec<String>) -> AgentProfile {
        AgentProfile {
            name: "test".to_string(),
            description: "test".to_string(),
            filesystem: puzzled_types::FilesystemRules {
                read_allowlist: vec![],
                write_allowlist: vec![],
                denylist: vec![],
                read_denylist: vec![],
                write_denylist: vec![],
            },
            exec_allowlist,
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
            seccomp_mode: Default::default(),
            allow_symlinks: false,
            allow_exec_overlay: false,
            credentials: None,
        }
    }

    // -----------------------------------------------------------------------
    // register_async tests
    // -----------------------------------------------------------------------

    /// Test register_async sends the Register command successfully.
    #[tokio::test]
    async fn test_register_async_success() {
        let handler = SeccompNotifHandler::spawn();
        let profile = make_test_profile(vec![]);
        let branch_id = BranchId::from("async-branch".to_string());

        let result = handler.register_async(42, branch_id, profile, None).await;
        assert!(result.is_ok(), "register_async should succeed");

        handler.shutdown().await;
    }

    /// Test register_async returns error when the handler has been shut down
    /// (channel closed).
    #[tokio::test]
    async fn test_register_async_after_shutdown() {
        let handler = SeccompNotifHandler::spawn();
        handler.shutdown().await;

        // Give the poll loop time to process shutdown and close the receiver
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let profile = make_test_profile(vec![]);
        let branch_id = BranchId::from("late-branch".to_string());

        let result = handler.register_async(42, branch_id, profile, None).await;
        assert!(
            result.is_err(),
            "register_async should fail after shutdown (channel closed)"
        );
    }

    // -----------------------------------------------------------------------
    // register error path tests
    // -----------------------------------------------------------------------

    /// Test register returns error when the handler has been shut down.
    #[tokio::test]
    async fn test_register_sync_after_shutdown() {
        let handler = SeccompNotifHandler::spawn();
        handler.shutdown().await;

        // Give the poll loop time to process shutdown
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let profile = make_test_profile(vec![]);
        let branch_id = BranchId::from("late-branch".to_string());

        let result = handler.register(42, branch_id, profile, None);
        assert!(
            result.is_err(),
            "register should fail after shutdown (channel closed)"
        );
    }

    // -----------------------------------------------------------------------
    // unregister_by_fd tests
    // -----------------------------------------------------------------------

    /// Test unregister_by_fd is a no-op and does not panic.
    #[tokio::test]
    async fn test_unregister_by_fd_is_noop() {
        let handler = SeccompNotifHandler::spawn();

        // Should not panic or cause any side effects
        handler.unregister_by_fd(42);
        handler.unregister_by_fd(-1);
        handler.unregister_by_fd(0);

        handler.shutdown().await;
    }

    // -----------------------------------------------------------------------
    // Double unregister / unregister unknown branch
    // -----------------------------------------------------------------------

    /// Unregistering a branch that was never registered should not panic.
    #[tokio::test]
    async fn test_unregister_unknown_branch() {
        let handler = SeccompNotifHandler::spawn();

        handler.unregister(BranchId::from("nonexistent".to_string()));

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        handler.shutdown().await;
    }

    /// Double unregister of the same branch should not panic.
    #[tokio::test]
    async fn test_double_unregister() {
        let handler = SeccompNotifHandler::spawn();
        let profile = make_test_profile(vec![]);
        let branch_id = BranchId::from("double-unreg".to_string());

        handler
            .register(50, branch_id.clone(), profile, None)
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        handler.unregister(branch_id.clone());
        handler.unregister(branch_id);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        handler.shutdown().await;
    }

    // -----------------------------------------------------------------------
    // Registering the same branch_id twice (second should overwrite)
    // -----------------------------------------------------------------------

    /// Registering the same branch_id twice should not panic; the second
    /// registration replaces the first in the internal maps.
    #[tokio::test]
    async fn test_register_same_branch_twice() {
        let handler = SeccompNotifHandler::spawn();
        let profile1 = make_test_profile(vec!["/usr/bin/python3".to_string()]);
        let profile2 = make_test_profile(vec!["/usr/bin/bash".to_string()]);
        let branch_id = BranchId::from("dup-branch".to_string());

        handler
            .register(60, branch_id.clone(), profile1, None)
            .unwrap();
        handler
            .register(61, branch_id.clone(), profile2, None)
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        handler.unregister(branch_id);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        handler.shutdown().await;
    }

    // -----------------------------------------------------------------------
    // inject_fd_for_execve_with_path (non-Linux stub)
    // -----------------------------------------------------------------------

    /// On non-Linux, inject_fd_for_execve_with_path always returns Err.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_inject_fd_for_execve_with_path_non_linux_stub() {
        let profile = make_test_profile(vec!["/usr/bin/python3".to_string()]);

        let result = inject_fd_for_execve_with_path(-1, 0, 99999, "/usr/bin/python3", &profile);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("requires Linux 5.9+"),
            "non-Linux stub should mention Linux 5.9+ requirement"
        );
    }

    /// On non-Linux, inject_fd_for_execve_with_path returns Err even with
    /// empty path (the stub doesn't validate — it unconditionally errors).
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_inject_fd_for_execve_with_path_empty_path_non_linux() {
        let profile = make_test_profile(vec![]);

        let result = inject_fd_for_execve_with_path(-1, 0, 1, "", &profile);
        assert!(result.is_err());
    }

    /// On non-Linux, inject_fd_for_execve_with_path returns Err unconditionally.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_inject_fd_for_execve_with_path_non_linux_stub() {
        let profile = make_test_profile(vec!["/usr/bin/*".to_string()]);

        let result = inject_fd_for_execve_with_path(-1, 0, 1, "/usr/bin/ls", &profile);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("requires Linux 5.9+"));
    }

    // -----------------------------------------------------------------------
    // inject_fd_for_execve_with_path (Linux: allowlist validation)
    // -----------------------------------------------------------------------

    /// On Linux, inject_fd_for_execve_with_path with empty exec_allowlist
    /// rejects the path.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_inject_fd_with_path_empty_allowlist_rejects() {
        let profile = make_test_profile(vec![]);

        let result = inject_fd_for_execve_with_path(-1, 0, 99999, "/usr/bin/python3", &profile);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("not in exec_allowlist"),
            "should be rejected by empty allowlist"
        );
    }

    /// On Linux, inject_fd_for_execve_with_path with empty path returns Err.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_inject_fd_with_path_empty_path_linux() {
        let profile = make_test_profile(vec!["/usr/bin/*".to_string()]);

        let result = inject_fd_for_execve_with_path(-1, 0, 99999, "", &profile);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("execve path is empty"));
    }

    /// On Linux, inject_fd_for_execve_with_path rejects paths not matching
    /// exact entries in exec_allowlist.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_inject_fd_with_path_exact_match_mismatch() {
        let profile = make_test_profile(vec!["/usr/bin/python3".to_string()]);

        let result = inject_fd_for_execve_with_path(-1, 0, 99999, "/usr/bin/bash", &profile);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in exec_allowlist"));
    }

    /// On Linux, inject_fd_for_execve_with_path rejects paths not matching
    /// glob entries in exec_allowlist.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_inject_fd_with_path_glob_mismatch() {
        let profile = make_test_profile(vec!["/usr/bin/*".to_string()]);

        let result = inject_fd_for_execve_with_path(-1, 0, 99999, "/usr/sbin/dangerous", &profile);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in exec_allowlist"));
    }

    // -----------------------------------------------------------------------
    // Concurrent access from multiple cloned handles
    // -----------------------------------------------------------------------

    /// Multiple cloned handles can concurrently register/unregister branches
    /// without panicking or deadlocking.
    #[tokio::test]
    async fn test_concurrent_register_unregister() {
        let handler = SeccompNotifHandler::spawn();

        let mut tasks = Vec::new();
        for i in 0..10u32 {
            let h = handler.clone();
            tasks.push(tokio::spawn(async move {
                let profile = make_test_profile(vec![]);
                let branch_id = BranchId::from(format!("concurrent-{}", i));
                h.register(200 + i as i32, branch_id.clone(), profile, None)
                    .unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                h.unregister(branch_id);
            }));
        }

        for task in tasks {
            task.await.unwrap();
        }

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        handler.shutdown().await;
    }

    // -----------------------------------------------------------------------
    // SeccompCommand enum variant construction
    // -----------------------------------------------------------------------

    /// Verify SeccompCommand variants can be constructed (compile-time check
    /// that the public enum API is stable).
    #[test]
    fn test_seccomp_command_variants() {
        let profile = make_test_profile(vec![]);
        let branch_id = BranchId::from("cmd-test".to_string());

        // Register variant
        let _cmd = SeccompCommand::Register {
            notify_fd: 10,
            branch_id: branch_id.clone(),
            profile: Box::new(profile),
            credential_proxy: None,
        };

        // Unregister variant
        let _cmd = SeccompCommand::Unregister {
            branch_id: branch_id.clone(),
        };

        // Shutdown variant
        let _cmd = SeccompCommand::Shutdown;

        // RegisterOomMonitor variant (Linux only)
        #[cfg(target_os = "linux")]
        {
            let _cmd = SeccompCommand::RegisterOomMonitor {
                branch_id,
                memory_events_path: std::path::PathBuf::from(
                    "/sys/fs/cgroup/puzzled/test/memory.events",
                ),
            };
        }
    }

    // -----------------------------------------------------------------------
    // shutdown idempotency
    // -----------------------------------------------------------------------

    /// Calling shutdown multiple times should not panic.
    #[tokio::test]
    async fn test_shutdown_idempotent() {
        let handler = SeccompNotifHandler::spawn();
        handler.shutdown().await;
        // Second shutdown — channel is closed, send fails silently (is_ok guard)
        handler.shutdown().await;
    }

    // -----------------------------------------------------------------------
    // unregister after shutdown
    // -----------------------------------------------------------------------

    /// Unregister after shutdown should not panic (try_send fails silently).
    #[tokio::test]
    async fn test_unregister_after_shutdown() {
        let handler = SeccompNotifHandler::spawn();
        handler.shutdown().await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Should not panic — try_send fails, is_ok() guard prevents wake_poll_loop
        handler.unregister(BranchId::from("ghost".to_string()));
    }

    // -----------------------------------------------------------------------
    // register_oom_monitor (Linux only)
    // -----------------------------------------------------------------------

    /// On Linux, register_oom_monitor sends the command successfully.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_register_oom_monitor_success() {
        let handler = SeccompNotifHandler::spawn();

        // The path doesn't need to exist — the inotify_add_watch will fail
        // inside the poll loop but that's logged, not propagated. The send
        // itself should succeed.
        let result = handler.register_oom_monitor(
            BranchId::from("oom-test".to_string()),
            std::path::PathBuf::from("/tmp/nonexistent-memory-events"),
        );
        assert!(result.is_ok(), "register_oom_monitor send should succeed");

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        handler.shutdown().await;
    }

    /// On Linux, register_oom_monitor after shutdown returns an error.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_register_oom_monitor_after_shutdown() {
        let handler = SeccompNotifHandler::spawn();
        handler.shutdown().await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let result = handler.register_oom_monitor(
            BranchId::from("late-oom".to_string()),
            std::path::PathBuf::from("/tmp/nope"),
        );
        assert!(
            result.is_err(),
            "register_oom_monitor should fail after shutdown"
        );
    }

    // -----------------------------------------------------------------------
    // Channel capacity: register with full channel
    // -----------------------------------------------------------------------

    /// When the channel is full, register should return an error rather than
    /// silently dropping the command (fail-closed behavior per H4).
    #[tokio::test]
    async fn test_register_channel_full() {
        // Create a handler — channel capacity is 64
        let handler = SeccompNotifHandler::spawn();

        // Shut down the poll loop so it stops draining the channel
        handler.shutdown().await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // The channel receiver is dropped after shutdown. try_send on a closed
        // channel returns an error immediately (Closed variant), which is what
        // we want to verify — register surfaces this as PuzzledError.
        let profile = make_test_profile(vec![]);
        let result = handler.register(300, BranchId::from("overflow".to_string()), profile, None);
        assert!(
            result.is_err(),
            "register should fail when channel is closed/full"
        );
    }

    // -----------------------------------------------------------------------
    // wake_poll_loop is safe to call (non-Linux no-op)
    // -----------------------------------------------------------------------

    /// Verify wake_poll_loop can be called without panicking (via register
    /// which calls it internally). On non-Linux this is a no-op.
    #[tokio::test]
    async fn test_wake_poll_loop_via_register() {
        let handler = SeccompNotifHandler::spawn();
        let profile = make_test_profile(vec![]);

        // register calls wake_poll_loop internally
        handler
            .register(70, BranchId::from("wake-test".to_string()), profile, None)
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        handler.shutdown().await;
    }

    /// K3: Verify inotify n_read is clamped to buffer size before use.
    #[test]
    fn test_k3_inotify_nread_clamped_to_buffer() {
        let source = include_str!("seccomp_handler.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        assert!(
            prod_source.contains("n_read_clamped = std::cmp::min(n_read as usize, ino_buf.len())"),
            "K3: inotify n_read must be clamped to buffer size"
        );
        assert!(
            prod_source.contains("std::mem::size_of::<libc::inotify_event>() <= n_read_clamped"),
            "K3: inotify loop must check minimum event size against clamped value"
        );
    }

    /// P2-N1: Verify inject_fd_for_execve_with_path checks denylist.
    /// A path that matches the allowlist but is also in the denylist must be rejected.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_p2n1_inject_fd_denylist_overrides_allowlist() {
        let mut profile = make_test_profile(vec!["/usr/bin/*".to_string()]);
        profile.exec_denylist = vec!["/usr/bin/rm".to_string()];

        // /usr/bin/rm matches allowlist (/usr/bin/*) but is in the denylist
        let result = inject_fd_for_execve_with_path(
            -1,    // invalid notify_fd — we won't reach the ioctl
            0,     // notify_id
            99999, // invalid pid
            "/usr/bin/rm",
            &profile,
        );
        assert!(result.is_err(), "denylist should override allowlist");
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("denied by exec_denylist"),
            "error should mention denylist, got: {err_msg}"
        );
    }

    /// M7: Verify epoll_wait timeout uses a named constant, not a magic number.
    #[test]
    fn test_m7_epoll_timeout_uses_named_constant() {
        let source = include_str!("seccomp_handler.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // The constant must be defined
        assert!(
            prod_source.contains("EPOLL_TIMEOUT_MS"),
            "M7: Must define EPOLL_TIMEOUT_MS constant for epoll_wait timeout"
        );
        // The epoll_wait call must use the constant, not a bare 100
        for (i, line) in prod_source.lines().enumerate() {
            if line.contains("epoll_wait") && line.contains(", 100)") {
                panic!(
                    "M7: epoll_wait uses magic number 100 at line {} — use EPOLL_TIMEOUT_MS",
                    i + 1
                );
            }
        }
    }
}
