// SPDX-License-Identifier: Apache-2.0
#[cfg(feature = "bpf_lsm")]
pub mod bpf_lsm;

#[cfg(not(feature = "bpf_lsm"))]
pub mod bpf_lsm {
    //! Stub module when BPF LSM feature is disabled.
    use crate::error::{PuzzledError, Result};
    use std::path::Path;

    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default)]
    pub struct RateLimitConfig {
        pub max_execs_per_second: u32,
        pub max_total_execs: u32,
        pub kill_switch: u32,
        pub _pad: u32,
    }

    pub struct BpfLsmManager;

    impl BpfLsmManager {
        pub fn new(_path: &Path) -> Self {
            BpfLsmManager
        }
        pub fn load(&mut self) -> Result<()> {
            Err(PuzzledError::Sandbox(
                "BPF LSM not available (compile with --features bpf_lsm)".into(),
            ))
        }
        pub fn is_attached(&self) -> bool {
            false
        }
        pub fn is_loaded(&self) -> bool {
            false
        }
        pub fn is_degraded(&self) -> bool {
            false
        }
        pub fn configure_cgroup(&self, _id: u64, _config: RateLimitConfig) -> Result<()> {
            Ok(())
        }
        pub fn remove_cgroup(&self, _id: u64) -> Result<()> {
            Ok(())
        }
    }
}
pub mod capabilities;
pub mod cgroup;
pub mod fanotify;
pub mod landlock;
pub mod namespace;
pub mod network;
pub mod overlay;
pub mod quota;
pub mod seccomp;
pub mod selinux;

use puzzled_types::AgentProfile;
use std::path::PathBuf;

use crate::error::Result;

// S35: Maximum length for messages received over the child socketpair.
// Bounds allocation to prevent attacker-controlled length from causing OOM.
#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const MAX_SOCKETPAIR_MSG_LEN: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// C4: Mask sensitive procfs/sysfs paths inside the mount namespace
// ---------------------------------------------------------------------------

/// Sensitive procfs/sysfs paths to mask by bind-mounting /dev/null over them.
/// These paths leak host information or provide dangerous capabilities
/// even inside a PID namespace.
/// H3: Sensitive procfs/sysfs paths to mask by bind-mounting /dev/null over them.
/// Each path is an information leak or privilege escalation vector:
///
/// - `/proc/kcore`        — physical memory access
/// - `/proc/sysrq-trigger` — kernel magic SysRq commands
/// - `/proc/keys`         — kernel keyring enumeration
/// - `/proc/kmsg`         — kernel log buffer (information leak)
/// - `/proc/kallsyms`     — kernel symbol addresses (KASLR bypass)
/// - `/proc/sched_debug`  — scheduler debug info (side-channel leak)
/// - `/proc/timer_list`   — kernel timer internals (timing side-channel)
/// - `/proc/acpi`         — ACPI table access (hardware info leak)
/// - `/proc/latency_stats` — scheduling latency histogram (timing side-channel)
/// - `/proc/timer_stats`  — timer statistics (timing attacks)
/// - `/proc/scsi`         — SCSI device enumeration (hardware info leak)
/// - `/sys/firmware`      — firmware tables (hardware info leak)
/// - `/sys/kernel/debug`  — kernel debug symbols (exploit development aid)
/// - `/sys/kernel/security` — LSM configuration (security policy leak)
/// - `/sys/fs/cgroup`     — cgroup hierarchy (escape vector via cgroup manipulation)
#[cfg(target_os = "linux")]
const SENSITIVE_PATHS: &[&str] = &[
    "/proc/kcore",
    "/proc/sysrq-trigger",
    "/proc/keys",
    "/proc/kmsg",
    "/proc/kallsyms",
    "/proc/sched_debug",
    "/proc/timer_list",
    "/proc/acpi",
    // Issue #9: Kernel info leak paths — aid targeted exploit development.
    "/proc/modules",   // loaded kernel modules enumeration
    "/proc/config.gz", // kernel configuration (enabled features, attack surface)
    "/proc/version",   // kernel version disclosure
    // S20+S27: Information-leak paths that Docker/Podman mask by default.
    "/proc/latency_stats", // scheduling latency histogram (timing side-channel)
    "/proc/timer_stats",   // timer statistics (timing attacks)
    "/proc/scsi",          // SCSI device enumeration
    "/sys/kernel/debug",   // kernel debug symbols (exploit development aid)
    "/sys/firmware",
    "/sys/kernel/security",
    "/sys/fs/cgroup",
    // R18: ALSA info leak (Docker masks this)
    "/proc/asound",
];

/// Mask sensitive procfs/sysfs paths by bind-mounting /dev/null over them.
///
/// This runs inside the child's mount namespace, so the masking only affects
/// the agent process tree.
///
/// H-20: Behavior depends on `fail_mode`:
/// - `FailClosed`: if any bind-mount mask fails, return `Err` immediately.
/// - Other modes: log a warning and continue (best-effort).
#[cfg(target_os = "linux")]
fn mask_sensitive_paths(
    fail_mode: puzzled_types::FailMode,
) -> std::result::Result<(), crate::error::PuzzledError> {
    let strict = fail_mode == puzzled_types::FailMode::FailClosed;
    let dev_null = std::ffi::CString::new("/dev/null").unwrap();
    let none = std::ffi::CString::new("none").unwrap();

    for path_str in SENSITIVE_PATHS {
        let target = match std::ffi::CString::new(*path_str) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Check if the path exists before attempting to mask it.
        // Some paths (e.g., /sys/firmware) may not be present in all environments.
        if unsafe { libc::access(target.as_ptr(), libc::F_OK) } != 0 {
            tracing::trace!(path = %path_str, "sensitive path does not exist, skipping mask");
            continue;
        }

        // Determine if the target is a directory or a file.
        // Directories need tmpfs mount; files get /dev/null bind mount.
        let is_dir = std::path::Path::new(path_str).is_dir();

        let ret = if is_dir {
            // Mount an empty tmpfs over the directory to hide its contents
            let tmpfs = std::ffi::CString::new("tmpfs").unwrap();
            unsafe {
                libc::mount(
                    tmpfs.as_ptr(),
                    target.as_ptr(),
                    tmpfs.as_ptr(),
                    libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                    std::ptr::null(),
                )
            }
        } else {
            // Bind mount /dev/null over the file
            unsafe {
                libc::mount(
                    dev_null.as_ptr(),
                    target.as_ptr(),
                    none.as_ptr(),
                    libc::MS_BIND | libc::MS_REC,
                    std::ptr::null(),
                )
            }
        };

        if ret != 0 {
            let err = std::io::Error::last_os_error();
            if strict {
                return Err(crate::error::PuzzledError::Sandbox(format!(
                    "failed to mask sensitive path {} (fail-closed): {}",
                    path_str, err
                )));
            }
            tracing::warn!(
                path = %path_str,
                error = %err,
                "failed to mask sensitive path (best-effort, continuing)"
            );
        } else {
            // For file bind mounts, remount read-only to prevent unmounting.
            // (tmpfs directories are already mounted read-only above.)
            if !is_dir {
                let ret = unsafe {
                    libc::mount(
                        dev_null.as_ptr(),
                        target.as_ptr(),
                        none.as_ptr(),
                        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
                        std::ptr::null(),
                    )
                };
                if ret != 0 {
                    let err = std::io::Error::last_os_error();
                    if strict {
                        return Err(crate::error::PuzzledError::Sandbox(format!(
                            "failed to remount masked path {} read-only (fail-closed): {}",
                            path_str, err
                        )));
                    }
                    tracing::warn!(
                        path = %path_str,
                        error = %err,
                        "failed to remount masked path read-only (best-effort)"
                    );
                }
            }
            tracing::debug!(path = %path_str, "masked sensitive path");
        }
    }

    // C5: Read-only bind-remount /proc/sys, /sys/devices, /sys/class to prevent
    // agents from tuning kernel parameters or enumerating hardware.
    for ro_path in &["/proc/sys", "/sys/devices", "/sys/class"] {
        let target = match std::ffi::CString::new(*ro_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if unsafe { libc::access(target.as_ptr(), libc::F_OK) } != 0 {
            tracing::trace!(path = %ro_path, "read-only remount path does not exist, skipping");
            continue;
        }

        // Bind-mount the path over itself
        let ret = unsafe {
            libc::mount(
                target.as_ptr(),
                target.as_ptr(),
                none.as_ptr(),
                libc::MS_BIND | libc::MS_REC,
                std::ptr::null(),
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            if strict {
                return Err(crate::error::PuzzledError::Sandbox(format!(
                    "failed to bind-mount {} for read-only remount (fail-closed): {}",
                    ro_path, err
                )));
            }
            tracing::warn!(path = %ro_path, error = %err, "failed to bind-mount for read-only remount (best-effort)");
            continue;
        }

        // Remount read-only
        // M2: MS_REC ensures submounts are also remounted read-only,
        // preventing agents from accessing writable submounts under
        // an otherwise read-only bind mount.
        let ret = unsafe {
            libc::mount(
                target.as_ptr(),
                target.as_ptr(),
                none.as_ptr(),
                libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_REC,
                std::ptr::null(),
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            if strict {
                return Err(crate::error::PuzzledError::Sandbox(format!(
                    "failed to remount {} read-only (fail-closed): {}",
                    ro_path, err
                )));
            }
            tracing::warn!(path = %ro_path, error = %err, "failed to remount read-only (best-effort)");
        } else {
            tracing::debug!(path = %ro_path, "remounted read-only (C5)");
        }
    }

    Ok(())
}

/// RAII guard for sandbox build cleanup on partial failure.
///
/// Tracks which resources have been allocated during SandboxBuilder::build().
/// If build() returns Err, Drop reverses completed steps in LIFO order.
/// On success, call defuse() to prevent cleanup.
#[cfg(target_os = "linux")]
struct SandboxCleanup {
    // M13: overlay_mounted removed — OverlayFS is now mounted inside the
    // child's mount namespace and is automatically cleaned up when the
    // child's mount namespace is destroyed.
    child_pid: Option<i32>,
    cgroup_path: Option<std::path::PathBuf>,
    pidfd: Option<i32>,
    parent_sock: Option<i32>,
    /// Named network namespace to clean up on failure.
    netns_name: Option<String>,
    defused: bool,
}

#[cfg(target_os = "linux")]
impl SandboxCleanup {
    fn new() -> Self {
        Self {
            child_pid: None,
            cgroup_path: None,
            pidfd: None,
            parent_sock: None,
            netns_name: None,
            defused: false,
        }
    }

    fn defuse(mut self) {
        self.defused = true;
    }
}

#[cfg(target_os = "linux")]
impl Drop for SandboxCleanup {
    fn drop(&mut self) {
        if self.defused {
            return;
        }
        // Reverse in LIFO order
        if let Some(sock) = self.parent_sock {
            unsafe { libc::close(sock) };
        }
        if let Some(path) = &self.cgroup_path {
            let _ = cgroup::CgroupManager::remove_scope(path);
        }
        if let Some(pid) = self.child_pid {
            // L5: Use pidfd_send_signal() for race-free process termination
            // when we have a pidfd, falling back to kill() otherwise.
            let killed_via_pidfd = if let Some(fd) = self.pidfd {
                // pidfd_send_signal(pidfd, SIGKILL, NULL, 0) is race-free:
                // the pidfd is tied to the exact process, so we cannot
                // accidentally kill a recycled PID.
                let ret = unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        fd,
                        libc::SIGKILL,
                        std::ptr::null::<libc::c_void>(),
                        0u32,
                    )
                };
                if ret != 0 {
                    tracing::warn!(
                        pidfd = fd,
                        error = %std::io::Error::last_os_error(),
                        "pidfd_send_signal failed, falling back to kill()"
                    );
                    false
                } else {
                    true
                }
            } else {
                false
            };

            if !killed_via_pidfd {
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        }
        if let Some(fd) = self.pidfd {
            unsafe { libc::close(fd) };
        }
        // Clean up named network namespace
        if let Some(ref name) = self.netns_name {
            network::delete_named_netns(name);
        }
        // M13: No overlay unmount needed — OverlayFS is mounted in the child's
        // mount namespace and is cleaned up when the namespace is destroyed.
        tracing::warn!("SandboxCleanup: reversed partial sandbox setup");
    }
}

/// Builds a complete sandbox for an agent process by composing kernel primitives.
///
/// Order of operations:
/// 1. Create OverlayFS directories
/// 2. Set up XFS project quotas on upper layer (best-effort)
/// 3. Create cgroup scope + set resource limits
/// 4. Open cgroup fd for CLONE_INTO_CGROUP
/// 5. Create socketpair for parent-child sync + notify fd transfer
/// 6. clone3() with CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS |
///    CLONE_NEWCGROUP | CLONE_INTO_CGROUP -> get pidfd (child placed directly
///    in cgroup, no race window). Child joins pre-created named netns via setns().
/// 7. Signal child to proceed (mount overlay, apply restrictions)
/// 8. In child: mount OverlayFS in child namespace
/// 9. In child: apply Landlock ruleset (irrevocable)
/// 10. In child: load seccomp-BPF filter (irrevocable), send notify fd to parent
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct SandboxBuilder {
    profile: AgentProfile,
    base_path: PathBuf,
    branch_root: PathBuf,
    /// UID to switch the agent process to after sandbox setup.
    /// If 0, the agent runs as root (with a warning).
    agent_uid: u32,
    /// GID to switch the agent process to after sandbox setup.
    agent_gid: u32,
    /// Command to execve after sandbox setup. If empty, falls back to pause() loop.
    command: Vec<String>,
}

/// Handle to a running sandbox (returned after successful creation).
///
/// ## Resource lifetime model (C5)
///
/// - **pidfd**: Kernel-managed; keeps the process reference alive. Closed in Drop.
/// - **seccomp_notify_fd**: Kernel-managed; used by SeccompNotifHandler. Closed in Drop.
/// - **BPF LSM programs**: Loaded once at daemon start (via BranchManager). Attached
///   per-cgroup at branch creation, detached at branch cleanup via `BpfLsmManager::remove_cgroup()`.
///   The BpfLsmManager is owned by BranchManager, not SandboxHandle.
/// - **fanotify**: Started per-branch in `build()`. The trigger receiver and counters
///   should be stored here and consumed by the BranchManager for governance decisions.
///   The fanotify fd is owned by the polling thread and closed when it exits.
pub struct SandboxHandle {
    /// pidfd for race-free process lifecycle management.
    pub pidfd: i32,
    /// PID of the agent init process (in the root PID namespace).
    pub pid: u32,
    /// OverlayFS upper directory path.
    pub upper_dir: PathBuf,
    /// OverlayFS work directory path.
    pub work_dir: PathBuf,
    /// OverlayFS merged directory path.
    pub merged_dir: PathBuf,
    /// cgroup path for this agent.
    pub cgroup_path: PathBuf,
    /// seccomp notification fd (for USER_NOTIF handling).
    pub seccomp_notify_fd: Option<i32>,
    /// C5/SH5: Fanotify trigger channel receiver — receives BehavioralTrigger
    /// events from the fanotify polling thread. Stored here to keep the channel
    /// alive as long as the sandbox; consumed by BranchManager for governance.
    pub fanotify_trigger_rx: Option<tokio::sync::mpsc::Receiver<puzzled_types::BehavioralTrigger>>,
    /// C5/SH5: Fanotify behavioral counters — shared with the fanotify polling
    /// thread. Provides real-time access to deletion/read/credential counts
    /// for governance decisions.
    pub fanotify_counters: Option<std::sync::Arc<fanotify::BehavioralCounters>>,
    /// Flag set by fanotify monitor on queue overflow — signals the diff engine
    /// to fall back to a full upper-dir walk instead of incremental tracking.
    pub fanotify_needs_full_diff: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// SH1: Parent socketpair fd — kept alive so the caller (BranchManager)
    /// can send the seccomp ACK byte AFTER registering the notify fd with
    /// SeccompNotifHandler. Closed on Drop or after ACK is sent.
    pub parent_sock: Option<i32>,
}

/// L4: Drop implementation for SandboxHandle — closes kernel file descriptors.
///
/// The pidfd and seccomp_notify_fd are kernel resources that must be closed
/// when the sandbox handle is dropped. Without this, they leak until process exit.
impl Drop for SandboxHandle {
    fn drop(&mut self) {
        if self.pidfd >= 0 {
            tracing::debug!(pidfd = self.pidfd, pid = self.pid, "closing pidfd");
            unsafe { libc::close(self.pidfd) };
        }
        if let Some(fd) = self.seccomp_notify_fd {
            if fd >= 0 {
                tracing::debug!(
                    seccomp_notify_fd = fd,
                    pid = self.pid,
                    "closing seccomp notify fd"
                );
                unsafe { libc::close(fd) };
            }
        }
        // SH1: Close parent socketpair fd if still open (ACK not yet sent).
        if let Some(fd) = self.parent_sock {
            if fd >= 0 {
                tracing::debug!(
                    parent_sock = fd,
                    pid = self.pid,
                    "closing parent socketpair fd (ACK may not have been sent)"
                );
                unsafe { libc::close(fd) };
            }
        }
    }
}

/// SH1: Send the seccomp ACK byte (0x42) to the child process over the
/// parent socketpair fd, then close the fd. This MUST be called after
/// `SeccompNotifHandler::register()` completes, so the child does not
/// call execve() before the parent is polling the notify fd.
///
/// Returns Ok(()) on success, or an error if the write fails.
/// After this call, the parent_sock in SandboxHandle is set to None.
#[cfg(target_os = "linux")]
pub fn send_seccomp_ack(handle: &mut SandboxHandle) -> Result<()> {
    if let Some(fd) = handle.parent_sock.take() {
        let ack: u8 = 0x42;
        if let Err(e) = write_all_raw(fd, &[ack]) {
            unsafe { libc::close(fd) };
            tracing::warn!(error = %e, "failed to send seccomp ACK to child");
            // Non-fatal — child may have exited already
            return Ok(());
        }
        unsafe { libc::close(fd) };
        tracing::debug!(pid = handle.pid, "seccomp ACK sent to child");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn send_seccomp_ack(_handle: &mut SandboxHandle) -> Result<()> {
    Err(crate::error::PuzzledError::Sandbox(
        "seccomp requires Linux".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// M11: Robust read helper for child process socketpair communication
// ---------------------------------------------------------------------------

/// Read exactly `buf.len()` bytes from a raw file descriptor, retrying on
/// `EINTR` and accumulating bytes on short reads.
///
/// This is used in the child process (post-fork, pre-exec) where we cannot
/// use std::io::Read because we only have a raw fd. Short reads are possible
/// on Unix domain sockets when the writer sends data in multiple write() calls
/// or the kernel buffers are under pressure.
#[cfg(target_os = "linux")]
fn read_exact_raw(fd: i32, buf: &mut [u8]) -> std::result::Result<(), std::io::Error> {
    let mut total = 0usize;
    while total < buf.len() {
        let n = unsafe {
            libc::read(
                fd,
                buf[total..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - total,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue; // Interrupted by signal — retry
            }
            return Err(err);
        }
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "socketpair closed before all bytes were read",
            ));
        }
        total += n as usize;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// M12: Robust write helper for parent process socketpair communication
// ---------------------------------------------------------------------------

/// Write all bytes to a raw file descriptor, checking return values.
///
/// Returns an error on EPIPE (child closed its end) or any other write error.
/// Used in the parent process to send data to the child over the socketpair.
#[cfg(target_os = "linux")]
fn write_all_raw(fd: i32, buf: &[u8]) -> std::result::Result<(), std::io::Error> {
    let mut total = 0usize;
    while total < buf.len() {
        let n = unsafe {
            libc::write(
                fd,
                buf[total..].as_ptr() as *const libc::c_void,
                buf.len() - total,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        total += n as usize;
    }
    Ok(())
}

impl SandboxBuilder {
    pub fn new(profile: AgentProfile, base_path: PathBuf, branch_root: PathBuf) -> Self {
        Self {
            profile,
            base_path,
            branch_root,
            agent_uid: 0,
            agent_gid: 0,
            command: Vec::new(),
        }
    }

    /// Set the UID/GID the agent process should switch to after sandbox setup.
    pub fn with_credentials(mut self, uid: u32, gid: u32) -> Self {
        self.agent_uid = uid;
        self.agent_gid = gid;
        self
    }

    /// Set the command to execve after sandbox setup.
    /// If empty, the child falls back to a pause() loop (for debugging/testing).
    pub fn with_command(mut self, command: Vec<String>) -> Self {
        self.command = command;
        self
    }

    /// Build and launch the sandbox. Returns a handle for monitoring/control.
    ///
    /// This is the core "Fork" operation in the Fork-Explore-Commit model.
    ///
    /// Uses a Unix socketpair instead of a pipe for bidirectional communication:
    /// - Parent → child: "go" signal after cgroup setup
    /// - Child → parent: seccomp notify fd via SCM_RIGHTS
    #[cfg(target_os = "linux")]
    pub fn build(&self, branch_id: &str) -> Result<SandboxHandle> {
        let mut cleanup = SandboxCleanup::new();

        // Step 1: Create OverlayFS directories
        let branch_dir = self.branch_root.join(branch_id);
        let (upper_dir, work_dir, merged_dir) = overlay::OverlayMount::create_dirs(&branch_dir)?;

        // SC4: Set up XFS project quotas on the upper dir BEFORE clone3.
        // This ensures the quota is in place before the agent can write anything.
        match quota::QuotaManager::setup(
            &upper_dir,
            self.profile.resource_limits.storage_quota_mb,
            self.profile.resource_limits.inode_quota,
        ) {
            Ok(quota::EnforcementStatus::Active) => {
                tracing::info!(branch_id, "XFS quota active");
            }
            Ok(quota::EnforcementStatus::Unavailable(reason)) => {
                if self.profile.enforcement.require_quota {
                    return Err(crate::error::PuzzledError::Sandbox(format!(
                        "XFS quota required but unavailable: {reason}"
                    )));
                }
                tracing::warn!(
                    branch_id,
                    reason,
                    "XFS quota unavailable (best-effort, continuing)"
                );
            }
            Err(e) => {
                if self.profile.enforcement.require_quota {
                    return Err(crate::error::PuzzledError::Sandbox(format!(
                        "XFS quota required but failed: {e}"
                    )));
                }
                tracing::warn!(
                    branch_id,
                    error = %e,
                    "XFS quota setup failed (best-effort, continuing)"
                );
            }
        }

        // Step 2: OverlayFS mount (deferred to child namespace)
        //
        // M13: OverlayFS mount architecture — IMPLEMENTED
        //
        // The OverlayFS mount happens INSIDE the child's mount namespace
        // (after clone3(CLONE_NEWNS)) to provide stronger isolation:
        //
        //   1. Parent creates overlay directories (upper, work, merged) — Step 1 above
        //   2. Parent calls clone3(CLONE_NEWNS) to create child
        //   3. Parent sends mount parameters to child via socketpair:
        //      - base_path (lower dir)
        //      - upper_dir, work_dir, merged_dir paths
        //   4. Child mounts OverlayFS inside its own mount namespace
        //
        // Benefits of in-child mount:
        //   - Mount is invisible to parent/host (namespace isolation)
        //   - No cleanup needed on parent side for mount failures
        //   - Prevents mount namespace escape via /proc/self/mountinfo
        //
        // The parent no longer owns the OverlayFS mount, so there is no
        // cleanup.overlay_mounted entry. Mount parameters are serialized
        // over the socketpair as length-prefixed UTF-8 strings.

        // Chown the OverlayFS upper dir to the agent's UID so the merged view's
        // root directory is writable by the agent. OverlayFS merged root inherits
        // metadata from the upper dir (which always exists as the mount parameter
        // directory), not the lower dir. Without this, the agent (UID != 0) gets
        // EACCES when creating files in the merged root.
        {
            // H22: Reject non-UTF-8 paths explicitly via to_str() rather than
            // silently mangling them via lossy conversion for chown.
            let upper_str = upper_dir.to_str().ok_or_else(|| {
                crate::error::PuzzledError::Sandbox(format!(
                    "upper dir path contains non-UTF-8 bytes: {}",
                    upper_dir.display()
                ))
            })?;
            let c_upper = std::ffi::CString::new(upper_str).map_err(|e| {
                crate::error::PuzzledError::Sandbox(format!("upper dir path: {}", e))
            })?;
            if unsafe { libc::chown(c_upper.as_ptr(), self.agent_uid, self.agent_gid) } != 0 {
                return Err(crate::error::PuzzledError::Sandbox(format!(
                    "failed to chown upper dir to uid {}: {}",
                    self.agent_uid,
                    std::io::Error::last_os_error()
                )));
            }
        }

        // Step 3: Create cgroup scope with resource limits (UID-scoped for multi-tenancy)
        // CR-1/CR-2: Cgroup MUST be created BEFORE clone3 so we can open an fd
        // and pass it via CLONE_INTO_CGROUP, placing the child directly into the
        // cgroup at creation time (no race window).
        let cgroup_path = cgroup::CgroupManager::create_scope_with_uid(
            branch_id,
            self.agent_uid,
            &self.profile.resource_limits,
        )?;
        cleanup.cgroup_path = Some(cgroup_path.clone());

        // CR-1: Open cgroup fd for CLONE_INTO_CGROUP. If this fails, we fall
        // back to post-clone add_process() (the pre-existing behavior).
        let cgroup_fd = match namespace::open_cgroup_fd(&cgroup_path) {
            Ok(fd) => {
                tracing::debug!(fd, cgroup = %cgroup_path.display(), "opened cgroup fd for CLONE_INTO_CGROUP");
                Some(fd)
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    cgroup = %cgroup_path.display(),
                    "failed to open cgroup fd, falling back to post-clone add_process()"
                );
                None
            }
        };

        // Step 4: Create socketpair for parent-child coordination + fd transfer
        let (parent_sock, child_sock) = {
            let mut fds = [0i32; 2];
            let ret = unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            };
            if ret < 0 {
                return Err(crate::error::PuzzledError::Sandbox(
                    "creating coordination socketpair".to_string(),
                ));
            }
            (fds[0], fds[1])
        };
        cleanup.parent_sock = Some(parent_sock);

        // H-21: clone_guard removed — seccomp + SELinux provide dual defense for clone containment.
        // clone/clone3 are always gated via seccomp USER_NOTIF for namespace flag inspection.
        let bpf_clone_guard_active = false;

        // Create the named network namespace BEFORE clone3 so it's visible
        // in the parent's mount namespace. The child will join it via setns().
        // clone3 does NOT include CLONE_NEWNET — the child inherits the parent's
        // network namespace initially and switches into the named netns immediately.
        let netns_name = format!("agentns_{:08x}", crc32fast::hash(branch_id.as_bytes()));
        network::create_named_netns(&netns_name)?;
        let netns_name_for_child = netns_name.clone();

        // Step 5: clone3() to create isolated process
        let profile_clone = self.profile.clone();
        let merged_dir_clone = merged_dir.clone();
        let agent_uid = self.agent_uid;
        let agent_gid = self.agent_gid;
        let command = self.command.clone();
        let child_fn = Box::new(move || -> i32 {
            // Close parent's end of socketpair
            unsafe { libc::close(parent_sock) };

            // Join the pre-created named network namespace.
            // The parent created it with `ip netns add` before clone3.
            // clone3 did NOT include CLONE_NEWNET, so the child is currently
            // in the parent's network namespace. We switch into the named
            // netns via setns() to get proper network isolation.
            {
                let netns_path = format!("/var/run/netns/{}", netns_name_for_child);
                // P2-N6: Post-fork — cannot use panic; write error and _exit(1)
                let netns_cstr = match std::ffi::CString::new(netns_path.as_str()) {
                    Ok(c) => c,
                    Err(_) => {
                        let msg = b"child: netns_path contains interior null byte\n";
                        unsafe { libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len()) };
                        unsafe { libc::close(child_sock) };
                        unsafe { libc::_exit(1) };
                    }
                };
                let netns_fd =
                    unsafe { libc::open(netns_cstr.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
                if netns_fd < 0 {
                    tracing::error!(
                        error = %std::io::Error::last_os_error(),
                        path = %netns_path,
                        "child: failed to open named netns"
                    );
                    unsafe { libc::close(child_sock) };
                    return 1;
                }
                let ret = unsafe { libc::setns(netns_fd, libc::CLONE_NEWNET) };
                unsafe { libc::close(netns_fd) };
                if ret != 0 {
                    tracing::error!(
                        error = %std::io::Error::last_os_error(),
                        path = %netns_path,
                        "child: failed to setns into named netns"
                    );
                    unsafe { libc::close(child_sock) };
                    return 1;
                }
                // Signal parent that we've joined the netns
                // H31: Check write() return value — failure means parent won't
                // know we're ready, leading to protocol deadlock.
                let ready: u8 = 1;
                let written = unsafe {
                    libc::write(child_sock, &ready as *const u8 as *const libc::c_void, 1)
                };
                if written != 1 {
                    tracing::error!(
                        error = %std::io::Error::last_os_error(),
                        "H31: child: failed to write netns ready signal to parent"
                    );
                    unsafe { libc::close(child_sock) };
                    return 1;
                }
            }

            // Wait for parent to signal (parent sets up cgroup + network first).
            // Protocol: child sends 1 byte (netns ready), then parent sends
            //   proxy_url_len (4 bytes LE) + proxy_url +
            //   mount_params (4x length-prefixed strings) + go (1 byte).
            // M6: Read proxy URL for environment variable injection.
            // M11: Use read_exact_raw to handle partial reads and EINTR.
            let mut len_buf = [0u8; 4];
            if let Err(e) = read_exact_raw(child_sock, &mut len_buf) {
                tracing::error!(error = %e, "child: failed to read proxy_url_len from parent");
                unsafe { libc::close(child_sock) };
                return 1;
            }
            // H26: Use usize::try_from for defense-in-depth on the u32→usize cast.
            let proxy_url_len = match usize::try_from(u32::from_le_bytes(len_buf)) {
                Ok(v) => v,
                Err(_) => {
                    tracing::error!("H26: proxy_url_len overflows usize");
                    unsafe { libc::close(child_sock) };
                    return 1;
                }
            };
            // S35: Bound allocation to prevent attacker-controlled length from causing OOM.
            if proxy_url_len > MAX_SOCKETPAIR_MSG_LEN {
                tracing::error!(
                    len = proxy_url_len,
                    max = MAX_SOCKETPAIR_MSG_LEN,
                    "child: proxy_url_len exceeds MAX_SOCKETPAIR_MSG_LEN"
                );
                unsafe { libc::close(child_sock) };
                return 1;
            }
            let proxy_url = if proxy_url_len > 0 {
                let mut url_buf = vec![0u8; proxy_url_len];
                if let Err(e) = read_exact_raw(child_sock, &mut url_buf) {
                    tracing::error!(error = %e, "child: failed to read proxy_url from parent");
                    unsafe { libc::close(child_sock) };
                    return 1;
                }
                String::from_utf8(url_buf).ok()
            } else {
                None
            };
            // M13: Read OverlayFS mount parameters from parent.
            // Protocol: 4 length-prefixed UTF-8 strings (base_path, upper, work, merged).
            // Each string is encoded as: len(4 bytes LE) + bytes.
            // M-ov2: Validate received paths (length, absolute, no null bytes).
            let mount_paths: Vec<std::path::PathBuf> = {
                let mut paths = Vec::with_capacity(4);
                for label in &["base_path", "upper_dir", "work_dir", "merged_dir"] {
                    let mut mlen_buf = [0u8; 4];
                    if let Err(e) = read_exact_raw(child_sock, &mut mlen_buf) {
                        tracing::error!(error = %e, field = label, "child: failed to read mount param length");
                        unsafe { libc::close(child_sock) };
                        return 1;
                    }
                    // Q4: u32-to-usize cast is safe here because the bounds check at
                    // the next line (mlen > 4096) ensures the value fits in usize on all platforms.
                    let mlen = u32::from_le_bytes(mlen_buf) as usize;
                    // M-ov2: Length bounds check before allocation
                    if mlen > 4096 {
                        tracing::error!(
                            field = label,
                            len = mlen,
                            "child: mount param exceeds max path length (4096)"
                        );
                        unsafe { libc::close(child_sock) };
                        return 1;
                    }
                    let mut mbuf = vec![0u8; mlen];
                    if let Err(e) = read_exact_raw(child_sock, &mut mbuf) {
                        tracing::error!(error = %e, field = label, "child: failed to read mount param value");
                        unsafe { libc::close(child_sock) };
                        return 1;
                    }
                    // M-ov2: Validate path before converting to PathBuf
                    if let Err(e) = overlay::OverlayMount::validate_received_path(&mbuf, label) {
                        tracing::error!(error = %e, field = label, "child: mount param validation failed");
                        unsafe { libc::close(child_sock) };
                        return 1;
                    }
                    match String::from_utf8(mbuf) {
                        Ok(s) => paths.push(std::path::PathBuf::from(s)),
                        Err(e) => {
                            tracing::error!(error = %e, field = label, "child: mount param is not valid UTF-8");
                            unsafe { libc::close(child_sock) };
                            return 1;
                        }
                    }
                }
                paths
            };

            // M13: Mount OverlayFS inside the child's mount namespace.
            // The mount is invisible to the parent/host.
            // H17: Pass allow_exec_overlay from profile to control MS_NOEXEC flag.
            if let Err(e) = overlay::OverlayMount::mount(
                &mount_paths[0], // base_path
                &mount_paths[1], // upper_dir
                &mount_paths[2], // work_dir
                &mount_paths[3], // merged_dir
                profile_clone.allow_exec_overlay,
            ) {
                tracing::error!(error = %e, "child: failed to mount OverlayFS in child namespace");
                unsafe { libc::close(child_sock) };
                return 1;
            }
            tracing::debug!("child: OverlayFS mounted in child namespace");

            // Read the final "go" byte
            let mut buf = [0u8; 1];
            if let Err(e) = read_exact_raw(child_sock, &mut buf) {
                tracing::error!(error = %e, "child: failed to read go byte from parent");
                unsafe { libc::close(child_sock) };
                return 1;
            }

            // Make the entire mount tree private to this namespace BEFORE any
            // mount/umount operations. By default, systemd marks mounts as
            // "shared", which causes mount/umount events to propagate between
            // namespaces. Without this, our umount2(/proc) would unmount /proc
            // in the PARENT namespace, breaking the host.
            unsafe {
                let root_path = std::ffi::CString::new("/").unwrap();
                if libc::mount(
                    std::ptr::null(),
                    root_path.as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                ) != 0
                {
                    tracing::error!(
                        error = %std::io::Error::last_os_error(),
                        "failed to make mount tree private in child"
                    );
                    libc::close(child_sock);
                    return 1;
                }
            }

            // V32: hidepid=2 omitted — PID namespace already limits /proc visibility
            // Remount /proc so it reflects only this PID namespace.
            // Without this, the agent sees host PIDs via the inherited /proc mount,
            // leaking process information and enabling /proc/<pid>/mem attacks.
            // M6: Check return values of umount/mount.
            unsafe {
                let proc_path = std::ffi::CString::new("/proc").unwrap();
                let proc_type = std::ffi::CString::new("proc").unwrap();
                // Detach the inherited /proc mount
                if libc::umount2(proc_path.as_ptr(), libc::MNT_DETACH) != 0 {
                    tracing::error!(
                        error = %std::io::Error::last_os_error(),
                        "failed to unmount /proc in child"
                    );
                    libc::close(child_sock);
                    return 1;
                }
                // Mount a fresh /proc scoped to this PID namespace
                // U10: proc mount uses default flags — nosuid/nodev/noexec would be added
                // in Podman-native mode via OCI spec. In direct mode, sensitive paths are
                // masked (C4) and /proc/sys is remounted read-only (C5) as compensating controls.
                if libc::mount(
                    proc_type.as_ptr(),
                    proc_path.as_ptr(),
                    proc_type.as_ptr(),
                    0,
                    std::ptr::null(),
                ) != 0
                {
                    tracing::error!(
                        error = %std::io::Error::last_os_error(),
                        "failed to mount /proc in child"
                    );
                    libc::close(child_sock);
                    return 1;
                }
            }

            // C4: Mask sensitive procfs/sysfs paths. This must happen after
            // /proc remount (so /proc/kcore exists) and before Landlock
            // (which would prevent the bind-mount).
            // H-20: Pass fail_mode to control strict vs best-effort behavior.
            if let Err(e) = mask_sensitive_paths(profile_clone.fail_mode) {
                tracing::error!(error = %e, "child: mask_sensitive_paths failed (fail-closed)");
                unsafe { libc::close(child_sock) };
                return 1;
            }

            // SECURITY-CRITICAL ORDERING: The following restrictions are applied
            // sequentially in the child process BEFORE execve(). This order is
            // mandatory — each step may require privileges that subsequent steps revoke:
            //   1. SELinux context (requires MAC_ADMIN, dropped in step 4)
            //   2. Landlock (irrevocable once applied)
            //   3. seccomp-BPF (irrevocable once loaded)
            //   4. Drop capabilities (irrevocable)
            //   5. Switch UID/GID (must be last — setuid drops ability to setgid)
            // All restrictions are applied before execve() so the agent process
            // NEVER runs with elevated privileges.
            //
            // M5: Set SELinux context BEFORE dropping capabilities.
            // Setting context on /proc/self/attr/current requires MAC_ADMIN capability,
            // which is dropped by drop_capabilities().
            if selinux::SelinuxEnforcer::verify_available() {
                if let Err(e) = selinux::SelinuxEnforcer::set_context(std::process::id(), "puzzlepod_t")
                {
                    tracing::warn!(error = %e, "failed to set SELinux context (continuing)");
                }
            }

            // Close inherited file descriptors > 2, EXCEPT child_sock.
            // The child inherits fds from the parent process (seccomp handler
            // epoll fds, notify fds from other branches, etc.). These are not
            // needed by the agent and represent an information leak vector.
            // Must happen BEFORE Landlock (which blocks /proc access).
            // child_sock is preserved — it's needed for seccomp fd exchange.
            unsafe {
                let proc_fd = std::ffi::CString::new("/proc/self/fd").unwrap();
                let dir = libc::opendir(proc_fd.as_ptr());
                if !dir.is_null() {
                    let dirfd = libc::dirfd(dir);
                    loop {
                        let entry = libc::readdir(dir);
                        if entry.is_null() {
                            break;
                        }
                        let name = std::ffi::CStr::from_ptr((*entry).d_name.as_ptr());
                        if let Ok(fd) = name.to_str().unwrap_or("").parse::<i32>() {
                            if fd > 2 && fd != dirfd && fd != child_sock {
                                libc::close(fd);
                            }
                        }
                    }
                    libc::closedir(dir);
                } else {
                    // Fallback: brute-force close fds 3..1024
                    for fd in 3..1024 {
                        if fd != child_sock {
                            libc::close(fd);
                        }
                    }
                }
            }

            // Apply Landlock (irrevocable)
            // PM5: proxy_port is not yet available inside the child closure;
            // pass None to use the default (3128) for now. The port value will
            // be threaded through when SandboxBuilder gains a proxy_port field.
            if let Err(e) = landlock::LandlockBuilder::apply(
                &profile_clone,
                std::slice::from_ref(&merged_dir_clone),
                None,
            ) {
                tracing::error!(error = %e, "failed to apply Landlock in child");
                unsafe { libc::close(child_sock) };
                return 1;
            }

            // Load seccomp filter (irrevocable)
            // SC2: bpf_clone_guard_active is captured from the parent's
            // load_clone_guard() result. When false, clone3 is added to the
            // USER_NOTIF list so namespace escape flags are checked.
            let seccomp_builder = seccomp::SeccompBuilder {
                bpf_clone_guard_active,
                seccomp_mode: profile_clone.seccomp_mode,
            };
            match seccomp_builder.apply(&profile_clone) {
                Ok(Some(notify_fd)) => {
                    // Send the notify fd to parent via SCM_RIGHTS
                    // H32: Make send_fd() failure fatal — if the parent doesn't
                    // receive the notify fd, seccomp USER_NOTIF-gated calls
                    // (execve, connect, bind) will hang indefinitely.
                    if send_fd(child_sock, notify_fd) < 0 {
                        tracing::error!(
                            "H32: failed to send seccomp notify fd to parent — aborting child"
                        );
                        unsafe { libc::close(child_sock) };
                        return 1;
                    }
                }
                Ok(None) => {
                    // No notify fd — send a sentinel byte
                    // H33: Check write() return value for sentinel byte.
                    let zero: u8 = 0;
                    let written = unsafe {
                        libc::write(child_sock, &zero as *const u8 as *const libc::c_void, 1)
                    };
                    if written != 1 {
                        tracing::error!(
                            error = %std::io::Error::last_os_error(),
                            "H33: child: failed to write sentinel byte to parent"
                        );
                        unsafe { libc::close(child_sock) };
                        return 1;
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to apply seccomp in child");
                    unsafe { libc::close(child_sock) };
                    return 1;
                }
            }

            // H1: Wait for parent ACK after seccomp notify fd registration.
            //
            // The parent must register the seccomp notify fd with the epoll-based
            // SeccompNotifHandler BEFORE the child calls execve(). Without this
            // synchronization, there is a race window where the child's first
            // execve/connect/bind would trigger a seccomp USER_NOTIF that the
            // parent is not yet polling for, causing the child to hang indefinitely.
            //
            // Protocol: child waits for a single ACK byte (0x42) from parent.
            //
            // H-32: Set a 30-second receive timeout so the child does not hang
            // indefinitely if the parent crashes or is slow to register the
            // seccomp notify fd.
            {
                let timeout = libc::timeval {
                    tv_sec: 30,
                    tv_usec: 0,
                };
                let ret = unsafe {
                    libc::setsockopt(
                        child_sock,
                        libc::SOL_SOCKET,
                        libc::SO_RCVTIMEO,
                        &timeout as *const libc::timeval as *const libc::c_void,
                        std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                    )
                };
                if ret != 0 {
                    tracing::warn!(
                        error = %std::io::Error::last_os_error(),
                        "child: failed to set SO_RCVTIMEO on socketpair (continuing without timeout)"
                    );
                }
            }
            let mut ack_buf = [0u8; 1];
            if let Err(e) = read_exact_raw(child_sock, &mut ack_buf) {
                tracing::error!(error = %e, "child: failed to read seccomp ACK from parent (timeout or error)");
                unsafe { libc::close(child_sock) };
                return 1;
            }
            if ack_buf[0] != 0x42 {
                tracing::error!(
                    ack = ack_buf[0],
                    "child: unexpected ACK byte from parent (expected 0x42)"
                );
                unsafe { libc::close(child_sock) };
                return 1;
            }

            // M8: Convert profile capability names to numeric values for retention.
            let keep_caps: Vec<u32> = profile_clone
                .capabilities
                .iter()
                .filter_map(|name| capabilities::cap_name_to_number(name))
                .collect();

            // Drop bounding set capabilities BEFORE switching credentials.
            // PR_CAPBSET_DROP requires CAP_SETPCAP in the effective set.
            // setuid() clears effective/permitted, so bounding set drops must
            // happen while we're still root. The bounding set limits what
            // capabilities can be acquired by this process or its children.
            if let Err(e) = capabilities::drop_bounding_set(&keep_caps) {
                tracing::error!(error = %e, "failed to drop bounding set in child");
                unsafe { libc::close(child_sock) };
                return 1;
            }

            // Switch to the agent's non-root UID/GID.
            // CAP_SETUID/CAP_SETGID are still in effective/permitted (only the
            // bounding set was cleared above). setuid() will then clear
            // effective/permitted as part of the UID transition.
            // C5: Reject uid=0 for FailClosed profiles.
            let reject_root = profile_clone.fail_mode == puzzled_types::FailMode::FailClosed;
            if let Err(e) = capabilities::switch_credentials(agent_uid, agent_gid, reject_root) {
                tracing::error!(error = %e, "failed to switch credentials in child");
                unsafe { libc::close(child_sock) };
                return 1;
            }

            // Drop remaining capabilities — clear effective, permitted, ambient
            // sets and set NO_NEW_PRIVS. The bounding set was already dropped above.
            // setuid() already cleared effective/permitted, but this ensures
            // ambient caps and NO_NEW_PRIVS are also handled.
            if let Err(e) = capabilities::drop_capabilities(&keep_caps) {
                tracing::error!(error = %e, "failed to drop capabilities in child");
                unsafe { libc::close(child_sock) };
                return 1;
            }

            unsafe { libc::close(child_sock) };

            // The child is now sandboxed — exec the agent binary or fall back to pause().
            if command.is_empty() {
                tracing::warn!(
                    "no command specified, falling back to pause() loop \
                     (use with_command() for production deployments)"
                );
                loop {
                    unsafe {
                        libc::pause();
                    }
                }
            }

            // chdir to the merged OverlayFS directory so the agent sees it as "/"
            // H23: Reject non-UTF-8 paths explicitly via to_str() rather than
            // silently mangling them via lossy conversion for chdir.
            let merged_str = match merged_dir_clone.to_str() {
                Some(s) => s,
                None => {
                    tracing::error!("H23: merged dir path contains non-UTF-8 bytes");
                    return 1;
                }
            };
            let merged_cstr = match std::ffi::CString::new(merged_str) {
                Ok(s) => s,
                Err(_) => {
                    tracing::error!("merged dir path contains null byte");
                    return 1;
                }
            };
            if unsafe { libc::chdir(merged_cstr.as_ptr()) } != 0 {
                tracing::error!(
                    path = %merged_dir_clone.display(),
                    "failed to chdir to merged dir"
                );
                return 1;
            }

            // Build CString args for execve
            let c_args: Vec<std::ffi::CString> = match command
                .iter()
                .map(|s| std::ffi::CString::new(s.as_str()))
                .collect::<std::result::Result<Vec<_>, _>>()
            {
                Ok(args) => args,
                Err(e) => {
                    tracing::error!(error = %e, "command argument contains null byte");
                    return 1;
                }
            };
            let c_arg_ptrs: Vec<*const libc::c_char> = c_args
                .iter()
                .map(|s| s.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect();

            // Minimal environment
            let env_path = std::ffi::CString::new("PATH=/usr/local/bin:/usr/bin:/bin").unwrap();
            let env_home = std::ffi::CString::new("HOME=/").unwrap();

            // M6: Inject proxy environment variables when network mode is Gated.
            // The proxy URL was received from the parent over the socketpair.
            let mut env_cstrings: Vec<std::ffi::CString> = Vec::new();
            if let Some(ref url) = proxy_url {
                // Set both upper and lower case variants for compatibility
                // with different HTTP client libraries.
                if let Ok(c) = std::ffi::CString::new(format!("HTTP_PROXY={}", url)) {
                    env_cstrings.push(c);
                }
                if let Ok(c) = std::ffi::CString::new(format!("HTTPS_PROXY={}", url)) {
                    env_cstrings.push(c);
                }
                if let Ok(c) = std::ffi::CString::new(format!("http_proxy={}", url)) {
                    env_cstrings.push(c);
                }
                if let Ok(c) = std::ffi::CString::new(format!("https_proxy={}", url)) {
                    env_cstrings.push(c);
                }
                // NO_PROXY for loopback — agents should not proxy localhost traffic
                if let Ok(c) =
                    std::ffi::CString::new("NO_PROXY=localhost,127.0.0.1,::1".to_string())
                {
                    env_cstrings.push(c);
                }
                if let Ok(c) =
                    std::ffi::CString::new("no_proxy=localhost,127.0.0.1,::1".to_string())
                {
                    env_cstrings.push(c);
                }
            }

            let mut c_env: Vec<*const libc::c_char> = vec![env_path.as_ptr(), env_home.as_ptr()];
            for cs in &env_cstrings {
                c_env.push(cs.as_ptr());
            }
            c_env.push(std::ptr::null());

            // Clear errno before execve so we get the real error code
            unsafe { *libc::__errno_location() = 0 };
            unsafe {
                libc::execve(c_arg_ptrs[0], c_arg_ptrs.as_ptr(), c_env.as_ptr());
            }

            // execve only returns on error
            let exec_err = std::io::Error::last_os_error();
            tracing::error!(
                command = ?command,
                error = %exec_err,
                "execve failed (if Permission denied: check Landlock read_allowlist and seccomp exec_allowlist)"
            );
            1
        });

        // CR-1/CR-2: Pass cgroup_fd to clone3 for CLONE_INTO_CGROUP
        let (pidfd, child_pid) =
            namespace::NamespaceBuilder::create_isolated_process(child_fn, cgroup_fd)?;
        // H24: Use i32::try_from instead of bare `as i32` to detect PID truncation.
        let child_pid_i32 = i32::try_from(child_pid).map_err(|_| {
            crate::error::PuzzledError::Sandbox(format!(
                "H24: child_pid {} exceeds i32::MAX — cannot safely use with waitpid",
                child_pid
            ))
        })?;
        cleanup.child_pid = Some(child_pid_i32);
        cleanup.pidfd = Some(pidfd);

        // CR-1: Close cgroup fd after clone3 — no longer needed
        if let Some(fd) = cgroup_fd {
            unsafe { libc::close(fd) };
        }

        // Close child's end of socketpair in parent
        unsafe { libc::close(child_sock) };

        // CR-1/CR-2: Only use post-clone add_process() if CLONE_INTO_CGROUP
        // was not available (cgroup_fd was None). When CLONE_INTO_CGROUP was
        // used, the child is already in the correct cgroup.
        if cgroup_fd.is_none() {
            cgroup::CgroupManager::add_process(&cgroup_path, child_pid)?;
        }

        // Verify child is still alive after cgroup assignment.
        // In cgroup v2, moving a process into a memory-limited cgroup can
        // trigger OOM kill if the process's memory exceeds the limit.
        {
            let mut status: libc::c_int = 0;
            let ret = unsafe { libc::waitpid(child_pid_i32, &mut status, libc::WNOHANG) };
            if ret > 0 {
                let exit_info = if libc::WIFEXITED(status) {
                    format!("exited with code {}", libc::WEXITSTATUS(status))
                } else if libc::WIFSIGNALED(status) {
                    let sig = libc::WTERMSIG(status);
                    format!(
                        "killed by signal {} ({})",
                        sig,
                        if sig == libc::SIGKILL {
                            "SIGKILL — likely OOM"
                        } else if sig == libc::SIGSEGV {
                            "SIGSEGV"
                        } else if sig == libc::SIGABRT {
                            "SIGABRT"
                        } else {
                            "unknown"
                        }
                    )
                } else {
                    format!("status=0x{:x}", status)
                };
                return Err(crate::error::PuzzledError::Sandbox(format!(
                    "child process {} died immediately after cgroup assignment: {}",
                    child_pid, exit_info
                )));
            }
        }

        // C5: Configure network isolation for this branch.
        // Must happen after clone3 (needs agent PID for veth setup) and before
        // signaling child to proceed (child needs proxy env vars at exec time).
        //
        // H2: Network setup failure handling depends on network mode:
        // - Blocked/Gated: fail-closed — network isolation is a security requirement,
        //   so failure must abort sandbox creation (unless fail_mode overrides).
        // - Monitored/Unrestricted: degrade gracefully — these modes don't enforce
        //   network restrictions, so failure is non-fatal.
        //
        // Wait for the child to join the named network namespace.
        // The child does setns() into the pre-created netns and then
        // writes 1 byte to signal readiness.
        cleanup.netns_name = Some(netns_name.clone());
        {
            let mut ready_buf = [0u8; 1];
            if let Err(e) = read_exact_raw(parent_sock, &mut ready_buf) {
                // Child likely died during netns setns(). Check waitpid for details.
                let mut status: libc::c_int = 0;
                let ret = unsafe { libc::waitpid(child_pid_i32, &mut status, libc::WNOHANG) };
                let child_info = if ret > 0 {
                    if libc::WIFEXITED(status) {
                        format!("child exited with code {}", libc::WEXITSTATUS(status))
                    } else if libc::WIFSIGNALED(status) {
                        format!("child killed by signal {}", libc::WTERMSIG(status))
                    } else {
                        format!("child status=0x{:x}", status)
                    }
                } else {
                    "child status unknown".to_string()
                };
                return Err(crate::error::PuzzledError::Sandbox(format!(
                    "child failed to join named netns '{}': {} ({})",
                    netns_name, e, child_info
                )));
            }
        }

        // PM5: Use the config default proxy port (3128) instead of a mismatched
        // hardcoded value. In production, this should be threaded through from
        // config.network.proxy_port via BranchManager to SandboxBuilder.
        let default_proxy_port = 3128u16;
        let net_setup = match network::NetworkSetup::configure(
            branch_id,
            self.profile.network.mode,
            &netns_name,
            default_proxy_port,
        ) {
            Ok(ns) => {
                tracing::info!(
                    branch_id,
                    mode = ?self.profile.network.mode,
                    "network setup complete"
                );
                Some(ns)
            }
            Err(e) => {
                match self.profile.network.mode {
                    puzzled_types::NetworkMode::Blocked | puzzled_types::NetworkMode::Gated => {
                        // H2: For Blocked/Gated profiles, network isolation failure
                        // is a security violation. Check fail_mode for override.
                        if self.profile.fail_mode == puzzled_types::FailMode::FailOperational
                            || self.profile.fail_mode == puzzled_types::FailMode::FailSilent
                        {
                            tracing::warn!(
                                branch_id,
                                error = %e,
                                mode = ?self.profile.network.mode,
                                fail_mode = ?self.profile.fail_mode,
                                "network setup failed but fail_mode allows degraded operation"
                            );
                            None
                        } else {
                            tracing::error!(
                                branch_id,
                                error = %e,
                                mode = ?self.profile.network.mode,
                                "network setup failed — aborting sandbox creation (fail-closed)"
                            );
                            return Err(crate::error::PuzzledError::Network(format!(
                                "network setup failed for {:?} mode: {}",
                                self.profile.network.mode, e
                            )));
                        }
                    }
                    puzzled_types::NetworkMode::Monitored
                    | puzzled_types::NetworkMode::Unrestricted => {
                        tracing::warn!(
                            branch_id,
                            error = %e,
                            mode = ?self.profile.network.mode,
                            "network setup failed (degrading gracefully for non-enforcing mode)"
                        );
                        None
                    }
                }
            }
        };

        // M6: Derive proxy URL from NetworkSetup for the child environment.
        let proxy_url: Option<String> = net_setup
            .as_ref()
            .and_then(|ns| ns.proxy_addr.map(|addr| format!("http://{}", addr)));

        // Step 7: Signal child to proceed (apply Landlock + seccomp).
        // Protocol: proxy_url_len (4 bytes LE) + proxy_url +
        //   mount_params (4x length-prefixed strings) + go (1 byte).
        // M12: Check write() return values — EPIPE means child died.
        let proxy_bytes = proxy_url.as_deref().unwrap_or("").as_bytes();
        // P2-N5: Safe conversion — reject absurdly long proxy URLs
        let proxy_len = u32::try_from(proxy_bytes.len())
            .map_err(|_| crate::error::PuzzledError::Sandbox("proxy URL too long".to_string()))?
            .to_le_bytes();
        if let Err(e) = write_all_raw(parent_sock, &proxy_len) {
            tracing::warn!(error = %e, "parent: failed to write proxy_url_len to child, aborting");
            unsafe { libc::close(parent_sock) };
            return Err(crate::error::PuzzledError::Sandbox(format!(
                "parent write to child socketpair failed: {}",
                e
            )));
        }
        if !proxy_bytes.is_empty() {
            if let Err(e) = write_all_raw(parent_sock, proxy_bytes) {
                tracing::warn!(error = %e, "parent: failed to write proxy_url to child, aborting");
                unsafe { libc::close(parent_sock) };
                return Err(crate::error::PuzzledError::Sandbox(format!(
                    "parent write to child socketpair failed: {}",
                    e
                )));
            }
        }

        // M13: Send OverlayFS mount parameters to child.
        // Protocol: 4 length-prefixed UTF-8 strings (base_path, upper, work, merged).
        for (label, path) in &[
            ("base_path", &self.base_path),
            ("upper_dir", &upper_dir),
            ("work_dir", &work_dir),
            ("merged_dir", &merged_dir),
        ] {
            // H21: Reject non-UTF-8 paths explicitly via to_str() rather than
            // silently replacing bytes with U+FFFD (lossy conversion).
            let path_str = path.to_str().ok_or_else(|| {
                crate::error::PuzzledError::Sandbox(format!(
                    "mount param '{}' contains non-UTF-8 bytes: {}",
                    label,
                    path.display()
                ))
            })?;
            let path_bytes = path_str.as_bytes().to_vec();
            // P2-N5: Safe conversion — reject absurdly long mount paths
            let path_len = u32::try_from(path_bytes.len())
                .map_err(|_| {
                    crate::error::PuzzledError::Sandbox(format!(
                        "mount param '{}' path too long",
                        label
                    ))
                })?
                .to_le_bytes();
            if let Err(e) = write_all_raw(parent_sock, &path_len) {
                tracing::warn!(error = %e, field = label, "parent: failed to write mount param length");
                unsafe { libc::close(parent_sock) };
                return Err(crate::error::PuzzledError::Sandbox(format!(
                    "parent write mount param {} length failed: {}",
                    label, e
                )));
            }
            if let Err(e) = write_all_raw(parent_sock, &path_bytes) {
                tracing::warn!(error = %e, field = label, "parent: failed to write mount param value");
                unsafe { libc::close(parent_sock) };
                return Err(crate::error::PuzzledError::Sandbox(format!(
                    "parent write mount param {} value failed: {}",
                    label, e
                )));
            }
        }

        let go: u8 = 1;
        if let Err(e) = write_all_raw(parent_sock, &[go]) {
            tracing::warn!(error = %e, "parent: failed to write go byte to child, aborting");
            unsafe { libc::close(parent_sock) };
            return Err(crate::error::PuzzledError::Sandbox(format!(
                "parent write to child socketpair failed: {}",
                e
            )));
        }

        // Step 8: Receive seccomp notify fd from child via SCM_RIGHTS
        let seccomp_notify_fd = match recv_fd(parent_sock) {
            Some(fd) if fd >= 0 => {
                tracing::debug!(notify_fd = fd, "received seccomp notify fd from child");
                Some(fd)
            }
            _ => {
                tracing::debug!("no seccomp notify fd received from child");
                None
            }
        };

        // SH1: Do NOT send ACK byte here. The ACK must be sent AFTER
        // SeccompNotifHandler::register() completes in BranchManager::create().
        // The parent_sock is kept alive in SandboxHandle so the caller can
        // send the ACK via send_seccomp_ack() at the right time.
        // The child blocks on reading the ACK before calling execve().

        // SC4: XFS quota setup moved to before clone3 (see above).

        // C6/SH5: Initialize fanotify behavioral monitoring on the merged directory.
        // This must happen after OverlayFS mount and after the child is running.
        // The monitor runs in a background thread and sends BehavioralTrigger
        // events that the branch manager consumes.
        #[cfg(target_os = "linux")]
        let (fanotify_trigger_rx, fanotify_counters, fanotify_needs_full_diff) = {
            match fanotify::FanotifyMonitor::init(
                puzzled_types::BranchId::from(branch_id.to_string()),
                merged_dir.clone(),
                self.profile.behavioral.clone(),
            ) {
                Ok(monitor) => {
                    let (trigger_rx, counters, _touched, needs_full_diff, _shutdown) =
                        monitor.start();
                    tracing::info!(
                        branch_id,
                        merged_dir = %merged_dir.display(),
                        "fanotify behavioral monitoring started"
                    );
                    // SH5: Store trigger_rx, counters, and needs_full_diff in
                    // SandboxHandle so they live as long as the branch and are
                    // accessible for governance decisions by BranchManager.
                    (Some(trigger_rx), Some(counters), Some(needs_full_diff))
                }
                Err(e) => {
                    tracing::warn!(
                        branch_id,
                        error = %e,
                        "fanotify monitoring initialization failed (continuing without behavioral monitoring)"
                    );
                    (None, None, None)
                }
            }
        };

        // C7: Load BPF LSM exec_guard program for exec rate limiting.
        // Best-effort: if BPF loading fails, the sandbox still has Landlock +
        // seccomp + namespace isolation. BPF LSM is an additional defense layer.
        #[cfg(target_os = "linux")]
        {
            let bpf_obj_path = std::path::PathBuf::from("/usr/lib/puzzled/bpf/exec_guard.bpf.o");
            let mut bpf_manager = bpf_lsm::BpfLsmManager::new(&bpf_obj_path);
            match bpf_manager.load() {
                Ok(()) => {
                    // Per-branch rate limiting is configured later in
                    // BranchManager::create() (branch.rs) which reads the cgroup inode
                    // via metadata().ino() and calls bpf_lsm.configure_cgroup().
                    // Here we only load and attach the global BPF program.
                    tracing::info!(
                        branch_id,
                        attached = bpf_manager.is_attached(),
                        "BPF LSM exec_guard loaded"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        branch_id,
                        error = %e,
                        "BPF LSM loading failed (continuing without exec rate limiting)"
                    );
                }
            }
        }

        tracing::info!(
            branch_id,
            pid = child_pid,
            pidfd,
            seccomp_notify_fd = ?seccomp_notify_fd,
            "sandbox created"
        );

        // All steps succeeded — defuse the cleanup guard
        cleanup.defuse();

        Ok(SandboxHandle {
            pidfd,
            pid: child_pid,
            upper_dir,
            work_dir,
            merged_dir,
            cgroup_path,
            seccomp_notify_fd,
            fanotify_trigger_rx,
            fanotify_counters,
            fanotify_needs_full_diff,
            // SH1: Keep parent_sock alive so BranchManager can send seccomp
            // ACK after registering the notify fd with SeccompNotifHandler.
            parent_sock: Some(parent_sock),
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn build(&self, _branch_id: &str) -> Result<SandboxHandle> {
        Err(crate::error::PuzzledError::Sandbox(
            "sandbox requires Linux".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// SCM_RIGHTS fd passing helpers
// ---------------------------------------------------------------------------

/// Send a file descriptor over a Unix socket using SCM_RIGHTS.
#[cfg(target_os = "linux")]
// L5: Returns isize directly from sendmsg() — no truncating cast to i32.
fn send_fd(sock: i32, fd: i32) -> isize {
    unsafe {
        let data: u8 = 1;
        let iov = libc::iovec {
            iov_base: &data as *const u8 as *mut libc::c_void,
            iov_len: 1,
        };

        // cmsg buffer: header + one i32 fd
        let cmsg_space = libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) as usize;
        let mut cmsg_buf = vec![0u8; cmsg_space];

        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &iov as *const libc::iovec as *mut libc::iovec;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_space;

        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as usize;

        let fd_ptr = libc::CMSG_DATA(cmsg) as *mut i32;
        *fd_ptr = fd;

        // L5: Return raw isize from sendmsg(); caller checks < 0 for error.
        libc::sendmsg(sock, &msg, 0)
    }
}

/// Receive a file descriptor over a Unix socket using SCM_RIGHTS.
#[cfg(target_os = "linux")]
fn recv_fd(sock: i32) -> Option<i32> {
    unsafe {
        let mut data: u8 = 0;
        let mut iov = libc::iovec {
            iov_base: &mut data as *mut u8 as *mut libc::c_void,
            iov_len: 1,
        };

        let cmsg_space = libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) as usize;
        let mut cmsg_buf = vec![0u8; cmsg_space];

        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_space;

        let ret = libc::recvmsg(sock, &mut msg, 0);
        if ret <= 0 {
            return None;
        }

        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return None;
        }

        // S46: Validate cmsg_len before extracting the fd to ensure the
        // control message actually contains a complete file descriptor.
        let required_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as usize;
        if (*cmsg).cmsg_len < required_len {
            return None;
        }

        if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
            let fd_ptr = libc::CMSG_DATA(cmsg) as *const i32;
            Some(*fd_ptr)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_profile() -> AgentProfile {
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
        }
    }

    #[test]
    fn test_sandbox_builder_new() {
        let profile = test_profile();
        let base_path = PathBuf::from("/base");
        let branch_root = PathBuf::from("/branches");

        let builder = SandboxBuilder::new(profile.clone(), base_path.clone(), branch_root.clone());

        assert_eq!(builder.profile.name, "test");
        assert_eq!(builder.base_path, base_path);
        assert_eq!(builder.branch_root, branch_root);
    }

    #[test]
    fn test_sandbox_builder_default_command_empty() {
        let profile = test_profile();
        let builder =
            SandboxBuilder::new(profile, PathBuf::from("/base"), PathBuf::from("/branches"));
        assert!(
            builder.command.is_empty(),
            "default command should be empty"
        );
    }

    #[test]
    fn test_sandbox_builder_with_command() {
        let profile = test_profile();
        let builder =
            SandboxBuilder::new(profile, PathBuf::from("/base"), PathBuf::from("/branches"))
                .with_command(vec!["/usr/bin/python3".to_string(), "agent.py".to_string()]);

        assert_eq!(builder.command.len(), 2);
        assert_eq!(builder.command[0], "/usr/bin/python3");
        assert_eq!(builder.command[1], "agent.py");
    }

    #[test]
    fn test_sandbox_builder_with_credentials_and_command() {
        let profile = test_profile();
        let builder =
            SandboxBuilder::new(profile, PathBuf::from("/base"), PathBuf::from("/branches"))
                .with_credentials(1000, 1000)
                .with_command(vec!["/bin/sh".to_string()]);

        assert_eq!(builder.agent_uid, 1000);
        assert_eq!(builder.agent_gid, 1000);
        assert_eq!(builder.command, vec!["/bin/sh".to_string()]);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_sandbox_builder_build_non_linux() {
        let profile = test_profile();
        let builder =
            SandboxBuilder::new(profile, PathBuf::from("/base"), PathBuf::from("/branches"));

        let result = builder.build("test-branch");
        assert!(result.is_err(), "build() should return error on non-Linux");
    }

    #[test]
    fn test_sandbox_handle_fields() {
        // Verify SandboxHandle can be constructed with all expected fields
        // Use std::mem::ManuallyDrop to prevent Drop from closing invalid fds
        let handle = std::mem::ManuallyDrop::new(SandboxHandle {
            pidfd: -1, // Use -1 to prevent Drop from closing invalid fd
            pid: 1234,
            upper_dir: PathBuf::from("/branches/test/upper"),
            work_dir: PathBuf::from("/branches/test/work"),
            merged_dir: PathBuf::from("/branches/test/merged"),
            cgroup_path: PathBuf::from("/sys/fs/cgroup/puzzle.slice/agent-test.scope"),
            seccomp_notify_fd: None, // Use None to prevent Drop from closing
            fanotify_trigger_rx: None,
            fanotify_counters: None,
            fanotify_needs_full_diff: None,
            parent_sock: None,
        });

        assert_eq!(handle.pidfd, -1);
        assert_eq!(handle.pid, 1234);
        assert_eq!(handle.upper_dir, PathBuf::from("/branches/test/upper"));
        assert_eq!(handle.work_dir, PathBuf::from("/branches/test/work"));
        assert_eq!(handle.merged_dir, PathBuf::from("/branches/test/merged"));
        assert_eq!(
            handle.cgroup_path,
            PathBuf::from("/sys/fs/cgroup/puzzle.slice/agent-test.scope")
        );
        assert_eq!(handle.seccomp_notify_fd, None);
    }

    /// H3: Verify SENSITIVE_PATHS has the expected number of entries.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_sensitive_paths_count() {
        assert_eq!(
            SENSITIVE_PATHS.len(),
            19,
            "SENSITIVE_PATHS should have 19 entries (H3, Issue #9, S20+S27, R18)"
        );
    }

    /// S20+S27: /proc/latency_stats must be in SENSITIVE_PATHS (scheduling
    /// latency histogram — timing side-channel).
    #[cfg(target_os = "linux")]
    #[test]
    fn test_sensitive_paths_includes_proc_latency_stats() {
        assert!(
            SENSITIVE_PATHS.contains(&"/proc/latency_stats"),
            "SENSITIVE_PATHS must include /proc/latency_stats (timing side-channel)"
        );
    }

    /// S20+S27: /proc/timer_stats must be in SENSITIVE_PATHS (timer
    /// statistics — timing attacks).
    #[cfg(target_os = "linux")]
    #[test]
    fn test_sensitive_paths_includes_proc_timer_stats() {
        assert!(
            SENSITIVE_PATHS.contains(&"/proc/timer_stats"),
            "SENSITIVE_PATHS must include /proc/timer_stats (timing attacks)"
        );
    }

    /// S20+S27: /proc/scsi must be in SENSITIVE_PATHS (SCSI device
    /// enumeration — hardware info leak).
    #[cfg(target_os = "linux")]
    #[test]
    fn test_sensitive_paths_includes_proc_scsi() {
        assert!(
            SENSITIVE_PATHS.contains(&"/proc/scsi"),
            "SENSITIVE_PATHS must include /proc/scsi (SCSI device enumeration)"
        );
    }

    /// S20+S27: /sys/kernel/debug must be in SENSITIVE_PATHS (kernel debug
    /// symbols — exploit development aid).
    #[cfg(target_os = "linux")]
    #[test]
    fn test_sensitive_paths_includes_sys_kernel_debug() {
        assert!(
            SENSITIVE_PATHS.contains(&"/sys/kernel/debug"),
            "SENSITIVE_PATHS must include /sys/kernel/debug (kernel debug symbols)"
        );
    }

    /// Issue #9: /proc/modules must be in SENSITIVE_PATHS (loaded kernel
    /// modules — enables targeted exploit development).
    #[cfg(target_os = "linux")]
    #[test]
    fn test_sensitive_paths_includes_proc_modules() {
        assert!(
            SENSITIVE_PATHS.contains(&"/proc/modules"),
            "SENSITIVE_PATHS must include /proc/modules (kernel module enumeration)"
        );
    }

    /// Issue #9: /proc/config.gz must be in SENSITIVE_PATHS (kernel
    /// configuration — reveals enabled features and attack surface).
    #[cfg(target_os = "linux")]
    #[test]
    fn test_sensitive_paths_includes_proc_config() {
        assert!(
            SENSITIVE_PATHS.contains(&"/proc/config.gz"),
            "SENSITIVE_PATHS must include /proc/config.gz (kernel config leak)"
        );
    }

    /// Issue #9: /proc/version must be in SENSITIVE_PATHS (kernel version
    /// disclosure aids targeted exploits).
    #[cfg(target_os = "linux")]
    #[test]
    fn test_sensitive_paths_includes_proc_version() {
        assert!(
            SENSITIVE_PATHS.contains(&"/proc/version"),
            "SENSITIVE_PATHS must include /proc/version (kernel version leak)"
        );
    }

    /// R18: /proc/asound must be in SENSITIVE_PATHS (Docker masks this).
    #[cfg(target_os = "linux")]
    #[test]
    fn test_r18_proc_asound_in_sensitive_paths() {
        assert!(
            SENSITIVE_PATHS.contains(&"/proc/asound"),
            "R18: /proc/asound must be in SENSITIVE_PATHS (Docker masks it)"
        );
    }

    /// R16: Verify production code in bpf_lsm.rs does not silently discard
    /// bpf_map_delete errors via `let _ = bpf_map_delete`.
    #[test]
    fn test_r16_no_silent_bpf_map_delete_discard() {
        let source = include_str!("bpf_lsm.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        assert!(
            !production_code.contains("let _ = bpf_map_delete"),
            "R16: production code must not use `let _ = bpf_map_delete` — errors must be logged"
        );
    }

    #[test]
    fn test_sandbox_builder_with_credentials() {
        let profile = test_profile();
        let builder =
            SandboxBuilder::new(profile, PathBuf::from("/base"), PathBuf::from("/branches"))
                .with_credentials(65534, 65534);

        assert_eq!(builder.agent_uid, 65534);
        assert_eq!(builder.agent_gid, 65534);
    }

    #[test]
    fn test_sandbox_builder_default_credentials() {
        let profile = test_profile();
        let builder =
            SandboxBuilder::new(profile, PathBuf::from("/base"), PathBuf::from("/branches"));

        assert_eq!(builder.agent_uid, 0, "default UID should be 0");
        assert_eq!(builder.agent_gid, 0, "default GID should be 0");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_sandbox_builder_build_error_message() {
        let profile = test_profile();
        let builder =
            SandboxBuilder::new(profile, PathBuf::from("/base"), PathBuf::from("/branches"));

        let result = builder.build("test-branch");
        assert!(result.is_err());
        match result {
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("Linux"),
                    "non-Linux build error should mention Linux, got: {}",
                    msg
                );
            }
            Ok(_) => panic!("expected error on non-Linux"),
        }
    }

    /// L4: Verify SandboxHandle Drop guards against invalid fds.
    /// S13: Non-Linux stub for send_seccomp_ack must return Err.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_send_seccomp_ack_non_linux_returns_error() {
        let mut handle = SandboxHandle {
            pidfd: -1,
            pid: 0,
            upper_dir: PathBuf::from("/tmp"),
            work_dir: PathBuf::from("/tmp"),
            merged_dir: PathBuf::from("/tmp"),
            cgroup_path: PathBuf::from("/tmp"),
            seccomp_notify_fd: None,
            fanotify_trigger_rx: None,
            fanotify_counters: None,
            fanotify_needs_full_diff: None,
            parent_sock: None,
        };
        let result = send_seccomp_ack(&mut handle);
        assert!(
            result.is_err(),
            "non-Linux send_seccomp_ack should return Err"
        );
        let err = result.err().unwrap().to_string();
        assert!(
            err.contains("requires Linux"),
            "error should mention Linux, got: {}",
            err
        );
    }

    /// S35: Verify socketpair message length is bounded by MAX_SOCKETPAIR_MSG_LEN
    /// to prevent unbounded allocation from attacker-controlled length field.
    #[test]
    fn test_s35_socketpair_bounded_alloc() {
        let source = include_str!("mod.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        assert!(
            production_code.contains("MAX_SOCKETPAIR_MSG_LEN"),
            "S35: production code must define MAX_SOCKETPAIR_MSG_LEN constant \
             to bound socketpair message allocation"
        );
        // Verify the constant is used in a bounds check before allocation
        assert!(
            production_code.contains("proxy_url_len > MAX_SOCKETPAIR_MSG_LEN"),
            "S35: proxy_url_len must be checked against MAX_SOCKETPAIR_MSG_LEN \
             before allocating the buffer"
        );
    }

    #[test]
    fn test_sandbox_handle_drop_negative_fds() {
        // Should not panic or error when dropping with -1 fds
        let _handle = SandboxHandle {
            pidfd: -1,
            pid: 0,
            upper_dir: PathBuf::from("/tmp"),
            work_dir: PathBuf::from("/tmp"),
            merged_dir: PathBuf::from("/tmp"),
            cgroup_path: PathBuf::from("/tmp"),
            seccomp_notify_fd: Some(-1),
            fanotify_trigger_rx: None,
            fanotify_counters: None,
            fanotify_needs_full_diff: None,
            parent_sock: Some(-1),
        };
        // Drop runs here — should not panic
    }

    /// H21: Mount param path serialization must not use to_string_lossy()
    /// which silently replaces non-UTF-8 bytes with U+FFFD.
    #[test]
    fn test_h21_no_to_string_lossy_mount_params() {
        let source = include_str!("mod.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // Find the mount param serialization loop
        let mount_loop = prod_source
            .find("M13: Send OverlayFS mount parameters")
            .expect("H21: must have mount param serialization section");
        let mount_section = &prod_source[mount_loop..];
        // Get up to the next major section (go byte write)
        let end = mount_section
            .find("let go: u8")
            .unwrap_or(mount_section.len());
        let mount_body = &mount_section[..end];
        assert!(
            !mount_body.contains("to_string_lossy"),
            "H21: mount param path serialization must use to_str() instead of \
             to_string_lossy() to reject non-UTF-8 paths explicitly.\n\
             Found to_string_lossy in mount param section."
        );
    }

    /// H22: upper_dir chown must not use to_string_lossy().
    #[test]
    fn test_h22_no_to_string_lossy_upper_dir_chown() {
        let source = include_str!("mod.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // Find the chown section
        let chown_idx = prod_source
            .find("libc::chown(c_upper")
            .expect("H22: must have chown(c_upper) call");
        // Check the ~20 lines before chown for to_string_lossy
        let start = chown_idx.saturating_sub(500);
        let chown_context = &prod_source[start..chown_idx];
        // Find only the CString construction for c_upper
        let c_upper_start = chown_context.rfind("let c_upper").unwrap_or(0);
        let c_upper_section = &chown_context[c_upper_start..];
        assert!(
            !c_upper_section.contains("to_string_lossy"),
            "H22: upper_dir CString for chown must use to_str() instead of to_string_lossy()"
        );
    }

    /// H23: merged_dir CString in child must not use to_string_lossy().
    #[test]
    fn test_h23_no_to_string_lossy_merged_dir_child() {
        let source = include_str!("mod.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // Find the merged_cstr construction in child
        let merged_idx = prod_source
            .find("chdir to the merged OverlayFS")
            .expect("H23: must have chdir section for merged dir");
        let merged_section = &prod_source[merged_idx..];
        let end = merged_section
            .find("libc::chdir")
            .unwrap_or(merged_section.len());
        let merged_body = &merged_section[..end];
        assert!(
            !merged_body.contains("to_string_lossy"),
            "H23: merged_dir CString in child must use to_str() instead of to_string_lossy()"
        );
    }

    /// H24: child_pid must not use bare `as i32` — use i32::try_from().
    #[test]
    fn test_h24_child_pid_safe_cast() {
        let source = include_str!("mod.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            !prod_source.contains("child_pid as i32"),
            "H24: must not use bare `child_pid as i32` — use i32::try_from(child_pid)"
        );
    }

    /// H26: proxy_url_len must use usize::try_from instead of bare `as usize`.
    #[test]
    fn test_h26_proxy_url_len_safe_cast() {
        let source = include_str!("mod.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            !prod_source.contains("from_le_bytes(len_buf) as usize"),
            "H26: proxy_url_len must use usize::try_from() instead of bare `as usize`"
        );
    }

    /// H31: netns ready signal write() must check return value.
    #[test]
    fn test_h31_netns_ready_write_checked() {
        let source = include_str!("mod.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // Find the "Signal parent that we've joined the netns" section
        let signal_idx = prod_source
            .find("Signal parent that we've joined the netns")
            .expect("H31: must have netns ready signal section");
        let signal_section = &prod_source[signal_idx..];
        // Get the next ~30 lines
        let end = signal_section
            .find("Wait for parent to signal")
            .unwrap_or(signal_section.len());
        let signal_body = &signal_section[..end];
        assert!(
            signal_body.contains("written != 1") || signal_body.contains("if written"),
            "H31: netns ready signal write() return value must be checked"
        );
    }

    /// H32: send_fd() failure must be fatal in child (return/exit, not just log).
    #[test]
    fn test_h32_send_fd_failure_fatal() {
        let source = include_str!("mod.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // Find the send_fd call in child
        let send_idx = prod_source
            .find("send_fd(child_sock, notify_fd)")
            .expect("H32: must have send_fd call in child");
        let send_section = &prod_source[send_idx..];
        let end = send_section.find("Ok(None)").unwrap_or(send_section.len());
        let send_body = &send_section[..end];
        assert!(
            send_body.contains("return 1"),
            "H32: send_fd() failure must cause child to return/exit, not just log"
        );
    }

    /// H33: Sentinel byte write() must check return value.
    #[test]
    fn test_h33_sentinel_write_checked() {
        let source = include_str!("mod.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // Find the sentinel byte section (Ok(None) branch)
        let sentinel_idx = prod_source
            .find("No notify fd — send a sentinel byte")
            .expect("H33: must have sentinel byte section");
        let sentinel_section = &prod_source[sentinel_idx..];
        let end = sentinel_section
            .find("Err(e) =>")
            .unwrap_or(sentinel_section.len());
        let sentinel_body = &sentinel_section[..end];
        assert!(
            sentinel_body.contains("written != 1") || sentinel_body.contains("if written"),
            "H33: sentinel byte write() return value must be checked"
        );
    }

    /// S46: Ensure recv_fd validates cmsg_len before extracting the fd.
    #[test]
    fn test_s46_recv_fd_cmsg_validation() {
        let source = include_str!("mod.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // Find the recv_fd function and check that cmsg_len validation exists
        let recv_fn_start = prod_source
            .find("fn recv_fd")
            .expect("recv_fd function must exist in sandbox/mod.rs");
        let recv_fn_block = &prod_source[recv_fn_start..];
        // The function should end at the next top-level fn or end of prod source
        let recv_fn_end = recv_fn_block[1..]
            .find("\nfn ")
            .map(|p| p + 1)
            .unwrap_or(recv_fn_block.len());
        let recv_fn_body = &recv_fn_block[..recv_fn_end];

        assert!(
            recv_fn_body.contains("cmsg_len"),
            "S46: recv_fd must validate cmsg_len before extracting the fd"
        );
        assert!(
            recv_fn_body.contains("cmsg_len < required_len") || recv_fn_body.contains("cmsg_len <"),
            "S46: recv_fd must check cmsg_len is large enough for a file descriptor. \
             Found recv_fd body without cmsg_len bounds check."
        );
    }

    // L5: Verify that send_fd does not truncate sendmsg() isize return to i32.
    #[test]
    fn l5_send_fd_no_isize_to_i32_truncation() {
        let source = include_str!("mod.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // Find the send_fd function body in production code.
        let send_fn_start = prod_source
            .find("fn send_fd(")
            .expect("send_fd function must exist in production code");
        let send_fn_block = &prod_source[send_fn_start..];

        // The function should end at the next top-level fn or end of prod source.
        let send_fn_end = send_fn_block[1..]
            .find("\nfn ")
            .map(|p| p + 1)
            .unwrap_or(send_fn_block.len());
        let send_fn_body = &send_fn_block[..send_fn_end];

        // L5: Must NOT contain `as i32` truncating cast of sendmsg return value.
        assert!(
            !send_fn_body.contains("sendmsg(sock, &msg, 0) as i32"),
            "L5: send_fd must not truncate sendmsg() isize return value via `as i32` cast"
        );
    }
}
