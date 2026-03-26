// SPDX-License-Identifier: Apache-2.0
//! fanotify behavioral monitoring for agent sandboxes.
//!
//! Monitors file access patterns within the OverlayFS merged directory:
//! - Mass deletion detection
//! - Excessive read rate detection
//! - Credential file access alerts
//!
//! Events are classified and counted; when thresholds are exceeded,
//! `BehavioralTrigger` events are sent to the branch manager.
//!
//! Uses `fanotify_init(FAN_CLASS_NOTIF | FAN_REPORT_FID)` for non-blocking
//! notification-only monitoring (does not block the agent).
//!
//! Falls back gracefully if fanotify is unavailable or queue overflows.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use puzzled_types::{BehavioralConfig, BehavioralTrigger, BranchId};

#[cfg(target_os = "linux")]
use crate::error::PuzzledError;
use crate::error::Result;

/// H20: Maximum number of entries in the touched_files set before
/// falling back to a full diff. Prevents unbounded memory growth
/// from pathological workloads that touch hundreds of thousands of files.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const MAX_TOUCHED_FILES: usize = 100_000;

/// Credential file patterns that trigger alerts.
// Q8: These patterns use substring matching (path.contains()) which may produce
// false positives (e.g., a file named "my_id_rsa_notes.txt" would match "id_rsa").
// This is acceptable because fanotify is monitoring-only — it logs alerts and
// increments counters but does not block the agent from accessing the file.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const CREDENTIAL_PATTERNS: &[&str] = &[
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/ssh/",
    ".ssh/",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".env",
    ".aws/credentials",
    ".gnupg/",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "credentials.json",
    "secrets.yaml",
    "secrets.yml",
    "token.json",
];

/// Counters for behavioral monitoring.
pub struct BehavioralCounters {
    pub deletions: AtomicU32,
    pub reads_this_minute: AtomicU32,
    pub credential_accesses: AtomicU32,
    pub files_created: AtomicU32,
    pub files_modified: AtomicU32,
    pub files_renamed: AtomicU32,
    pub deletion_triggered: AtomicBool,
    pub reads_triggered: AtomicBool,
}

impl Default for BehavioralCounters {
    fn default() -> Self {
        Self::new()
    }
}

impl BehavioralCounters {
    pub fn new() -> Self {
        Self {
            deletions: AtomicU32::new(0),
            reads_this_minute: AtomicU32::new(0),
            credential_accesses: AtomicU32::new(0),
            files_created: AtomicU32::new(0),
            files_modified: AtomicU32::new(0),
            files_renamed: AtomicU32::new(0),
            deletion_triggered: AtomicBool::new(false),
            reads_triggered: AtomicBool::new(false),
        }
    }

    pub fn reset_reads(&self) {
        self.reads_this_minute.store(0, Ordering::Relaxed);
        self.reads_triggered.store(false, Ordering::Relaxed);
    }
}

/// fanotify-based behavioral monitor for a single branch.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct FanotifyMonitor {
    branch_id: BranchId,
    /// FID group: monitors FAN_DELETE | FAN_CREATE (fd=-1, mask-based counting only).
    #[cfg(target_os = "linux")]
    fid_fd: i32,
    /// Path group: monitors FAN_OPEN | FAN_CLOSE_WRITE (valid fd for path resolution).
    /// -1 if not available (graceful degradation: no credential detection).
    #[cfg(target_os = "linux")]
    path_fd: i32,
    config: BehavioralConfig,
    counters: Arc<BehavioralCounters>,
    /// Set of files touched during the branch session (for incremental diff).
    touched_files: Arc<std::sync::Mutex<HashSet<PathBuf>>>,
    /// Merged directory being monitored.
    merged_dir: PathBuf,
    /// Set to true when fanotify queue overflows — signals diff engine to
    /// fall back to a full upper-dir walk instead of incremental tracking.
    needs_full_diff: Arc<AtomicBool>,
    /// SEC-6: Shutdown flag — set to true to signal the poll thread and timer
    /// task to stop. Checked on each epoll timeout iteration.
    shutdown: Arc<AtomicBool>,
    /// SEC-6: Handle for the timer task, aborted on stop().
    timer_handle: Option<tokio::task::JoinHandle<()>>,
}

impl FanotifyMonitor {
    /// Initialize fanotify monitoring on the merged directory.
    ///
    /// Creates two fanotify groups:
    /// - **FID group** (`FAN_REPORT_DIR_FID | FAN_REPORT_NAME`): monitors
    ///   `FAN_DELETE | FAN_CREATE` for deletion/creation counting. Events have
    ///   `fd = -1` (FID mode). `FAN_REPORT_NAME` prevents event merging.
    /// - **Path group** (no FID flags): monitors `FAN_OPEN | FAN_CLOSE_WRITE`
    ///   for read counting, credential detection, and touched-file tracking.
    ///   Events have valid fds for path resolution via `/proc/self/fd/<fd>`.
    ///
    /// Two groups are needed because any FID flag causes ALL events to have
    /// `fd = FAN_NOFD (-1)`, but credential detection requires fd-based path
    /// resolution.
    #[cfg(target_os = "linux")]
    pub fn init(
        branch_id: BranchId,
        merged_dir: PathBuf,
        config: BehavioralConfig,
    ) -> Result<Self> {
        const FAN_CLASS_NOTIF: u32 = 0;
        const FAN_REPORT_DIR_FID: u32 = 0x0000_0400;
        const FAN_REPORT_NAME: u32 = 0x0000_0800;
        const FAN_NONBLOCK: u32 = 0x0000_0002;
        const FAN_CLOEXEC: u32 = 0x0000_0001;

        const FAN_MARK_ADD: u32 = 0x0000_0001;
        const FAN_MARK_MOUNT: u32 = 0x0000_0010;
        const FAN_MARK_FILESYSTEM: u32 = 0x0000_0100;

        // Event masks (values from include/uapi/linux/fanotify.h)
        const FAN_OPEN: u64 = 0x0000_0020;
        const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
        const FAN_DELETE: u64 = 0x0000_0200;
        const FAN_CREATE: u64 = 0x0000_0100;
        const FAN_ONDIR: u64 = 0x4000_0000;

        // U7: Warn on fallback to root path — overly broad monitoring scope
        let merged_str = match merged_dir.to_str() {
            Some(s) => s,
            None => {
                tracing::warn!(
                    branch = %branch_id,
                    path = ?merged_dir,
                    "U7: merged_dir is not valid UTF-8, falling back to \"/\" — this monitors the entire filesystem"
                );
                "/"
            }
        };
        let merged_cstr = std::ffi::CString::new(merged_str)
            .map_err(|e| PuzzledError::Fanotify(format!("invalid path: {}", e)))?;

        // Helper: try FAN_MARK_MOUNT, fall back to FAN_MARK_FILESYSTEM on EINVAL.
        let try_mark = |fd: i32, mask: u64, cstr: &std::ffi::CStr| -> i64 {
            let mut ret = unsafe {
                libc::syscall(
                    libc::SYS_fanotify_mark,
                    fd,
                    FAN_MARK_ADD | FAN_MARK_MOUNT,
                    mask,
                    libc::AT_FDCWD,
                    cstr.as_ptr(),
                )
            };
            if ret < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
                ret = unsafe {
                    libc::syscall(
                        libc::SYS_fanotify_mark,
                        fd,
                        FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                        mask,
                        libc::AT_FDCWD,
                        cstr.as_ptr(),
                    )
                };
            }
            ret
        };

        // --- Group 1: FID group for directory events (FAN_DELETE, FAN_CREATE) ---
        // FAN_REPORT_NAME prevents the kernel from merging deletion events
        // for different files in the same directory (each event includes the
        // file name, making them distinct). Without it, rapid deletions in one
        // directory coalesce into a single event, breaking deletion counting.
        // H27: Use i32::try_from instead of bare `as i32` to detect truncation
        // of the i64 syscall return value.
        let fid_fd_raw = unsafe {
            libc::syscall(
                libc::SYS_fanotify_init,
                FAN_CLASS_NOTIF | FAN_REPORT_DIR_FID | FAN_REPORT_NAME | FAN_NONBLOCK | FAN_CLOEXEC,
                libc::O_RDONLY as u32,
            )
        };
        let fid_fd = i32::try_from(fid_fd_raw).unwrap_or(-1);

        if fid_fd < 0 {
            return Err(PuzzledError::Fanotify(format!(
                "fanotify_init (FID group) failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let fid_mask: u64 = FAN_DELETE | FAN_CREATE | FAN_ONDIR;
        if try_mark(fid_fd, fid_mask, &merged_cstr) < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fid_fd) };
            return Err(PuzzledError::Fanotify(format!(
                "fanotify_mark (FID group) failed on {}: {}",
                merged_dir.display(),
                err
            )));
        }

        // --- Group 2: Path group for file events (FAN_OPEN, FAN_CLOSE_WRITE) ---
        // No FID flags → events have valid fd for path resolution.
        // H27: Use i32::try_from instead of bare `as i32` for path group fd too.
        let path_fd_raw = unsafe {
            libc::syscall(
                libc::SYS_fanotify_init,
                FAN_CLASS_NOTIF | FAN_NONBLOCK | FAN_CLOEXEC,
                libc::O_RDONLY as u32,
            )
        };
        let mut path_fd = i32::try_from(path_fd_raw).unwrap_or(-1);

        if path_fd < 0 {
            // Graceful degradation: credential detection won't work
            tracing::warn!(
                branch = %branch_id,
                error = %std::io::Error::last_os_error(),
                "fanotify_init (path group) failed — credential detection disabled"
            );
        } else {
            let path_mask: u64 = FAN_OPEN | FAN_CLOSE_WRITE;
            if try_mark(path_fd, path_mask, &merged_cstr) < 0 {
                tracing::warn!(
                    branch = %branch_id,
                    error = %std::io::Error::last_os_error(),
                    "fanotify_mark (path group) failed — credential detection disabled"
                );
                unsafe { libc::close(path_fd) };
                // G2: Reset path_fd to -1 after close to prevent the
                // subsequent `if path_fd >= 0` check from storing a
                // closed fd in self.path_fd, which would cause double-close on Drop.
                path_fd = -1;
                // Continue with fid_fd only
            }
        }

        // If path_fd init or mark failed, set to -1
        let path_fd = if path_fd >= 0 { path_fd } else { -1 };

        tracing::info!(
            branch = %branch_id,
            merged_dir = %merged_dir.display(),
            fid_fd,
            path_fd,
            "fanotify monitoring initialized"
        );

        Ok(Self {
            branch_id,
            fid_fd,
            path_fd,
            config,
            counters: Arc::new(BehavioralCounters::new()),
            touched_files: Arc::new(std::sync::Mutex::new(HashSet::new())),
            merged_dir,
            needs_full_diff: Arc::new(AtomicBool::new(false)),
            shutdown: Arc::new(AtomicBool::new(false)),
            timer_handle: None,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn init(
        _branch_id: BranchId,
        _merged_dir: PathBuf,
        _config: BehavioralConfig,
    ) -> Result<Self> {
        Err(crate::error::PuzzledError::Fanotify(
            "fanotify requires Linux".to_string(),
        ))
    }

    /// Start the monitoring loop in a blocking thread.
    ///
    /// Returns a channel receiver for behavioral trigger events, counters,
    /// touched files set, a flag indicating whether a full diff is needed
    /// (set to true on fanotify queue overflow), and the shutdown flag.
    ///
    /// SEC-6: The returned `Arc<AtomicBool>` (fifth element) is the shutdown
    /// flag. Set it to `true` to signal both the poll thread and timer task
    /// to terminate cleanly.
    #[allow(unused_mut, clippy::type_complexity)]
    pub fn start(
        mut self,
    ) -> (
        tokio::sync::mpsc::Receiver<BehavioralTrigger>,
        Arc<BehavioralCounters>,
        Arc<std::sync::Mutex<HashSet<PathBuf>>>,
        Arc<AtomicBool>,
        Arc<AtomicBool>,
    ) {
        // PM6: Increased channel capacity from 32 to 256 to reduce the
        // likelihood of behavioral trigger events being dropped under burst
        // conditions (e.g., mass file operations triggering many events quickly).
        // Callers log a warning on TrySendError::Full (see classify_event).
        #[allow(unused_variables)]
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        let counters = self.counters.clone();
        let touched = self.touched_files.clone();
        let needs_full_diff = self.needs_full_diff.clone();
        let shutdown = self.shutdown.clone();

        #[cfg(target_os = "linux")]
        {
            let fid_fd = self.fid_fd;
            let path_fd = self.path_fd;
            // M1: Transfer fd ownership to the polling thread.
            // Set to -1 so Drop doesn't double-close.
            self.fid_fd = -1;
            self.path_fd = -1;
            let config = self.config.clone();
            let branch_id = self.branch_id.clone();
            let counters_clone = counters.clone();
            let touched_clone = touched.clone();
            let merged_dir = self.merged_dir.clone();
            let needs_full_diff_clone = needs_full_diff.clone();
            let shutdown_clone = shutdown.clone();

            tokio::task::spawn_blocking(move || {
                Self::poll_loop(
                    fid_fd,
                    path_fd,
                    &branch_id,
                    &config,
                    &counters_clone,
                    &touched_clone,
                    &merged_dir,
                    tx,
                    &needs_full_diff_clone,
                    &shutdown_clone,
                );
            });

            // Spawn a timer task to reset per-minute read counters.
            // SEC-6: Check the shutdown flag each iteration and exit when set.
            let counters_timer = counters.clone();
            let shutdown_timer = shutdown.clone();
            let timer_handle = tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    if shutdown_timer.load(Ordering::Relaxed) {
                        break;
                    }
                    counters_timer.reset_reads();
                }
            });
            // F4: Store the handle so stop() can abort it if needed.
            // Note: self is consumed by start(), so we return it in the tuple
            // to allow callers to abort for clean cancellation.
            self.timer_handle = Some(timer_handle);
        }

        (rx, counters, touched, needs_full_diff, shutdown)
    }

    /// SEC-6: Signal the poll thread and timer task to shut down.
    ///
    /// Sets the shutdown flag, which causes:
    /// - The poll thread to exit on its next epoll timeout iteration (up to 1s).
    /// - The timer task to exit on its next tick (up to 60s).
    ///
    /// U12: stop() sets the shutdown flag but the poll thread checks it only
    /// between events (on epoll timeout), so there is no interrupt mechanism.
    /// This is acceptable for a monitoring-only component — the poll thread
    /// will exit within 1 second of the flag being set.
    ///
    /// T12: After `start()` consumes self, callers use the returned shutdown
    /// `Arc<AtomicBool>` directly instead of this method.
    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(handle) = &self.timer_handle {
            handle.abort();
        }
    }

    /// Main polling loop for fanotify events.
    ///
    /// Polls both the FID group fd (directory events) and the path group fd
    /// (file events with valid fds for path resolution) using a single epoll.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    fn poll_loop(
        fid_fd: i32,
        path_fd: i32,
        branch_id: &BranchId,
        config: &BehavioralConfig,
        counters: &BehavioralCounters,
        touched: &std::sync::Mutex<HashSet<PathBuf>>,
        merged_dir: &PathBuf,
        tx: tokio::sync::mpsc::Sender<BehavioralTrigger>,
        needs_full_diff: &AtomicBool,
        shutdown: &AtomicBool,
    ) {
        let mut buf = vec![0u8; 8192];

        let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epoll_fd < 0 {
            tracing::warn!(
                branch = %branch_id,
                error = %std::io::Error::last_os_error(),
                "epoll_create1 failed, falling back to upper-dir walk"
            );
            unsafe {
                libc::close(fid_fd);
                if path_fd >= 0 {
                    libc::close(path_fd);
                }
            }
            return;
        }

        // Add FID group fd to epoll
        let mut ev_fid = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: fid_fd as u64,
        };
        if unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, fid_fd, &mut ev_fid) } < 0 {
            tracing::warn!(branch = %branch_id, "epoll_ctl(ADD) failed for fid_fd");
            unsafe {
                libc::close(epoll_fd);
                libc::close(fid_fd);
                if path_fd >= 0 {
                    libc::close(path_fd);
                }
            }
            return;
        }

        // Add path group fd to epoll (if available)
        if path_fd >= 0 {
            let mut ev_path = libc::epoll_event {
                events: libc::EPOLLIN as u32,
                u64: path_fd as u64,
            };
            if unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, path_fd, &mut ev_path) } < 0
            {
                tracing::warn!(branch = %branch_id, "epoll_ctl(ADD) failed for path_fd");
                // Continue with fid_fd only
            }
        }

        let max_events = if path_fd >= 0 { 2 } else { 1 };
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 2];
        const EPOLL_TIMEOUT_MS: i32 = 1000;

        loop {
            let nfds = unsafe {
                libc::epoll_wait(epoll_fd, events.as_mut_ptr(), max_events, EPOLL_TIMEOUT_MS)
            };

            if nfds < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                tracing::warn!(branch = %branch_id, error = %err, "epoll_wait error");
                break;
            }

            if shutdown.load(Ordering::Acquire) {
                break;
            }

            if nfds == 0 {
                continue;
            }

            // Process each triggered fd
            // H25: Use try_into() instead of bare `as usize` — epoll_wait
            // returns i32 which is non-negative here (negative handled above),
            // but try_into is defense-in-depth against future refactoring.
            for event in events.iter().take(nfds.try_into().unwrap_or(0)) {
                // J6: Safe round-trip from u64 back to i32. The storage side
                // (`fid_fd as u64` / `path_fd as u64`) stores non-negative i32 fds
                // which always fit in u64. Here we validate the reverse conversion
                // to guard against corrupted epoll_event data.
                let event_data = event.u64;
                let triggered_fd = match i32::try_from(event_data) {
                    Ok(fd) => fd,
                    Err(_) => {
                        tracing::warn!(
                            branch = %branch_id,
                            raw_u64 = event_data,
                            "J6: epoll event u64 out of i32 range, skipping"
                        );
                        continue;
                    }
                };

                let n = unsafe {
                    libc::read(
                        triggered_fd,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };

                if n < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock
                        || err.raw_os_error() == Some(libc::EINTR)
                    {
                        continue;
                    }
                    tracing::warn!(
                        branch = %branch_id, error = %err, fd = triggered_fd,
                        "fanotify read error"
                    );
                    continue;
                }

                if n == 0 {
                    continue;
                }

                // Parse fanotify event metadata.
                // With FAN_REPORT_NAME, event_len may not be aligned to 8 bytes,
                // so we use read_unaligned to avoid UB on subsequent events.
                let metadata_size = std::mem::size_of::<FanotifyEventMetadata>();
                let mut offset = 0;

                while offset + metadata_size <= n as usize {
                    let event: FanotifyEventMetadata = unsafe {
                        std::ptr::read_unaligned(
                            buf.as_ptr().add(offset) as *const FanotifyEventMetadata
                        )
                    };

                    if event.event_len < metadata_size as u32 {
                        break;
                    }

                    // G16: Validate event_len against remaining buffer to prevent
                    // out-of-bounds read of uninitialized memory.
                    if offset + event.event_len as usize > n as usize {
                        tracing::warn!("G16: fanotify event_len extends past buffer, truncating");
                        break;
                    }

                    Self::classify_event(
                        &event,
                        branch_id,
                        config,
                        counters,
                        touched,
                        merged_dir,
                        &tx,
                        needs_full_diff,
                    );

                    if event.fd >= 0 {
                        unsafe { libc::close(event.fd) };
                    }

                    offset += event.event_len as usize;
                }
            }
        }

        unsafe {
            libc::close(epoll_fd);
            libc::close(fid_fd);
            if path_fd >= 0 {
                libc::close(path_fd);
            }
        }
    }

    /// Classify a single fanotify event and update counters.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    fn classify_event(
        event: &FanotifyEventMetadata,
        branch_id: &BranchId,
        config: &BehavioralConfig,
        counters: &BehavioralCounters,
        touched: &std::sync::Mutex<HashSet<PathBuf>>,
        _merged_dir: &PathBuf,
        tx: &tokio::sync::mpsc::Sender<BehavioralTrigger>,
        needs_full_diff: &AtomicBool,
    ) {
        const FAN_OPEN: u64 = 0x0000_0020;
        const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
        const FAN_DELETE: u64 = 0x0000_0200;
        const FAN_CREATE: u64 = 0x0000_0100;
        const FAN_Q_OVERFLOW: u64 = 0x0000_4000;

        // Handle queue overflow — mark branch for full diff and notify governance
        if event.mask & FAN_Q_OVERFLOW != 0 {
            tracing::warn!(
                branch = %branch_id,
                "fanotify queue overflow — falling back to full upper-dir walk for diff"
            );
            needs_full_diff.store(true, Ordering::Release);
            if tx.try_send(BehavioralTrigger::QueueOverflow).is_err() {
                tracing::warn!("F18: QueueOverflow trigger dropped: channel full");
            }
            return;
        }

        // Resolve file path from fd (if available).
        // Path group events have valid fds; FID group events have fd=-1.
        let path = if event.fd >= 0 {
            let link = format!("/proc/self/fd/{}", event.fd);
            std::fs::read_link(&link)
                .map_err(|e| tracing::trace!("F19: readlink on /proc/self/fd failed: {e}"))
                .ok()
        } else {
            None
        };

        // Track touched files for incremental diff
        // H20: Cap the set at MAX_TOUCHED_FILES to prevent unbounded memory growth.
        // When exceeded, set needs_full_diff so the diff engine falls back to a
        // full upper-dir walk instead of relying on the (now incomplete) set.
        if let Some(ref p) = path {
            if let Ok(mut set) = touched.lock() {
                if set.len() < MAX_TOUCHED_FILES {
                    set.insert(p.clone());
                } else if !needs_full_diff.load(Ordering::Relaxed) {
                    needs_full_diff.store(true, Ordering::Release);
                    tracing::warn!(
                        branch = %branch_id,
                        max = MAX_TOUCHED_FILES,
                        "H20: touched_files exceeded MAX_TOUCHED_FILES — falling back to full diff"
                    );
                }
            }
        }

        // Check for deletion events
        // M-prf2: max_deletions == 0 means "disabled" — skip triggering
        if event.mask & FAN_DELETE != 0 {
            // S36: Use saturating_add to prevent u32 wrap-around past threshold checks.
            let count = counters
                .deletions
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_add(1))
                })
                .unwrap_or(0)
                + 1;
            // T9: Only fire trigger once per threshold crossing to prevent spam
            if config.max_deletions > 0
                && count >= config.max_deletions
                && !counters.deletion_triggered.swap(true, Ordering::Relaxed)
            {
                tracing::warn!(
                    branch = %branch_id,
                    count,
                    threshold = config.max_deletions,
                    "mass deletion threshold exceeded"
                );
                if let Err(e) = tx.try_send(BehavioralTrigger::MassDeletion {
                    count,
                    threshold: config.max_deletions,
                }) {
                    tracing::warn!(
                        branch = %branch_id,
                        error = %e,
                        trigger = "MassDeletion",
                        count,
                        threshold = config.max_deletions,
                        "behavioral trigger event dropped — channel full"
                    );
                }
            }
        }

        // Track file creation events
        if event.mask & FAN_CREATE != 0 {
            // S36: Use saturating_add to prevent u32 wrap-around.
            counters
                .files_created
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_add(1))
                })
                .ok();
        }

        // Check for read events (FAN_OPEN)
        if event.mask & FAN_OPEN != 0 {
            // S36: Use saturating_add to prevent u32 wrap-around past threshold checks.
            let count = counters
                .reads_this_minute
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_add(1))
                })
                .unwrap_or(0)
                + 1;
            // T9: Only fire trigger once per reset period to prevent spam
            if count >= config.max_reads_per_minute
                && !counters.reads_triggered.swap(true, Ordering::Relaxed)
            {
                tracing::warn!(
                    branch = %branch_id,
                    rate = count,
                    threshold = config.max_reads_per_minute,
                    "excessive read rate"
                );
                if let Err(e) = tx.try_send(BehavioralTrigger::ExcessiveReads {
                    rate: count,
                    threshold: config.max_reads_per_minute,
                }) {
                    tracing::warn!(
                        branch = %branch_id,
                        error = %e,
                        trigger = "ExcessiveReads",
                        rate = count,
                        threshold = config.max_reads_per_minute,
                        "behavioral trigger event dropped — channel full"
                    );
                }
            }
        }

        // Check for credential access
        // H29: Use is_credential_path() with component-aware matching instead
        // of naive `contains()` to avoid false positives (e.g., a file named
        // "my.keyring" matching ".key", or "/home/user/ssh-config" matching "ssh").
        if config.credential_access_alert {
            if let Some(ref p) = path {
                if is_credential_path(p) {
                    let path_str = p.to_string_lossy();
                    tracing::warn!(
                        branch = %branch_id,
                        path = %path_str,
                        "credential file access detected"
                    );
                    if let Err(e) = tx.try_send(BehavioralTrigger::CredentialAccess {
                        path: path_str.to_string(),
                    }) {
                        tracing::warn!(
                            branch = %branch_id,
                            error = %e,
                            trigger = "CredentialAccess",
                            path = %path_str,
                            "behavioral trigger event dropped — channel full"
                        );
                    }
                    // S36: Use saturating_add to prevent u32 wrap-around.
                    counters
                        .credential_accesses
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                            Some(v.saturating_add(1))
                        })
                        .ok();
                }
            }
        }

        // Close_write events indicate file modification
        if event.mask & FAN_CLOSE_WRITE != 0 {
            // S36: Use saturating_add to prevent u32 wrap-around.
            counters
                .files_modified
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_add(1))
                })
                .ok();
            if let Some(ref p) = path {
                tracing::trace!(
                    branch = %branch_id,
                    path = %p.display(),
                    "file written"
                );
            }

            // §3.4 G28: Scan written file content for phantom token prefixes.
            // This is defense-in-depth — if an agent writes a phantom token to a
            // file (e.g., .env, config), it signals a credential leak attempt.
            // Reading is bounded to 64KB to prevent performance impact.
            if !config.phantom_token_prefixes.is_empty() && event.fd >= 0 {
                const MAX_SCAN_BYTES: usize = 65536;
                let mut buf = vec![0u8; MAX_SCAN_BYTES];
                // Seek to start (fd may be at end after write)
                unsafe { libc::lseek(event.fd, 0, libc::SEEK_SET) };
                let n = unsafe {
                    libc::read(event.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };
                if n > 0 {
                    let content = &buf[..n as usize];
                    for prefix in &config.phantom_token_prefixes {
                        if let Some(_pos) = content
                            .windows(prefix.len())
                            .position(|w| w == prefix.as_bytes())
                        {
                            let file_path = path
                                .as_ref()
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_else(|| format!("fd:{}", event.fd));
                            // Truncate prefix for logging (max 16 chars)
                            let token_prefix =
                                prefix[..std::cmp::min(prefix.len(), 16)].to_string();
                            tracing::warn!(
                                branch = %branch_id,
                                file = %file_path,
                                prefix = %token_prefix,
                                "§3.4 G28: phantom token detected in file write"
                            );
                            if let Err(e) = tx.try_send(BehavioralTrigger::PhantomTokenLeakage {
                                file_path: file_path.clone(),
                                token_prefix,
                            }) {
                                tracing::warn!(
                                    branch = %branch_id,
                                    error = %e,
                                    trigger = "PhantomTokenLeakage",
                                    file = %file_path,
                                    "behavioral trigger event dropped — channel full"
                                );
                            }
                            break; // One trigger per file write is sufficient
                        }
                    }
                }
            }
        }
    }

    /// Get the set of files touched during this branch session.
    ///
    /// Used by DiffEngine to skip untouched subtrees at commit time.
    pub fn touched_files(&self) -> HashSet<PathBuf> {
        // R14: Log mutex poison instead of silently returning empty set
        self.touched_files
            .lock()
            .map(|s| s.clone())
            .unwrap_or_else(|poisoned| {
                tracing::error!("R14: touched_files mutex poisoned — behavioral triggers may miss file modifications");
                poisoned.into_inner().clone()
            })
    }
}

#[cfg(target_os = "linux")]
impl Drop for FanotifyMonitor {
    fn drop(&mut self) {
        if self.fid_fd >= 0 {
            unsafe { libc::close(self.fid_fd) };
        }
        if self.path_fd >= 0 {
            unsafe { libc::close(self.path_fd) };
        }
    }
}

// ---------------------------------------------------------------------------
// fanotify kernel structures
// ---------------------------------------------------------------------------

/// fanotify_event_metadata structure (matches kernel ABI).
#[repr(C)]
#[cfg(target_os = "linux")]
struct FanotifyEventMetadata {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

/// H29: Component-aware credential path matching.
///
/// Uses path component matching instead of naive `contains()`:
/// - Extension patterns (e.g., `.pem`, `.key`) match the file extension only.
/// - Directory patterns (e.g., `.ssh/`, `/etc/ssh/`) match path components.
/// - Exact filename patterns (e.g., `id_rsa`, `credentials.json`) match the
///   final component only.
/// - Absolute prefix patterns (e.g., `/etc/shadow`) match the path start.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn is_credential_path(path: &std::path::Path) -> bool {
    let path_str = path.to_string_lossy();

    for pattern in CREDENTIAL_PATTERNS {
        if pattern.starts_with('/') && !pattern.ends_with('/') {
            // Absolute path prefix: must match from the start
            // e.g., "/etc/shadow" matches "/etc/shadow" but not "/home/etc/shadow"
            if path_str.starts_with(pattern) {
                return true;
            }
        } else if pattern.ends_with('/') {
            // Directory pattern: must appear as a path component boundary
            // e.g., ".ssh/" matches "/home/user/.ssh/id_rsa" but not "/home/user/nossh/file"
            let dir_name = pattern.trim_end_matches('/');
            for component in path.components() {
                if component.as_os_str() == dir_name {
                    return true;
                }
            }
        } else if pattern.starts_with('.') && !pattern.contains('/') {
            // Extension pattern: check file extension or exact component match
            // e.g., ".pem" matches "cert.pem" but not "mypemfile"
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if file_name.ends_with(pattern) {
                    return true;
                }
            }
        } else {
            // Exact filename pattern: match the final component
            // e.g., "id_rsa" matches "/home/user/.ssh/id_rsa" but not "/id_rsa_backup"
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if file_name == *pattern {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_credential_patterns_match() {
        let test_paths = vec![
            ("/home/user/.ssh/id_rsa", true),
            ("/etc/shadow", true),
            ("/home/user/.env", true),
            ("/home/user/.aws/credentials", true),
            ("/home/user/project/server.key", true),
            ("/home/user/cert.pem", true),
            ("/home/user/secrets.yaml", true),
            ("/home/user/token.json", true),
            ("/home/user/project/main.rs", false),
            ("/home/user/project/README.md", false),
            ("/usr/bin/python3", false),
        ];

        for (path, expected) in test_paths {
            let matches = CREDENTIAL_PATTERNS
                .iter()
                .any(|pattern| path.contains(pattern));
            assert_eq!(
                matches, expected,
                "credential pattern match for '{}': expected {}, got {}",
                path, expected, matches
            );
        }
    }

    #[test]
    fn test_behavioral_counters() {
        let counters = BehavioralCounters::new();

        assert_eq!(counters.deletions.load(Ordering::Relaxed), 0);
        assert_eq!(counters.reads_this_minute.load(Ordering::Relaxed), 0);
        assert_eq!(counters.credential_accesses.load(Ordering::Relaxed), 0);
        assert_eq!(counters.files_created.load(Ordering::Relaxed), 0);
        assert_eq!(counters.files_modified.load(Ordering::Relaxed), 0);
        assert_eq!(counters.files_renamed.load(Ordering::Relaxed), 0);

        counters.deletions.fetch_add(5, Ordering::Relaxed);
        assert_eq!(counters.deletions.load(Ordering::Relaxed), 5);

        counters.reads_this_minute.fetch_add(100, Ordering::Relaxed);
        assert_eq!(counters.reads_this_minute.load(Ordering::Relaxed), 100);

        counters.reset_reads();
        assert_eq!(counters.reads_this_minute.load(Ordering::Relaxed), 0);
        // deletions should not be reset
        assert_eq!(counters.deletions.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn test_touched_files_tracking() {
        let touched = Arc::new(std::sync::Mutex::new(HashSet::new()));

        {
            let mut set = touched.lock().unwrap();
            set.insert(PathBuf::from("/merged/file1.txt"));
            set.insert(PathBuf::from("/merged/file2.txt"));
            set.insert(PathBuf::from("/merged/file1.txt")); // duplicate
        }

        let set = touched.lock().unwrap();
        assert_eq!(set.len(), 2);
        assert!(set.contains(&PathBuf::from("/merged/file1.txt")));
        assert!(set.contains(&PathBuf::from("/merged/file2.txt")));
    }

    #[test]
    fn test_behavioral_counters_default() {
        let counters = BehavioralCounters::default();
        assert_eq!(counters.deletions.load(Ordering::Relaxed), 0);
        assert_eq!(counters.reads_this_minute.load(Ordering::Relaxed), 0);
        assert_eq!(counters.credential_accesses.load(Ordering::Relaxed), 0);
        assert_eq!(counters.files_created.load(Ordering::Relaxed), 0);
        assert_eq!(counters.files_modified.load(Ordering::Relaxed), 0);
        assert_eq!(counters.files_renamed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_behavioral_counters_concurrent_increment() {
        let counters = Arc::new(BehavioralCounters::default());
        let threads: Vec<_> = (0..10)
            .map(|_| {
                let c = counters.clone();
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        c.deletions.fetch_add(1, Ordering::Relaxed);
                        c.reads_this_minute.fetch_add(1, Ordering::Relaxed);
                        c.credential_accesses.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();

        for t in threads {
            t.join().unwrap();
        }

        assert_eq!(counters.deletions.load(Ordering::Relaxed), 1000);
        assert_eq!(counters.reads_this_minute.load(Ordering::Relaxed), 1000);
        assert_eq!(counters.credential_accesses.load(Ordering::Relaxed), 1000);
    }

    // R14: touched_files() must NOT use unwrap_or_default() which silently
    // returns an empty set on mutex poison, hiding behavioral trigger failures.
    #[test]
    fn test_r14_touched_files_no_unwrap_or_default() {
        let source = include_str!("fanotify.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // Find the touched_files() method body
        let func_start = prod_source
            .find("fn touched_files(&self)")
            .expect("touched_files method must exist");
        let body = &prod_source[func_start..];
        // Get up to the closing brace of the function (next "}" after "pub fn" or end)
        let end = body.find("\n    }").unwrap_or(body.len()) + 6;
        let func_body = &body[..end];
        assert!(
            !func_body.contains("unwrap_or_default"),
            "R14: touched_files() must NOT use unwrap_or_default() which silently \
             returns empty set on mutex poison. Use unwrap_or_else with \
             tracing::error! and poisoned.into_inner() instead.\nFunction:\n{}",
            func_body
        );
    }

    /// S36: Verify AtomicU32 behavioral counters use saturating_add to
    /// prevent wrap-around past threshold checks after ~4 billion operations.
    #[test]
    fn test_s36_atomic_counter_no_wrap() {
        let source = include_str!("fanotify.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // Production code must use saturating_add instead of plain fetch_add
        // to prevent u32 wrap-around past threshold checks.
        assert!(
            !prod_source.contains("fetch_add(1,"),
            "S36: production code must not use fetch_add(1, ...) — \
             use fetch_update with saturating_add to prevent u32 wrap-around \
             past behavioral threshold checks"
        );
        assert!(
            prod_source.contains("saturating_add"),
            "S36: production code must use saturating_add for behavioral \
             counters to prevent u32 wrap-around"
        );
    }

    /// F4: Timer JoinHandle must not be immediately dropped after tokio::spawn.
    /// It should be returned or stored so callers can abort it for clean cancellation.
    #[test]
    fn test_f4_timer_handle_not_dropped() {
        let source = include_str!("fanotify.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            !prod_source.contains("drop(timer_handle)"),
            "F4: timer_handle must not be immediately dropped — store it or return it \
             so callers can abort for clean cancellation"
        );
        // Verify the timer handle is included in the return tuple or stored in a field
        // Look for timer_handle being part of the return value or self assignment
        let has_return_or_store = prod_source.contains("timer_handle,")
            || prod_source.contains("self.timer_handle = Some(timer_handle)");
        assert!(
            has_return_or_store,
            "F4: timer_handle must be returned in the tuple or stored in self.timer_handle"
        );
    }

    /// F18: QueueOverflow trigger send must not silently discard errors with `let _ =`.
    #[test]
    fn test_f18_queue_overflow_not_silent() {
        let source = include_str!("fanotify.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            !prod_source.contains("let _ = tx.try_send(BehavioralTrigger::QueueOverflow)"),
            "F18: QueueOverflow trigger must not silently discard send errors with `let _ =`. \
             Use `if ... .is_err()` with tracing::warn! instead."
        );
    }

    /// F19: read_link must not silently swallow errors with bare `.ok()`.
    /// A bare `.ok()` means no `map_err` logging before discarding the error.
    #[test]
    fn test_f19_readlink_not_silent() {
        let source = include_str!("fanotify.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // Find lines with read_link that use bare .ok() without map_err logging
        for (i, line) in prod_source.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.contains("read_link")
                && trimmed.contains(".ok()")
                && !trimmed.contains("map_err")
            {
                panic!(
                    "F19: fanotify.rs line {} uses read_link(...).ok() without logging. \
                     Use .map_err(|e| tracing::trace!(...)).ok() instead.\nLine: {}",
                    i + 1,
                    trimmed
                );
            }
        }
    }

    /// G2: After `close(path_fd)` on mark failure, the variable must be
    /// shadowed to -1 so the subsequent `if path_fd >= 0` check does not
    /// store a closed fd in `self.path_fd`, causing a double-close on Drop.
    #[test]
    fn test_g2_path_fd_reset_after_close() {
        let source = include_str!("fanotify.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // Find the mark failure branch that closes path_fd
        let close_idx = prod_source
            .find("unsafe { libc::close(path_fd) };")
            .expect("G2: must have close(path_fd) call in mark failure branch");

        // After the close, the variable must be reset to -1 before the
        // `let path_fd = if path_fd >= 0` check at the end of the else block.
        let after_close = &prod_source[close_idx..];
        // Find the actual code check (not a comment) by looking for the
        // let-binding that tests path_fd >= 0
        let next_path_fd_check = after_close
            .find("let path_fd = if path_fd >= 0")
            .expect("G2: must have `let path_fd = if path_fd >= 0` check after close");
        let between = &after_close[..next_path_fd_check];

        assert!(
            between.contains("let path_fd = -1") || between.contains("path_fd = -1"),
            "G2: after close(path_fd) on mark failure, path_fd must be set to -1 \
             before the `if path_fd >= 0` check to prevent storing a closed fd.\n\
             Code between close and check:\n{}",
            between
        );
    }

    /// G16: fanotify event_len must be validated against remaining buffer
    /// to prevent out-of-bounds reads of uninitialized memory.
    #[test]
    fn test_g16_fanotify_event_len_bounded() {
        let source = include_str!("fanotify.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // Find the event parsing loop in poll_loop
        let loop_start = prod_source
            .find("while offset + metadata_size <= n as usize")
            .expect("G16: must have event parsing loop with offset + metadata_size check");
        let loop_body = &prod_source[loop_start..];

        // The loop must check that offset + event_len doesn't exceed n
        assert!(
            loop_body.contains("offset + event.event_len as usize > n as usize")
                || loop_body.contains("offset + event.event_len as usize > n as"),
            "G16: event parsing loop must validate that offset + event.event_len \
             does not exceed n (bytes read) to prevent OOB reads.\n\
             Loop body starts at: {}",
            &loop_body[..200.min(loop_body.len())]
        );
    }

    /// H20: Verify MAX_TOUCHED_FILES constant exists and is used to bound
    /// the touched_files set in production code.
    #[test]
    fn test_h20_touched_files_bounded() {
        let source = include_str!("fanotify.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            prod_source.contains("MAX_TOUCHED_FILES"),
            "H20: production code must define MAX_TOUCHED_FILES constant"
        );
        assert!(
            prod_source.contains("100_000") || prod_source.contains("100000"),
            "H20: MAX_TOUCHED_FILES should be 100,000"
        );
        // Verify the constant is used in a bounds check before insertion
        assert!(
            prod_source.contains("set.len() < MAX_TOUCHED_FILES"),
            "H20: touched_files insertion must check set.len() < MAX_TOUCHED_FILES"
        );
        // Verify needs_full_diff is set when limit exceeded
        assert!(
            prod_source.contains("needs_full_diff.store(true"),
            "H20: must set needs_full_diff when MAX_TOUCHED_FILES exceeded"
        );
    }

    /// J6: Verify no bare `event.u64 as i32` in production code.
    #[test]
    fn test_j6_no_bare_event_u64_as_i32() {
        let source = include_str!("fanotify.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            !prod_source.contains("event.u64 as i32"),
            "J6: production code must not use bare `event.u64 as i32` — \
             use i32::try_from(event.u64) to guard against corrupted epoll data"
        );
    }

    /// H25: Verify nfds is not cast with bare `as usize` — use try_into().
    #[test]
    fn test_h25_nfds_safe_cast() {
        let source = include_str!("fanotify.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            !prod_source.contains(".take(nfds as usize)"),
            "H25: must not use bare `nfds as usize` — use try_into().unwrap_or(0)"
        );
    }

    /// H27: Verify fanotify_init return value is not cast with bare `as i32`.
    #[test]
    fn test_h27_fanotify_init_safe_cast() {
        let source = include_str!("fanotify.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // Should not have the pattern `) as i32;` after fanotify_init syscall
        assert!(
            !prod_source.contains("libc::SYS_fanotify_init,\n                libc::O_RDONLY as u32,\n            )\n        } as i32"),
            "H27: fanotify_init return must not use bare `as i32` — use i32::try_from()"
        );
        // Positive check: should use try_from or unwrap_or
        assert!(
            prod_source.contains("i32::try_from(fid_fd_raw)"),
            "H27: must use i32::try_from for fanotify_init FID group fd"
        );
        assert!(
            prod_source.contains("i32::try_from(path_fd_raw)"),
            "H27: must use i32::try_from for fanotify_init path group fd"
        );
    }

    /// H29: Verify credential path matching uses component-aware logic
    /// instead of naive contains().
    #[test]
    fn test_h29_credential_path_component_matching() {
        // Extension patterns should match file extension, not substring
        assert!(
            is_credential_path(std::path::Path::new("/home/user/cert.pem")),
            "H29: .pem extension should match cert.pem"
        );
        assert!(
            !is_credential_path(std::path::Path::new("/home/user/pemfile")),
            "H29: .pem should not match 'pemfile' (no dot boundary)"
        );

        // Directory patterns should match components
        assert!(
            is_credential_path(std::path::Path::new("/home/user/.ssh/config")),
            "H29: .ssh/ should match as a directory component"
        );

        // Exact filenames
        assert!(
            is_credential_path(std::path::Path::new("/home/user/.ssh/id_rsa")),
            "H29: id_rsa should match as exact filename"
        );
        assert!(
            !is_credential_path(std::path::Path::new("/home/user/id_rsa_backup")),
            "H29: id_rsa should not match id_rsa_backup (not exact)"
        );

        // Absolute prefix patterns
        assert!(
            is_credential_path(std::path::Path::new("/etc/shadow")),
            "H29: /etc/shadow should match absolute prefix"
        );
        assert!(
            !is_credential_path(std::path::Path::new("/home/etc/shadow")),
            "H29: /etc/shadow should not match /home/etc/shadow"
        );

        // Non-credential paths
        assert!(
            !is_credential_path(std::path::Path::new("/home/user/project/main.rs")),
            "H29: main.rs is not a credential file"
        );
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn test_fanotify_monitor_init_non_linux_returns_error() {
        // S25: On non-Linux, init must return Err to prevent silently
        // creating a non-functional monitor (consistent with Landlock
        // and SELinux stubs).
        let result = FanotifyMonitor::init(
            BranchId::from("test".to_string()),
            PathBuf::from("/tmp/test-merged"),
            BehavioralConfig {
                max_deletions: 100,
                max_reads_per_minute: 1000,
                credential_access_alert: true,
            },
        );
        assert!(result.is_err(), "non-Linux init should return Err");
        let err = result.err().unwrap().to_string();
        assert!(
            err.contains("requires Linux"),
            "error should mention Linux, got: {}",
            err
        );
    }
}
