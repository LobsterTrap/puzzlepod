// SPDX-License-Identifier: Apache-2.0
use std::path::{Path, PathBuf};

use crate::error::Result;

/// OverlayFS mount management for branch isolation.
///
/// Each branch gets:
/// - `upper/` — copy-on-write layer (agent writes here)
/// - `work/`  — OverlayFS internal work directory
/// - `merged/` — union mount point visible to the agent
///
/// The lower layer is the base filesystem (read-only from the agent's perspective).
#[allow(dead_code)] // Fields used by mount/unmount on Linux only
pub struct OverlayMount {
    upper_dir: PathBuf,
    work_dir: PathBuf,
    merged_dir: PathBuf,
    lower_dir: PathBuf,
    /// Tracks the fuse-overlayfs child process in rootless mode.
    /// `None` for kernel OverlayFS (rootful) mounts.
    fuse_child: Option<std::process::Child>,
}

impl OverlayMount {
    /// Create directory structure for a new branch.
    ///
    /// M-ov1: Before creating directories, checks that `branch_dir` and its
    /// subdirectories are not symlinks. A symlink in the branch path could be
    /// used to redirect writes to arbitrary locations outside the branch.
    // V29: Intermediate path components are not checked for symlinks — the branch base path
    // is admin-configured in puzzled.conf, not agent-controlled. Agent-created symlinks are
    // caught by the leaf directory checks and Landlock enforcement.
    pub fn create_dirs(branch_dir: &Path) -> Result<(PathBuf, PathBuf, PathBuf)> {
        // M-ov1: Check branch_dir itself for symlinks before creating subdirs.
        if branch_dir.exists()
            && branch_dir
                .symlink_metadata()
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
        {
            return Err(crate::error::PuzzledError::Sandbox(format!(
                "symlink detected in branch directory path: {}",
                branch_dir.display()
            )));
        }

        let upper = branch_dir.join("upper");
        let work = branch_dir.join("work");
        let merged = branch_dir.join("merged");

        // M-ov1: Check each subdirectory for symlinks before create_dir_all.
        for subdir in &[&upper, &work, &merged] {
            if subdir.exists()
                && subdir
                    .symlink_metadata()
                    .map(|m| m.file_type().is_symlink())
                    .unwrap_or(false)
            {
                return Err(crate::error::PuzzledError::Sandbox(format!(
                    "symlink detected in branch directory path: {}",
                    subdir.display()
                )));
            }
        }

        std::fs::create_dir_all(&upper)?;
        std::fs::create_dir_all(&work)?;
        std::fs::create_dir_all(&merged)?;

        // H28: Post-creation symlink verification to close the TOCTOU window
        // between the pre-creation check and create_dir_all(). An attacker could
        // race to replace a path component with a symlink after the check but
        // before directory creation.
        for subdir in &[&upper, &work, &merged] {
            if subdir
                .symlink_metadata()
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
            {
                return Err(crate::error::PuzzledError::Sandbox(format!(
                    "H28: symlink detected after creation in branch directory path: {}",
                    subdir.display()
                )));
            }
        }

        Ok((upper, work, merged))
    }

    /// Validate that a mount path does not contain characters that could inject
    /// additional mount options (commas) or other control characters.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn validate_mount_path(path: &Path) -> Result<()> {
        // H1: Use to_str() instead of to_string_lossy() to reject non-UTF-8 paths
        // explicitly. to_string_lossy() silently replaces non-UTF-8 bytes with U+FFFD,
        // which could mask malicious byte sequences in path names.
        let s = path.to_str().ok_or_else(|| {
            crate::error::PuzzledError::Sandbox(format!(
                "mount path contains non-UTF-8 bytes: {}",
                path.to_string_lossy()
            ))
        })?;

        // V34: Shell metacharacters are safe in mount() context — no shell invocation
        // Check for characters that could inject mount options or escape shell contexts:
        // - comma: separates mount options, enabling option injection
        // - newline: breaks line-based parsing
        // - null: C string terminator, truncates path
        // - backslash: escape character that could alter path interpretation
        // - control characters (ASCII < 0x20): could interfere with terminal output,
        //   log parsing, or shell interpretation
        if let Some(bad_char) = s
            .chars()
            .find(|&c| c == ',' || c == '\\' || c == '\0' || (c as u32) < 0x20)
        {
            let description = match bad_char {
                ',' => "comma".to_string(),
                '\\' => "backslash".to_string(),
                '\n' => "newline".to_string(),
                '\0' => "null".to_string(),
                c => format!("control character 0x{:02x}", c as u32),
            };
            return Err(crate::error::PuzzledError::Sandbox(format!(
                "mount path contains illegal character ({}): {}",
                description, s
            )));
        }
        Ok(())
    }

    /// Mount the OverlayFS filesystem.
    ///
    /// mount -t overlay overlay -o lowerdir=<lower>,upperdir=<upper>,workdir=<work> <merged>
    ///
    /// # Arguments
    /// * `allow_exec` — if false, MS_NOEXEC is added to mount flags (default behavior).
    ///   Set to true only for profiles that legitimately need to execute binaries from
    ///   the overlay (e.g., compiler workloads).
    #[cfg(target_os = "linux")]
    pub fn mount(
        lower: &Path,
        upper: &Path,
        work: &Path,
        merged: &Path,
        allow_exec: bool,
    ) -> Result<Self> {
        use nix::mount::MsFlags;

        // H5: Validate paths before constructing mount options to prevent injection
        Self::validate_mount_path(lower)?;
        Self::validate_mount_path(upper)?;
        Self::validate_mount_path(work)?;
        Self::validate_mount_path(merged)?;

        // Rootless mode: use fuse-overlayfs instead of kernel overlayfs
        if nix::unistd::geteuid().as_raw() != 0 {
            return Self::mount_fuse_overlayfs(lower, upper, work, merged, allow_exec);
        }

        let options = Self::build_mount_options(lower, upper, work);

        // H17: Prevent setuid binaries and device nodes in the overlay.
        // MS_NOSUID ignores set-user-ID and set-group-ID bits on execution.
        // MS_NODEV prevents interpretation of block/character special devices.
        // MS_NOEXEC prevents execution of binaries from the overlay unless
        // the profile explicitly allows it via allow_exec_overlay.
        let mut flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV;
        if !allow_exec {
            flags |= MsFlags::MS_NOEXEC;
        }

        nix::mount::mount(
            Some("overlay"),
            merged,
            Some("overlay"),
            flags,
            Some(options.as_str()),
        )
        .map_err(|e| {
            crate::error::PuzzledError::Sandbox(format!(
                "mounting OverlayFS at {}: {}",
                merged.display(),
                e
            ))
        })?;

        tracing::info!(
            merged = %merged.display(),
            lower = %lower.display(),
            "OverlayFS mounted"
        );

        Ok(Self {
            upper_dir: upper.to_path_buf(),
            work_dir: work.to_path_buf(),
            merged_dir: merged.to_path_buf(),
            lower_dir: lower.to_path_buf(),
            fuse_child: None,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn mount(
        lower: &Path,
        upper: &Path,
        work: &Path,
        merged: &Path,
        allow_exec: bool,
    ) -> Result<Self> {
        let _ = (lower, upper, work, merged, allow_exec);
        Err(crate::error::PuzzledError::Sandbox(
            "OverlayFS requires Linux".to_string(),
        ))
    }

    /// M-ov2: Validate a path received over the socketpair from the parent process.
    ///
    /// Checks:
    /// - Length does not exceed 4096 bytes (PATH_MAX on Linux)
    /// - Path is absolute (starts with `/`)
    /// - Path contains no null bytes
    pub fn validate_received_path(path_bytes: &[u8], label: &str) -> Result<()> {
        // M-ov2: Length bounds check
        if path_bytes.len() > 4096 {
            return Err(crate::error::PuzzledError::Sandbox(format!(
                "mount param '{}' exceeds max path length (got {}, max 4096)",
                label,
                path_bytes.len()
            )));
        }

        // M-ov2: Check for null bytes
        if path_bytes.contains(&0) {
            return Err(crate::error::PuzzledError::Sandbox(format!(
                "mount param '{}' contains null byte",
                label
            )));
        }

        // M-ov2: Validate path is absolute
        if path_bytes.first() != Some(&b'/') {
            return Err(crate::error::PuzzledError::Sandbox(format!(
                "mount param '{}' is not an absolute path",
                label
            )));
        }

        Ok(())
    }

    /// Build the OverlayFS mount options string.
    ///
    /// Extracted for testability — the actual `mount()` call is Linux-only,
    /// but the options string can be validated cross-platform.
    #[cfg_attr(not(test), allow(dead_code))]
    fn build_mount_options(lower: &Path, upper: &Path, work: &Path) -> String {
        // metacopy=off: ensures full data copy-up (not just metadata).
        // redirect_dir=off: prevents rename-based bypass of upper-layer
        // tracking — without this, agents could use rename operations to
        // evade the diff engine (Issue #10).
        format!(
            "lowerdir={},upperdir={},workdir={},metacopy=off,redirect_dir=off",
            lower.display(),
            upper.display(),
            work.display()
        )
    }

    /// Mount using fuse-overlayfs for rootless (non-root) operation.
    ///
    /// Spawns fuse-overlayfs in foreground mode (`-f`) so the process handle
    /// can be tracked for cleanup. Verifies the mount established by checking
    /// that the process is still running and the merged path is a mountpoint.
    #[cfg(target_os = "linux")]
    fn mount_fuse_overlayfs(
        lower: &Path,
        upper: &Path,
        work: &Path,
        merged: &Path,
        allow_exec: bool,
    ) -> Result<Self> {
        let fuse_bin = Self::find_fuse_overlayfs()?;

        // H17: nosuid/nodev always set; noexec unless profile allows execution
        let mut opts = format!(
            "lowerdir={},upperdir={},workdir={},nosuid,nodev",
            lower.display(),
            upper.display(),
            work.display()
        );
        if !allow_exec {
            opts.push_str(",noexec");
        }

        let mut child = std::process::Command::new(&fuse_bin)
            .arg("-f")
            .arg("-o")
            .arg(&opts)
            .arg(merged)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .spawn()
            .map_err(|e| {
                crate::error::PuzzledError::Sandbox(format!("spawning fuse-overlayfs: {}", e))
            })?;

        std::thread::sleep(std::time::Duration::from_millis(100));

        // If fuse-overlayfs exited within the settle window, the mount failed
        match child.try_wait() {
            Ok(Some(status)) => {
                return Err(crate::error::PuzzledError::Sandbox(format!(
                    "fuse-overlayfs exited immediately with {} — \
                     verify fuse-overlayfs is installed correctly and {} is a valid mountpoint",
                    status,
                    merged.display()
                )));
            }
            Ok(None) => { /* still running — mount is likely up */ }
            Err(e) => {
                return Err(crate::error::PuzzledError::Sandbox(format!(
                    "checking fuse-overlayfs process status: {}",
                    e
                )));
            }
        }

        // Verify mount via device ID comparison with parent directory
        if !Self::is_fuse_mountpoint(merged) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(crate::error::PuzzledError::Sandbox(format!(
                "fuse-overlayfs process is running but {} does not appear to be a mountpoint",
                merged.display()
            )));
        }

        tracing::info!(
            merged = %merged.display(),
            lower = %lower.display(),
            "fuse-overlayfs mounted (rootless)"
        );

        Ok(Self {
            upper_dir: upper.to_path_buf(),
            work_dir: work.to_path_buf(),
            merged_dir: merged.to_path_buf(),
            lower_dir: lower.to_path_buf(),
            fuse_child: Some(child),
        })
    }

    /// Locate the `fuse-overlayfs` binary in well-known paths or `$PATH`.
    #[cfg(target_os = "linux")]
    fn find_fuse_overlayfs() -> Result<PathBuf> {
        for candidate in &["/usr/bin/fuse-overlayfs", "/usr/local/bin/fuse-overlayfs"] {
            let p = Path::new(candidate);
            if p.is_file() {
                return Ok(p.to_path_buf());
            }
        }
        if let Some(found) = Self::find_in_path("fuse-overlayfs") {
            return Ok(found);
        }
        Err(crate::error::PuzzledError::Sandbox(
            "rootless mode requires fuse-overlayfs but it was not found in PATH".to_string(),
        ))
    }

    /// Search `$PATH` for a binary by name.
    #[cfg(target_os = "linux")]
    fn find_in_path(binary: &str) -> Option<PathBuf> {
        std::env::var_os("PATH").and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|dir| dir.join(binary))
                .find(|p| p.is_file())
        })
    }

    /// Check whether `path` is a mountpoint by comparing its device ID
    /// with that of its parent directory.
    #[cfg(target_os = "linux")]
    fn is_fuse_mountpoint(path: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        let Ok(path_meta) = std::fs::metadata(path) else {
            return false;
        };
        let Some(parent) = path.parent() else {
            return false;
        };
        let Ok(parent_meta) = std::fs::metadata(parent) else {
            return false;
        };
        path_meta.dev() != parent_meta.dev()
    }

    /// Unmount a FUSE filesystem using fusermount3 (preferred) or fusermount.
    #[cfg(target_os = "linux")]
    fn fusermount_unmount(merged: &Path) -> Result<()> {
        for cmd in &["fusermount3", "fusermount"] {
            if Self::find_in_path(cmd).is_some() {
                let output = std::process::Command::new(cmd)
                    .arg("-u")
                    .arg(merged)
                    .output()
                    .map_err(|e| {
                        crate::error::PuzzledError::Sandbox(format!(
                            "running {} -u {}: {}",
                            cmd,
                            merged.display(),
                            e
                        ))
                    })?;
                if output.status.success() {
                    return Ok(());
                }
                let stderr = String::from_utf8_lossy(&output.stderr);
                tracing::warn!(
                    cmd,
                    stderr = %stderr.trim(),
                    "fusermount failed, trying fallback"
                );
            }
        }
        Err(crate::error::PuzzledError::Sandbox(format!(
            "failed to unmount fuse-overlayfs at {}: \
             neither fusermount3 nor fusermount succeeded",
            merged.display()
        )))
    }

    /// Unmount the OverlayFS filesystem.
    #[cfg(target_os = "linux")]
    pub fn unmount(&mut self) -> Result<()> {
        if let Some(ref mut child) = self.fuse_child {
            // Rootless: unmount via fusermount3/fusermount, then clean up child
            Self::fusermount_unmount(&self.merged_dir)?;

            match child.try_wait() {
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                Ok(Some(_)) => {}
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "failed to check fuse-overlayfs status during unmount"
                    );
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }

            tracing::info!(
                merged = %self.merged_dir.display(),
                "fuse-overlayfs unmounted (rootless)"
            );
            return Ok(());
        }

        // Rootful: kernel unmount (unchanged)
        nix::mount::umount2(&self.merged_dir, nix::mount::MntFlags::MNT_DETACH).map_err(|e| {
            crate::error::PuzzledError::Sandbox(format!(
                "unmounting OverlayFS at {}: {}",
                self.merged_dir.display(),
                e
            ))
        })?;

        tracing::info!(merged = %self.merged_dir.display(), "OverlayFS unmounted");
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn unmount(&mut self) -> Result<()> {
        Err(crate::error::PuzzledError::Sandbox(
            "OverlayFS requires Linux".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let branch_dir = tmp.path().join("branch-1");
        std::fs::create_dir_all(&branch_dir).unwrap();

        let (upper, work, merged) = OverlayMount::create_dirs(&branch_dir).unwrap();

        assert!(upper.exists(), "upper dir should exist");
        assert!(work.exists(), "work dir should exist");
        assert!(merged.exists(), "merged dir should exist");
    }

    #[test]
    fn test_create_dirs_nested() {
        let tmp = tempfile::tempdir().unwrap();
        // Parent doesn't exist yet — create_dirs should create recursively
        let branch_dir = tmp.path().join("deep").join("nested").join("branch");

        let (upper, work, merged) = OverlayMount::create_dirs(&branch_dir).unwrap();

        assert!(
            upper.exists(),
            "upper dir should exist after recursive creation"
        );
        assert!(
            work.exists(),
            "work dir should exist after recursive creation"
        );
        assert!(
            merged.exists(),
            "merged dir should exist after recursive creation"
        );
    }

    #[test]
    fn test_create_dirs_returns_correct_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let branch_dir = tmp.path().join("branch-check");

        let (upper, work, merged) = OverlayMount::create_dirs(&branch_dir).unwrap();

        assert_eq!(upper, branch_dir.join("upper"));
        assert_eq!(work, branch_dir.join("work"));
        assert_eq!(merged, branch_dir.join("merged"));
    }

    // ── create_dirs: symlink rejection (M-ov1) ──

    #[test]
    fn test_create_dirs_rejects_symlink_branch_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let real_dir = tmp.path().join("real");
        std::fs::create_dir_all(&real_dir).unwrap();

        let symlink_dir = tmp.path().join("branch-link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();
        #[cfg(not(unix))]
        {
            // Skip on non-unix platforms where symlink creation differs
            return;
        }

        let err = OverlayMount::create_dirs(&symlink_dir).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("symlink detected"),
            "expected symlink error, got: {msg}"
        );
    }

    #[test]
    fn test_create_dirs_rejects_symlink_subdir() {
        let tmp = tempfile::tempdir().unwrap();
        let branch_dir = tmp.path().join("branch-sub");
        std::fs::create_dir_all(&branch_dir).unwrap();

        // Pre-create "upper" as a symlink targeting somewhere else
        let target = tmp.path().join("elsewhere");
        std::fs::create_dir_all(&target).unwrap();

        let upper_link = branch_dir.join("upper");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &upper_link).unwrap();
        #[cfg(not(unix))]
        {
            return;
        }

        let err = OverlayMount::create_dirs(&branch_dir).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("symlink detected"),
            "expected symlink error for subdir, got: {msg}"
        );
    }

    #[test]
    fn test_create_dirs_nonexistent_branch_dir_no_symlink_error() {
        // A non-existent branch_dir should NOT trigger the symlink check
        let tmp = tempfile::tempdir().unwrap();
        let branch_dir = tmp.path().join("does-not-exist");

        let result = OverlayMount::create_dirs(&branch_dir);
        assert!(result.is_ok(), "non-existent dir should succeed");
    }

    #[test]
    fn test_create_dirs_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let branch_dir = tmp.path().join("branch-idem");

        // Call twice — second call should succeed (create_dir_all is idempotent)
        OverlayMount::create_dirs(&branch_dir).unwrap();
        let (upper, work, merged) = OverlayMount::create_dirs(&branch_dir).unwrap();

        assert!(upper.exists());
        assert!(work.exists());
        assert!(merged.exists());
    }

    // ── validate_mount_path ──

    #[test]
    fn test_validate_mount_path_valid() {
        let path = Path::new("/var/lib/puzzled/branches/branch-1/upper");
        assert!(OverlayMount::validate_mount_path(path).is_ok());
    }

    #[test]
    fn test_validate_mount_path_rejects_comma() {
        let path = Path::new("/var/lib/puzzled/branches/evil,rw/upper");
        let err = OverlayMount::validate_mount_path(path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("comma"), "expected comma error, got: {msg}");
    }

    #[test]
    fn test_validate_mount_path_rejects_backslash() {
        let path = Path::new("/var/lib/puzzled/branches/evil\\path/upper");
        let err = OverlayMount::validate_mount_path(path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("backslash"),
            "expected backslash error, got: {msg}"
        );
    }

    #[test]
    fn test_validate_mount_path_rejects_newline() {
        let path = PathBuf::from("/var/lib/puzzled/branches/evil\npath/upper");
        let err = OverlayMount::validate_mount_path(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("newline"),
            "expected newline error, got: {msg}"
        );
    }

    #[test]
    fn test_validate_mount_path_rejects_null_byte() {
        use std::ffi::OsStr;
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let path = PathBuf::from(OsStr::from_bytes(b"/var/lib/puzzled/\x00evil"));
            let err = OverlayMount::validate_mount_path(&path).unwrap_err();
            let msg = err.to_string();
            // Null byte in OsStr makes to_str() return None → non-UTF-8 error,
            // or if it somehow passes, it hits the null check.
            assert!(
                msg.contains("null") || msg.contains("non-UTF-8"),
                "expected null or non-UTF-8 error, got: {msg}"
            );
        }
    }

    #[test]
    fn test_validate_mount_path_rejects_control_chars() {
        // Test tab (0x09)
        let path = PathBuf::from("/var/lib/puzzled/branches/evil\tpath");
        let err = OverlayMount::validate_mount_path(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("control character 0x09"),
            "expected control char error for tab, got: {msg}"
        );
    }

    #[test]
    fn test_validate_mount_path_rejects_carriage_return() {
        let path = PathBuf::from("/var/lib/puzzled/branches/evil\rpath");
        let err = OverlayMount::validate_mount_path(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("control character 0x0d"),
            "expected control char error for CR, got: {msg}"
        );
    }

    #[test]
    fn test_validate_mount_path_rejects_bell_char() {
        // ASCII BEL = 0x07
        let path = PathBuf::from("/var/lib/puzzled/branches/evil\x07path");
        let err = OverlayMount::validate_mount_path(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("control character 0x07"),
            "expected control char error for BEL, got: {msg}"
        );
    }

    #[test]
    fn test_validate_mount_path_rejects_non_utf8() {
        #[cfg(unix)]
        {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;
            // 0x80 is not valid UTF-8 as a standalone byte
            let path = PathBuf::from(OsStr::from_bytes(b"/var/lib/puzzled/\x80evil"));
            let err = OverlayMount::validate_mount_path(&path).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("non-UTF-8"),
                "expected non-UTF-8 error, got: {msg}"
            );
        }
    }

    #[test]
    fn test_validate_mount_path_allows_spaces_and_dashes() {
        // Spaces, dashes, underscores, dots should all be fine
        let path = Path::new("/var/lib/agent d/branch-name_1.0/upper");
        assert!(OverlayMount::validate_mount_path(path).is_ok());
    }

    #[test]
    fn test_validate_mount_path_allows_unicode() {
        let path = Path::new("/var/lib/puzzled/brünch/上层");
        assert!(OverlayMount::validate_mount_path(path).is_ok());
    }

    // ── validate_received_path ──

    #[test]
    fn test_validate_received_path_valid() {
        let path = b"/var/lib/puzzled/branches/branch-1/upper";
        assert!(OverlayMount::validate_received_path(path, "upper").is_ok());
    }

    #[test]
    fn test_validate_received_path_root() {
        assert!(OverlayMount::validate_received_path(b"/", "root").is_ok());
    }

    #[test]
    fn test_validate_received_path_rejects_too_long() {
        let mut long_path = vec![b'/'];
        long_path.extend(vec![b'a'; 4096]); // 4097 bytes total
        let err = OverlayMount::validate_received_path(&long_path, "test").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("exceeds max path length"),
            "expected length error, got: {msg}"
        );
    }

    #[test]
    fn test_validate_received_path_accepts_exactly_4096() {
        let mut path = vec![b'/'];
        path.extend(vec![b'a'; 4095]); // exactly 4096 bytes
        assert!(OverlayMount::validate_received_path(&path, "test").is_ok());
    }

    #[test]
    fn test_validate_received_path_rejects_null_byte() {
        let path = b"/var/lib/\x00puzzled";
        let err = OverlayMount::validate_received_path(path, "test").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("null byte"),
            "expected null byte error, got: {msg}"
        );
    }

    #[test]
    fn test_validate_received_path_rejects_null_at_end() {
        let path = b"/var/lib/puzzled\x00";
        let err = OverlayMount::validate_received_path(path, "test").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("null byte"),
            "expected null byte error, got: {msg}"
        );
    }

    #[test]
    fn test_validate_received_path_rejects_relative() {
        let path = b"var/lib/puzzled";
        let err = OverlayMount::validate_received_path(path, "test").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not an absolute path"),
            "expected relative path error, got: {msg}"
        );
    }

    #[test]
    fn test_validate_received_path_rejects_dot_relative() {
        let path = b"./var/lib/puzzled";
        let err = OverlayMount::validate_received_path(path, "test").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not an absolute path"),
            "expected relative path error, got: {msg}"
        );
    }

    #[test]
    fn test_validate_received_path_rejects_empty() {
        let err = OverlayMount::validate_received_path(b"", "test").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not an absolute path"),
            "expected empty path error, got: {msg}"
        );
    }

    #[test]
    fn test_validate_received_path_label_in_error() {
        let err = OverlayMount::validate_received_path(b"relative", "my_label").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("my_label"),
            "error should contain the label, got: {msg}"
        );
    }

    // ── mount / unmount non-Linux stubs ──

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_mount_returns_error_on_non_linux() {
        let result = OverlayMount::mount(
            Path::new("/lower"),
            Path::new("/upper"),
            Path::new("/work"),
            Path::new("/merged"),
            false,
        );
        match result {
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("OverlayFS requires Linux"),
                    "expected Linux-required error, got: {msg}"
                );
            }
            Ok(_) => panic!("expected error on non-Linux, got Ok"),
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_mount_with_allow_exec_returns_error_on_non_linux() {
        let result = OverlayMount::mount(
            Path::new("/lower"),
            Path::new("/upper"),
            Path::new("/work"),
            Path::new("/merged"),
            true,
        );
        match result {
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("OverlayFS requires Linux"),
                    "expected Linux-required error, got: {msg}"
                );
            }
            Ok(_) => panic!("expected error on non-Linux, got Ok"),
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_unmount_returns_error_on_non_linux() {
        let mut om = OverlayMount {
            upper_dir: PathBuf::from("/upper"),
            work_dir: PathBuf::from("/work"),
            merged_dir: PathBuf::from("/merged"),
            lower_dir: PathBuf::from("/lower"),
            fuse_child: None,
        };
        match om.unmount() {
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("OverlayFS requires Linux"),
                    "expected Linux-required error, got: {msg}"
                );
            }
            Ok(_) => panic!("expected error on non-Linux, got Ok"),
        }
    }

    /// Issue #10: OverlayFS mount options must include redirect_dir=off to
    /// prevent rename-based diff evasion. Without this, an agent could use
    /// rename operations to bypass upper-layer tracking.
    #[test]
    fn test_mount_options_include_redirect_dir_off() {
        let options = OverlayMount::build_mount_options(
            Path::new("/lower"),
            Path::new("/upper"),
            Path::new("/work"),
        );
        assert!(
            options.contains("redirect_dir=off"),
            "mount options must include redirect_dir=off to prevent diff evasion, got: {}",
            options
        );
    }

    /// Verify mount options include metacopy=off (existing requirement).
    #[test]
    fn test_mount_options_include_metacopy_off() {
        let options = OverlayMount::build_mount_options(
            Path::new("/lower"),
            Path::new("/upper"),
            Path::new("/work"),
        );
        assert!(
            options.contains("metacopy=off"),
            "mount options must include metacopy=off, got: {}",
            options
        );
    }

    // ── fuse-overlayfs / rootless helpers ──

    #[cfg(target_os = "linux")]
    #[test]
    fn test_find_in_path_finds_sh() {
        // /bin/sh exists on every Linux system
        let result = OverlayMount::find_in_path("sh");
        assert!(result.is_some(), "find_in_path should locate 'sh' in PATH");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_find_in_path_nonexistent() {
        let result = OverlayMount::find_in_path("this_binary_definitely_does_not_exist_zzz");
        assert!(
            result.is_none(),
            "find_in_path should return None for missing binary"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_is_fuse_mountpoint_returns_false_for_regular_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let subdir = tmp.path().join("sub");
        std::fs::create_dir_all(&subdir).unwrap();
        assert!(
            !OverlayMount::is_fuse_mountpoint(&subdir),
            "regular subdir should not be detected as a mountpoint"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_is_fuse_mountpoint_returns_false_for_nonexistent() {
        let path = Path::new("/tmp/this_path_does_not_exist_zzz_overlay_test");
        assert!(
            !OverlayMount::is_fuse_mountpoint(path),
            "nonexistent path should not be a mountpoint"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_fuse_overlayfs_error_message_when_missing() {
        // Temporarily set PATH to empty so fuse-overlayfs cannot be found,
        // and skip if fuse-overlayfs is in a well-known location.
        if Path::new("/usr/bin/fuse-overlayfs").is_file()
            || Path::new("/usr/local/bin/fuse-overlayfs").is_file()
        {
            // Can't test the "not found" path when it's installed in a well-known location
            return;
        }
        let saved = std::env::var_os("PATH");
        std::env::set_var("PATH", "/nonexistent_dir_for_test");
        let result = OverlayMount::find_fuse_overlayfs();
        if let Some(p) = saved {
            std::env::set_var("PATH", p);
        } else {
            std::env::remove_var("PATH");
        }
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("fuse-overlayfs") && msg.contains("not found"),
            "expected fuse-overlayfs not-found error, got: {msg}"
        );
    }

    /// Verify the overlay module has rootless detection via geteuid.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_mount_has_rootless_detection() {
        let source = include_str!("overlay.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            prod_source.contains("geteuid"),
            "mount() must check geteuid for rootless detection"
        );
        assert!(
            prod_source.contains("mount_fuse_overlayfs"),
            "mount() must dispatch to mount_fuse_overlayfs for rootless mode"
        );
    }

    /// H28: Verify post-creation symlink check exists to close TOCTOU window.
    #[test]
    fn test_h28_post_creation_symlink_check() {
        let source = include_str!("overlay.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // The post-creation check must appear AFTER create_dir_all calls
        let last_create = prod_source
            .rfind("create_dir_all")
            .expect("H28: must have create_dir_all calls");
        let after_create = &prod_source[last_create..];
        assert!(
            after_create.contains("H28: symlink detected after creation")
                || after_create.contains("H28:"),
            "H28: must have post-creation symlink verification after create_dir_all()"
        );
        // Also verify it checks symlink_metadata after creation
        assert!(
            after_create.contains("symlink_metadata"),
            "H28: post-creation check must use symlink_metadata()"
        );
    }
}
