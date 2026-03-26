// SPDX-License-Identifier: Apache-2.0
use puzzled_types::ResourceLimits;
use std::path::PathBuf;

use crate::error::Result;

/// cgroup v2 scope manager — creates per-agent cgroup scopes
/// and enforces resource limits.
pub struct CgroupManager;

impl CgroupManager {
    /// Create a new cgroup scope for an agent and apply resource limits.
    ///
    /// Creates: /sys/fs/cgroup/puzzle.slice/user-<uid>.slice/agent-<branch_id>.scope/
    /// Sets: memory.max, cpu.weight, io.weight, pids.max
    #[cfg(target_os = "linux")]
    pub fn create_scope(branch_id: &str, limits: &ResourceLimits) -> Result<PathBuf> {
        Self::create_scope_with_uid(branch_id, 0, limits)
    }

    /// Sanitize a branch_id for use in cgroup path names.
    ///
    /// M8: Only allow alphanumeric characters and hyphens. All other characters
    /// are replaced with hyphens to prevent path traversal or injection attacks.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn sanitize_branch_id(branch_id: &str) -> String {
        branch_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c
                } else {
                    '-'
                }
            })
            .collect()
    }

    /// Create a new cgroup scope with UID-based scoping for multi-tenancy.
    ///
    /// If uid > 0, creates: /sys/fs/cgroup/puzzle.slice/user-<uid>.slice/agent-<branch_id>.scope/
    /// If uid == 0, creates: /sys/fs/cgroup/puzzle.slice/agent-<branch_id>.scope/
    #[cfg(target_os = "linux")]
    pub fn create_scope_with_uid(
        branch_id: &str,
        uid: u32,
        limits: &ResourceLimits,
    ) -> Result<PathBuf> {
        // M8: Sanitize branch_id before using in cgroup path names
        let safe_branch_id = Self::sanitize_branch_id(branch_id);
        if safe_branch_id != branch_id {
            tracing::warn!(
                original = branch_id,
                sanitized = %safe_branch_id,
                "branch_id contained unsafe characters for cgroup path; sanitized"
            );
        }

        let scope_path = if uid > 0 {
            PathBuf::from(format!(
                "/sys/fs/cgroup/puzzle.slice/user-{}.slice/agent-{}.scope",
                uid, safe_branch_id
            ))
        } else {
            PathBuf::from(format!(
                "/sys/fs/cgroup/puzzle.slice/agent-{}.scope",
                safe_branch_id
            ))
        };

        // Create the puzzle.slice if it doesn't exist
        let agent_slice = PathBuf::from("/sys/fs/cgroup/puzzle.slice");
        let slice_path = if uid > 0 {
            PathBuf::from(format!("/sys/fs/cgroup/puzzle.slice/user-{}.slice", uid))
        } else {
            agent_slice.clone()
        };
        if !slice_path.exists() {
            std::fs::create_dir_all(&slice_path).map_err(|e| {
                crate::error::PuzzledError::Sandbox(format!(
                    "creating {}: {}",
                    slice_path.display(),
                    e
                ))
            })?;
        }

        // Create the scope directory
        std::fs::create_dir_all(&scope_path).map_err(|e| {
            crate::error::PuzzledError::Sandbox(format!(
                "creating cgroup scope {}: {}",
                scope_path.display(),
                e
            ))
        })?;

        // Enable cgroup v2 subtree controllers at each level of the hierarchy.
        // Without this, writing to control files (memory.max, cpu.weight, etc.)
        // in child cgroups fails with ENOENT or EPERM because the controllers
        // are not delegated to the subtree.
        let controllers = "+memory +cpu +io +pids";
        let cgroup_root = PathBuf::from("/sys/fs/cgroup");
        // Enable at root -> puzzle.slice
        Self::enable_subtree_controllers(&cgroup_root, controllers);
        // Enable at puzzle.slice -> user-<uid>.slice (or puzzle.slice -> scope)
        Self::enable_subtree_controllers(&agent_slice, controllers);
        // Enable at user-<uid>.slice -> scope (if uid-scoped)
        if uid > 0 {
            Self::enable_subtree_controllers(&slice_path, controllers);
        }

        // Write resource limits
        Self::write_limit(&scope_path, "memory.max", &limits.memory_bytes.to_string())?;
        // memory.high — soft limit for throttling before OOM
        if let Some(high) = limits.memory_high {
            Self::write_limit(&scope_path, "memory.high", &high.to_string())?;
        }
        // M7: Enable group OOM kill — when the cgroup hits the memory limit, the
        // kernel kills ALL processes in the cgroup rather than just one. This ensures
        // the entire agent process tree is terminated cleanly on OOM.
        Self::write_limit(&scope_path, "memory.oom.group", "1")?;
        Self::write_limit(&scope_path, "cpu.weight", &limits.cpu_shares.to_string())?;
        // L6: Set cpu.max (quota/period) to cap CPU usage in addition to cpu.weight.
        // Format is "$QUOTA $PERIOD" in microseconds. Default: 50000/100000 = 50% of
        // one CPU core. L-prf1: Reduced from 100% to prevent a single agent from
        // monopolizing CPU time even when cpu.weight would otherwise allow it under
        // low contention.
        // Uses profile's cpu_quota_us if set, otherwise defaults to 50000 (50% of one core).
        let cpu_quota = limits.cpu_quota_us.unwrap_or(50_000);
        let cpu_max_value = format!("{} 100000", cpu_quota);
        Self::write_limit(&scope_path, "cpu.max", &cpu_max_value)?;
        Self::write_limit(
            &scope_path,
            "io.weight",
            &format!("default {}", limits.io_weight),
        )?;
        // io.max — per-device I/O bandwidth limits (if configured)
        if let Some(ref io_max) = limits.io_max {
            Self::write_limit(&scope_path, "io.max", io_max)?;
        }
        Self::write_limit(&scope_path, "pids.max", &limits.max_pids.to_string())?;

        tracing::info!(
            scope = %scope_path.display(),
            memory_max = limits.memory_bytes,
            cpu_weight = limits.cpu_shares,
            pids_max = limits.max_pids,
            "cgroup scope created"
        );

        Ok(scope_path)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn create_scope(_branch_id: &str, _limits: &ResourceLimits) -> Result<PathBuf> {
        Err(crate::error::PuzzledError::Sandbox(
            "cgroups require Linux".to_string(),
        ))
    }

    /// Move a process into the cgroup scope.
    #[cfg(target_os = "linux")]
    pub fn add_process(cgroup_path: &std::path::Path, pid: u32) -> Result<()> {
        let procs_path = cgroup_path.join("cgroup.procs");
        std::fs::write(&procs_path, pid.to_string()).map_err(|e| {
            crate::error::PuzzledError::Sandbox(format!(
                "adding PID {} to {}: {}",
                pid,
                procs_path.display(),
                e
            ))
        })?;

        tracing::debug!(pid, cgroup = %cgroup_path.display(), "process added to cgroup");
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn add_process(_cgroup_path: &std::path::Path, _pid: u32) -> Result<()> {
        Err(crate::error::PuzzledError::Sandbox(
            "cgroups require Linux".to_string(),
        ))
    }

    /// Freeze all processes in a cgroup (for TOCTOU-free diff).
    ///
    /// `cgroup.freeze` is asynchronous — writing "1" initiates the freeze but
    /// processes may still be runnable briefly. We poll `cgroup.events` for
    /// `frozen 1` to confirm all processes are actually frozen before returning.
    #[cfg(target_os = "linux")]
    pub fn freeze(cgroup_path: &std::path::Path) -> Result<()> {
        let freeze_path = cgroup_path.join("cgroup.freeze");
        std::fs::write(&freeze_path, "1").map_err(|e| {
            crate::error::PuzzledError::Sandbox(format!(
                "freezing cgroup {}: {}",
                cgroup_path.display(),
                e
            ))
        })?;

        // M-cg1: Poll cgroup.events for "frozen 1" with exponential backoff.
        // Freeze is asynchronous — writing "1" initiates the freeze but processes
        // may still be runnable briefly. We use exponential backoff (1ms → 2ms →
        // 4ms → ... → 64ms cap) to avoid busy-waiting while still detecting the
        // frozen state promptly. Total deadline: 5 seconds.
        let events_path = cgroup_path.join("cgroup.events");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut backoff_ms: u64 = 1;
        const MAX_BACKOFF_MS: u64 = 64;
        loop {
            if let Ok(contents) = std::fs::read_to_string(&events_path) {
                if contents.lines().any(|l| l.trim() == "frozen 1") {
                    break;
                }
            }
            if std::time::Instant::now() > deadline {
                return Err(crate::error::PuzzledError::Sandbox(format!(
                    "cgroup {} did not freeze within 5s",
                    cgroup_path.display()
                )));
            }
            std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
            backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
        }

        tracing::info!(cgroup = %cgroup_path.display(), "cgroup frozen (confirmed via cgroup.events)");
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn freeze(_cgroup_path: &std::path::Path) -> Result<()> {
        Err(crate::error::PuzzledError::Sandbox(
            "cgroups require Linux".to_string(),
        ))
    }

    /// Thaw (unfreeze) all processes in a cgroup.
    #[cfg(target_os = "linux")]
    pub fn thaw(cgroup_path: &std::path::Path) -> Result<()> {
        let freeze_path = cgroup_path.join("cgroup.freeze");
        std::fs::write(&freeze_path, "0").map_err(|e| {
            crate::error::PuzzledError::Sandbox(format!(
                "thawing cgroup {}: {}",
                cgroup_path.display(),
                e
            ))
        })?;

        tracing::info!(cgroup = %cgroup_path.display(), "cgroup thawed");
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn thaw(_cgroup_path: &std::path::Path) -> Result<()> {
        Err(crate::error::PuzzledError::Sandbox(
            "cgroups require Linux".to_string(),
        ))
    }

    /// Kill all processes in a cgroup by writing to cgroup.kill.
    #[cfg(target_os = "linux")]
    pub fn kill(cgroup_path: &std::path::Path) -> Result<()> {
        let kill_path = cgroup_path.join("cgroup.kill");
        std::fs::write(&kill_path, "1").map_err(|e| {
            crate::error::PuzzledError::Sandbox(format!(
                "killing cgroup {}: {}",
                cgroup_path.display(),
                e
            ))
        })?;
        tracing::info!(cgroup = %cgroup_path.display(), "cgroup.kill written");
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn kill(_cgroup_path: &std::path::Path) -> Result<()> {
        Err(crate::error::PuzzledError::Sandbox(
            "cgroups require Linux".to_string(),
        ))
    }

    /// Remove the cgroup scope directory.
    #[cfg(target_os = "linux")]
    pub fn remove_scope(cgroup_path: &PathBuf) -> Result<()> {
        // First try to kill all processes in the cgroup
        let kill_path = cgroup_path.join("cgroup.kill");
        if kill_path.exists() {
            if let Err(e) = std::fs::write(&kill_path, "1") {
                tracing::error!(
                    path = %kill_path.display(),
                    error = %e,
                    "S31: failed to write cgroup.kill during remove_scope — processes may survive"
                );
            }
        }

        // Then remove the directory
        if cgroup_path.exists() {
            std::fs::remove_dir(cgroup_path).map_err(|e| {
                crate::error::PuzzledError::Sandbox(format!(
                    "removing cgroup scope {}: {}",
                    cgroup_path.display(),
                    e
                ))
            })?;
        }

        tracing::info!(cgroup = %cgroup_path.display(), "cgroup scope removed");
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn remove_scope(_cgroup_path: &PathBuf) -> Result<()> {
        Err(crate::error::PuzzledError::Sandbox(
            "cgroups require Linux".to_string(),
        ))
    }

    /// L8: Full cleanup of a cgroup scope during branch teardown/rollback.
    ///
    /// Kills all processes, removes the cgroup directory, and attempts to
    /// remove the parent user slice directory if it is empty (best-effort).
    #[cfg(target_os = "linux")]
    pub fn cleanup(cgroup_path: &PathBuf) -> Result<()> {
        // Kill all processes first
        if let Err(e) = Self::kill(cgroup_path) {
            tracing::error!(
                path = %cgroup_path.display(),
                error = %e,
                "R11: cgroup kill failed during cleanup — agent processes may survive"
            );
        }

        // M-cg2: Poll cgroup.procs for empty instead of a fixed sleep.
        // After cgroup.kill, processes receive SIGKILL but may take time to
        // exit (especially if in uninterruptible sleep). Poll at 100ms intervals
        // with a 3s deadline before proceeding to removal.
        let procs_path = cgroup_path.join("cgroup.procs");
        let cleanup_deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            match std::fs::read_to_string(&procs_path) {
                Ok(contents) if contents.trim().is_empty() => break,
                Ok(_) => {
                    // Processes still present
                    if std::time::Instant::now() > cleanup_deadline {
                        tracing::warn!(
                            cgroup = %cgroup_path.display(),
                            "cgroup.procs not empty after 3s deadline, proceeding with removal"
                        );
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(_) => {
                    // cgroup.procs may not exist if cgroup was already removed
                    break;
                }
            }
        }

        // Remove the scope directory
        if cgroup_path.exists() {
            std::fs::remove_dir(cgroup_path).map_err(|e| {
                crate::error::PuzzledError::Sandbox(format!(
                    "removing cgroup scope {}: {}",
                    cgroup_path.display(),
                    e
                ))
            })?;
        }

        // Best-effort: remove parent user slice if empty (e.g., user-1000.slice)
        if let Some(parent) = cgroup_path.parent() {
            let parent_name = parent
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if parent_name.starts_with("user-") && parent_name.ends_with(".slice") {
                if let Ok(mut entries) = std::fs::read_dir(parent) {
                    if entries.next().is_none() {
                        let _ = std::fs::remove_dir(parent);
                        tracing::debug!(
                            path = %parent.display(),
                            "removed empty user slice directory"
                        );
                    }
                }
            }
        }

        tracing::info!(cgroup = %cgroup_path.display(), "cgroup cleanup complete");
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn cleanup(_cgroup_path: &PathBuf) -> Result<()> {
        Err(crate::error::PuzzledError::Sandbox(
            "cgroups require Linux".to_string(),
        ))
    }

    /// Enable cgroup v2 subtree controllers at a given cgroup directory.
    ///
    /// Writes to `cgroup.subtree_control` to delegate controllers (memory, cpu,
    /// io, pids) to child cgroups. Best-effort: failures are logged but not fatal,
    /// since the controllers may already be enabled or the hierarchy may not
    /// support delegation at this level.
    #[cfg(target_os = "linux")]
    fn enable_subtree_controllers(cgroup_dir: &std::path::Path, controllers: &str) {
        let path = cgroup_dir.join("cgroup.subtree_control");
        if let Err(e) = std::fs::write(&path, controllers) {
            tracing::debug!(
                path = %path.display(),
                controllers,
                error = %e,
                "failed to enable subtree controllers (may already be enabled)"
            );
        }
    }

    /// Write a value to a cgroup control file.
    #[cfg(target_os = "linux")]
    fn write_limit(scope_path: &std::path::Path, file: &str, value: &str) -> Result<()> {
        let path = scope_path.join(file);
        std::fs::write(&path, value).map_err(|e| {
            crate::error::PuzzledError::Sandbox(format!(
                "writing {} to {}: {}",
                value,
                path.display(),
                e
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_cgroup_create_scope_non_linux() {
        let limits = ResourceLimits::default();
        let result = CgroupManager::create_scope("test-branch", &limits);
        assert!(
            result.is_err(),
            "create_scope should return error on non-Linux"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_cgroup_add_process_non_linux() {
        let path = PathBuf::from("/sys/fs/cgroup/test");
        let result = CgroupManager::add_process(&path, 1234);
        assert!(
            result.is_err(),
            "add_process should return error on non-Linux"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_cgroup_freeze_non_linux() {
        let path = PathBuf::from("/sys/fs/cgroup/test");
        let result = CgroupManager::freeze(&path);
        assert!(result.is_err(), "freeze should return error on non-Linux");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_cgroup_thaw_non_linux() {
        let path = PathBuf::from("/sys/fs/cgroup/test");
        let result = CgroupManager::thaw(&path);
        assert!(result.is_err(), "thaw should return error on non-Linux");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_cgroup_remove_scope_non_linux() {
        let path = PathBuf::from("/sys/fs/cgroup/test");
        let result = CgroupManager::remove_scope(&path);
        assert!(
            result.is_err(),
            "remove_scope should return error on non-Linux"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_cgroup_kill_non_linux() {
        let path = PathBuf::from("/sys/fs/cgroup/test");
        let result = CgroupManager::kill(&path);
        assert!(result.is_err(), "kill should return error on non-Linux");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_cgroup_cleanup_non_linux() {
        let path = PathBuf::from("/sys/fs/cgroup/test");
        let result = CgroupManager::cleanup(&path);
        assert!(result.is_err(), "cleanup should return error on non-Linux");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_cgroup_create_scope_with_uid_non_linux() {
        let limits = ResourceLimits::default();
        let result = CgroupManager::create_scope("test-branch", &limits);
        // On non-Linux, create_scope (which wraps create_scope_with_uid) returns error
        assert!(
            result.is_err(),
            "create_scope (wrapping create_scope_with_uid) should return error on non-Linux"
        );
    }

    #[test]
    fn test_cgroup_manager_is_unit_struct() {
        // CgroupManager is a unit struct — verify it can be instantiated
        let _manager = CgroupManager;
    }

    // sanitize_branch_id tests — function is private, but tests are inside the module
    #[test]
    fn test_sanitize_clean_id() {
        let result = CgroupManager::sanitize_branch_id("my-branch-123");
        assert_eq!(result, "my-branch-123");
    }

    #[test]
    fn test_sanitize_already_clean_alphanumeric() {
        let result = CgroupManager::sanitize_branch_id("abc123");
        assert_eq!(result, "abc123");
    }

    #[test]
    fn test_sanitize_dots_replaced() {
        let result = CgroupManager::sanitize_branch_id("branch.v1.0");
        assert_eq!(result, "branch-v1-0");
    }

    #[test]
    fn test_sanitize_slashes_replaced() {
        let result = CgroupManager::sanitize_branch_id("feature/my-branch");
        assert_eq!(result, "feature-my-branch");
    }

    #[test]
    fn test_sanitize_spaces_replaced() {
        let result = CgroupManager::sanitize_branch_id("my branch name");
        assert_eq!(result, "my-branch-name");
    }

    #[test]
    fn test_sanitize_special_chars() {
        let result = CgroupManager::sanitize_branch_id("branch@#$%^&*()!");
        assert_eq!(result, "branch----------");
    }

    #[test]
    fn test_sanitize_path_traversal() {
        let result = CgroupManager::sanitize_branch_id("../../etc/passwd");
        assert_eq!(result, "------etc-passwd");
    }

    #[test]
    fn test_sanitize_double_dot_traversal() {
        let result = CgroupManager::sanitize_branch_id("../../../root");
        assert_eq!(result, "---------root");
    }

    #[test]
    fn test_sanitize_hyphen_only() {
        let result = CgroupManager::sanitize_branch_id("---");
        assert_eq!(result, "---");
    }

    #[test]
    fn test_sanitize_empty_string() {
        let result = CgroupManager::sanitize_branch_id("");
        assert_eq!(result, "");
    }

    #[test]
    fn test_sanitize_underscores_replaced() {
        let result = CgroupManager::sanitize_branch_id("my_branch_name");
        assert_eq!(result, "my-branch-name");
    }

    #[test]
    fn test_sanitize_null_bytes() {
        let result = CgroupManager::sanitize_branch_id("branch\0id");
        assert_eq!(result, "branch-id");
    }

    #[test]
    fn test_sanitize_newlines_and_tabs() {
        let result = CgroupManager::sanitize_branch_id("branch\nid\there");
        assert_eq!(result, "branch-id-here");
    }

    /// S31: Verify that remove_scope does not use `let _ =` to silently discard
    /// the cgroup kill write result. Errors must be logged.
    #[test]
    fn test_s31_remove_scope_no_silent_kill() {
        let source = include_str!("cgroup.rs");
        // Extract the remove_scope function body from production code
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        // Find the remove_scope function
        let remove_scope_start = production_code
            .find("fn remove_scope")
            .expect("remove_scope function must exist");
        let remove_scope_body = &production_code[remove_scope_start..];
        // Take only up to the next `pub fn` or end of impl
        let remove_scope_end = remove_scope_body[1..]
            .find("\n    pub fn")
            .or_else(|| remove_scope_body[1..].find("\n    #[cfg(not"))
            .unwrap_or(remove_scope_body.len() - 1);
        let remove_scope_text = &remove_scope_body[..remove_scope_end + 1];
        assert!(
            !remove_scope_text.contains("let _ ="),
            "S31: remove_scope must not use `let _ =` to silently discard errors. \
             Found in:\n{}",
            remove_scope_text
        );
    }

    /// R11: Verify that production code does not silently discard cgroup kill errors
    /// via `.ok()`. The `kill()` call in `cleanup()` must log on failure.
    #[test]
    fn test_r11_no_silent_kill_ok_in_cleanup() {
        let source = include_str!("cgroup.rs");
        // Find the cleanup function and check it does not use kill(...).ok()
        // We look for the pattern in the #[cfg(target_os = "linux")] cleanup function
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        assert!(
            !production_code.contains("kill(cgroup_path).ok()"),
            "R11: production code must not use `.ok()` on cgroup kill — errors must be logged"
        );
    }
}
