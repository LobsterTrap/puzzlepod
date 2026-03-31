// SPDX-License-Identifier: Apache-2.0
use puzzled_types::{FileChange, FileChangeKind};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::error::{PuzzledError, Result};

/// Shannon entropy of a byte buffer (0.0 for uniform, up to 8.0 for maximally random).
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&f| f > 0)
        .map(|&f| {
            let p = f as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Check whether `data` contains a run of base64-alphabet characters longer than 64
/// on any single line. Lines are delimited by `\n` or `\r`.
fn has_base64_blocks(data: &[u8]) -> bool {
    let mut run = 0u32;
    for &b in data {
        if b == b'\n' || b == b'\r' {
            run = 0;
        } else if b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' {
            run += 1;
            if run > 64 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// H2: Maximum directory depth for upper-layer walk to prevent
/// pathological deep directory trees from causing stack overflow
/// or unbounded resource consumption.
const MAX_DEPTH: usize = 256;

/// The OverlayFS extended attribute that indicates a rename/move operation.
/// When present, its value contains the original path of the file before rename.
#[cfg(target_os = "linux")]
const OVERLAY_REDIRECT_XATTR: &str = "trusted.overlay.redirect";

/// M12: Read the mtime from a file path and format as RFC 3339.
fn read_mtime(path: &Path) -> Option<String> {
    fs::symlink_metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .map(|t| {
            let dt: chrono::DateTime<chrono::Utc> = t.into();
            dt.to_rfc3339()
        })
}

/// Walk an OverlayFS upper directory and produce a list of file changes,
/// filtering out copy-up artifacts using checksum comparison against the
/// lower (base) layer.
pub struct DiffEngine;

impl Default for DiffEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DiffEngine {
    pub fn new() -> Self {
        Self
    }

    /// Generate a diff by walking the upper directory.
    ///
    /// - Whiteout files (`.wh.*`) -> `Deleted`
    /// - Opaque dirs (`.wh..wh..opq`) -> mark directory as replaced (all contents are `Added`)
    /// - New files (not in lower) -> `Added`
    /// - Modified files (checksum differs from lower) -> `Modified`
    /// - Metadata-only changes (same checksum, different mode/owner) -> `MetadataChanged`
    /// - Copy-up artifacts (identical checksum + metadata) -> filtered out
    ///
    /// ## M3: Optional cgroup freeze verification
    ///
    /// When `cgroup_path` is `Some`, verifies that the cgroup is frozen before
    /// generating the diff. This provides TOCTOU protection: the agent cannot
    /// modify files while we are reading them. The `diff()` D-Bus method passes
    /// `None` (unfrozen diff is an inspection tool), while `commit()` passes the
    /// cgroup path to ensure freeze is active.
    pub fn generate(
        &self,
        upper_dir: &Path,
        lower_dir: &Path,
        cgroup_path: Option<&Path>,
    ) -> Result<Vec<FileChange>> {
        // M3: Verify cgroup is frozen when cgroup_path is provided
        if let Some(cg_path) = cgroup_path {
            Self::verify_cgroup_frozen(cg_path)?;
        }
        let mut changes = Vec::new();
        // M3: Track opaque directories — children should not compare against lower layer
        let mut opaque_dirs: HashSet<PathBuf> = HashSet::new();
        // M8: Track maximum depth seen during walk for truncation warning
        let mut max_depth_seen: usize = 0;

        // M4: Don't follow symlinks — prevents reading files outside the branch
        // H2: Limit recursion depth to MAX_DEPTH to prevent pathological trees
        for entry in WalkDir::new(upper_dir)
            .min_depth(1)
            .max_depth(MAX_DEPTH)
            .follow_links(false)
        {
            let entry = entry.map_err(|e| {
                // H2: WalkDir returns an error when max_depth is exceeded for
                // entries that have IO errors; depth limit itself silently stops.
                PuzzledError::Diff(e.to_string())
            })?;
            // M8: Track maximum depth for truncation warning
            if entry.depth() > max_depth_seen {
                max_depth_seen = entry.depth();
            }
            let upper_path = entry.path();

            // Relative path from the upper dir root
            let rel_path = upper_path
                .strip_prefix(upper_dir)
                .map_err(|e| PuzzledError::Diff(e.to_string()))?;

            // V26: Non-UTF-8 filenames produce empty string — whiteout detection may miss these.
            // Mitigated: OverlayFS creates whiteouts with ASCII-only names (.wh.*)
            let file_name = upper_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            // M3: Record opaque directory markers — in OverlayFS, .wh..wh..opq means
            // "the entire lower directory is replaced". All children are new.
            if file_name == ".wh..wh..opq" {
                if let Some(parent) = upper_path.parent() {
                    let parent_rel = parent.strip_prefix(upper_dir).unwrap_or(parent);
                    opaque_dirs.insert(parent_rel.to_path_buf());
                }
                continue;
            }

            // Handle whiteout files -> Deleted
            if Self::is_whiteout(upper_path) {
                let original_name = &file_name[4..]; // strip ".wh." prefix
                let deleted_path = rel_path
                    .parent()
                    .map(|p| p.join(original_name))
                    .unwrap_or_else(|| PathBuf::from(original_name));

                changes.push(FileChange {
                    path: deleted_path,
                    kind: FileChangeKind::Deleted,
                    size: 0,
                    checksum: String::new(),
                    old_size: None,
                    old_mode: None,
                    new_mode: None,
                    timestamp: read_mtime(upper_path),
                    target: None,
                    entropy: None,
                    has_base64_blocks: None,
                });
                continue;
            }

            // H1: Use symlink_metadata() to detect symlinks in the changeset.
            // Symlinks are reported as FileChangeKind::Symlink instead of being
            // followed, which prevents reading files outside the branch boundary.
            // Identical symlinks in both layers are still filtered as copy-up artifacts.
            if entry.file_type().is_symlink() {
                let lower_path = lower_dir.join(rel_path);
                let upper_link_target = std::fs::read_link(upper_path).ok();

                // Check if lower has an identical symlink
                let lower_link_target = lower_path
                    .symlink_metadata()
                    .ok()
                    .filter(|m| m.file_type().is_symlink())
                    .and_then(|_| std::fs::read_link(&lower_path).ok());

                match (&upper_link_target, &lower_link_target) {
                    (Some(upper_target), Some(lower_target)) if upper_target == lower_target => {
                        // M4: Identical symlink in both layers — copy-up artifact, skip
                        continue;
                    }
                    _ => {
                        // H1: Report symlink as FileChangeKind::Symlink — new or changed
                        // K60: Populate target field so Rego policies can validate symlink destinations
                        changes.push(FileChange {
                            path: rel_path.to_path_buf(),
                            kind: FileChangeKind::Symlink,
                            size: 0,
                            checksum: String::new(),
                            old_size: None,
                            old_mode: None,
                            new_mode: None,
                            timestamp: read_mtime(upper_path),
                            target: upper_link_target.map(|p| p.to_string_lossy().to_string()),
                            entropy: None,
                            has_base64_blocks: None,
                        });
                        continue;
                    }
                }
            }

            // Skip directories themselves (we care about files)
            if entry.file_type().is_dir() {
                continue;
            }

            // Q6/Q9: Detect special file types (block/char devices, FIFOs, hardlinks)
            // using raw mode bits from metadata, before normal file processing.
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if let Ok(meta) = upper_path.symlink_metadata() {
                    let mode = meta.mode();
                    #[allow(clippy::unnecessary_cast)] // libc::S_IF* is u16 on macOS, u32 on Linux
                    let ft = mode & (libc::S_IFMT as u32);
                    #[allow(clippy::unnecessary_cast)]
                    let special_kind = if ft == (libc::S_IFBLK as u32) {
                        Some(FileChangeKind::BlockDevice)
                    } else if ft == (libc::S_IFCHR as u32) {
                        Some(FileChangeKind::CharDevice)
                    } else if ft == (libc::S_IFIFO as u32) {
                        Some(FileChangeKind::Fifo)
                    } else if meta.nlink() > 1 && ft == (libc::S_IFREG as u32) {
                        Some(FileChangeKind::Hardlink)
                    } else {
                        None
                    };
                    if let Some(kind) = special_kind {
                        changes.push(FileChange {
                            path: rel_path.to_path_buf(),
                            kind,
                            size: meta.len(),
                            checksum: String::new(),
                            old_size: None,
                            old_mode: None,
                            new_mode: Some(mode),
                            timestamp: read_mtime(upper_path),
                            target: None,
                            entropy: None,
                            has_base64_blocks: None,
                        });
                        continue;
                    }
                }
            }

            // M3: If this file is under an opaque directory, treat as Added (no lower comparison)
            let is_opaque = opaque_dirs.iter().any(|d| rel_path.starts_with(d));
            if is_opaque {
                // Q11: Log metadata failures instead of silently defaulting to size 0
                let size = upper_path.metadata().map(|m| m.len()).unwrap_or_else(|e| {
                    tracing::warn!(path = %upper_path.display(), error = %e, "Q11: metadata read failed — using size 0");
                    0
                });
                // R13: Log checksum failures instead of silently using empty checksum
                let checksum = Self::checksum(upper_path).unwrap_or_else(|e| {
                    tracing::warn!(path = %upper_path.display(), error = %e, "R13: checksum computation failed — using empty checksum");
                    String::new()
                });
                let (entropy, has_base64_blocks) = Self::content_inspection(upper_path);
                changes.push(FileChange {
                    path: rel_path.to_path_buf(),
                    kind: FileChangeKind::Added,
                    size,
                    checksum,
                    old_size: None,
                    old_mode: None,
                    new_mode: None,
                    timestamp: read_mtime(upper_path),
                    target: None,
                    entropy,
                    has_base64_blocks,
                });
                continue;
            }

            // M21: Check for OverlayFS redirect xattr indicating a rename operation.
            // When OverlayFS processes a rename, it sets trusted.overlay.redirect on the
            // destination entry with the value being the original path.
            #[cfg(target_os = "linux")]
            {
                if let Some(original_path) = Self::get_overlay_redirect(upper_path) {
                    // Q11: Log metadata failures instead of silently defaulting to size 0
                    let size = upper_path.metadata().map(|m| m.len()).unwrap_or_else(|e| {
                        tracing::warn!(path = %upper_path.display(), error = %e, "Q11: metadata read failed — using size 0");
                        0
                    });
                    // R13: Log checksum failures instead of silently using empty checksum
                    let checksum = Self::checksum(upper_path).unwrap_or_else(|e| {
                    tracing::warn!(path = %upper_path.display(), error = %e, "R13: checksum computation failed — using empty checksum");
                    String::new()
                });
                    tracing::debug!(
                        new_path = %rel_path.display(),
                        original_path = %original_path,
                        "detected OverlayFS rename via redirect xattr"
                    );
                    changes.push(FileChange {
                        path: rel_path.to_path_buf(),
                        kind: FileChangeKind::Renamed,
                        size,
                        checksum,
                        old_size: None,
                        old_mode: None,
                        new_mode: None,
                        timestamp: read_mtime(upper_path),
                        target: None,
                        entropy: None,
                        has_base64_blocks: None,
                    });
                    continue;
                }
            }

            let lower_path = lower_dir.join(rel_path);

            // Don't follow symlinks in lower layer — could read outside branch
            if lower_path
                .symlink_metadata()
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
            {
                // Q11: Log metadata failures instead of silently defaulting to size 0
                let size = upper_path.metadata().map(|m| m.len()).unwrap_or_else(|e| {
                    tracing::warn!(path = %upper_path.display(), error = %e, "Q11: metadata read failed — using size 0");
                    0
                });
                // R13: Log checksum failures instead of silently using empty checksum
                let checksum = Self::checksum(upper_path).unwrap_or_else(|e| {
                    tracing::warn!(path = %upper_path.display(), error = %e, "R13: checksum computation failed — using empty checksum");
                    String::new()
                });
                let (entropy, has_base64_blocks) = Self::content_inspection(upper_path);
                changes.push(FileChange {
                    path: rel_path.to_path_buf(),
                    kind: FileChangeKind::Added,
                    size,
                    checksum,
                    old_size: None,
                    old_mode: None,
                    new_mode: None,
                    timestamp: read_mtime(upper_path),
                    target: None,
                    entropy,
                    has_base64_blocks,
                });
                continue;
            }

            match Self::classify_change(upper_path, &lower_path, lower_dir)? {
                Some(kind) => {
                    // Q11: Log metadata failures instead of silently defaulting to size 0
                    let size = upper_path.metadata().map(|m| m.len()).unwrap_or_else(|e| {
                        tracing::warn!(path = %upper_path.display(), error = %e, "Q11: metadata read failed — using size 0");
                        0
                    });
                    // R13: Log checksum failures instead of silently using empty checksum
                    let checksum = Self::checksum(upper_path).unwrap_or_else(|e| {
                    tracing::warn!(path = %upper_path.display(), error = %e, "R13: checksum computation failed — using empty checksum");
                    String::new()
                });

                    // Populate old_size and mode fields from lower/upper metadata
                    // when available (Modified/MetadataChanged cases).
                    let lower_meta = lower_path.metadata().ok();
                    let upper_meta = upper_path.metadata().ok();
                    let old_size = lower_meta.as_ref().map(|m| m.len());
                    #[cfg(unix)]
                    let (old_mode, new_mode) = {
                        use std::os::unix::fs::MetadataExt;
                        (
                            lower_meta.as_ref().map(|m| m.mode()),
                            upper_meta.as_ref().map(|m| m.mode()),
                        )
                    };
                    #[cfg(not(unix))]
                    let (old_mode, new_mode) = (None, None);

                    let (entropy, has_base64_blocks) =
                        if matches!(kind, FileChangeKind::Added | FileChangeKind::Modified) {
                            Self::content_inspection(upper_path)
                        } else {
                            (None, None)
                        };
                    changes.push(FileChange {
                        path: rel_path.to_path_buf(),
                        kind,
                        size,
                        checksum,
                        old_size,
                        old_mode,
                        new_mode,
                        timestamp: read_mtime(upper_path),
                        target: None,
                        entropy,
                        has_base64_blocks,
                    });
                }
                None => {
                    // Copy-up artifact with identical content+metadata; skip
                }
            }
        }

        // M8: Warn if diff walk may have been truncated by depth limit.
        if max_depth_seen >= MAX_DEPTH {
            tracing::warn!(
                max_depth = MAX_DEPTH,
                "M8: diff walk reached MAX_DEPTH={} — deeper changes may be missed",
                MAX_DEPTH
            );
        }

        Ok(changes)
    }

    /// Compute SHA-256 checksum for a file using streaming I/O.
    ///
    /// Uses buffered reads (8KB buffer) instead of loading the entire file into
    /// memory, preventing OOM on large files in the OverlayFS upper layer.
    /// C2: No size cap — streaming hash handles arbitrary file sizes with constant
    /// memory. For files >1GB, progress is logged every 1GB to aid debugging.
    fn checksum(path: &Path) -> Result<String> {
        use std::io::Read;

        let file = fs::File::open(path)
            .map_err(|e| PuzzledError::Diff(format!("reading {}: {}", path.display(), e)))?;
        let mut reader = std::io::BufReader::new(file);
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        let mut total_bytes: u64 = 0;
        let mut last_progress_gb: u64 = 0;
        loop {
            let n = reader
                .read(&mut buf)
                .map_err(|e| PuzzledError::Diff(format!("reading {}: {}", path.display(), e)))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            // H9: Use saturating_add to prevent overflow on extremely large files.
            total_bytes = total_bytes.saturating_add(n as u64);
            // C2: Log progress every 1GB for large files
            let current_gb = total_bytes / (1024 * 1024 * 1024);
            if current_gb > last_progress_gb {
                last_progress_gb = current_gb;
                tracing::info!(
                    path = %path.display(),
                    progress_gb = current_gb,
                    "checksum progress for large file"
                );
            }
        }
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// M21: Check for the OverlayFS redirect extended attribute on a file/directory.
    /// Returns the original path string if the xattr is present (indicating a rename).
    /// Uses `libc::lgetxattr` to avoid following symlinks.
    /// G12: Uses a retry loop to handle TOCTOU when xattr size changes between calls.
    #[cfg(target_os = "linux")]
    fn get_overlay_redirect(path: &Path) -> Option<String> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
        let c_name = CString::new(OVERLAY_REDIRECT_XATTR).ok()?;

        // G12: Retry loop to handle TOCTOU — if the xattr value grows between
        // the sizing call and the read call, we retry with a larger buffer.
        const MAX_RETRIES: usize = 3;
        for _ in 0..MAX_RETRIES {
            // First call to get the size of the xattr value
            let size = unsafe {
                libc::lgetxattr(c_path.as_ptr(), c_name.as_ptr(), std::ptr::null_mut(), 0)
            };

            if size <= 0 {
                return None;
            }

            // S47: Use try_into for safe cast from c_long to usize
            let size_usize: usize = match size.try_into() {
                Ok(s) => s,
                Err(_) => return None,
            };

            // Allocate buffer and read the value
            let mut buf = vec![0u8; size_usize];
            let result = unsafe {
                libc::lgetxattr(
                    c_path.as_ptr(),
                    c_name.as_ptr(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };

            if result <= 0 {
                return None;
            }

            let result_usize: usize = match result.try_into() {
                Ok(r) => r,
                Err(_) => return None,
            };

            // G12: If value grew between sizing call and read, retry with larger buffer
            if result_usize > size_usize {
                continue;
            }

            buf.truncate(result_usize);
            return String::from_utf8(buf).ok();
        }

        // G12: Exhausted retries — xattr keeps changing, give up
        None
    }

    /// Compute Shannon entropy and base64-block detection for a file.
    /// Returns `(None, None)` if the file cannot be read.
    fn content_inspection(path: &Path) -> (Option<f64>, Option<bool>) {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => return (None, None),
        };
        if data.is_empty() {
            return (Some(0.0), Some(false));
        }
        (Some(shannon_entropy(&data)), Some(has_base64_blocks(&data)))
    }

    /// Check if a file is an OverlayFS whiteout.
    fn is_whiteout(path: &Path) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with(".wh."))
            .unwrap_or(false)
    }

    /// Determine the kind of change for a file in the upper layer.
    ///
    /// Returns `None` if the file is a copy-up artifact (identical to lower).
    ///
    /// BC5: `lower_root` is the root of the lower (base) layer. Before following
    /// any path in the lower layer, we verify via `symlink_metadata()` that no
    /// component is a symlink escaping outside the lower root. If `canonicalize()`
    /// resolves to a path outside `lower_root`, the file is treated as Added
    /// (i.e., not present in lower layer) to prevent symlink escape attacks.
    fn classify_change(
        upper_path: &Path,
        lower_path: &Path,
        lower_root: &Path,
    ) -> Result<Option<FileChangeKind>> {
        // BC5: Check for symlink escape in lower layer path.
        // Use symlink_metadata first to detect if lower_path itself is a symlink.
        // Then canonicalize the path and verify it stays within the lower root.
        if let Ok(meta) = fs::symlink_metadata(lower_path) {
            if meta.file_type().is_symlink() {
                // Lower path is a symlink — check if target is within lower_root
                match fs::canonicalize(lower_path) {
                    Ok(canonical) => {
                        let canonical_root = fs::canonicalize(lower_root)
                            .unwrap_or_else(|_| lower_root.to_path_buf());
                        if !canonical.starts_with(&canonical_root) {
                            tracing::warn!(
                                lower_path = %lower_path.display(),
                                canonical = %canonical.display(),
                                lower_root = %canonical_root.display(),
                                "BC5: symlink in lower layer escapes branch root — treating as Added"
                            );
                            return Ok(Some(FileChangeKind::Added));
                        }
                    }
                    Err(_) => {
                        // Cannot resolve symlink — treat as not present in lower
                        return Ok(Some(FileChangeKind::Added));
                    }
                }
            }
        }

        if !lower_path.exists() {
            return Ok(Some(FileChangeKind::Added));
        }

        // BC5: Verify canonicalized lower path stays within lower root
        // (catches symlink components in parent directories)
        if let Ok(canonical) = fs::canonicalize(lower_path) {
            let canonical_root =
                fs::canonicalize(lower_root).unwrap_or_else(|_| lower_root.to_path_buf());
            if !canonical.starts_with(&canonical_root) {
                tracing::warn!(
                    lower_path = %lower_path.display(),
                    canonical = %canonical.display(),
                    lower_root = %canonical_root.display(),
                    "BC5: canonicalized lower path escapes branch root — treating as Added"
                );
                return Ok(Some(FileChangeKind::Added));
            }
        }

        let upper_checksum = Self::checksum(upper_path)?;
        let lower_checksum = Self::checksum(lower_path)?;

        if upper_checksum != lower_checksum {
            return Ok(Some(FileChangeKind::Modified));
        }

        // C2: Legacy sentinel check retained for forward-compatibility with
        // any external tools that might produce SIZE: checksums.
        if upper_checksum.starts_with("SIZE:") || lower_checksum.starts_with("SIZE:") {
            tracing::warn!(
                upper = %upper_path.display(),
                lower = %lower_path.display(),
                "size-based sentinel checksum — treating as Modified (cannot verify copy-up)"
            );
            return Ok(Some(FileChangeKind::Modified));
        }

        // Same content — check metadata (permissions, ownership)
        let upper_meta = fs::metadata(upper_path)
            .map_err(|e| PuzzledError::Diff(format!("metadata {}: {}", upper_path.display(), e)))?;
        let lower_meta = fs::metadata(lower_path)
            .map_err(|e| PuzzledError::Diff(format!("metadata {}: {}", lower_path.display(), e)))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if upper_meta.mode() != lower_meta.mode()
                || upper_meta.uid() != lower_meta.uid()
                || upper_meta.gid() != lower_meta.gid()
            {
                return Ok(Some(FileChangeKind::MetadataChanged));
            }
        }

        #[cfg(not(unix))]
        {
            // On non-unix, check readonly flag as proxy for permissions
            if upper_meta.permissions().readonly() != lower_meta.permissions().readonly() {
                return Ok(Some(FileChangeKind::MetadataChanged));
            }
        }

        // Identical content + metadata = copy-up artifact
        Ok(None)
    }

    /// M3: Verify that a cgroup is frozen by reading `cgroup.events`.
    ///
    /// The `cgroup.events` file contains key-value pairs; we look for `frozen 1`.
    /// Returns an error if the cgroup is not frozen, which would mean the agent
    /// could modify files during diff generation (TOCTOU vulnerability).
    fn verify_cgroup_frozen(cgroup_path: &Path) -> Result<()> {
        let events_path = cgroup_path.join("cgroup.events");
        let contents = fs::read_to_string(&events_path).map_err(|e| {
            PuzzledError::Diff(format!(
                "M3: cannot read cgroup.events at {}: {} — cannot verify freeze",
                events_path.display(),
                e
            ))
        })?;

        // cgroup.events format: "key value\n" per line
        let is_frozen = contents.lines().any(|line| line.trim() == "frozen 1");

        if !is_frozen {
            return Err(PuzzledError::Diff(
                "M3: cgroup is not frozen — refusing to generate diff for commit (TOCTOU protection)".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_diff_engine_default() {
        // DiffEngine implements Default
        let _engine: DiffEngine = Default::default();
    }

    #[test]
    fn test_diff_engine_new() {
        let engine = DiffEngine::new();
        // Verify it works by generating an empty diff
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();
        let changes = engine.generate(upper.path(), lower.path(), None).unwrap();
        assert!(changes.is_empty());
    }

    #[test]
    fn test_generate_empty_upper() {
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();
        let engine = DiffEngine::new();
        let changes = engine.generate(upper.path(), lower.path(), None).unwrap();
        assert!(changes.is_empty(), "empty upper should produce no changes");
    }

    #[test]
    fn test_generate_nested_added_files() {
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        // Create nested directory structure
        fs::create_dir_all(upper.path().join("a/b/c")).unwrap();
        fs::write(upper.path().join("a/b/c/deep.txt"), "deep content").unwrap();

        let engine = DiffEngine::new();
        let changes = engine.generate(upper.path(), lower.path(), None).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, FileChangeKind::Added);
        assert_eq!(changes[0].path, std::path::Path::new("a/b/c/deep.txt"));
    }

    #[test]
    fn test_checksum_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("empty.txt");
        fs::write(&file, "").unwrap();

        let checksum = DiffEngine::checksum(&file).unwrap();
        // SHA-256 of empty string
        assert_eq!(
            checksum,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_m3_freeze_guard_missing_cgroup_events() {
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();
        let cgroup = tempfile::tempdir().unwrap();
        // Don't create cgroup.events file

        let engine = DiffEngine::new();
        let result = engine.generate(upper.path(), lower.path(), Some(cgroup.path()));
        assert!(result.is_err(), "missing cgroup.events should fail");
    }

    #[test]
    fn test_is_whiteout() {
        assert!(DiffEngine::is_whiteout(Path::new("/tmp/.wh.deleted_file")));
        assert!(!DiffEngine::is_whiteout(Path::new("/tmp/normal_file")));
    }

    #[test]
    fn test_checksum() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.txt");
        fs::write(&file, "hello world").unwrap();

        let checksum = DiffEngine::checksum(&file).unwrap();
        assert!(!checksum.is_empty());
        // SHA-256 of "hello world"
        assert_eq!(
            checksum,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_generate_added_files() {
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        fs::write(upper.path().join("new_file.txt"), "new content").unwrap();

        let engine = DiffEngine::new();
        let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, FileChangeKind::Added);
        assert_eq!(changes[0].path, PathBuf::from("new_file.txt"));
    }

    #[test]
    fn test_generate_modified_files() {
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        fs::write(lower.path().join("file.txt"), "original").unwrap();
        fs::write(upper.path().join("file.txt"), "modified").unwrap();

        let engine = DiffEngine::new();
        let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, FileChangeKind::Modified);
    }

    #[test]
    fn test_generate_deleted_files() {
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        // OverlayFS represents deletion as .wh.<filename>
        fs::write(upper.path().join(".wh.removed.txt"), "").unwrap();

        let engine = DiffEngine::new();
        let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, FileChangeKind::Deleted);
        assert_eq!(changes[0].path, PathBuf::from("removed.txt"));
    }

    #[test]
    fn test_diff_symlink_target_within_boundary() {
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        // Create a symlink within the upper directory
        let target_file = upper.path().join("real_file.txt");
        fs::write(&target_file, "content").unwrap();

        #[cfg(unix)]
        {
            let link = upper.path().join("internal_link");
            std::os::unix::fs::symlink("real_file.txt", &link).unwrap();

            let engine = DiffEngine::new();
            let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

            // Should contain the real file and the symlink
            assert!(
                !changes.is_empty(),
                "should detect changes including symlink"
            );

            // H1: Symlink should be reported as Symlink (not followed)
            let link_change = changes
                .iter()
                .find(|c| c.path == std::path::Path::new("internal_link"));
            assert!(link_change.is_some(), "symlink should be in changeset");
            assert_eq!(link_change.unwrap().kind, FileChangeKind::Symlink);
        }
    }

    #[test]
    fn test_diff_symlink_target_outside_boundary_reported() {
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        #[cfg(unix)]
        {
            // Create a symlink pointing outside the upper directory
            let link = upper.path().join("escape_link");
            std::os::unix::fs::symlink("/etc/passwd", &link).unwrap();

            let engine = DiffEngine::new();
            let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

            // Symlink should be reported (WalkDir doesn't follow symlinks)
            let link_change = changes
                .iter()
                .find(|c| c.path == std::path::Path::new("escape_link"));
            assert!(
                link_change.is_some(),
                "symlink pointing outside should still be reported"
            );
            // H1: It should be Symlink (symlink itself is new), with empty checksum (not followed)
            assert_eq!(link_change.unwrap().kind, FileChangeKind::Symlink);
            assert!(
                link_change.unwrap().checksum.is_empty(),
                "symlink checksum should be empty (not followed)"
            );
        }
    }

    #[test]
    fn test_diff_streaming_checksum() {
        // C2: Verify streaming checksum produces real SHA-256 for all file sizes.
        // No size cap — streaming I/O handles arbitrary file sizes with constant memory.
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        // Create a small file — should produce real SHA-256 hash
        let file = upper.path().join("small.txt");
        fs::write(&file, "small content").unwrap();

        let engine = DiffEngine::new();
        let changes = engine.generate(upper.path(), lower.path(), None).unwrap();
        assert_eq!(changes.len(), 1);
        // Checksum should be a real SHA-256 hash (64 hex chars), not a size sentinel
        assert_eq!(
            changes[0].checksum.len(),
            64,
            "checksum should be 64-char SHA-256 hex, got: {}",
            changes[0].checksum
        );
        assert!(
            !changes[0].checksum.starts_with("SIZE:"),
            "streaming checksum should never produce size sentinels"
        );
    }

    #[test]
    fn test_generate_filters_copy_up_artifacts() {
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        // Same content in both = copy-up artifact, should be filtered
        fs::write(lower.path().join("untouched.txt"), "same").unwrap();
        fs::write(upper.path().join("untouched.txt"), "same").unwrap();

        let engine = DiffEngine::new();
        let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

        assert!(changes.is_empty());
    }

    #[test]
    fn test_m3_freeze_guard_rejects_non_frozen_cgroup() {
        // M3: When cgroup_path is provided but not frozen, generate() should fail.
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        // Create a fake cgroup directory with cgroup.events showing not frozen
        let cgroup = tempfile::tempdir().unwrap();
        fs::write(
            cgroup.path().join("cgroup.events"),
            "populated 1\nfrozen 0\n",
        )
        .unwrap();

        let engine = DiffEngine::new();
        let result = engine.generate(upper.path(), lower.path(), Some(cgroup.path()));
        assert!(
            result.is_err(),
            "should reject diff when cgroup is not frozen"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not frozen"),
            "error should mention not frozen: {}",
            err
        );
    }

    #[test]
    fn test_m3_freeze_guard_accepts_frozen_cgroup() {
        // M3: When cgroup is frozen, generate() should succeed.
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        let cgroup = tempfile::tempdir().unwrap();
        fs::write(
            cgroup.path().join("cgroup.events"),
            "populated 1\nfrozen 1\n",
        )
        .unwrap();

        fs::write(upper.path().join("new.txt"), "content").unwrap();

        let engine = DiffEngine::new();
        let result = engine.generate(upper.path(), lower.path(), Some(cgroup.path()));
        assert!(result.is_ok(), "should accept diff when cgroup is frozen");
    }

    #[test]
    fn test_m3_freeze_guard_none_skips_check() {
        // M3: When cgroup_path is None, no freeze check is performed (inspection mode).
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        fs::write(upper.path().join("new.txt"), "content").unwrap();

        let engine = DiffEngine::new();
        let result = engine.generate(upper.path(), lower.path(), None);
        assert!(result.is_ok(), "should succeed without cgroup_path");
    }

    #[cfg(unix)]
    #[test]
    fn test_m4_symlink_copy_up_filtered() {
        // M4: Identical symlinks in upper and lower should be filtered as copy-up artifacts.
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        // Create identical symlink in both layers
        std::os::unix::fs::symlink("target.txt", upper.path().join("link")).unwrap();
        std::os::unix::fs::symlink("target.txt", lower.path().join("link")).unwrap();

        let engine = DiffEngine::new();
        let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

        // Identical symlink should be filtered out
        let link_change = changes.iter().find(|c| c.path == Path::new("link"));
        assert!(
            link_change.is_none(),
            "M4: identical symlink should be filtered as copy-up artifact"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_m4_symlink_different_target_reported() {
        // M4: Symlink with different target in upper vs lower should be reported as Modified.
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        std::os::unix::fs::symlink("new_target.txt", upper.path().join("link")).unwrap();
        std::os::unix::fs::symlink("old_target.txt", lower.path().join("link")).unwrap();

        let engine = DiffEngine::new();
        let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

        let link_change = changes.iter().find(|c| c.path == Path::new("link"));
        assert!(
            link_change.is_some(),
            "M4: symlink with different target should be reported"
        );
        assert_eq!(
            link_change.unwrap().kind,
            FileChangeKind::Symlink,
            "H1: symlink with different target should be Symlink"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_m4_symlink_new_reported_as_added() {
        // M4: New symlink (not in lower) should be reported as Added.
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        std::os::unix::fs::symlink("target.txt", upper.path().join("new_link")).unwrap();

        let engine = DiffEngine::new();
        let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

        let link_change = changes.iter().find(|c| c.path == Path::new("new_link"));
        assert!(link_change.is_some(), "M4: new symlink should be reported");
        assert_eq!(
            link_change.unwrap().kind,
            FileChangeKind::Symlink,
            "H1: new symlink should be Symlink"
        );
    }

    // -----------------------------------------------------------------------
    // Additional unit tests for comprehensive diff engine coverage
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_upper_with_populated_lower() {
        // Files only in lower should NOT appear in the changeset.
        // The diff engine only walks the upper layer.
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        fs::create_dir_all(lower.path().join("subdir")).unwrap();
        fs::write(lower.path().join("base_file.txt"), "base content").unwrap();
        fs::write(lower.path().join("subdir/nested.txt"), "nested").unwrap();

        let engine = DiffEngine::new();
        let changes = engine.generate(upper.path(), lower.path(), None).unwrap();
        assert!(
            changes.is_empty(),
            "lower-only files must not appear in changeset; got {:?}",
            changes
        );
    }

    #[test]
    fn test_multiple_new_files_detected() {
        // Multiple new files in the upper layer should each be reported as Added.
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        fs::write(upper.path().join("alpha.txt"), "a").unwrap();
        fs::write(upper.path().join("beta.txt"), "b").unwrap();
        fs::write(upper.path().join("gamma.txt"), "c").unwrap();

        let engine = DiffEngine::new();
        let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

        assert_eq!(changes.len(), 3, "should detect all 3 new files");
        for change in &changes {
            assert_eq!(
                change.kind,
                FileChangeKind::Added,
                "file {:?} should be Added",
                change.path
            );
        }

        let mut names: Vec<String> = changes
            .iter()
            .map(|c| c.path.to_string_lossy().to_string())
            .collect();
        names.sort();
        assert_eq!(names, vec!["alpha.txt", "beta.txt", "gamma.txt"]);
    }

    #[test]
    fn test_modified_file_has_different_checksum_from_lower() {
        // A file present in both layers with different content should be Modified,
        // and the reported checksum should match the upper (modified) content.
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        fs::write(lower.path().join("data.txt"), "original data").unwrap();
        fs::write(upper.path().join("data.txt"), "updated data").unwrap();

        let engine = DiffEngine::new();
        let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, FileChangeKind::Modified);

        // Verify the checksum belongs to the upper file content
        let expected = DiffEngine::checksum(&upper.path().join("data.txt")).unwrap();
        assert_eq!(
            changes[0].checksum, expected,
            "reported checksum must match the upper layer file"
        );

        // Ensure it differs from the lower layer checksum
        let lower_cksum = DiffEngine::checksum(&lower.path().join("data.txt")).unwrap();
        assert_ne!(
            changes[0].checksum, lower_cksum,
            "upper checksum must differ from lower for Modified files"
        );
    }

    #[test]
    fn test_whiteout_in_subdirectory() {
        // A whiteout file inside a subdirectory should produce a Deleted entry
        // with the correct relative path (subdir/filename, not .wh.filename).
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        fs::create_dir_all(upper.path().join("subdir/deep")).unwrap();
        fs::write(upper.path().join("subdir/deep/.wh.removed.log"), "").unwrap();

        let engine = DiffEngine::new();
        let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, FileChangeKind::Deleted);
        assert_eq!(
            changes[0].path,
            PathBuf::from("subdir/deep/removed.log"),
            "deleted path should strip .wh. prefix and preserve directory"
        );
        assert_eq!(changes[0].size, 0, "deleted entries should have size 0");
        assert!(
            changes[0].checksum.is_empty(),
            "deleted entries should have empty checksum"
        );
    }

    #[test]
    fn test_copy_up_artifact_filtering_identical_content_and_metadata() {
        // When upper and lower files have identical content (same SHA-256) and
        // identical metadata, the file is a copy-up artifact and must be filtered.
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        let content = "identical content for copy-up test";
        fs::write(lower.path().join("copyup.txt"), content).unwrap();
        fs::write(upper.path().join("copyup.txt"), content).unwrap();

        // Also add a genuinely new file to confirm filtering is selective
        fs::write(upper.path().join("genuine.txt"), "new stuff").unwrap();

        let engine = DiffEngine::new();
        let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

        // Only the genuine new file should appear
        assert_eq!(changes.len(), 1, "copy-up artifact should be filtered out");
        assert_eq!(changes[0].path, PathBuf::from("genuine.txt"));
        assert_eq!(changes[0].kind, FileChangeKind::Added);
    }

    #[cfg(unix)]
    #[test]
    fn test_symlink_not_followed_during_walk() {
        // H1/M4: Symlinks in the upper layer must not be followed (follow_links=false).
        // A symlink pointing to a regular file should be reported as Symlink,
        // not as a regular Added file with the target's content.
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        // Create a real file and a symlink to it
        fs::write(upper.path().join("real.txt"), "real content").unwrap();
        std::os::unix::fs::symlink("real.txt", upper.path().join("sym.txt")).unwrap();

        let engine = DiffEngine::new();
        let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

        let sym_change = changes.iter().find(|c| c.path == Path::new("sym.txt"));
        assert!(sym_change.is_some(), "symlink should appear in changeset");
        assert_eq!(
            sym_change.unwrap().kind,
            FileChangeKind::Symlink,
            "symlink must be reported as Symlink, not Added (follow_links=false)"
        );
        assert!(
            sym_change.unwrap().checksum.is_empty(),
            "symlink checksum should be empty — content must not be read through the link"
        );
    }

    #[test]
    fn test_opaque_directory_marks_children_as_added() {
        // M3: An opaque directory marker (.wh..wh..opq) means the entire lower
        // directory is replaced. All children in the upper layer under that
        // directory must be treated as Added, even if identically-named files
        // exist in the lower layer.
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        // Lower has a file in the directory
        fs::create_dir_all(lower.path().join("replaced_dir")).unwrap();
        fs::write(
            lower.path().join("replaced_dir/existing.txt"),
            "old content",
        )
        .unwrap();

        // Upper has the opaque marker + a brand new file (not in lower)
        fs::create_dir_all(upper.path().join("replaced_dir")).unwrap();
        fs::write(upper.path().join("replaced_dir/.wh..wh..opq"), "").unwrap();
        fs::write(
            upper.path().join("replaced_dir/brand_new.txt"),
            "new content",
        )
        .unwrap();
        fs::write(
            upper.path().join("replaced_dir/another_new.txt"),
            "more content",
        )
        .unwrap();

        let engine = DiffEngine::new();
        let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

        // Both new files should be Added (opaque dir means lower is irrelevant)
        assert_eq!(
            changes.len(),
            2,
            "opaque dir: all children should be reported; got {:?}",
            changes
        );
        for change in &changes {
            assert_eq!(
                change.kind,
                FileChangeKind::Added,
                "file {:?} under opaque dir should be Added, not {:?}",
                change.path,
                change.kind
            );
        }

        let paths: Vec<String> = changes
            .iter()
            .map(|c| c.path.to_string_lossy().to_string())
            .collect();
        assert!(
            paths.contains(&"replaced_dir/brand_new.txt".to_string()),
            "brand_new.txt should be reported as Added under opaque dir"
        );
        assert!(
            paths.contains(&"replaced_dir/another_new.txt".to_string()),
            "another_new.txt should be reported as Added under opaque dir"
        );
        // The .wh..wh..opq marker itself must NOT appear in the changeset
        assert!(
            !paths.iter().any(|p| p.contains(".wh..wh..opq")),
            "opaque marker file should not appear in changeset"
        );
    }

    #[test]
    fn test_multiple_whiteouts_classified_as_deleted() {
        // Multiple whiteout files should each be classified as Deleted with
        // the correct original name (stripping .wh. prefix).
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        fs::write(upper.path().join(".wh.config.yaml"), "").unwrap();
        fs::write(upper.path().join(".wh.secrets.env"), "").unwrap();
        fs::create_dir_all(upper.path().join("logs")).unwrap();
        fs::write(upper.path().join("logs/.wh.app.log"), "").unwrap();

        let engine = DiffEngine::new();
        let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

        assert_eq!(changes.len(), 3, "should detect 3 deletions");
        for change in &changes {
            assert_eq!(
                change.kind,
                FileChangeKind::Deleted,
                "whiteout {:?} should be Deleted",
                change.path
            );
            assert_eq!(change.size, 0);
            assert!(change.checksum.is_empty());
        }

        let mut paths: Vec<String> = changes
            .iter()
            .map(|c| c.path.to_string_lossy().to_string())
            .collect();
        paths.sort();
        assert_eq!(paths, vec!["config.yaml", "logs/app.log", "secrets.env"]);
    }

    #[cfg(unix)]
    #[test]
    fn test_permission_only_change_detected_as_metadata_changed() {
        // When file content is identical (same SHA-256) but permissions differ,
        // the change should be classified as MetadataChanged.
        use std::os::unix::fs::PermissionsExt;

        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        let content = "same content for permission test";
        fs::write(lower.path().join("script.sh"), content).unwrap();
        fs::write(upper.path().join("script.sh"), content).unwrap();

        // Change permissions on the upper file (e.g., make executable)
        let perms = std::fs::Permissions::from_mode(0o755);
        fs::set_permissions(upper.path().join("script.sh"), perms).unwrap();
        let lower_perms = std::fs::Permissions::from_mode(0o644);
        fs::set_permissions(lower.path().join("script.sh"), lower_perms).unwrap();

        let engine = DiffEngine::new();
        let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

        assert_eq!(changes.len(), 1, "permission change should be detected");
        assert_eq!(changes[0].kind, FileChangeKind::MetadataChanged);
        assert_eq!(changes[0].path, PathBuf::from("script.sh"));
    }

    #[test]
    fn test_special_characters_in_paths() {
        // Paths with spaces, unicode, and other special characters should be
        // handled correctly by the diff engine.
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        // File with spaces in name
        fs::write(upper.path().join("my document.txt"), "content a").unwrap();
        // File with unicode characters
        fs::write(upper.path().join("datos_\u{00e9}l.txt"), "content b").unwrap();
        // Directory with spaces containing a file
        fs::create_dir_all(upper.path().join("path with spaces")).unwrap();
        fs::write(
            upper.path().join("path with spaces/\u{1f4c4}_notes.txt"),
            "content c",
        )
        .unwrap();

        let engine = DiffEngine::new();
        let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

        assert_eq!(
            changes.len(),
            3,
            "all files with special chars should be detected; got {:?}",
            changes
        );

        let paths: Vec<String> = changes
            .iter()
            .map(|c| c.path.to_string_lossy().to_string())
            .collect();

        assert!(
            paths.contains(&"my document.txt".to_string()),
            "file with spaces should be detected"
        );
        assert!(
            paths.contains(&"datos_\u{00e9}l.txt".to_string()),
            "file with unicode (accented e) should be detected"
        );
        assert!(
            paths.contains(&"path with spaces/\u{1f4c4}_notes.txt".to_string()),
            "file in directory with spaces + emoji should be detected"
        );

        for change in &changes {
            assert_eq!(change.kind, FileChangeKind::Added);
            assert!(!change.checksum.is_empty(), "checksum should be computed");
            assert!(change.size > 0, "size should be non-zero");
        }
    }

    // R13: Checksum failures must NOT use unwrap_or_default() which silently
    // produces empty checksums. Use unwrap_or_else with logging instead.
    #[test]
    fn test_r13_checksum_no_unwrap_or_default() {
        let source = include_str!("diff.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        for (i, line) in prod_source.lines().enumerate() {
            if line.contains("checksum(") && line.contains("unwrap_or_default()") {
                panic!(
                    "R13: diff.rs line {} uses checksum(...).unwrap_or_default() which \
                     silently produces empty checksums on failure. Use unwrap_or_else \
                     with tracing::warn! instead.\nLine: {}",
                    i + 1,
                    line.trim()
                );
            }
        }
    }

    /// S47: Ensure lgetxattr return values use try_into for safe usize casts
    /// instead of bare `as usize` which can truncate on 32-bit platforms.
    #[test]
    fn test_s47_lgetxattr_safe_cast() {
        let source = include_str!("diff.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // Find the get_overlay_redirect function
        let fn_start = prod_source
            .find("fn get_overlay_redirect")
            .expect("get_overlay_redirect function must exist");
        let fn_block = &prod_source[fn_start..];
        let fn_end = fn_block[1..]
            .find("\n    fn ")
            .or_else(|| fn_block[1..].find("\n}"))
            .map(|p| p + 1)
            .unwrap_or(fn_block.len());
        let fn_body = &fn_block[..fn_end];

        assert!(
            fn_body.contains("try_into"),
            "S47: get_overlay_redirect must use try_into() for safe \
             c_long-to-usize conversion instead of bare `as usize`"
        );
        // Ensure no bare `size as usize` or `result as usize` remains
        for (i, line) in fn_body.lines().enumerate() {
            let trimmed = line.trim();
            if (trimmed.contains("size as usize") || trimmed.contains("result as usize"))
                && !trimmed.starts_with("//")
            {
                panic!(
                    "S47: get_overlay_redirect line {} still uses bare `as usize` cast: {}",
                    i + 1,
                    trimmed
                );
            }
        }
    }

    /// G12: get_overlay_redirect must retry lgetxattr if the value size grows
    /// between the sizing call and the read call (TOCTOU mitigation).
    #[test]
    fn test_g12_lgetxattr_retries_on_size_change() {
        let source = include_str!("diff.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // Find the get_overlay_redirect function body
        let fn_start = prod_source
            .find("fn get_overlay_redirect")
            .expect("get_overlay_redirect function must exist");
        let fn_block = &prod_source[fn_start..];

        // The function must contain a loop to retry on size change
        let fn_end = fn_block
            .find("\n    /// ")
            .or_else(|| fn_block.find("\n    #["))
            .or_else(|| fn_block.find("\n    fn "))
            .unwrap_or(fn_block.len());
        let fn_body = &fn_block[..fn_end];

        assert!(
            fn_body.contains("loop"),
            "G12: get_overlay_redirect must use a retry loop to handle \
             TOCTOU when xattr size changes between the two lgetxattr calls"
        );
    }

    // ---------------------------------------------------------------
    // H9: total_bytes must use saturating_add
    // ---------------------------------------------------------------

    #[test]
    fn test_h9_total_bytes_uses_saturating_add() {
        let source = include_str!("diff.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            prod_source.contains("total_bytes = total_bytes.saturating_add("),
            "H9: total_bytes accumulation must use saturating_add to prevent \
             overflow on extremely large files"
        );
        assert!(
            !prod_source.contains("total_bytes += n as u64"),
            "H9: production code must not contain bare `total_bytes += n as u64` — \
             use saturating_add instead"
        );
    }

    /// M8: Verify diff walk tracks max_depth_seen and warns on truncation.
    #[test]
    fn test_m8_max_depth_truncation_warning() {
        let source = include_str!("diff.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // Must track depth during walk
        assert!(
            prod_source.contains("max_depth_seen"),
            "M8: generate() must track max_depth_seen during walk"
        );
        // Must log warning when MAX_DEPTH is reached
        assert!(
            prod_source.contains("diff walk reached MAX_DEPTH"),
            "M8: generate() must warn when diff walk reaches MAX_DEPTH"
        );
    }

    /// Q6/Q9: Verify that FIFO (named pipe) files are detected as FileChangeKind::Fifo.
    #[cfg(unix)]
    #[test]
    fn test_q6_fifo_detection() {
        use std::ffi::CString;

        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        // Create a FIFO in the upper layer
        let fifo_path = upper.path().join("test.fifo");
        let c_path = CString::new(fifo_path.to_str().unwrap()).unwrap();
        let ret = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
        assert_eq!(ret, 0, "mkfifo should succeed");

        let engine = DiffEngine::new();
        let changes = engine.generate(upper.path(), lower.path(), None).unwrap();
        assert_eq!(changes.len(), 1, "should detect exactly one change");
        assert_eq!(changes[0].kind, FileChangeKind::Fifo, "should detect FIFO");
        assert_eq!(changes[0].path, std::path::Path::new("test.fifo"));
    }
}
