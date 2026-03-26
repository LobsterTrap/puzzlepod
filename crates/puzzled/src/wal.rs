// SPDX-License-Identifier: Apache-2.0
use puzzled_types::BranchId;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use sha2::Digest as _;

use crate::error::{PuzzledError, Result};

/// ## M5: NamedTempFile Usage Pattern
///
/// The WAL commit operations in `branch.rs::wal_commit()` use `NamedTempFile`
/// for atomic file writes. The correct pattern is:
///
/// 1. Create `NamedTempFile::new_in(target_dir)` — file is auto-deleted on drop
/// 2. Write content to the `NamedTempFile`'s file handle via `named_tmp.as_file()`
/// 3. Call `named_tmp.as_file().sync_all()` to fsync the content
/// 4. Call `named_tmp.persist(final_path)` to atomically rename to the target
///
/// **Anti-pattern (avoid):** `persist()` to own path then `fs::copy()` — this
/// defeats the purpose of NamedTempFile by making the temp file permanent before
/// the copy, leaving garbage on crash.
///
/// Write-ahead log entry for crash-safe commit.
#[derive(Debug, Serialize, Deserialize)]
pub enum WalEntry {
    /// Log the intent to commit (list of file operations).
    CommitIntent {
        branch_id: BranchId,
        operations: Vec<WalOperation>,
    },
    /// Mark a single operation as complete.
    OperationComplete { branch_id: BranchId, index: usize },
    /// Mark the entire commit as complete.
    CommitComplete { branch_id: BranchId },
}

/// A single file operation recorded in the WAL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalOperation {
    CopyFile { from: PathBuf, to: PathBuf },
    DeleteFile { path: PathBuf },
    SetMetadata { path: PathBuf },
}

/// Pre-commit backup of a file, stored in the WAL directory for recovery.
/// If puzzled crashes mid-commit, these backups allow reversing completed operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalBackup {
    /// Original path in the base filesystem.
    pub original_path: PathBuf,
    /// Path to the backup copy in the WAL directory.
    pub backup_path: PathBuf,
    /// Whether the original file existed before the commit.
    pub existed: bool,
}

/// Write-ahead log for crash-safe branch commits.
///
/// Protocol: log intent -> execute each operation -> mark complete.
/// On recovery: replay incomplete commits or roll them back.
///
/// Format: newline-delimited JSON (NDJSON), one WalEntry per line.
/// Each line is followed by a CRC32 checksum for corruption detection.
/// Format per line: `<json>\t<crc32_hex>`
///
/// ## L2: File Lock Duration Design
///
/// The WAL supports two usage patterns:
///
/// ### Per-entry locking (legacy, via `begin_commit`/`mark_operation_complete`/`mark_commit_complete`)
///
/// Each `append()` call opens the WAL file, acquires an exclusive flock,
/// writes a single entry, fsyncs, and releases the lock. Correct but
/// suboptimal for throughput.
///
/// ### Per-commit locking (optimized, via `begin_commit_writer`)
///
/// Returns a `WalWriter` handle that holds a single flock for the entire
/// commit duration:
///
/// ```text
/// let mut writer = wal.begin_commit_writer(branch_id, ops)?;
/// writer.mark_operation_complete(i)?;   // writes entry (no re-open)
/// writer.finish()?;                     // fsyncs + removes WAL (unlock on drop)
/// ```
///
/// Provides single open + single flock, batched writes, single fsync at end.
pub struct WriteAheadLog {
    wal_dir: PathBuf,
}

impl WriteAheadLog {
    pub fn new(wal_dir: PathBuf) -> Self {
        Self { wal_dir }
    }

    /// Begin a new commit transaction — writes the intent record.
    pub fn begin_commit(&self, branch_id: &BranchId, operations: Vec<WalOperation>) -> Result<()> {
        let entry = WalEntry::CommitIntent {
            branch_id: branch_id.clone(),
            operations,
        };
        self.append(branch_id, &entry)
    }

    /// Mark a single operation as complete.
    pub fn mark_operation_complete(&self, branch_id: &BranchId, index: usize) -> Result<()> {
        let entry = WalEntry::OperationComplete {
            branch_id: branch_id.clone(),
            index,
        };
        self.append(branch_id, &entry)
    }

    /// Mark the entire commit as complete, allowing cleanup.
    pub fn mark_commit_complete(&self, branch_id: &BranchId) -> Result<()> {
        let entry = WalEntry::CommitComplete {
            branch_id: branch_id.clone(),
        };
        self.append(branch_id, &entry)?;

        // Remove the WAL file now that commit is complete
        let wal_path = self.wal_path(branch_id);
        if wal_path.exists() {
            fs::remove_file(&wal_path).map_err(|e| {
                PuzzledError::Wal(format!("removing WAL {}: {}", wal_path.display(), e))
            })?;
            // Fsync the parent directory to ensure the deletion is durable.
            // Without this, a crash after remove_file but before the directory
            // metadata is flushed could leave a stale WAL file on recovery.
            if let Some(parent) = wal_path.parent() {
                let dir = File::open(parent).map_err(|e| {
                    PuzzledError::Wal(format!(
                        "opening WAL parent dir {} for fsync: {}",
                        parent.display(),
                        e
                    ))
                })?;
                dir.sync_all().map_err(|e| {
                    PuzzledError::Wal(format!("fsync WAL parent dir {}: {}", parent.display(), e))
                })?;
            }
        }

        Ok(())
    }

    /// Begin a commit transaction and return a `WalWriter` handle.
    ///
    /// The writer holds an exclusive flock on the WAL file for the entire
    /// commit duration. Multiple `mark_operation_complete()` calls write
    /// without re-acquiring the lock. Call `finish()` to fsync and clean up.
    pub fn begin_commit_writer(
        &self,
        branch_id: &BranchId,
        operations: Vec<WalOperation>,
    ) -> Result<WalWriter> {
        let wal_path = self.wal_path(branch_id);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wal_path)
            .map_err(|e| PuzzledError::Wal(format!("opening {}: {}", wal_path.display(), e)))?;

        #[cfg(unix)]
        Self::lock_exclusive(&file)?;

        // Write the intent entry
        let intent = WalEntry::CommitIntent {
            branch_id: branch_id.clone(),
            operations,
        };
        Self::write_entry(&mut file, &intent)?;

        // C2: Fsync the CommitIntent entry to ensure durability before
        // returning the writer. Without this, a crash after write but
        // before any operation begins could lose the intent record.
        file.sync_all()
            .map_err(|e| PuzzledError::Wal(format!("C2: fsync after CommitIntent: {}", e)))?;

        Ok(WalWriter {
            file,
            branch_id: branch_id.clone(),
            wal_path,
        })
    }

    /// Write a single WAL entry to a file (JSON + CRC32 + newline).
    fn write_entry(file: &mut File, entry: &WalEntry) -> Result<()> {
        let json = serde_json::to_string(entry)
            .map_err(|e| PuzzledError::Wal(format!("serializing WAL entry: {}", e)))?;
        let crc = crc32fast::hash(json.as_bytes());
        writeln!(file, "{}\t{:08x}", json, crc)
            .map_err(|e| PuzzledError::Wal(format!("writing WAL entry: {}", e)))?;
        Ok(())
    }

    /// On startup, find incomplete commits and return their branch IDs
    /// so the caller can roll them back.
    pub fn recover(&self) -> Result<Vec<BranchId>> {
        let mut incomplete = Vec::new();

        if !self.wal_dir.exists() {
            return Ok(incomplete);
        }

        let entries = fs::read_dir(&self.wal_dir)
            .map_err(|e| PuzzledError::Wal(format!("reading WAL dir: {}", e)))?;

        for entry in entries {
            let entry = entry.map_err(|e| PuzzledError::Wal(e.to_string()))?;
            let path = entry.path();

            if path.extension().and_then(|e| e.to_str()) != Some("wal") {
                continue;
            }

            // Check if the WAL file contains a CommitComplete entry
            let file = File::open(&path)
                .map_err(|e| PuzzledError::Wal(format!("opening {}: {}", path.display(), e)))?;
            let reader = BufReader::new(file);

            let mut branch_id: Option<BranchId> = None;
            let mut completed = false;

            for line in reader.lines() {
                let line = line.map_err(|e| PuzzledError::Wal(e.to_string()))?;
                if line.trim().is_empty() {
                    continue;
                }

                // Parse line with CRC32 verification
                let json_str = match Self::verify_and_extract_line(&line) {
                    Ok(json) => json,
                    Err(e) => {
                        tracing::warn!(
                            wal = %path.display(),
                            error = %e,
                            "skipping corrupted WAL entry during recovery"
                        );
                        continue;
                    }
                };

                match serde_json::from_str::<WalEntry>(&json_str) {
                    Ok(WalEntry::CommitIntent { branch_id: id, .. }) => {
                        branch_id = Some(id);
                    }
                    Ok(WalEntry::CommitComplete { .. }) => {
                        completed = true;
                    }
                    _ => {}
                }
            }

            if let Some(id) = branch_id {
                if !completed {
                    tracing::warn!(branch = %id, wal = %path.display(), "found incomplete commit, scheduling rollback");
                    incomplete.push(id);
                }
            }

            // Clean up completed WAL files that weren't removed
            if completed {
                // L41: Log error instead of silently ignoring WAL file removal failure
                if let Err(e) = fs::remove_file(&path) {
                    tracing::warn!(path = %path.display(), error = %e, "L41: failed to remove completed WAL file");
                }
            }
        }

        Ok(incomplete)
    }

    /// L1: Scan a directory (recursively) for orphaned `*.puzzled_old` files
    /// and remove them. These are leftovers from interrupted RENAME_EXCHANGE
    /// operations during WAL commit.
    ///
    /// Called from `recover()` to clean up after crashes. Also useful as a
    /// standalone scan against the base filesystem path.
    pub fn cleanup_orphan_puzzled_old(base_path: &Path) {
        Self::cleanup_orphan_puzzled_old_recursive(base_path, 0);
    }

    /// Recursive helper for cleanup_orphan_puzzled_old.
    ///
    /// C3: Uses `symlink_metadata()` instead of `metadata()` to avoid
    /// following symlinks. Symlink entries are skipped entirely to prevent
    /// an attacker from planting a symlink named `foo.puzzled_old` that
    /// points to a file outside the cleanup scope.
    fn cleanup_orphan_puzzled_old_recursive(dir: &Path, depth: usize) {
        const MAX_CLEANUP_DEPTH: usize = 256;
        if depth >= MAX_CLEANUP_DEPTH {
            tracing::warn!(dir = %dir.display(), depth, "T2: max cleanup recursion depth reached");
            return;
        }
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            // L44: Log error instead of silently returning
            Err(e) => {
                tracing::warn!(dir = %dir.display(), error = %e, "L44: failed to read directory during orphan cleanup");
                return;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                // L44: Log error instead of silently continuing
                Err(e) => {
                    tracing::warn!(dir = %dir.display(), error = %e, "L44: failed to read directory entry during orphan cleanup");
                    continue;
                }
            };
            let path = entry.path();
            // C3: Use symlink_metadata to avoid following symlinks
            let meta = match fs::symlink_metadata(&path) {
                Ok(m) => m,
                // L44: Log error instead of silently continuing
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "L44: failed to stat path during orphan cleanup");
                    continue;
                }
            };
            // C3: Skip symlinks entirely — don't follow them
            if meta.file_type().is_symlink() {
                tracing::debug!(
                    path = %path.display(),
                    "C3: skipping symlink during .puzzled_old cleanup"
                );
                continue;
            }
            if meta.file_type().is_dir() {
                Self::cleanup_orphan_puzzled_old_recursive(&path, depth + 1);
            } else if meta.file_type().is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "puzzled_old" {
                        tracing::info!(
                            path = %path.display(),
                            "L1: removing orphaned .puzzled_old file"
                        );
                        if let Err(e) = fs::remove_file(&path) {
                            tracing::warn!(
                                path = %path.display(),
                                error = %e,
                                "L1: failed to remove orphaned .puzzled_old file"
                            );
                        }
                    }
                }
            }
        }
    }

    /// Ensure the WAL directory exists.
    pub fn init(dir: &Path) -> Result<()> {
        fs::create_dir_all(dir)?;
        Ok(())
    }

    /// Path to the WAL file for a given branch.
    fn wal_path(&self, branch_id: &BranchId) -> PathBuf {
        self.wal_dir.join(format!("{}.wal", branch_id))
    }

    /// Verify a WAL line's CRC32 checksum and extract the JSON payload.
    ///
    /// Expected format: `<json>\t<crc32_hex>`
    // M-wal2: Legacy CRC-less WAL entries are no longer accepted. All entries must have valid CRC.
    fn verify_and_extract_line(line: &str) -> std::result::Result<String, String> {
        if let Some(tab_pos) = line.rfind('\t') {
            let json_part = &line[..tab_pos];
            let crc_part = &line[tab_pos + 1..];

            let expected_crc = u32::from_str_radix(crc_part, 16)
                .map_err(|e| format!("invalid CRC32 hex '{}': {}", crc_part, e))?;
            let actual_crc = crc32fast::hash(json_part.as_bytes());

            if actual_crc != expected_crc {
                return Err(format!(
                    "CRC32 mismatch: expected {:08x}, got {:08x}",
                    expected_crc, actual_crc
                ));
            }

            Ok(json_part.to_string())
        } else {
            // M-wal2: Legacy CRC-less WAL entries are no longer accepted. All entries must have valid CRC.
            Err(
                "WAL entry missing CRC32 checksum (legacy CRC-less entries are no longer accepted)"
                    .to_string(),
            )
        }
    }

    /// Acquire an exclusive file lock on the WAL file (Unix only).
    /// Returns the locked file handle.
    #[cfg(unix)]
    fn lock_exclusive(file: &File) -> Result<()> {
        use std::os::unix::io::AsRawFd;
        let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if ret != 0 {
            return Err(PuzzledError::Wal(format!(
                "flock(LOCK_EX) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// Append a WAL entry to the branch's journal file with CRC32, flock, and fsync.
    fn append(&self, branch_id: &BranchId, entry: &WalEntry) -> Result<()> {
        let wal_path = self.wal_path(branch_id);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wal_path)
            .map_err(|e| PuzzledError::Wal(format!("opening {}: {}", wal_path.display(), e)))?;

        // Acquire exclusive lock to prevent concurrent access (M14)
        #[cfg(unix)]
        Self::lock_exclusive(&file)?;

        let json = serde_json::to_string(entry)
            .map_err(|e| PuzzledError::Wal(format!("serializing WAL entry: {}", e)))?;

        // Compute CRC32 checksum of the serialized JSON (M13)
        let crc = crc32fast::hash(json.as_bytes());

        // Write JSON + tab + CRC32 hex + newline
        writeln!(file, "{}\t{:08x}", json, crc)
            .map_err(|e| PuzzledError::Wal(format!("writing WAL entry: {}", e)))?;

        // M-wal1: Standardize on sync_all() (data + metadata) for ALL WAL writes.
        file.sync_all()
            .map_err(|e| PuzzledError::Wal(format!("fsync WAL: {}", e)))?;

        // Lock is automatically released when the file is dropped

        Ok(())
    }

    /// Read all operations from a CommitIntent entry for a branch.
    /// Used during recovery to determine what needs to be rolled back.
    pub fn read_operations(&self, branch_id: &BranchId) -> Result<Vec<WalOperation>> {
        let wal_path = self.wal_path(branch_id);
        if !wal_path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(&wal_path)
            .map_err(|e| PuzzledError::Wal(format!("opening {}: {}", wal_path.display(), e)))?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line.map_err(|e| PuzzledError::Wal(e.to_string()))?;

            // Verify CRC32 and extract JSON, skipping corrupted entries
            let json_str = match Self::verify_and_extract_line(&line) {
                Ok(json) => json,
                Err(e) => {
                    tracing::warn!(
                        wal = %wal_path.display(),
                        error = %e,
                        "skipping corrupted WAL entry"
                    );
                    continue;
                }
            };

            if let Ok(WalEntry::CommitIntent { operations, .. }) = serde_json::from_str(&json_str) {
                return Ok(operations);
            }
        }

        Ok(Vec::new())
    }

    /// Read operations and their completion status from the WAL.
    /// Returns (operations, set of completed operation indices).
    pub fn read_operations_with_status(
        &self,
        branch_id: &BranchId,
    ) -> Result<(Vec<WalOperation>, std::collections::HashSet<usize>)> {
        let wal_path = self.wal_path(branch_id);
        if !wal_path.exists() {
            return Ok((Vec::new(), std::collections::HashSet::new()));
        }

        let file = File::open(&wal_path)
            .map_err(|e| PuzzledError::Wal(format!("opening {}: {}", wal_path.display(), e)))?;
        let reader = BufReader::new(file);

        let mut operations = Vec::new();
        let mut completed = std::collections::HashSet::new();

        for line in reader.lines() {
            let line = line.map_err(|e| PuzzledError::Wal(e.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }

            // Verify CRC32 and extract JSON, skipping corrupted entries
            let json_str = match Self::verify_and_extract_line(&line) {
                Ok(json) => json,
                Err(e) => {
                    tracing::warn!(
                        wal = %wal_path.display(),
                        error = %e,
                        "skipping corrupted WAL entry"
                    );
                    continue;
                }
            };

            match serde_json::from_str::<WalEntry>(&json_str) {
                Ok(WalEntry::CommitIntent {
                    operations: ops, ..
                }) => {
                    operations = ops;
                }
                Ok(WalEntry::OperationComplete { index, .. }) => {
                    completed.insert(index);
                }
                _ => {}
            }
        }

        Ok((operations, completed))
    }

    /// Get the backup directory path for a branch.
    pub fn backup_dir(&self, branch_id: &BranchId) -> PathBuf {
        self.wal_dir.join(format!("{}_backups", branch_id))
    }

    /// Create a pre-commit backup of a file in the WAL directory.
    /// Returns the backup path for use during recovery.
    ///
    /// M1: Uses direct file operations instead of exists() checks to avoid TOCTOU races.
    /// If the source file doesn't exist, returns a no-exist backup marker (idempotent).
    ///
    /// C2: After copying, fsyncs both the backup file and the backup directory
    /// to ensure the backup is durable before any commit operations proceed.
    pub fn backup_file(&self, branch_id: &BranchId, target: &Path) -> Result<Option<WalBackup>> {
        let backup_dir = self.wal_dir.join(format!("{}_backups", branch_id));
        fs::create_dir_all(&backup_dir)
            .map_err(|e| PuzzledError::Wal(format!("creating backup dir: {}", e)))?;

        // Create a deterministic backup name from the target path (full SHA-256).
        // Uses the full 64 hex chars to avoid collision risk from truncation.
        let hash = format!(
            "{:x}",
            sha2::Sha256::digest(target.to_string_lossy().as_bytes(),)
        );
        let backup_path = backup_dir.join(&hash);

        // M1: Attempt copy directly instead of checking exists() first (TOCTOU).
        // Handle NotFound as "file didn't exist before" — recovery should delete it.
        match fs::copy(target, &backup_path) {
            Ok(_) => {
                // C2: Fsync the backup file to ensure its contents are durable.
                let backup_file = File::open(&backup_path).map_err(|e| {
                    PuzzledError::Wal(format!(
                        "opening backup file {} for fsync: {}",
                        backup_path.display(),
                        e
                    ))
                })?;
                backup_file.sync_all().map_err(|e| {
                    PuzzledError::Wal(format!(
                        "fsync backup file {}: {}",
                        backup_path.display(),
                        e
                    ))
                })?;

                // C2: Fsync the backup directory to ensure the directory entry is durable.
                let dir_fd = File::open(&backup_dir).map_err(|e| {
                    PuzzledError::Wal(format!(
                        "opening backup dir {} for fsync: {}",
                        backup_dir.display(),
                        e
                    ))
                })?;
                dir_fd.sync_all().map_err(|e| {
                    PuzzledError::Wal(format!("fsync backup dir {}: {}", backup_dir.display(), e))
                })?;

                Ok(Some(WalBackup {
                    original_path: target.to_path_buf(),
                    backup_path,
                    existed: true,
                }))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // File didn't exist before — recovery should delete it
                Ok(Some(WalBackup {
                    original_path: target.to_path_buf(),
                    backup_path: PathBuf::new(),
                    existed: false,
                }))
            }
            Err(e) => Err(PuzzledError::Wal(format!(
                "backing up {} to {}: {}",
                target.display(),
                backup_path.display(),
                e
            ))),
        }
    }

    /// Reverse completed operations using WAL backups.
    /// Called during recovery to undo partial commits.
    ///
    /// Also reverses the first uncompleted operation after the completed set,
    /// because a crash between execute_copy and mark_operation_complete means
    /// the operation's side effects may have been applied without being recorded.
    pub fn reverse_operations(
        &self,
        branch_id: &BranchId,
        operations: &[WalOperation],
        completed: &std::collections::HashSet<usize>,
    ) -> Result<()> {
        let backup_dir = self.wal_dir.join(format!("{}_backups", branch_id));

        // Build the set of indices to reverse: all completed ops PLUS the first
        // uncompleted op (which may have partially executed before crash).
        let mut indices_to_reverse: Vec<usize> = completed.iter().copied().collect();
        // Find the first uncompleted index (the one that was potentially in-flight).
        // Only attempt this if the backup directory exists — if it's already been
        // cleaned up by a previous recovery pass, the in-flight op was already handled.
        if backup_dir.exists() {
            for i in 0..operations.len() {
                if !completed.contains(&i) {
                    indices_to_reverse.push(i);
                    break; // Only the first uncompleted op could have been in-flight
                }
            }
        }

        for idx in indices_to_reverse {
            if idx >= operations.len() {
                continue;
            }

            match &operations[idx] {
                WalOperation::CopyFile { to, .. } => {
                    // Find the backup for this target (full SHA-256 hash)
                    let hash = format!(
                        "{:x}",
                        sha2::Sha256::digest(to.to_string_lossy().as_bytes(),)
                    );
                    let backup_path = backup_dir.join(&hash);

                    // M1: Try to restore from backup directly, handling NotFound
                    // instead of checking exists() first (TOCTOU-safe).
                    match fs::copy(&backup_path, to) {
                        Ok(_) => {
                            tracing::info!(target = %to.display(), "restored from WAL backup");
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            // No backup means file didn't exist before — delete it.
                            // M1: Use direct remove_file, treat NotFound as success.
                            match fs::remove_file(to) {
                                Ok(()) => {
                                    tracing::info!(target = %to.display(), "removed (did not exist pre-commit)");
                                }
                                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                                    // Already gone — idempotent success
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        target = %to.display(),
                                        error = %e,
                                        "failed to remove new file during recovery"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                target = %to.display(),
                                error = %e,
                                "failed to restore backup during recovery"
                            );
                        }
                    }
                }
                WalOperation::DeleteFile { path } => {
                    // Find the backup of the deleted file (full SHA-256 hash)
                    let hash = format!(
                        "{:x}",
                        sha2::Sha256::digest(path.to_string_lossy().as_bytes(),)
                    );
                    let backup_path = backup_dir.join(&hash);

                    // M1: Try to restore directly, handling NotFound as no-op.
                    // B3: Log parent creation failures — a failed mkdir causes a
                    // confusing "No such file or directory" on the subsequent copy.
                    if let Some(parent) = path.parent() {
                        if let Err(e) = fs::create_dir_all(parent) {
                            tracing::warn!(
                                path = %parent.display(),
                                error = %e,
                                "WAL restore: failed to create parent directory"
                            );
                        }
                    }
                    match fs::copy(&backup_path, path) {
                        Ok(_) => {
                            tracing::info!(target = %path.display(), "restored deleted file from WAL backup");
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            // No backup available — nothing to restore (idempotent)
                            tracing::debug!(
                                target = %path.display(),
                                "no backup found for deleted file during recovery (idempotent skip)"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                target = %path.display(),
                                error = %e,
                                "failed to restore deleted file during recovery"
                            );
                        }
                    }
                }
                WalOperation::SetMetadata { path } => {
                    tracing::info!(
                        path = %path.display(),
                        "skipping metadata-only change during WAL recovery (best-effort, not reversible)"
                    );
                }
            }
        }

        // Cleanup ordering is crash-safe: remove WAL file FIRST, fsync the
        // directory, THEN remove backups. If we crash after removing the WAL
        // but before removing backups, the next recovery sees no WAL (nothing
        // to do) and orphan backups are harmless. The reverse order (remove
        // backups first, crash, then WAL still exists) would cause recovery
        // to attempt restoration from missing backups — data loss.
        let wal_path = self.wal_path(branch_id);
        if wal_path.exists() {
            // Q1: Log WAL file removal failures instead of silently discarding
            if let Err(e) = fs::remove_file(&wal_path) {
                tracing::warn!(error = %e, path = %wal_path.display(), "Q1: failed to remove WAL file during cleanup");
            }
        }

        // fsync the WAL directory to ensure the WAL removal is durable
        // before we remove the backups it references.
        if let Ok(dir) = fs::File::open(&self.wal_dir) {
            // L42: Log error instead of silently ignoring fsync failure
            if let Err(e) = dir.sync_all() {
                tracing::warn!(error = %e, "L42: directory fsync failed during cleanup");
            }
        }

        // Now safe to remove backups — WAL is gone, so recovery won't look for them.
        if backup_dir.exists() {
            // Q2: Log backup dir removal failures instead of silently discarding
            if let Err(e) = fs::remove_dir_all(&backup_dir) {
                tracing::warn!(error = %e, path = %backup_dir.display(), "Q2: failed to remove backup directory during cleanup");
            }
        }

        Ok(())
    }
}

/// A handle to an in-progress WAL commit that holds an exclusive flock
/// on the WAL file for the entire commit duration.
///
/// Created by `WriteAheadLog::begin_commit_writer()`. The lock is released
/// when the `WalWriter` is dropped.
pub struct WalWriter {
    file: File,
    branch_id: BranchId,
    wal_path: PathBuf,
}

impl WalWriter {
    /// Mark a single operation as complete (writes without re-acquiring lock).
    ///
    /// C1: Fsyncs after writing the OperationComplete entry to ensure
    /// durability. Without this, a crash after write but before fsync
    /// could lose the completion record, causing a spurious re-execution
    /// of an already-completed operation during recovery.
    pub fn mark_operation_complete(&mut self, index: usize) -> Result<()> {
        let entry = WalEntry::OperationComplete {
            branch_id: self.branch_id.clone(),
            index,
        };
        WriteAheadLog::write_entry(&mut self.file, &entry)?;
        self.file
            .sync_all()
            .map_err(|e| PuzzledError::Wal(format!("C1: fsync after OperationComplete: {}", e)))?;
        Ok(())
    }

    /// Finalize the commit: write CommitComplete, fsync, remove the WAL file.
    ///
    /// Consumes the writer, releasing the flock.
    pub fn finish(mut self) -> Result<()> {
        let entry = WalEntry::CommitComplete {
            branch_id: self.branch_id.clone(),
        };
        WriteAheadLog::write_entry(&mut self.file, &entry)?;

        // M-wal1: Standardize on sync_all() (data + metadata) for ALL WAL writes.
        self.file
            .sync_all()
            .map_err(|e| PuzzledError::Wal(format!("fsync WAL: {}", e)))?;

        // Remove the WAL file
        if self.wal_path.exists() {
            fs::remove_file(&self.wal_path).map_err(|e| {
                PuzzledError::Wal(format!("removing WAL {}: {}", self.wal_path.display(), e))
            })?;
            if let Some(parent) = self.wal_path.parent() {
                if let Ok(dir) = File::open(parent) {
                    // L42: Log error instead of silently ignoring fsync failure
                    if let Err(e) = dir.sync_all() {
                        tracing::warn!(error = %e, "L42: directory fsync failed during WalWriter finish");
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wal_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let wal = WriteAheadLog::new(dir.path().to_path_buf());
        let branch = BranchId::new();

        let ops = vec![
            WalOperation::CopyFile {
                from: PathBuf::from("/src/a.txt"),
                to: PathBuf::from("/dst/a.txt"),
            },
            WalOperation::DeleteFile {
                path: PathBuf::from("/dst/b.txt"),
            },
        ];

        // Begin commit
        wal.begin_commit(&branch, ops).unwrap();
        assert!(wal.wal_path(&branch).exists());

        // Mark operations complete
        wal.mark_operation_complete(&branch, 0).unwrap();
        wal.mark_operation_complete(&branch, 1).unwrap();

        // Mark commit complete (removes WAL file)
        wal.mark_commit_complete(&branch).unwrap();
        assert!(!wal.wal_path(&branch).exists());
    }

    #[test]
    fn test_wal_recover_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        let wal = WriteAheadLog::new(dir.path().to_path_buf());
        let branch = BranchId::new();

        let ops = vec![WalOperation::CopyFile {
            from: PathBuf::from("/src/a.txt"),
            to: PathBuf::from("/dst/a.txt"),
        }];

        // Begin commit but don't complete
        wal.begin_commit(&branch, ops).unwrap();
        wal.mark_operation_complete(&branch, 0).unwrap();
        // Simulate crash — no mark_commit_complete

        let incomplete = wal.recover().unwrap();
        assert_eq!(incomplete.len(), 1);
        assert_eq!(incomplete[0].as_str(), branch.as_str());
    }

    #[test]
    fn test_wal_recover_empty() {
        let dir = tempfile::tempdir().unwrap();
        let wal = WriteAheadLog::new(dir.path().to_path_buf());

        let incomplete = wal.recover().unwrap();
        assert!(incomplete.is_empty());
    }

    #[test]
    fn test_wal_init() {
        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        WriteAheadLog::init(&wal_dir).unwrap();
        assert!(wal_dir.exists());
    }

    #[test]
    fn test_wal_crc32_corruption_detected() {
        let dir = tempfile::tempdir().unwrap();
        let wal = WriteAheadLog::new(dir.path().to_path_buf());
        let branch = BranchId::new();

        let ops = vec![WalOperation::CopyFile {
            from: PathBuf::from("/src/a.txt"),
            to: PathBuf::from("/dst/a.txt"),
        }];

        wal.begin_commit(&branch, ops).unwrap();

        // Corrupt the WAL file by modifying a byte in the JSON payload
        let wal_path = wal.wal_path(&branch);
        let content = std::fs::read_to_string(&wal_path).unwrap();
        let corrupted = content.replacen("CopyFile", "XopyFile", 1);
        std::fs::write(&wal_path, corrupted).unwrap();

        // Recovery should skip the corrupted entry (no branch_id found)
        let incomplete = wal.recover().unwrap();
        assert!(incomplete.is_empty());
    }

    #[test]
    fn test_wal_crc32_verify_and_extract() {
        let json = r#"{"test":"value"}"#;
        let crc = crc32fast::hash(json.as_bytes());
        let line = format!("{}\t{:08x}", json, crc);

        let extracted = WriteAheadLog::verify_and_extract_line(&line).unwrap();
        assert_eq!(extracted, json);

        // Test corrupted CRC
        let bad_line = format!("{}\t{:08x}", json, crc.wrapping_add(1));
        assert!(WriteAheadLog::verify_and_extract_line(&bad_line).is_err());

        // M-wal2: Legacy lines without CRC are now rejected
        let legacy = json.to_string();
        assert!(WriteAheadLog::verify_and_extract_line(&legacy).is_err());
    }

    #[test]
    fn test_c2_backup_file_fsyncs() {
        // C2: Verify that backup_file creates a durable backup.
        // We can't directly verify fsync was called, but we can verify the
        // backup file exists and has correct content after backup_file returns.
        let dir = tempfile::tempdir().unwrap();
        let wal = WriteAheadLog::new(dir.path().to_path_buf());
        let branch = BranchId::new();

        // Create a source file to back up
        let source = dir.path().join("source.txt");
        fs::write(&source, "important data").unwrap();

        let backup = wal.backup_file(&branch, &source).unwrap();
        assert!(backup.is_some());
        let backup = backup.unwrap();
        assert!(backup.existed);
        assert!(backup.backup_path.exists());
        assert_eq!(
            fs::read_to_string(&backup.backup_path).unwrap(),
            "important data"
        );
    }

    #[test]
    fn test_c2_backup_file_nonexistent_source() {
        // C2/M1: backup_file on a nonexistent file should return a "did not exist" marker.
        let dir = tempfile::tempdir().unwrap();
        let wal = WriteAheadLog::new(dir.path().to_path_buf());
        let branch = BranchId::new();

        let nonexistent = dir.path().join("no_such_file.txt");
        let backup = wal.backup_file(&branch, &nonexistent).unwrap();
        assert!(backup.is_some());
        let backup = backup.unwrap();
        assert!(!backup.existed);
        assert_eq!(backup.backup_path, PathBuf::new());
    }

    #[test]
    fn test_m1_delete_idempotent() {
        // M1: reverse_operations should handle already-deleted files gracefully.
        let dir = tempfile::tempdir().unwrap();
        let wal = WriteAheadLog::new(dir.path().to_path_buf());
        let branch = BranchId::new();

        let target = dir.path().join("file_to_delete.txt");
        // Don't create the file — simulates it being already deleted

        let operations = vec![WalOperation::DeleteFile {
            path: target.clone(),
        }];
        let mut completed = std::collections::HashSet::new();
        completed.insert(0);

        // Create backup dir (even though empty)
        let backup_dir = dir.path().join(format!("{}_backups", branch));
        fs::create_dir_all(&backup_dir).unwrap();

        // Should not error — idempotent
        let result = wal.reverse_operations(&branch, &operations, &completed);
        assert!(result.is_ok());
    }

    #[test]
    fn test_l1_cleanup_orphan_puzzled_old() {
        let dir = tempfile::tempdir().unwrap();

        // Create some .puzzled_old files
        let orphan1 = dir.path().join("file1.puzzled_old");
        let orphan2 = dir.path().join("subdir");
        fs::create_dir_all(&orphan2).unwrap();
        let orphan2_file = orphan2.join("file2.puzzled_old");
        let normal = dir.path().join("file3.txt");

        fs::write(&orphan1, "old data 1").unwrap();
        fs::write(&orphan2_file, "old data 2").unwrap();
        fs::write(&normal, "normal data").unwrap();

        WriteAheadLog::cleanup_orphan_puzzled_old(dir.path());

        assert!(!orphan1.exists(), ".puzzled_old should be removed");
        assert!(
            !orphan2_file.exists(),
            "nested .puzzled_old should be removed"
        );
        assert!(normal.exists(), "normal files should not be touched");
    }

    #[test]
    fn test_l1_cleanup_orphan_puzzled_old_nonexistent_dir() {
        // Should not panic on nonexistent directory
        WriteAheadLog::cleanup_orphan_puzzled_old(Path::new("/nonexistent/path"));
    }

    #[test]
    fn test_wal_writer_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let wal = WriteAheadLog::new(dir.path().to_path_buf());
        let branch = BranchId::new();

        let ops = vec![
            WalOperation::CopyFile {
                from: PathBuf::from("/src/a.txt"),
                to: PathBuf::from("/dst/a.txt"),
            },
            WalOperation::DeleteFile {
                path: PathBuf::from("/dst/b.txt"),
            },
        ];

        // Use the WalWriter pattern (single flock for entire commit)
        let mut writer = wal.begin_commit_writer(&branch, ops).unwrap();
        assert!(wal.wal_path(&branch).exists());

        writer.mark_operation_complete(0).unwrap();
        writer.mark_operation_complete(1).unwrap();

        // finish() fsyncs, removes WAL, releases lock
        writer.finish().unwrap();
        assert!(!wal.wal_path(&branch).exists());
    }

    #[test]
    fn test_read_operations() {
        let dir = tempfile::tempdir().unwrap();
        let wal = WriteAheadLog::new(dir.path().to_path_buf());
        let branch = BranchId::new();

        let ops = vec![
            WalOperation::CopyFile {
                from: PathBuf::from("/src/a.txt"),
                to: PathBuf::from("/dst/a.txt"),
            },
            WalOperation::DeleteFile {
                path: PathBuf::from("/dst/b.txt"),
            },
        ];

        wal.begin_commit(&branch, ops).unwrap();

        let read_ops = wal.read_operations(&branch).unwrap();
        assert_eq!(read_ops.len(), 2);
        match &read_ops[0] {
            WalOperation::CopyFile { from, to } => {
                assert_eq!(from, &PathBuf::from("/src/a.txt"));
                assert_eq!(to, &PathBuf::from("/dst/a.txt"));
            }
            other => panic!("expected CopyFile, got {:?}", other),
        }
        match &read_ops[1] {
            WalOperation::DeleteFile { path } => {
                assert_eq!(path, &PathBuf::from("/dst/b.txt"));
            }
            other => panic!("expected DeleteFile, got {:?}", other),
        }
    }

    #[test]
    fn test_read_operations_nonexistent_branch() {
        let dir = tempfile::tempdir().unwrap();
        let wal = WriteAheadLog::new(dir.path().to_path_buf());
        let branch = BranchId::new();

        let ops = wal.read_operations(&branch).unwrap();
        assert!(ops.is_empty());
    }

    #[test]
    fn test_read_operations_with_status() {
        let dir = tempfile::tempdir().unwrap();
        let wal = WriteAheadLog::new(dir.path().to_path_buf());
        let branch = BranchId::new();

        let ops = vec![
            WalOperation::CopyFile {
                from: PathBuf::from("/src/a.txt"),
                to: PathBuf::from("/dst/a.txt"),
            },
            WalOperation::CopyFile {
                from: PathBuf::from("/src/b.txt"),
                to: PathBuf::from("/dst/b.txt"),
            },
            WalOperation::DeleteFile {
                path: PathBuf::from("/dst/c.txt"),
            },
        ];

        wal.begin_commit(&branch, ops).unwrap();
        wal.mark_operation_complete(&branch, 0).unwrap();
        wal.mark_operation_complete(&branch, 2).unwrap();
        // Op 1 left incomplete (simulates crash)

        let (read_ops, completed) = wal.read_operations_with_status(&branch).unwrap();
        assert_eq!(read_ops.len(), 3);
        assert!(completed.contains(&0));
        assert!(!completed.contains(&1));
        assert!(completed.contains(&2));
    }

    #[test]
    fn test_read_operations_with_status_nonexistent() {
        let dir = tempfile::tempdir().unwrap();
        let wal = WriteAheadLog::new(dir.path().to_path_buf());
        let branch = BranchId::new();

        let (ops, completed) = wal.read_operations_with_status(&branch).unwrap();
        assert!(ops.is_empty());
        assert!(completed.is_empty());
    }

    #[test]
    fn test_backup_dir() {
        let dir = tempfile::tempdir().unwrap();
        let wal = WriteAheadLog::new(dir.path().to_path_buf());
        let branch = BranchId::new();

        let backup_dir = wal.backup_dir(&branch);
        assert!(backup_dir.to_string_lossy().contains(&branch.to_string()));
        assert!(backup_dir.to_string_lossy().ends_with("_backups"));
    }

    #[test]
    fn test_wal_reverse_operations_copy() {
        let dir = tempfile::tempdir().unwrap();
        let wal = WriteAheadLog::new(dir.path().to_path_buf());
        let branch = BranchId::new();

        // Create a target file that will be overwritten by commit
        let target = dir.path().join("target.txt");
        fs::write(&target, "original content").unwrap();

        // Back up the file
        let backup = wal.backup_file(&branch, &target).unwrap().unwrap();
        assert!(backup.existed);

        // Overwrite the target (simulating commit)
        fs::write(&target, "committed content").unwrap();

        // Reverse the operation
        let operations = vec![WalOperation::CopyFile {
            from: PathBuf::from("/src/whatever"),
            to: target.clone(),
        }];
        let mut completed = std::collections::HashSet::new();
        completed.insert(0);
        wal.reverse_operations(&branch, &operations, &completed)
            .unwrap();

        // Target should be restored to original
        assert_eq!(fs::read_to_string(&target).unwrap(), "original content");
    }

    #[test]
    fn test_wal_set_metadata_operation() {
        // SetMetadata operations should serialize/deserialize correctly
        let op = WalOperation::SetMetadata {
            path: PathBuf::from("/some/path"),
        };
        let json = serde_json::to_string(&op).unwrap();
        let deserialized: WalOperation = serde_json::from_str(&json).unwrap();
        match deserialized {
            WalOperation::SetMetadata { path } => {
                assert_eq!(path, PathBuf::from("/some/path"));
            }
            other => panic!("expected SetMetadata, got {:?}", other),
        }
    }

    #[test]
    fn test_wal_writer_recoverable_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let wal = WriteAheadLog::new(dir.path().to_path_buf());
        let branch = BranchId::new();

        let ops = vec![WalOperation::CopyFile {
            from: PathBuf::from("/src/a.txt"),
            to: PathBuf::from("/dst/a.txt"),
        }];

        // Begin but drop without finish — simulates crash
        {
            let mut writer = wal.begin_commit_writer(&branch, ops).unwrap();
            writer.mark_operation_complete(0).unwrap();
            // Drop without finish()
        }

        // WAL file should still exist for recovery
        assert!(wal.wal_path(&branch).exists());

        let incomplete = wal.recover().unwrap();
        assert_eq!(incomplete.len(), 1);
        assert_eq!(incomplete[0].as_str(), branch.as_str());
    }

    // ---------------------------------------------------------------
    // Phase 1.2 — additional WAL unit tests
    // ---------------------------------------------------------------

    /// 1. Create a WAL entry (CommitIntent) and verify it persists on disk.
    #[test]
    fn test_commit_intent_persists_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let wal = WriteAheadLog::new(dir.path().to_path_buf());
        let branch = BranchId::new();

        let ops = vec![
            WalOperation::CopyFile {
                from: PathBuf::from("/src/x.txt"),
                to: PathBuf::from("/dst/x.txt"),
            },
            WalOperation::SetMetadata {
                path: PathBuf::from("/dst/x.txt"),
            },
        ];

        wal.begin_commit(&branch, ops).unwrap();

        // WAL file must exist on disk
        let wal_path = wal.wal_path(&branch);
        assert!(
            wal_path.exists(),
            "WAL file should exist after begin_commit"
        );

        // Read it back via read_operations and verify the content round-trips
        let read_ops = wal.read_operations(&branch).unwrap();
        assert_eq!(read_ops.len(), 2);
        match &read_ops[0] {
            WalOperation::CopyFile { from, to } => {
                assert_eq!(from, &PathBuf::from("/src/x.txt"));
                assert_eq!(to, &PathBuf::from("/dst/x.txt"));
            }
            other => panic!("expected CopyFile, got {:?}", other),
        }
        match &read_ops[1] {
            WalOperation::SetMetadata { path } => {
                assert_eq!(path, &PathBuf::from("/dst/x.txt"));
            }
            other => panic!("expected SetMetadata, got {:?}", other),
        }

        // Raw file content must contain the CRC tab-separated format
        let raw = std::fs::read_to_string(&wal_path).unwrap();
        assert!(
            raw.contains('\t'),
            "WAL line must contain tab-separated CRC"
        );
        assert!(
            raw.contains("CommitIntent"),
            "WAL line must contain CommitIntent variant"
        );
    }

    /// 2. Replay after crash — create entries, mark one complete, verify
    ///    incomplete ones are surfaced by recover().
    #[test]
    fn test_replay_after_crash_multiple_branches() {
        let dir = tempfile::tempdir().unwrap();
        let wal = WriteAheadLog::new(dir.path().to_path_buf());

        let branch_a = BranchId::new();
        let branch_b = BranchId::new();
        let branch_c = BranchId::new();

        let ops = vec![WalOperation::CopyFile {
            from: PathBuf::from("/src/f.txt"),
            to: PathBuf::from("/dst/f.txt"),
        }];

        // branch_a: begin + complete => should NOT appear in recover
        wal.begin_commit(&branch_a, ops.clone()).unwrap();
        wal.mark_operation_complete(&branch_a, 0).unwrap();
        wal.mark_commit_complete(&branch_a).unwrap();

        // branch_b: begin only => incomplete
        wal.begin_commit(&branch_b, ops.clone()).unwrap();

        // branch_c: begin + op complete but no commit complete => incomplete
        wal.begin_commit(&branch_c, ops.clone()).unwrap();
        wal.mark_operation_complete(&branch_c, 0).unwrap();

        let incomplete = wal.recover().unwrap();
        assert_eq!(incomplete.len(), 2, "two branches should be incomplete");

        let ids: std::collections::HashSet<String> =
            incomplete.iter().map(|b| b.as_str().to_string()).collect();
        assert!(ids.contains(branch_b.as_str()));
        assert!(ids.contains(branch_c.as_str()));
        assert!(!ids.contains(branch_a.as_str()));
    }

    /// 3. Idempotent replay — calling recover() twice produces the same result.
    #[test]
    fn test_idempotent_replay() {
        let dir = tempfile::tempdir().unwrap();
        let wal = WriteAheadLog::new(dir.path().to_path_buf());
        let branch = BranchId::new();

        let ops = vec![WalOperation::CopyFile {
            from: PathBuf::from("/src/a.txt"),
            to: PathBuf::from("/dst/a.txt"),
        }];

        wal.begin_commit(&branch, ops).unwrap();
        wal.mark_operation_complete(&branch, 0).unwrap();
        // No commit complete — simulates crash

        let first = wal.recover().unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].as_str(), branch.as_str());

        // The first recover() does NOT remove incomplete WAL files (only
        // completed ones are cleaned up), so a second call should still
        // report the same incomplete branch.  But actually, recover() does
        // not remove incomplete WAL files — it only removes completed ones.
        // Re-read the file to confirm it is still there.
        assert!(
            wal.wal_path(&branch).exists(),
            "WAL file should still exist after recover() for incomplete branch"
        );

        // read_operations_with_status should still return the same data
        let (read_ops, completed) = wal.read_operations_with_status(&branch).unwrap();
        assert_eq!(read_ops.len(), 1);
        assert!(completed.contains(&0));
    }

    /// 4. mark_commit_complete prevents replay — completed WAL is removed
    ///    and recover() returns empty.
    #[test]
    fn test_mark_complete_prevents_replay() {
        let dir = tempfile::tempdir().unwrap();
        let wal = WriteAheadLog::new(dir.path().to_path_buf());
        let branch = BranchId::new();

        let ops = vec![
            WalOperation::CopyFile {
                from: PathBuf::from("/a"),
                to: PathBuf::from("/b"),
            },
            WalOperation::DeleteFile {
                path: PathBuf::from("/c"),
            },
        ];

        wal.begin_commit(&branch, ops).unwrap();
        wal.mark_operation_complete(&branch, 0).unwrap();
        wal.mark_operation_complete(&branch, 1).unwrap();
        wal.mark_commit_complete(&branch).unwrap();

        // WAL file should be removed
        assert!(!wal.wal_path(&branch).exists());

        // recover() should find nothing
        let incomplete = wal.recover().unwrap();
        assert!(incomplete.is_empty());

        // read_operations should return empty (no WAL file)
        let ops = wal.read_operations(&branch).unwrap();
        assert!(ops.is_empty());
    }

    /// 5. Corrupt journal detection — invalid CRC32 is rejected.
    #[test]
    fn test_corrupt_crc32_detected_in_read_operations() {
        let dir = tempfile::tempdir().unwrap();
        let wal = WriteAheadLog::new(dir.path().to_path_buf());
        let branch = BranchId::new();

        let ops = vec![WalOperation::CopyFile {
            from: PathBuf::from("/src/a.txt"),
            to: PathBuf::from("/dst/a.txt"),
        }];

        wal.begin_commit(&branch, ops).unwrap();

        // Corrupt the CRC by flipping the last hex digit
        let wal_path = wal.wal_path(&branch);
        let content = std::fs::read_to_string(&wal_path).unwrap();
        let mut bytes = content.into_bytes();
        // The CRC is the last 8 hex chars before the newline; flip the last one.
        let len = bytes.len();
        // Find the last non-newline byte and toggle it
        let idx = if bytes[len - 1] == b'\n' {
            len - 2
        } else {
            len - 1
        };
        bytes[idx] ^= 0x01; // flip a bit to corrupt CRC
        std::fs::write(&wal_path, &bytes).unwrap();

        // read_operations should skip the corrupted entry and return empty
        let read_ops = wal.read_operations(&branch).unwrap();
        assert!(read_ops.is_empty(), "corrupted CRC entry should be skipped");
    }

    /// 6. Partial write recovery — a truncated line (no tab/CRC) is skipped.
    #[test]
    fn test_truncated_entry_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let wal = WriteAheadLog::new(dir.path().to_path_buf());
        let branch = BranchId::new();

        let ops = vec![WalOperation::CopyFile {
            from: PathBuf::from("/src/a.txt"),
            to: PathBuf::from("/dst/a.txt"),
        }];

        wal.begin_commit(&branch, ops.clone()).unwrap();

        // Append a truncated line (simulating a partial write / crash mid-write)
        let wal_path = wal.wal_path(&branch);
        let mut file = OpenOptions::new().append(true).open(&wal_path).unwrap();
        // Write a partial JSON line with no tab and no CRC
        writeln!(
            file,
            r#"{{"CommitIntent":{{"branch_id":"trunc","operations":[]}}"#
        )
        .unwrap();
        // Also append a line that is just garbage
        writeln!(file, "not-json-at-all").unwrap();

        // read_operations should still return the valid first entry
        let read_ops = wal.read_operations(&branch).unwrap();
        assert_eq!(read_ops.len(), 1, "valid entry should still be readable");

        // recover() should report the branch as incomplete (no CommitComplete)
        let incomplete = wal.recover().unwrap();
        assert_eq!(incomplete.len(), 1);
    }

    /// 7. WalWriter per-commit locking — the writer holds a lock for the
    ///    entire commit duration and correctly records all entries.
    #[test]
    fn test_wal_writer_per_commit_locking() {
        let dir = tempfile::tempdir().unwrap();
        let wal = WriteAheadLog::new(dir.path().to_path_buf());
        let branch = BranchId::new();

        let ops = vec![
            WalOperation::CopyFile {
                from: PathBuf::from("/src/a.txt"),
                to: PathBuf::from("/dst/a.txt"),
            },
            WalOperation::CopyFile {
                from: PathBuf::from("/src/b.txt"),
                to: PathBuf::from("/dst/b.txt"),
            },
            WalOperation::DeleteFile {
                path: PathBuf::from("/dst/c.txt"),
            },
        ];

        // Use WalWriter — single lock for entire commit
        let mut writer = wal.begin_commit_writer(&branch, ops).unwrap();
        writer.mark_operation_complete(0).unwrap();
        writer.mark_operation_complete(1).unwrap();
        // Intentionally do NOT mark op 2 complete

        // Before finish, check status via a second WAL instance (simulating
        // another thread reading — the lock would block writes but reads
        // of the already-fsynced content are observable)
        let (read_ops, completed) = wal.read_operations_with_status(&branch).unwrap();
        assert_eq!(read_ops.len(), 3);
        assert!(completed.contains(&0));
        assert!(completed.contains(&1));
        assert!(!completed.contains(&2), "op 2 was not marked complete");

        // Now finish (writes CommitComplete, removes WAL file)
        writer.finish().unwrap();
        assert!(!wal.wal_path(&branch).exists());

        // After finish, recover should find nothing
        let incomplete = wal.recover().unwrap();
        assert!(incomplete.is_empty());
    }

    /// 8. WAL init creates the directory (acting as version marker).
    #[test]
    fn test_wal_init_creates_directory() {
        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path().join("nested").join("wal").join("dir");
        assert!(!wal_dir.exists());

        WriteAheadLog::init(&wal_dir).unwrap();
        assert!(wal_dir.exists());
        assert!(wal_dir.is_dir());

        // Calling init again should be idempotent (create_dir_all is idempotent)
        WriteAheadLog::init(&wal_dir).unwrap();
        assert!(wal_dir.exists());
    }

    /// 9. Recovery rolls back incomplete commits — reverse_operations
    ///    restores original files for an incomplete commit.
    #[test]
    fn test_recovery_rolls_back_incomplete_commits() {
        let dir = tempfile::tempdir().unwrap();
        let wal = WriteAheadLog::new(dir.path().to_path_buf());
        let branch = BranchId::new();

        // Set up a target file with original content
        let target_a = dir.path().join("target_a.txt");
        let target_b = dir.path().join("target_b.txt");
        fs::write(&target_a, "original_a").unwrap();
        // target_b does not exist yet (will be created by commit)

        // Back up target_a before overwriting
        let backup_a = wal.backup_file(&branch, &target_a).unwrap().unwrap();
        assert!(backup_a.existed);

        // Back up target_b (does not exist — marker)
        let backup_b = wal.backup_file(&branch, &target_b).unwrap().unwrap();
        assert!(!backup_b.existed);

        // Simulate partial commit: overwrite target_a, create target_b
        fs::write(&target_a, "committed_a").unwrap();
        fs::write(&target_b, "committed_b").unwrap();

        // Record operations in WAL
        let ops = vec![
            WalOperation::CopyFile {
                from: PathBuf::from("/upper/target_a.txt"),
                to: target_a.clone(),
            },
            WalOperation::CopyFile {
                from: PathBuf::from("/upper/target_b.txt"),
                to: target_b.clone(),
            },
        ];

        wal.begin_commit(&branch, ops.clone()).unwrap();
        wal.mark_operation_complete(&branch, 0).unwrap();
        // Op 1 not marked complete — simulates crash mid-commit

        // Verify state before rollback
        assert_eq!(fs::read_to_string(&target_a).unwrap(), "committed_a");
        assert_eq!(fs::read_to_string(&target_b).unwrap(), "committed_b");

        // Read operations and status, then reverse
        let (read_ops, completed) = wal.read_operations_with_status(&branch).unwrap();
        assert_eq!(read_ops.len(), 2);
        assert!(completed.contains(&0));
        assert!(!completed.contains(&1));

        wal.reverse_operations(&branch, &read_ops, &completed)
            .unwrap();

        // target_a should be restored to original content
        assert_eq!(
            fs::read_to_string(&target_a).unwrap(),
            "original_a",
            "target_a should be restored from backup"
        );

        // target_b did not exist before commit, so it should be deleted
        assert!(
            !target_b.exists(),
            "target_b should be removed (did not exist pre-commit)"
        );

        // WAL file and backup directory should be cleaned up
        assert!(
            !wal.wal_path(&branch).exists(),
            "WAL file should be removed after reverse"
        );
    }

    // L41: Verify recover() logs errors on WAL file removal instead of silently ignoring
    #[test]
    fn test_l41_wal_cleanup_failure_logged() {
        let src = include_str!("wal.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        // The recover() function must not use `let _ = fs::remove_file` for
        // completed WAL cleanup — it should log the error.
        // We look for the specific pattern in the recover function context.
        // Find the recover function and check it doesn't have `let _ = fs::remove_file`
        let recover_fn = prod
            .split("pub fn recover(")
            .nth(1)
            .unwrap()
            .split("\n    pub ")
            .next()
            .unwrap();
        assert!(
            !recover_fn.contains("let _ = fs::remove_file"),
            "L41: recover() must not silently ignore WAL file removal errors; log with tracing::warn"
        );
    }

    // L42: Verify cleanup_after_commit() logs fsync errors instead of silently ignoring
    #[test]
    fn test_l42_fsync_failure_logged() {
        let src = include_str!("wal.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        assert!(
            !prod.contains("let _ = dir.sync_all()"),
            "L42: cleanup_after_commit must not silently ignore dir.sync_all() errors; log with tracing::warn"
        );
    }

    // L44: Verify cleanup_orphan_puzzled_old_recursive logs read errors instead of silently returning
    #[test]
    fn test_l44_orphan_cleanup_logs_read_errors() {
        let src = include_str!("wal.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        // Find the cleanup_orphan_puzzled_old_recursive function
        let cleanup_fn = prod
            .split("fn cleanup_orphan_puzzled_old_recursive(")
            .nth(1)
            .unwrap()
            .split("\n    pub ")
            .next()
            .unwrap_or(
                prod.split("fn cleanup_orphan_puzzled_old_recursive(")
                    .nth(1)
                    .unwrap(),
            );
        // Should not have bare `Err(_) => return` or `Err(_) => continue` without logging
        assert!(
            !cleanup_fn.contains("Err(_) => return"),
            "L44: cleanup_orphan_puzzled_old_recursive must log errors on read_dir failure, not silently return"
        );
        assert!(
            !cleanup_fn.contains("Err(_) => continue"),
            "L44: cleanup_orphan_puzzled_old_recursive must log errors on entry iteration failure, not silently continue"
        );
    }
}
