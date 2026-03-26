// SPDX-License-Identifier: Apache-2.0
//! Cross-branch conflict detection.
//!
//! Tracks which files are modified by each active branch, and detects
//! conflicts when multiple branches modify the same file. Conflicts
//! are evaluated at commit time and resolved according to the
//! configured strategy.
//!
//! OverlayFS copy-up artifacts are filtered using the same checksum
//! logic as the diff engine to avoid false positives.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

use puzzled_types::{
    BranchId, Conflict, ConflictKind, ConflictResolution, FileChange, FileChangeKind,
};

use crate::error::{PuzzledError, Result};

/// R27: Maximum number of entries in the modified_files map to prevent
/// unbounded memory growth from pathological workloads.
const MAX_MODIFIED_FILES: usize = 100_000;

/// C8: Maximum time a path reservation is valid before it expires.
/// Prevents stale reservations from blocking commits indefinitely
/// (e.g., if puzzled crashes between reserve and confirm/cancel).
const RESERVATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// H5: Record of a committed branch's file changes, for post-commit conflict detection.
#[derive(Debug, Clone)]
struct CommittedBranchRecord {
    /// Paths that were modified by the committed branch.
    paths: Vec<PathBuf>,
    /// When the branch was committed.
    committed_at: chrono::DateTime<chrono::Utc>,
}

/// Tracks file modifications across concurrent branches.
pub struct ConflictDetector {
    /// Map of (base_path, relative_path) -> set of branch IDs that modified it.
    modified_files: HashMap<(PathBuf, PathBuf), HashSet<BranchId>>,
    /// Map of (base_path, relative_path) -> kind of modification per branch.
    modification_kinds: HashMap<(PathBuf, PathBuf, BranchId), FileChangeKind>,
    /// Resolution strategy (configurable per-daemon).
    resolution: ConflictResolution,
    /// C8: Two-phase reservation protocol — tracks paths reserved by branches
    /// between conflict check and WAL commit. Each reservation has a timestamp
    /// so expired reservations can be cleaned up.
    reservations: HashMap<BranchId, (HashSet<PathBuf>, Instant)>,
    /// H5: Committed branch records — tracks which paths were modified by
    /// recently committed branches, so we can detect conflicts against branches
    /// that were created before the commit but haven't committed yet.
    ///
    /// M3-CQ4: This state is NOT persisted across daemon restarts. On crash or
    /// restart, committed_changes will be empty, meaning conflict detection
    /// against recently-committed branches will have a blind spot until new
    /// commits populate this map again. Persisting this would require a
    /// durable store (e.g., WAL or on-disk journal), which is deferred.
    committed_changes: HashMap<String, CommittedBranchRecord>,
}

impl Default for ConflictDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ConflictDetector {
    /// Create a new conflict detector with default Reject strategy.
    pub fn new() -> Self {
        // M3-CQ4: Log that conflict detection state is not persisted.
        tracing::warn!(
            "Conflict detection state is not persisted across restarts; \
             committed_changes will be empty after daemon restart"
        );
        Self {
            modified_files: HashMap::new(),
            modification_kinds: HashMap::new(),
            resolution: ConflictResolution::Reject,
            reservations: HashMap::new(),
            committed_changes: HashMap::new(),
        }
    }

    /// Create a new conflict detector with a specific resolution strategy.
    pub fn with_resolution(resolution: ConflictResolution) -> Self {
        // M3-CQ4: Log that conflict detection state is not persisted.
        tracing::warn!(
            "Conflict detection state is not persisted across restarts; \
             committed_changes will be empty after daemon restart"
        );
        Self {
            modified_files: HashMap::new(),
            modification_kinds: HashMap::new(),
            resolution,
            reservations: HashMap::new(),
            committed_changes: HashMap::new(),
        }
    }

    /// Register file changes from a branch's diff.
    ///
    /// Called after `DiffEngine::generate()` produces the changeset.
    pub fn register_changes(
        &mut self,
        branch_id: &BranchId,
        base_path: &Path,
        changes: &[FileChange],
    ) {
        for change in changes {
            // R27: Enforce size bound on modified_files to prevent unbounded memory growth.
            // V27: Conflict detection is best-effort after MAX_MODIFIED_FILES — documented in R27.
            // Callers should check branch file count against this limit before relying on conflict results.
            if self.modified_files.len() >= MAX_MODIFIED_FILES {
                tracing::warn!(
                    branch_id = %branch_id,
                    limit = MAX_MODIFIED_FILES,
                    "R27: modified_files map reached size limit; skipping further registrations"
                );
                break;
            }

            let key = (base_path.to_path_buf(), change.path.clone());

            self.modified_files
                .entry(key.clone())
                .or_default()
                .insert(branch_id.clone());

            self.modification_kinds.insert(
                (
                    base_path.to_path_buf(),
                    change.path.clone(),
                    branch_id.clone(),
                ),
                change.kind,
            );
        }
    }

    /// Check for conflicts between the given branch and all other active branches,
    /// as well as recently committed branches (H5).
    ///
    /// `branch_created_at` is the creation time of the branch being checked. It is
    /// used to determine which committed branches could conflict: only those committed
    /// after this branch was created are relevant.
    ///
    /// Returns a list of conflicts, or empty if none found.
    pub fn check_conflicts(
        &self,
        branch_id: &BranchId,
        base_path: &Path,
        changes: &[FileChange],
    ) -> Vec<Conflict> {
        self.check_conflicts_with_time(branch_id, base_path, changes, None)
    }

    /// Check conflicts with an optional branch creation time for H5 committed branch checking.
    pub fn check_conflicts_with_time(
        &self,
        branch_id: &BranchId,
        base_path: &Path,
        changes: &[FileChange],
        branch_created_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Vec<Conflict> {
        let mut conflicts = Vec::new();

        // H5: Build a set of paths modified by recently committed branches
        // that committed after this branch was created.
        let committed_conflict_paths: HashSet<PathBuf> = if let Some(created_at) = branch_created_at
        {
            self.committed_changes
                .iter()
                .filter(|(_, record)| record.committed_at > created_at)
                .flat_map(|(_, record)| record.paths.iter().cloned())
                .collect()
        } else {
            HashSet::new()
        };

        for change in changes {
            let key = (base_path.to_path_buf(), change.path.clone());

            let mut other_branches: Vec<BranchId> = Vec::new();

            // Check active branches
            if let Some(branches) = self.modified_files.get(&key) {
                other_branches.extend(branches.iter().filter(|b| *b != branch_id).cloned());
            }

            // H5: Check committed branches
            if committed_conflict_paths.contains(&change.path) {
                // We don't have a specific branch ID for committed conflicts,
                // but the conflict is still real. We'll flag it with a sentinel.
                // The conflict kind will be BothModified by default.
                if other_branches.is_empty() {
                    // Only add a conflict entry if not already conflicting with active branches
                    let mut all_branches = vec![branch_id.clone()];
                    // Add a sentinel for the committed branch
                    all_branches.push(BranchId::from("_committed_".to_string()));
                    conflicts.push(Conflict {
                        path: change.path.clone(),
                        conflicting_branches: all_branches,
                        kind: ConflictKind::BothModified,
                    });
                    continue;
                }
            }

            if other_branches.is_empty() {
                continue;
            }

            // Determine conflict kind
            let kind = self.classify_conflict(
                base_path,
                &change.path,
                branch_id,
                change.kind,
                &other_branches,
            );

            let mut all_branches = other_branches;
            all_branches.push(branch_id.clone());

            conflicts.push(Conflict {
                path: change.path.clone(),
                conflicting_branches: all_branches,
                kind,
            });
        }

        conflicts
    }

    /// Classify the type of conflict based on modification kinds.
    fn classify_conflict(
        &self,
        base_path: &Path,
        rel_path: &Path,
        _current_branch: &BranchId,
        current_kind: FileChangeKind,
        other_branches: &[BranchId],
    ) -> ConflictKind {
        for other_id in other_branches {
            let key = (
                base_path.to_path_buf(),
                rel_path.to_path_buf(),
                other_id.clone(),
            );
            if let Some(&other_kind) = self.modification_kinds.get(&key) {
                match (current_kind, other_kind) {
                    (FileChangeKind::Added, FileChangeKind::Added) => {
                        return ConflictKind::BothCreated;
                    }
                    (FileChangeKind::Modified, FileChangeKind::Deleted)
                    | (FileChangeKind::Deleted, FileChangeKind::Modified) => {
                        return ConflictKind::ModifiedAndDeleted;
                    }
                    _ => {
                        return ConflictKind::BothModified;
                    }
                }
            }
        }

        ConflictKind::BothModified
    }

    /// Apply the conflict resolution strategy.
    ///
    /// Returns Ok(()) if the commit can proceed, or Err if it should be rejected.
    pub fn resolve(&self, conflicts: &[Conflict]) -> Result<()> {
        if conflicts.is_empty() {
            return Ok(());
        }

        match self.resolution {
            ConflictResolution::Reject => {
                let conflict_summary: Vec<String> = conflicts
                    .iter()
                    .map(|c| {
                        format!(
                            "{}: {:?} (branches: {})",
                            c.path.display(),
                            c.kind,
                            c.conflicting_branches
                                .iter()
                                .map(|b| b.as_str().to_string())
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    })
                    .collect();

                Err(PuzzledError::Conflict(format!(
                    "cross-branch conflicts detected:\n{}",
                    conflict_summary.join("\n")
                )))
            }
            ConflictResolution::LastWriterWins => {
                tracing::warn!(
                    count = conflicts.len(),
                    "conflicts resolved via last-writer-wins"
                );
                Ok(())
            }
            ConflictResolution::MergeIfText => {
                // L3: Check if any conflicting files are binary.
                // Binary files cannot be merged — return conflict error.
                // Text files would be merged via 3-way merge (deferred — requires `similar` crate).
                for conflict in conflicts {
                    if Self::is_binary_file(&conflict.path) {
                        return Err(PuzzledError::Conflict(format!(
                            "L3: cannot merge binary file: {} — 3-way merge only supports text files",
                            conflict.path.display()
                        )));
                    }
                }
                // L3: MergeIfText is not yet implemented — falls through to reject
                tracing::warn!(
                    count = conflicts.len(),
                    "MergeIfText conflict resolution is not implemented; treating as unresolved conflict"
                );
                Err(PuzzledError::Conflict(format!(
                    "L3: MergeIfText resolution is not yet implemented; {} text file conflict(s) cannot be auto-merged",
                    conflicts.len()
                )))
            }
            ConflictResolution::ScopePartition => {
                // This should have been prevented at branch creation time
                tracing::warn!(
                    count = conflicts.len(),
                    "scope partition conflict — this shouldn't happen"
                );
                Err(PuzzledError::Conflict(
                    "scope partition violation".to_string(),
                ))
            }
        }
    }

    /// H5: Mark a branch as committed, moving its tracked paths from active to
    /// the committed_changes map. This allows detecting conflicts against branches
    /// that were created before this commit but haven't committed yet.
    ///
    /// Called from BranchManager::commit() after a successful commit, before
    /// unregister_branch().
    pub fn mark_committed(
        &mut self,
        branch_id: &BranchId,
        paths: Vec<PathBuf>,
        timestamp: chrono::DateTime<chrono::Utc>,
    ) {
        self.committed_changes.insert(
            branch_id.as_str().to_string(),
            CommittedBranchRecord {
                paths,
                committed_at: timestamp,
            },
        );
    }

    /// H5: Periodically remove committed branch records older than `max_age`.
    ///
    /// Called from a cleanup task to prevent unbounded growth of the
    /// committed_changes map.
    ///
    /// C1: Two-level eviction:
    /// 1. Age-based: remove entries older than `max_age`
    /// 2. Size-based: if still over MAX_COMMITTED_RECORDS, remove oldest entries
    pub fn cleanup_old_committed(&mut self, max_age: chrono::Duration) {
        let cutoff = chrono::Utc::now() - max_age;
        self.committed_changes
            .retain(|_, record| record.committed_at > cutoff);

        // C1: Hard cap to prevent unbounded growth even with high commit rates
        const MAX_COMMITTED_RECORDS: usize = 1000;
        if self.committed_changes.len() > MAX_COMMITTED_RECORDS {
            // Sort by commit time, keep only the newest MAX_COMMITTED_RECORDS
            let mut entries: Vec<_> = self.committed_changes.drain().collect();
            entries.sort_by(|a, b| b.1.committed_at.cmp(&a.1.committed_at));
            entries.truncate(MAX_COMMITTED_RECORDS);
            self.committed_changes = entries.into_iter().collect();
            tracing::info!(
                kept = MAX_COMMITTED_RECORDS,
                "conflict detector: evicted oldest committed records (size cap)"
            );
        }
    }

    /// L3: Check if a file is binary by looking for null bytes in the first 8KB.
    ///
    /// This is a heuristic used by Git and other tools. A file containing a
    /// null byte in the first 8KB is considered binary.
    /// If the file cannot be read (e.g., doesn't exist), returns false.
    fn is_binary_file(path: &Path) -> bool {
        use std::io::Read;
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let mut reader = std::io::BufReader::new(file);
        let mut buf = [0u8; 8192];
        let n = match reader.read(&mut buf) {
            Ok(n) => n,
            Err(_) => return false,
        };
        buf[..n].contains(&0)
    }

    /// C8: Reserve paths for a branch as part of the two-phase commit protocol.
    ///
    /// Called after conflict check passes but before WAL commit begins. This
    /// prevents a TOCTOU race where another branch could commit the same paths
    /// between our conflict check and our WAL commit.
    ///
    /// Returns `Err` if any path is already reserved by another branch.
    pub fn reserve_paths(
        &mut self,
        branch_id: &BranchId,
        paths: Vec<PathBuf>,
    ) -> std::result::Result<(), String> {
        // C8: Clean up expired reservations before checking
        self.cleanup_expired_reservations();

        // Check for conflicts with existing reservations from other branches
        for (other_branch, (reserved_paths, _)) in &self.reservations {
            if other_branch == branch_id {
                continue;
            }
            for path in &paths {
                if reserved_paths.contains(path) {
                    return Err(format!(
                        "C8: path '{}' is already reserved by branch '{}'",
                        path.display(),
                        other_branch.as_str()
                    ));
                }
            }
        }

        // No conflicts — insert reservation with current timestamp
        self.reservations.insert(
            branch_id.clone(),
            (paths.into_iter().collect(), Instant::now()),
        );

        Ok(())
    }

    /// C8: Confirm a reservation after successful WAL commit.
    ///
    /// Removes the reservation for this branch, since the commit has been
    /// persisted and the paths are now part of the committed state.
    pub fn confirm_commit(&mut self, branch_id: &BranchId) {
        self.reservations.remove(branch_id);
    }

    /// C8: Cancel a reservation after a failed or rolled-back commit.
    ///
    /// Removes the reservation for this branch so the paths are available
    /// for other branches to reserve.
    pub fn cancel_reservation(&mut self, branch_id: &BranchId) {
        self.reservations.remove(branch_id);
    }

    /// C8: Remove reservations that have exceeded RESERVATION_TIMEOUT.
    ///
    /// This prevents stale reservations from blocking commits indefinitely
    /// (e.g., if the committing branch's process died without cleanup).
    fn cleanup_expired_reservations(&mut self) {
        let now = Instant::now();
        self.reservations.retain(|branch_id, (_, created_at)| {
            let age = now.duration_since(*created_at);
            if age > RESERVATION_TIMEOUT {
                tracing::warn!(
                    branch = %branch_id.as_str(),
                    age_secs = age.as_secs(),
                    "C8: removing expired path reservation (>{} seconds)",
                    RESERVATION_TIMEOUT.as_secs()
                );
                false
            } else {
                true
            }
        });
    }

    /// Unregister all changes for a branch (on rollback or commit).
    pub fn unregister_branch(&mut self, branch_id: &BranchId) {
        // Remove from modified_files
        for branches in self.modified_files.values_mut() {
            branches.remove(branch_id);
        }

        // Remove empty entries
        self.modified_files
            .retain(|_, branches| !branches.is_empty());

        // Remove from modification_kinds
        self.modification_kinds.retain(|key, _| &key.2 != branch_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_conflicts() {
        let mut detector = ConflictDetector::new();
        let branch_a = BranchId::from("branch-a".to_string());
        let branch_b = BranchId::from("branch-b".to_string());
        let base = PathBuf::from("/base");

        let changes_a = vec![FileChange {
            path: PathBuf::from("file_a.txt"),
            kind: FileChangeKind::Modified,
            size: 100,
            checksum: "abc".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        }];
        let changes_b = vec![FileChange {
            path: PathBuf::from("file_b.txt"),
            kind: FileChangeKind::Modified,
            size: 200,
            checksum: "def".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        }];

        detector.register_changes(&branch_a, &base, &changes_a);
        detector.register_changes(&branch_b, &base, &changes_b);

        let conflicts = detector.check_conflicts(&branch_b, &base, &changes_b);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_both_modified_conflict() {
        let mut detector = ConflictDetector::new();
        let branch_a = BranchId::from("branch-a".to_string());
        let branch_b = BranchId::from("branch-b".to_string());
        let base = PathBuf::from("/base");

        let change = FileChange {
            path: PathBuf::from("shared.txt"),
            kind: FileChangeKind::Modified,
            size: 100,
            checksum: "abc".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        };

        detector.register_changes(&branch_a, &base, std::slice::from_ref(&change));
        detector.register_changes(&branch_b, &base, std::slice::from_ref(&change));

        let conflicts = detector.check_conflicts(&branch_b, &base, &[change]);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].kind, ConflictKind::BothModified);
    }

    #[test]
    fn test_unregister_clears_conflicts() {
        let mut detector = ConflictDetector::new();
        let branch_a = BranchId::from("branch-a".to_string());
        let branch_b = BranchId::from("branch-b".to_string());
        let base = PathBuf::from("/base");

        let change = FileChange {
            path: PathBuf::from("shared.txt"),
            kind: FileChangeKind::Modified,
            size: 100,
            checksum: "abc".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        };

        detector.register_changes(&branch_a, &base, std::slice::from_ref(&change));
        detector.register_changes(&branch_b, &base, std::slice::from_ref(&change));

        // Unregister branch_a (simulating commit)
        detector.unregister_branch(&branch_a);

        let conflicts = detector.check_conflicts(&branch_b, &base, &[change]);
        assert!(conflicts.is_empty());
    }

    // -- H5: Committed branch conflict detection --

    #[test]
    fn test_h5_mark_committed_tracks_paths() {
        let mut detector = ConflictDetector::new();
        let branch_a = BranchId::from("branch-a".to_string());

        let now = chrono::Utc::now();
        detector.mark_committed(
            &branch_a,
            vec![PathBuf::from("file1.txt"), PathBuf::from("file2.txt")],
            now,
        );

        assert!(detector.committed_changes.contains_key("branch-a"));
        assert_eq!(detector.committed_changes["branch-a"].paths.len(), 2);
    }

    #[test]
    fn test_h5_conflict_with_committed_branch() {
        let mut detector = ConflictDetector::new();
        let branch_a = BranchId::from("branch-a".to_string());
        let branch_b = BranchId::from("branch-b".to_string());

        // branch_b was created before branch_a committed
        let branch_b_created = chrono::Utc::now() - chrono::Duration::seconds(10);
        let commit_time = chrono::Utc::now();

        // branch_a committed and modified file1.txt
        detector.mark_committed(&branch_a, vec![PathBuf::from("file1.txt")], commit_time);

        // branch_b also modifies file1.txt — should conflict
        let change = FileChange {
            path: PathBuf::from("file1.txt"),
            kind: FileChangeKind::Modified,
            size: 100,
            checksum: "abc".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        };

        let conflicts = detector.check_conflicts_with_time(
            &branch_b,
            &PathBuf::from("/base"),
            &[change],
            Some(branch_b_created),
        );

        assert_eq!(
            conflicts.len(),
            1,
            "H5: should detect conflict with committed branch"
        );
    }

    #[test]
    fn test_h5_no_conflict_when_committed_before_branch_creation() {
        let mut detector = ConflictDetector::new();
        let branch_a = BranchId::from("branch-a".to_string());
        let branch_b = BranchId::from("branch-b".to_string());

        // branch_a committed BEFORE branch_b was created
        let commit_time = chrono::Utc::now() - chrono::Duration::seconds(20);
        let branch_b_created = chrono::Utc::now() - chrono::Duration::seconds(5);

        detector.mark_committed(&branch_a, vec![PathBuf::from("file1.txt")], commit_time);

        let change = FileChange {
            path: PathBuf::from("file1.txt"),
            kind: FileChangeKind::Modified,
            size: 100,
            checksum: "abc".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        };

        let conflicts = detector.check_conflicts_with_time(
            &branch_b,
            &PathBuf::from("/base"),
            &[change],
            Some(branch_b_created),
        );

        assert!(
            conflicts.is_empty(),
            "H5: no conflict when commit happened before branch was created"
        );
    }

    #[test]
    fn test_h5_cleanup_old_committed() {
        let mut detector = ConflictDetector::new();
        let branch_a = BranchId::from("branch-a".to_string());
        let branch_b = BranchId::from("branch-b".to_string());

        // branch_a committed 2 hours ago
        let old_time = chrono::Utc::now() - chrono::Duration::hours(2);
        detector.mark_committed(&branch_a, vec![PathBuf::from("old.txt")], old_time);

        // branch_b committed 5 minutes ago
        let recent_time = chrono::Utc::now() - chrono::Duration::minutes(5);
        detector.mark_committed(&branch_b, vec![PathBuf::from("recent.txt")], recent_time);

        // Cleanup entries older than 1 hour
        detector.cleanup_old_committed(chrono::Duration::hours(1));

        assert!(
            !detector.committed_changes.contains_key("branch-a"),
            "H5: old committed record should be cleaned up"
        );
        assert!(
            detector.committed_changes.contains_key("branch-b"),
            "H5: recent committed record should be kept"
        );
    }

    // -- L3: MergeIfText binary detection --

    #[test]
    fn test_l3_is_binary_file_detects_null_bytes() {
        let dir = tempfile::tempdir().unwrap();

        // Create a binary file with null bytes
        let binary = dir.path().join("binary.bin");
        std::fs::write(&binary, b"header\x00\x01\x02binary data").unwrap();
        assert!(
            ConflictDetector::is_binary_file(&binary),
            "L3: file with null bytes should be detected as binary"
        );

        // Create a text file
        let text = dir.path().join("text.txt");
        std::fs::write(&text, "hello world\nthis is text\n").unwrap();
        assert!(
            !ConflictDetector::is_binary_file(&text),
            "L3: text file should not be detected as binary"
        );
    }

    #[test]
    fn test_l3_is_binary_nonexistent_file() {
        assert!(
            !ConflictDetector::is_binary_file(Path::new("/nonexistent/file.bin")),
            "L3: nonexistent file should return false"
        );
    }

    #[test]
    fn test_l3_merge_if_text_rejects_binary_conflicts() {
        let dir = tempfile::tempdir().unwrap();
        let detector = ConflictDetector::with_resolution(ConflictResolution::MergeIfText);

        // Create a binary file
        let binary = dir.path().join("data.bin");
        std::fs::write(&binary, b"\x00binary\x01data").unwrap();

        let conflicts = vec![Conflict {
            path: binary,
            conflicting_branches: vec![
                BranchId::from("a".to_string()),
                BranchId::from("b".to_string()),
            ],
            kind: ConflictKind::BothModified,
        }];

        let result = detector.resolve(&conflicts);
        assert!(
            result.is_err(),
            "L3: MergeIfText should reject binary file conflicts"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("binary"),
            "error should mention binary: {}",
            err
        );
    }

    #[test]
    fn test_l3_merge_if_text_rejects_text_conflicts_not_implemented() {
        let dir = tempfile::tempdir().unwrap();
        let detector = ConflictDetector::with_resolution(ConflictResolution::MergeIfText);

        // Create a text file
        let text = dir.path().join("code.rs");
        std::fs::write(&text, "fn main() {\n    println!(\"hello\");\n}\n").unwrap();

        let conflicts = vec![Conflict {
            path: text,
            conflicting_branches: vec![
                BranchId::from("a".to_string()),
                BranchId::from("b".to_string()),
            ],
            kind: ConflictKind::BothModified,
        }];

        // L3: MergeIfText is not yet implemented — falls through to reject
        let result = detector.resolve(&conflicts);
        assert!(
            result.is_err(),
            "L3: MergeIfText is not yet implemented and should reject"
        );
    }

    // -- C8: Two-phase reservation protocol --

    #[test]
    fn test_c8_reserve_paths_succeeds_when_no_conflicts() {
        let mut detector = ConflictDetector::new();
        let branch_a = BranchId::from("branch-a".to_string());

        let result = detector.reserve_paths(
            &branch_a,
            vec![PathBuf::from("file1.txt"), PathBuf::from("file2.txt")],
        );
        assert!(
            result.is_ok(),
            "C8: reservation should succeed with no conflicts"
        );
    }

    #[test]
    fn test_c8_reserve_paths_rejects_conflict() {
        let mut detector = ConflictDetector::new();
        let branch_a = BranchId::from("branch-a".to_string());
        let branch_b = BranchId::from("branch-b".to_string());

        detector
            .reserve_paths(&branch_a, vec![PathBuf::from("shared.txt")])
            .unwrap();

        let result = detector.reserve_paths(&branch_b, vec![PathBuf::from("shared.txt")]);
        assert!(
            result.is_err(),
            "C8: reservation should fail when path is already reserved"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("shared.txt"),
            "error should mention the path: {}",
            err
        );
        assert!(
            err.contains("branch-a"),
            "error should mention the holder: {}",
            err
        );
    }

    #[test]
    fn test_c8_confirm_commit_releases_reservation() {
        let mut detector = ConflictDetector::new();
        let branch_a = BranchId::from("branch-a".to_string());
        let branch_b = BranchId::from("branch-b".to_string());

        detector
            .reserve_paths(&branch_a, vec![PathBuf::from("file.txt")])
            .unwrap();

        // Confirm the commit — should release the reservation
        detector.confirm_commit(&branch_a);

        // Now branch_b should be able to reserve the same path
        let result = detector.reserve_paths(&branch_b, vec![PathBuf::from("file.txt")]);
        assert!(
            result.is_ok(),
            "C8: reservation should succeed after confirm_commit releases it"
        );
    }

    #[test]
    fn test_c8_cancel_reservation_releases_paths() {
        let mut detector = ConflictDetector::new();
        let branch_a = BranchId::from("branch-a".to_string());
        let branch_b = BranchId::from("branch-b".to_string());

        detector
            .reserve_paths(&branch_a, vec![PathBuf::from("file.txt")])
            .unwrap();

        // Cancel the reservation (rollback)
        detector.cancel_reservation(&branch_a);

        // Now branch_b should be able to reserve the same path
        let result = detector.reserve_paths(&branch_b, vec![PathBuf::from("file.txt")]);
        assert!(
            result.is_ok(),
            "C8: reservation should succeed after cancel_reservation releases it"
        );
    }

    #[test]
    fn test_c8_same_branch_can_re_reserve() {
        let mut detector = ConflictDetector::new();
        let branch_a = BranchId::from("branch-a".to_string());

        detector
            .reserve_paths(&branch_a, vec![PathBuf::from("file.txt")])
            .unwrap();

        // Same branch re-reserving should overwrite (not conflict with itself)
        let result = detector.reserve_paths(
            &branch_a,
            vec![PathBuf::from("file.txt"), PathBuf::from("file2.txt")],
        );
        assert!(
            result.is_ok(),
            "C8: same branch should be able to re-reserve its own paths"
        );
    }

    // -- Phase 1.6: Additional conflict detection tests --

    #[test]
    fn test_no_conflict_on_disjoint_paths() {
        let mut detector = ConflictDetector::new();
        let branch_a = BranchId::from("branch-a".to_string());
        let branch_b = BranchId::from("branch-b".to_string());
        let base = PathBuf::from("/project");

        // branch_a modifies files in src/, branch_b modifies files in docs/
        let changes_a = vec![
            FileChange {
                path: PathBuf::from("src/main.rs"),
                kind: FileChangeKind::Modified,
                size: 500,
                checksum: "aaa".to_string(),
                old_size: None,
                old_mode: None,
                new_mode: None,
                timestamp: None,
                target: None,
            },
            FileChange {
                path: PathBuf::from("src/lib.rs"),
                kind: FileChangeKind::Added,
                size: 200,
                checksum: "bbb".to_string(),
                old_size: None,
                old_mode: None,
                new_mode: None,
                timestamp: None,
                target: None,
            },
        ];
        let changes_b = vec![
            FileChange {
                path: PathBuf::from("docs/readme.md"),
                kind: FileChangeKind::Modified,
                size: 300,
                checksum: "ccc".to_string(),
                old_size: None,
                old_mode: None,
                new_mode: None,
                timestamp: None,
                target: None,
            },
            FileChange {
                path: PathBuf::from("docs/guide.md"),
                kind: FileChangeKind::Added,
                size: 150,
                checksum: "ddd".to_string(),
                old_size: None,
                old_mode: None,
                new_mode: None,
                timestamp: None,
                target: None,
            },
        ];

        detector.register_changes(&branch_a, &base, &changes_a);
        detector.register_changes(&branch_b, &base, &changes_b);

        // Neither branch should see conflicts with the other
        let conflicts_a = detector.check_conflicts(&branch_a, &base, &changes_a);
        let conflicts_b = detector.check_conflicts(&branch_b, &base, &changes_b);
        assert!(
            conflicts_a.is_empty(),
            "disjoint paths should not produce conflicts for branch_a"
        );
        assert!(
            conflicts_b.is_empty(),
            "disjoint paths should not produce conflicts for branch_b"
        );
    }

    #[test]
    fn test_same_file_conflict_detected_with_classification() {
        let mut detector = ConflictDetector::new();
        let branch_a = BranchId::from("a".to_string());
        let branch_b = BranchId::from("b".to_string());
        let base = PathBuf::from("/base");

        // branch_a modifies config.yaml, branch_b deletes it
        let change_a = FileChange {
            path: PathBuf::from("config.yaml"),
            kind: FileChangeKind::Modified,
            size: 100,
            checksum: "abc".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        };
        let change_b = FileChange {
            path: PathBuf::from("config.yaml"),
            kind: FileChangeKind::Deleted,
            size: 0,
            checksum: "".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        };

        detector.register_changes(&branch_a, &base, &[change_a]);
        detector.register_changes(&branch_b, &base, std::slice::from_ref(&change_b));

        let conflicts = detector.check_conflicts(&branch_b, &base, &[change_b]);
        assert_eq!(conflicts.len(), 1, "same-file conflict should be detected");
        assert_eq!(
            conflicts[0].kind,
            ConflictKind::ModifiedAndDeleted,
            "modify vs delete should classify as ModifiedAndDeleted"
        );
        assert!(
            conflicts[0].conflicting_branches.contains(&branch_a),
            "conflicting_branches should include branch_a"
        );
    }

    #[test]
    fn test_parent_directory_deletion_conflict() {
        // When branch_a deletes a parent directory and branch_b modifies a
        // file inside that directory, conflict detection should flag both if
        // they touch the same path. OverlayFS represents directory deletion
        // as a whiteout on the directory path itself.
        let mut detector = ConflictDetector::new();
        let branch_a = BranchId::from("a".to_string());
        let branch_b = BranchId::from("b".to_string());
        let base = PathBuf::from("/base");

        // branch_a deletes the directory entry "src/subdir"
        let delete_dir = FileChange {
            path: PathBuf::from("src/subdir"),
            kind: FileChangeKind::Deleted,
            size: 0,
            checksum: "".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        };
        // branch_b also touches "src/subdir" (e.g., modifying a file causes
        // OverlayFS copy-up of the directory — tracked at the same path)
        let modify_in_dir = FileChange {
            path: PathBuf::from("src/subdir"),
            kind: FileChangeKind::Modified,
            size: 4096,
            checksum: "dir_hash".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        };

        detector.register_changes(&branch_a, &base, &[delete_dir]);
        detector.register_changes(&branch_b, &base, std::slice::from_ref(&modify_in_dir));

        let conflicts = detector.check_conflicts(&branch_b, &base, &[modify_in_dir]);
        assert_eq!(
            conflicts.len(),
            1,
            "parent directory deletion vs modification should conflict"
        );
        assert_eq!(conflicts[0].kind, ConflictKind::ModifiedAndDeleted);
    }

    #[test]
    fn test_bounded_memory_max_committed_records() {
        // C1: cleanup_old_committed enforces a hard cap of 1000 entries.
        // After inserting more than 1000, cleanup should evict the oldest.
        let mut detector = ConflictDetector::new();

        let base_time = chrono::Utc::now();
        for i in 0..1200 {
            let branch_id = BranchId::from(format!("branch-{}", i));
            let commit_time = base_time + chrono::Duration::seconds(i as i64);
            detector.mark_committed(
                &branch_id,
                vec![PathBuf::from(format!("file_{}.txt", i))],
                commit_time,
            );
        }
        assert_eq!(
            detector.committed_changes.len(),
            1200,
            "should have 1200 entries before cleanup"
        );

        // Cleanup with a very long max_age so age-based eviction does not apply;
        // only the size cap should take effect.
        detector.cleanup_old_committed(chrono::Duration::hours(999));

        assert_eq!(
            detector.committed_changes.len(),
            1000,
            "C1: committed_changes should be capped at 1000 after cleanup"
        );

        // The oldest 200 entries (branch-0 through branch-199) should have been evicted.
        // The newest 1000 (branch-200 through branch-1199) should remain.
        assert!(
            !detector.committed_changes.contains_key("branch-0"),
            "oldest entry should be evicted"
        );
        assert!(
            detector.committed_changes.contains_key("branch-1199"),
            "newest entry should be retained"
        );
    }
}
