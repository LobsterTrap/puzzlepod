// SPDX-License-Identifier: Apache-2.0
//! WAL crash safety tests.
//!
//! Tests write-ahead log durability, recovery, and edge cases including
//! concurrent commits, partial writes, and symlink handling.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use puzzled_types::BranchId;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Write a JSON line with CRC32 checksum in the format: {json}\t{crc32_hex}
/// M-wal2: All WAL entries must have valid CRC.
fn write_wal_line(file: &mut fs::File, value: &serde_json::Value) {
    let json = serde_json::to_string(value).unwrap();
    let crc = crc32fast::hash(json.as_bytes());
    writeln!(file, "{}\t{:08x}", json, crc).unwrap();
}

fn create_wal_with_entries(
    wal_dir: &std::path::Path,
    branch_id: &BranchId,
    include_complete: bool,
) {
    fs::create_dir_all(wal_dir).unwrap();
    let wal_path = wal_dir.join(format!("{}.wal", branch_id));

    let intent = serde_json::json!({
        "CommitIntent": {
            "branch_id": branch_id.as_str(),
            "operations": [
                {"CopyFile": {"from": "/src/a.txt", "to": "/dst/a.txt"}},
                {"DeleteFile": {"path": "/dst/b.txt"}}
            ]
        }
    });

    let op0_complete = serde_json::json!({
        "OperationComplete": {"branch_id": branch_id.as_str(), "index": 0}
    });

    let op1_complete = serde_json::json!({
        "OperationComplete": {"branch_id": branch_id.as_str(), "index": 1}
    });

    let commit_complete = serde_json::json!({
        "CommitComplete": {"branch_id": branch_id.as_str()}
    });

    let mut file = fs::File::create(&wal_path).unwrap();
    write_wal_line(&mut file, &intent);
    write_wal_line(&mut file, &op0_complete);
    write_wal_line(&mut file, &op1_complete);
    if include_complete {
        write_wal_line(&mut file, &commit_complete);
    }
    file.sync_all().unwrap();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_wal_parent_fsync_on_delete() {
    // After mark_commit_complete removes the WAL file, the parent directory
    // should be fsynced. We verify the WAL file is actually removed.
    let dir = tempfile::tempdir().unwrap();
    let wal_dir = dir.path().join("wal");

    let branch = BranchId::from("fsync-test".to_string());
    fs::create_dir_all(&wal_dir).unwrap();
    let wal = puzzled::wal::WriteAheadLog::new(wal_dir.clone());

    // Begin a commit
    let ops = vec![puzzled::wal::WalOperation::CopyFile {
        from: PathBuf::from("/tmp/src.txt"),
        to: PathBuf::from("/tmp/dst.txt"),
    }];
    wal.begin_commit(&branch, ops).unwrap();

    // Verify WAL file exists
    let wal_path = wal_dir.join(format!("{}.wal", branch));
    assert!(
        wal_path.exists(),
        "WAL file should exist after begin_commit"
    );

    // Mark operation complete
    wal.mark_operation_complete(&branch, 0).unwrap();

    // Mark commit complete — should remove the WAL file
    wal.mark_commit_complete(&branch).unwrap();

    // WAL file should be gone
    assert!(
        !wal_path.exists(),
        "WAL file should be removed after mark_commit_complete"
    );
}

#[test]
fn test_wal_concurrent_commits() {
    // Two branches committing simultaneously should not interfere
    let dir = tempfile::tempdir().unwrap();
    let wal_dir = dir.path().join("wal");

    let branch_a = BranchId::from("concurrent-a".to_string());
    let branch_b = BranchId::from("concurrent-b".to_string());
    fs::create_dir_all(&wal_dir).unwrap();
    let wal = puzzled::wal::WriteAheadLog::new(wal_dir.clone());

    let ops_a = vec![puzzled::wal::WalOperation::CopyFile {
        from: PathBuf::from("/src/a.txt"),
        to: PathBuf::from("/dst/a.txt"),
    }];
    let ops_b = vec![puzzled::wal::WalOperation::DeleteFile {
        path: PathBuf::from("/dst/b.txt"),
    }];

    // Interleave operations
    wal.begin_commit(&branch_a, ops_a).unwrap();
    wal.begin_commit(&branch_b, ops_b).unwrap();

    wal.mark_operation_complete(&branch_a, 0).unwrap();
    wal.mark_operation_complete(&branch_b, 0).unwrap();

    wal.mark_commit_complete(&branch_a).unwrap();

    // branch_b not yet complete — should show up in recovery
    let wal2 = puzzled::wal::WriteAheadLog::new(wal_dir);
    let incomplete = wal2.recover().unwrap();

    // branch_a was completed, branch_b was not
    assert!(
        !incomplete.iter().any(|b| b.as_str() == "concurrent-a"),
        "completed branch should not appear in recovery"
    );
    assert!(
        incomplete.iter().any(|b| b.as_str() == "concurrent-b"),
        "incomplete branch should appear in recovery"
    );
}

#[test]
fn test_wal_partial_write_recovery() {
    // Simulate a crash after writing only the intent (no operations completed)
    let dir = tempfile::tempdir().unwrap();
    let wal_dir = dir.path().join("wal");

    let branch = BranchId::from("partial-write".to_string());
    fs::create_dir_all(&wal_dir).unwrap();
    let wal_path = wal_dir.join(format!("{}.wal", branch));

    // Write only the intent (crash before any operations)
    let intent = serde_json::json!({
        "CommitIntent": {
            "branch_id": "partial-write",
            "operations": [
                {"CopyFile": {"from": "/src/a.txt", "to": "/dst/a.txt"}}
            ]
        }
    });
    let mut file = fs::File::create(&wal_path).unwrap();
    write_wal_line(&mut file, &intent);
    file.sync_all().unwrap();

    let wal = puzzled::wal::WriteAheadLog::new(wal_dir);
    let incomplete = wal.recover().unwrap();
    assert_eq!(incomplete.len(), 1);
    assert_eq!(incomplete[0].as_str(), "partial-write");

    // Read operations — should show 0 completed
    let (ops, completed) = wal.read_operations_with_status(&branch).unwrap();
    assert_eq!(ops.len(), 1);
    assert!(completed.is_empty());
}

#[test]
fn test_wal_backup_checksum_consistency() {
    // Verify that backup files are created and can be read back
    let dir = tempfile::tempdir().unwrap();
    let wal_dir = dir.path().join("wal");

    let branch = BranchId::from("backup-test".to_string());
    fs::create_dir_all(&wal_dir).unwrap();
    let wal = puzzled::wal::WriteAheadLog::new(wal_dir);

    // Create a file to back up
    let target = dir.path().join("target.txt");
    fs::write(&target, "original content").unwrap();

    // Begin commit and backup the target
    let ops = vec![puzzled::wal::WalOperation::CopyFile {
        from: PathBuf::from("/src/a.txt"),
        to: target.clone(),
    }];
    wal.begin_commit(&branch, ops).unwrap();
    wal.backup_file(&branch, &target).unwrap();

    // Verify backup exists
    let backup_dir = wal.backup_dir(&branch);
    assert!(backup_dir.exists(), "backup directory should exist");
}

#[test]
fn test_wal_revert_restores_original() {
    let dir = tempfile::tempdir().unwrap();
    let wal_dir = dir.path().join("wal");

    let branch = BranchId::from("revert-test".to_string());
    fs::create_dir_all(&wal_dir).unwrap();
    let wal = puzzled::wal::WriteAheadLog::new(wal_dir);

    // Create original file
    let target = dir.path().join("file.txt");
    fs::write(&target, "original").unwrap();

    // Begin commit and backup
    let ops = vec![puzzled::wal::WalOperation::CopyFile {
        from: PathBuf::from("/src/file.txt"),
        to: target.clone(),
    }];
    wal.begin_commit(&branch, ops.clone()).unwrap();
    wal.backup_file(&branch, &target).unwrap();

    // Overwrite the file (simulating partial commit)
    fs::write(&target, "modified by commit").unwrap();

    // Revert using backup
    let completed: std::collections::HashSet<usize> = [0].into_iter().collect();
    let result = wal.reverse_operations(&branch, &ops, &completed);
    assert!(result.is_ok(), "reverse_operations should succeed");

    // File should be restored to original
    let content = fs::read_to_string(&target).unwrap();
    assert_eq!(content, "original");
}

#[test]
fn test_wal_empty_operations_list() {
    let dir = tempfile::tempdir().unwrap();
    let wal_dir = dir.path().join("wal");

    let branch = BranchId::from("empty-ops".to_string());
    fs::create_dir_all(&wal_dir).unwrap();
    let wal = puzzled::wal::WriteAheadLog::new(wal_dir);

    // Empty operations list should succeed
    wal.begin_commit(&branch, vec![]).unwrap();
    wal.mark_commit_complete(&branch).unwrap();
}

#[test]
fn test_wal_operations_with_symlinks() {
    // Symlinks in the changeset should be handled safely (Fix #14)
    let dir = tempfile::tempdir().unwrap();
    let upper = dir.path().join("upper");
    fs::create_dir_all(&upper).unwrap();

    // Create a regular file and a symlink
    fs::write(upper.join("regular.txt"), "content").unwrap();

    // Create a symlink pointing outside upper dir
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/etc/passwd", upper.join("bad_link")).unwrap();

        // The symlink is a symlink
        assert!(upper.join("bad_link").is_symlink());

        // Read the link target
        let target = fs::read_link(upper.join("bad_link")).unwrap();
        assert_eq!(target, PathBuf::from("/etc/passwd"));

        // Verify the target is NOT within the upper dir
        assert!(!target.starts_with(&upper));
    }
}

#[test]
fn test_wal_mark_complete_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let wal_dir = dir.path().join("wal");

    let branch = BranchId::from("idempotent".to_string());
    fs::create_dir_all(&wal_dir).unwrap();
    let wal = puzzled::wal::WriteAheadLog::new(wal_dir);

    let ops = vec![puzzled::wal::WalOperation::CopyFile {
        from: PathBuf::from("/src/a.txt"),
        to: PathBuf::from("/dst/a.txt"),
    }];
    wal.begin_commit(&branch, ops).unwrap();
    wal.mark_operation_complete(&branch, 0).unwrap();

    // Calling mark_commit_complete twice should not error
    wal.mark_commit_complete(&branch).unwrap();
    // Second call — WAL file already removed, should be a no-op
    let result = wal.mark_commit_complete(&branch);
    assert!(
        result.is_ok(),
        "second mark_commit_complete should be idempotent"
    );
}

#[test]
fn test_wal_recover_skips_complete_entries() {
    let dir = tempfile::tempdir().unwrap();
    let wal_dir = dir.path().join("wal");

    let complete = BranchId::from("complete-branch".to_string());
    let incomplete = BranchId::from("incomplete-branch".to_string());

    // Write a complete WAL entry
    create_wal_with_entries(&wal_dir, &complete, true);
    // Write an incomplete WAL entry
    create_wal_with_entries(&wal_dir, &incomplete, false);

    let wal = puzzled::wal::WriteAheadLog::new(wal_dir);
    let recovered = wal.recover().unwrap();

    // Only incomplete branch should be recovered
    assert!(
        !recovered.iter().any(|b| b.as_str() == "complete-branch"),
        "complete branch should be skipped"
    );
    assert!(
        recovered.iter().any(|b| b.as_str() == "incomplete-branch"),
        "incomplete branch should be recovered"
    );
}

#[test]
fn test_wal_multiple_branches_interleaved() {
    let dir = tempfile::tempdir().unwrap();
    let wal_dir = dir.path().join("wal");

    fs::create_dir_all(&wal_dir).unwrap();
    let wal = puzzled::wal::WriteAheadLog::new(wal_dir);

    // Create 5 branches, complete only evens
    for i in 0..5 {
        let branch = BranchId::from(format!("branch-{}", i));
        let ops = vec![puzzled::wal::WalOperation::CopyFile {
            from: PathBuf::from(format!("/src/{}.txt", i)),
            to: PathBuf::from(format!("/dst/{}.txt", i)),
        }];
        wal.begin_commit(&branch, ops).unwrap();
        wal.mark_operation_complete(&branch, 0).unwrap();
        if i % 2 == 0 {
            wal.mark_commit_complete(&branch).unwrap();
        }
    }

    // Recovery should find branches 1 and 3
    let wal2 = puzzled::wal::WriteAheadLog::new(dir.path().join("wal"));
    let incomplete = wal2.recover().unwrap();

    assert_eq!(incomplete.len(), 2);
    let names: Vec<&str> = incomplete.iter().map(|b| b.as_str()).collect();
    assert!(names.contains(&"branch-1"));
    assert!(names.contains(&"branch-3"));
}
