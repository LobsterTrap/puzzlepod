// SPDX-License-Identifier: Apache-2.0
//! Integration test: WAL recovery execution.
//!
//! Tests that WAL recovery actually reverses incomplete operations. Creates
//! a WAL with partial operations, runs recovery with backups, and verifies
//! that files are correctly restored or removed.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use puzzled_types::BranchId;

use puzzled::wal::{WalOperation, WriteAheadLog};

// ---------------------------------------------------------------------------
// T6: WAL recovery reverses incomplete CopyFile operations
// ---------------------------------------------------------------------------

#[test]
fn test_wal_recovery_reverses_copy_with_backup() {
    let dir = tempfile::tempdir().unwrap();
    let wal_dir = dir.path().join("wal");
    let wal = WriteAheadLog::new(wal_dir.clone());
    let branch = BranchId::from("recovery-copy".to_string());

    // Set up: a target file that existed before the commit
    let target_path = dir.path().join("target.txt");
    fs::write(&target_path, "original content").unwrap();

    // Create a backup of the original file via WAL
    let backup = wal.backup_file(&branch, &target_path).unwrap().unwrap();
    assert!(backup.existed);
    assert!(backup.backup_path.exists());

    // Simulate a partial commit: the CopyFile operation completed
    // (overwrote the target), but the commit was not finalized.
    fs::write(&target_path, "committed content -- should be reverted").unwrap();

    let operations = vec![WalOperation::CopyFile {
        from: PathBuf::from("/src/file.txt"),
        to: target_path.clone(),
    }];

    // Record the WAL entries
    wal.begin_commit(&branch, operations.clone()).unwrap();
    wal.mark_operation_complete(&branch, 0).unwrap();
    // Deliberately do NOT call mark_commit_complete -- simulating a crash

    // Verify recovery identifies the incomplete commit
    let incomplete = wal.recover().unwrap();
    assert_eq!(incomplete.len(), 1);
    assert_eq!(incomplete[0].as_str(), "recovery-copy");

    // Read operations and completion status
    let (ops, completed) = wal.read_operations_with_status(&branch).unwrap();
    assert_eq!(ops.len(), 1);
    assert!(completed.contains(&0));

    // Execute recovery: reverse completed operations
    wal.reverse_operations(&branch, &ops, &completed).unwrap();

    // Verify the target file was restored to its original content
    let restored = fs::read_to_string(&target_path).unwrap();
    assert_eq!(
        restored, "original content",
        "file should be restored to pre-commit state"
    );
}

#[test]
fn test_wal_recovery_reverses_copy_no_preexisting_file() {
    let dir = tempfile::tempdir().unwrap();
    let wal_dir = dir.path().join("wal");
    let wal = WriteAheadLog::new(wal_dir.clone());
    let branch = BranchId::from("recovery-new-file".to_string());

    // Target file did not exist before the commit
    let target_path = dir.path().join("new_file.txt");

    // Create a backup (file does not exist)
    let backup = wal.backup_file(&branch, &target_path).unwrap().unwrap();
    assert!(!backup.existed);

    // Simulate the commit writing a new file
    fs::write(&target_path, "should be deleted on recovery").unwrap();

    let operations = vec![WalOperation::CopyFile {
        from: PathBuf::from("/src/new.txt"),
        to: target_path.clone(),
    }];

    wal.begin_commit(&branch, operations.clone()).unwrap();
    wal.mark_operation_complete(&branch, 0).unwrap();

    // Read operations with status (before full recovery cycle)
    let (ops, completed) = wal.read_operations_with_status(&branch).unwrap();

    // Execute recovery
    wal.reverse_operations(&branch, &ops, &completed).unwrap();

    // File should be deleted (it did not exist before the commit)
    assert!(
        !target_path.exists(),
        "new file should be removed during recovery"
    );
}

// ---------------------------------------------------------------------------
// T6: WAL recovery reverses incomplete DeleteFile operations
// ---------------------------------------------------------------------------

#[test]
fn test_wal_recovery_reverses_delete_with_backup() {
    let dir = tempfile::tempdir().unwrap();
    let wal_dir = dir.path().join("wal");
    let wal = WriteAheadLog::new(wal_dir.clone());
    let branch = BranchId::from("recovery-delete".to_string());

    // Set up: a file that existed before the commit
    let deleted_path = dir.path().join("will_be_deleted.txt");
    fs::write(&deleted_path, "precious data").unwrap();

    // Create a backup of the file before deletion
    let backup = wal.backup_file(&branch, &deleted_path).unwrap().unwrap();
    assert!(backup.existed);

    // Simulate the commit deleting the file
    fs::remove_file(&deleted_path).unwrap();
    assert!(!deleted_path.exists());

    let operations = vec![WalOperation::DeleteFile {
        path: deleted_path.clone(),
    }];

    wal.begin_commit(&branch, operations.clone()).unwrap();
    wal.mark_operation_complete(&branch, 0).unwrap();

    let (ops, completed) = wal.read_operations_with_status(&branch).unwrap();

    // Execute recovery
    wal.reverse_operations(&branch, &ops, &completed).unwrap();

    // Verify the file was restored
    assert!(
        deleted_path.exists(),
        "deleted file should be restored during recovery"
    );
    let content = fs::read_to_string(&deleted_path).unwrap();
    assert_eq!(content, "precious data");
}

// ---------------------------------------------------------------------------
// T6: WAL recovery with multiple operations (partial completion)
// ---------------------------------------------------------------------------

#[test]
fn test_wal_recovery_partial_multi_operation() {
    let dir = tempfile::tempdir().unwrap();
    let wal_dir = dir.path().join("wal");
    let wal = WriteAheadLog::new(wal_dir.clone());
    let branch = BranchId::from("recovery-multi".to_string());

    // Set up files
    let file_a = dir.path().join("file_a.txt");
    let file_b = dir.path().join("file_b.txt");
    let file_c = dir.path().join("file_c.txt");

    fs::write(&file_a, "original A").unwrap();
    fs::write(&file_b, "original B").unwrap();
    // file_c does not exist

    // Create backups
    wal.backup_file(&branch, &file_a).unwrap();
    wal.backup_file(&branch, &file_b).unwrap();
    wal.backup_file(&branch, &file_c).unwrap(); // does not exist

    let operations = vec![
        WalOperation::CopyFile {
            from: PathBuf::from("/src/a.txt"),
            to: file_a.clone(),
        },
        WalOperation::DeleteFile {
            path: file_b.clone(),
        },
        WalOperation::CopyFile {
            from: PathBuf::from("/src/c.txt"),
            to: file_c.clone(),
        },
    ];

    wal.begin_commit(&branch, operations.clone()).unwrap();

    // Only operations 0 and 1 completed (crash before op 2)
    wal.mark_operation_complete(&branch, 0).unwrap();
    wal.mark_operation_complete(&branch, 1).unwrap();

    // Simulate the effects of completed operations
    fs::write(&file_a, "committed A").unwrap();
    fs::remove_file(&file_b).unwrap();

    let (ops, completed) = wal.read_operations_with_status(&branch).unwrap();
    assert_eq!(completed.len(), 2);
    assert!(completed.contains(&0));
    assert!(completed.contains(&1));
    assert!(!completed.contains(&2));

    // Execute recovery (only reverse completed operations)
    wal.reverse_operations(&branch, &ops, &completed).unwrap();

    // file_a should be restored to original
    assert_eq!(fs::read_to_string(&file_a).unwrap(), "original A");

    // file_b should be restored (was deleted by the commit)
    assert!(file_b.exists());
    assert_eq!(fs::read_to_string(&file_b).unwrap(), "original B");

    // file_c was never touched (operation 2 never completed)
    assert!(!file_c.exists());
}

// ---------------------------------------------------------------------------
// T6: WAL recovery is idempotent
// ---------------------------------------------------------------------------

#[test]
fn test_wal_recovery_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let wal_dir = dir.path().join("wal");
    let wal = WriteAheadLog::new(wal_dir.clone());
    let branch = BranchId::from("recovery-idempotent".to_string());

    let target = dir.path().join("target.txt");
    fs::write(&target, "original").unwrap();
    wal.backup_file(&branch, &target).unwrap();

    // Simulate committed change
    fs::write(&target, "committed").unwrap();

    let operations = vec![WalOperation::CopyFile {
        from: PathBuf::from("/src/file.txt"),
        to: target.clone(),
    }];

    wal.begin_commit(&branch, operations).unwrap();
    wal.mark_operation_complete(&branch, 0).unwrap();

    let (ops, completed) = wal.read_operations_with_status(&branch).unwrap();

    // First recovery
    wal.reverse_operations(&branch, &ops, &completed).unwrap();
    assert_eq!(fs::read_to_string(&target).unwrap(), "original");

    // Second recovery (should be a no-op; backup dir already cleaned)
    // Re-create WAL for the second pass since reverse_operations cleans up
    let wal2 = WriteAheadLog::new(wal_dir);
    let empty_completed = HashSet::new();
    wal2.reverse_operations(&branch, &ops, &empty_completed)
        .unwrap();

    // File should still be "original"
    assert_eq!(fs::read_to_string(&target).unwrap(), "original");
}

// ---------------------------------------------------------------------------
// T6: WAL recovery with empty operations
// ---------------------------------------------------------------------------

#[test]
fn test_wal_recovery_empty_operations() {
    let dir = tempfile::tempdir().unwrap();
    let wal_dir = dir.path().join("wal");
    let wal = WriteAheadLog::new(wal_dir);
    let branch = BranchId::from("recovery-empty".to_string());

    let operations: Vec<WalOperation> = vec![];
    let completed = HashSet::new();

    // Recovery with no operations should succeed
    let result = wal.reverse_operations(&branch, &operations, &completed);
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// T6: WAL recovery handles SetMetadata gracefully
// ---------------------------------------------------------------------------

#[test]
fn test_wal_recovery_set_metadata_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let wal_dir = dir.path().join("wal");
    let wal = WriteAheadLog::new(wal_dir);
    let branch = BranchId::from("recovery-metadata".to_string());

    let operations = vec![WalOperation::SetMetadata {
        path: PathBuf::from("/some/file.txt"),
    }];

    let mut completed = HashSet::new();
    completed.insert(0);

    // SetMetadata recovery is best-effort (skipped)
    let result = wal.reverse_operations(&branch, &operations, &completed);
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// T6: WAL read_operations returns CommitIntent operations
// ---------------------------------------------------------------------------

#[test]
fn test_wal_read_operations() {
    let dir = tempfile::tempdir().unwrap();
    let wal_dir = dir.path().to_path_buf();
    let wal = WriteAheadLog::new(wal_dir);
    let branch = BranchId::from("read-ops-test".to_string());

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
}

#[test]
fn test_wal_read_operations_nonexistent_branch() {
    let dir = tempfile::tempdir().unwrap();
    let wal = WriteAheadLog::new(dir.path().to_path_buf());
    let branch = BranchId::from("nonexistent".to_string());

    let ops = wal.read_operations(&branch).unwrap();
    assert!(ops.is_empty());
}
