// SPDX-License-Identifier: Apache-2.0
//! Integration test: WAL crash recovery at BranchManager level.
//!
//! Simulates crashes during commit by writing partial WAL entries,
//! then verifies recovery logic correctly identifies incomplete commits.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use puzzled_types::BranchId;

/// Write a JSON line with CRC32 checksum in the format: {json}\t{crc32_hex}
/// M-wal2: All WAL entries must have valid CRC.
fn write_wal_line(file: &mut fs::File, value: &serde_json::Value) {
    let json = serde_json::to_string(value).unwrap();
    let crc = crc32fast::hash(json.as_bytes());
    writeln!(file, "{}\t{:08x}", json, crc).unwrap();
}

/// Helper to create a WAL directory with a partial commit entry.
fn write_partial_wal(wal_dir: &std::path::Path, branch_id: &BranchId) {
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

    let op_complete = serde_json::json!({
        "OperationComplete": {
            "branch_id": branch_id.as_str(),
            "index": 0
        }
    });

    let mut file = fs::File::create(&wal_path).unwrap();
    write_wal_line(&mut file, &intent);
    write_wal_line(&mut file, &op_complete);
    // Deliberately omit CommitComplete — simulating crash
    file.sync_all().unwrap();
}

/// Helper to create a complete WAL entry.
fn write_complete_wal(wal_dir: &std::path::Path, branch_id: &BranchId) {
    fs::create_dir_all(wal_dir).unwrap();
    let wal_path = wal_dir.join(format!("{}.wal", branch_id));

    let intent = serde_json::json!({
        "CommitIntent": {
            "branch_id": branch_id.as_str(),
            "operations": [
                {"CopyFile": {"from": "/src/a.txt", "to": "/dst/a.txt"}}
            ]
        }
    });
    let op_complete = serde_json::json!({
        "OperationComplete": {"branch_id": branch_id.as_str(), "index": 0}
    });
    let commit_complete = serde_json::json!({
        "CommitComplete": {"branch_id": branch_id.as_str()}
    });

    let mut file = fs::File::create(&wal_path).unwrap();
    write_wal_line(&mut file, &intent);
    write_wal_line(&mut file, &op_complete);
    write_wal_line(&mut file, &commit_complete);
    file.sync_all().unwrap();
}

#[test]
fn test_wal_recovery_identifies_incomplete_commit() {
    let dir = tempfile::tempdir().unwrap();
    let wal_dir = dir.path().join("wal");

    let branch = BranchId::from("crash-branch-1".to_string());
    write_partial_wal(&wal_dir, &branch);

    let wal = puzzled::wal::WriteAheadLog::new(wal_dir);
    let incomplete = wal.recover().unwrap();

    assert_eq!(incomplete.len(), 1);
    assert_eq!(incomplete[0].as_str(), "crash-branch-1");
}

#[test]
fn test_wal_recovery_ignores_complete_commits() {
    let dir = tempfile::tempdir().unwrap();
    let wal_dir = dir.path().join("wal");

    let branch = BranchId::from("complete-branch-1".to_string());
    write_complete_wal(&wal_dir, &branch);

    let wal = puzzled::wal::WriteAheadLog::new(wal_dir);
    let incomplete = wal.recover().unwrap();

    assert!(incomplete.is_empty());
}

#[test]
fn test_wal_recovery_mixed_complete_and_incomplete() {
    let dir = tempfile::tempdir().unwrap();
    let wal_dir = dir.path().join("wal");

    let complete = BranchId::from("done-branch".to_string());
    let incomplete = BranchId::from("crash-branch".to_string());

    write_complete_wal(&wal_dir, &complete);
    write_partial_wal(&wal_dir, &incomplete);

    let wal = puzzled::wal::WriteAheadLog::new(wal_dir);
    let result = wal.recover().unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].as_str(), "crash-branch");
}

#[test]
fn test_wal_recovery_empty_directory() {
    let dir = tempfile::tempdir().unwrap();
    let wal_dir = dir.path().join("wal");
    fs::create_dir_all(&wal_dir).unwrap();

    let wal = puzzled::wal::WriteAheadLog::new(wal_dir);
    let incomplete = wal.recover().unwrap();

    assert!(incomplete.is_empty());
}

#[test]
fn test_wal_recovery_nonexistent_directory() {
    let dir = tempfile::tempdir().unwrap();
    let wal_dir = dir.path().join("nonexistent_wal");

    let wal = puzzled::wal::WriteAheadLog::new(wal_dir);
    let incomplete = wal.recover().unwrap();

    assert!(incomplete.is_empty());
}

#[test]
fn test_wal_full_lifecycle_then_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let wal_dir = dir.path().to_path_buf();

    let wal = puzzled::wal::WriteAheadLog::new(wal_dir.clone());
    let branch = BranchId::new();

    // Complete lifecycle
    let ops = vec![puzzled::wal::WalOperation::CopyFile {
        from: PathBuf::from("/src/file.txt"),
        to: PathBuf::from("/dst/file.txt"),
    }];

    wal.begin_commit(&branch, ops).unwrap();
    wal.mark_operation_complete(&branch, 0).unwrap();
    wal.mark_commit_complete(&branch).unwrap();

    // Recovery should find nothing
    let wal2 = puzzled::wal::WriteAheadLog::new(wal_dir);
    let incomplete = wal2.recover().unwrap();
    assert!(incomplete.is_empty());
}
