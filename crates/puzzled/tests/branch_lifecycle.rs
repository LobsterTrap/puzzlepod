// SPDX-License-Identifier: Apache-2.0
//! Integration test: Full branch lifecycle (Linux-only).
//!
//! Tests the complete Fork-Explore-Commit cycle using real kernel primitives.
//! Requires root on Linux. Ignored on macOS.

#![cfg(target_os = "linux")]

use std::fs;
use std::path::PathBuf;

use puzzled_types::{BranchState, PolicyDecision};

mod common;

/// Full lifecycle: create branch -> write files -> commit
#[test]
#[ignore] // Requires root on Linux
fn test_full_fork_explore_commit() {
    let dir = tempfile::tempdir().unwrap();
    let base_path = dir.path().join("workspace");
    fs::create_dir_all(&base_path).unwrap();

    // Write a base file
    fs::write(base_path.join("existing.txt"), "original content").unwrap();

    let manager = common::make_manager(dir.path());

    // Fork: create a branch
    let info = manager
        .create("standard", &base_path, 1000, vec![])
        .unwrap();
    assert_eq!(info.state, BranchState::Active);
    assert!(info.pid.is_some());

    // Explore: write files inside the branch (via upper layer)
    fs::write(info.upper_dir.join("new_file.txt"), "agent wrote this").unwrap();

    // Commit: evaluate policy and apply
    let result = manager.commit(&info.id).unwrap();
    assert!(matches!(result.policy_result, PolicyDecision::Approved));
    assert_eq!(result.files_committed, 1);

    // Verify the file was committed to base
    assert!(base_path.join("new_file.txt").exists());
    let content = fs::read_to_string(base_path.join("new_file.txt")).unwrap();
    assert_eq!(content, "agent wrote this");
}

/// Test rollback discards changes
#[test]
#[ignore] // Requires root on Linux
fn test_rollback_discards_changes() {
    let dir = tempfile::tempdir().unwrap();
    let base_path = dir.path().join("workspace");
    fs::create_dir_all(&base_path).unwrap();

    let manager = common::make_manager(dir.path());

    let info = manager
        .create("standard", &base_path, 1000, vec![])
        .unwrap();

    // Write something in the branch
    fs::write(info.upper_dir.join("should_not_exist.txt"), "nope").unwrap();

    // Rollback instead of commit
    manager.rollback("test rollback", &info.id).unwrap();

    // Verify the file was NOT committed
    assert!(!base_path.join("should_not_exist.txt").exists());

    // Verify branch was cleaned up (rolled-back branches are removed from the map)
    assert!(
        manager.inspect(&info.id).is_none(),
        "rolled-back branch should be removed from branch map"
    );
}

// ---------------------------------------------------------------------------
// T7: Policy rejection -> rollback flow
// ---------------------------------------------------------------------------

// make_policy_rejection_manager is now common::make_manager_with_policies

/// Test that OPA policy rejection causes proper branch rollback and cleanup.
///
/// Creates a branch, writes files that violate the commit policy (e.g., a
/// .env file containing secrets), attempts commit, and verifies:
/// 1. The commit is rejected with specific violation rules
/// 2. The branch transitions to RolledBack state
/// 3. No changes are applied to the base filesystem
/// 4. The upper layer is cleaned up
#[test]
#[ignore] // Requires root on Linux
fn test_policy_rejection_triggers_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let base_path = dir.path().join("workspace");
    fs::create_dir_all(&base_path).unwrap();

    let policies_dir = common::policies_dir();

    let manager = common::make_manager_with_policies(dir.path(), &policies_dir);

    // Create a branch
    let info = manager
        .create("standard", &base_path, 1000, vec![])
        .unwrap();
    assert_eq!(info.state, BranchState::Active);

    // Write a policy-violating file (sensitive .env file)
    fs::write(info.upper_dir.join(".env"), "SECRET_KEY=abc123").unwrap();

    // Attempt to commit — should be rejected by the no_sensitive_files policy
    let result = manager.commit(&info.id).unwrap();
    match result.policy_result {
        PolicyDecision::Rejected(violations) => {
            assert!(
                !violations.is_empty(),
                "should have at least one policy violation"
            );
            assert!(
                violations.iter().any(|v| v.rule == "no_sensitive_files"),
                "should include no_sensitive_files violation, got: {:?}",
                violations
            );
        }
        PolicyDecision::Approved => {
            panic!("commit with .env file should have been rejected by policy");
        }
        PolicyDecision::Error(e) => {
            panic!("unexpected policy error: {e}");
        }
    }

    // Verify the .env file was NOT committed to the base filesystem
    assert!(
        !base_path.join(".env").exists(),
        ".env file should not exist in base after policy rejection"
    );

    // Branch should be rolled back and removed from the map
    assert!(
        manager.inspect(&info.id).is_none(),
        "rolled-back branch should be removed from branch map"
    );
}

/// Test that policy rejection with system file modification triggers rollback.
#[test]
#[ignore] // Requires root on Linux
fn test_policy_rejection_system_files() {
    let dir = tempfile::tempdir().unwrap();
    let base_path = dir.path().join("workspace");
    fs::create_dir_all(&base_path).unwrap();

    let policies_dir = common::policies_dir();

    let manager = common::make_manager_with_policies(dir.path(), &policies_dir);

    let info = manager
        .create("standard", &base_path, 1000, vec![])
        .unwrap();

    // Write to a system path (should be rejected by no_system_modifications)
    let usr_bin_dir = info.upper_dir.join("usr").join("bin");
    fs::create_dir_all(&usr_bin_dir).unwrap();
    fs::write(usr_bin_dir.join("evil_binary"), "#!/bin/sh\necho pwned").unwrap();

    let result = manager.commit(&info.id).unwrap();
    match result.policy_result {
        PolicyDecision::Rejected(violations) => {
            assert!(
                violations
                    .iter()
                    .any(|v| v.rule == "no_system_modifications"),
                "should reject system file modifications, got: {:?}",
                violations
            );
        }
        PolicyDecision::Approved => {
            panic!("commit with /usr/bin file should have been rejected");
        }
        PolicyDecision::Error(e) => {
            panic!("unexpected policy error: {e}");
        }
    }

    // Verify base is untouched
    assert!(
        !base_path.join("usr/bin/evil_binary").exists(),
        "system file should not be committed"
    );
}

/// Test that policy rejection with no loaded policies fails closed.
#[test]
fn test_policy_rejection_no_policies_loaded() {
    // This test exercises the fail-closed behavior of the policy engine
    // when no policies are loaded (cross-platform, no kernel features needed).
    let empty_dir = tempfile::tempdir().unwrap();

    let policy_engine = puzzled::policy::PolicyEngine::new(empty_dir.path().to_path_buf());
    policy_engine.reload().unwrap();
    assert_eq!(policy_engine.policy_count(), 0);

    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("safe_file.txt"),
        kind: puzzled_types::FileChangeKind::Added,
        size: 100,
        checksum: "abc123".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
        entropy: None,
        has_base64_blocks: None,
    }];

    let decision = policy_engine.evaluate(&changes, None).unwrap();
    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(
                violations.iter().any(|v| v.rule == "no_policies_loaded"),
                "should fail closed with no_policies_loaded, got: {:?}",
                violations
            );
        }
        PolicyDecision::Approved => {
            panic!("empty policy engine should reject (fail-closed)");
        }
        PolicyDecision::Error(e) => {
            panic!("unexpected policy error: {e}");
        }
    }
}
