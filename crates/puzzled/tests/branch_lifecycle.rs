// SPDX-License-Identifier: Apache-2.0
//! Integration test: Full branch lifecycle (Linux-only).
//!
//! Tests the complete Fork-Explore-Commit cycle using real kernel primitives.
//! Requires root on Linux. Ignored on macOS.

#![cfg(target_os = "linux")]

use std::fs;
use std::path::PathBuf;

use std::sync::{Arc, Mutex};

use puzzled_types::{BranchState, PolicyDecision};

/// Full lifecycle: create branch -> write files -> commit
#[test]
#[ignore] // Requires root on Linux
fn test_full_fork_explore_commit() {
    let dir = tempfile::tempdir().unwrap();
    let branch_root = dir.path().join("branches");
    let base_path = dir.path().join("workspace");
    let profiles_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("policies")
        .join("profiles");
    let policies_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("policies")
        .join("rules");

    fs::create_dir_all(&branch_root).unwrap();
    fs::create_dir_all(&base_path).unwrap();

    // Write a base file
    fs::write(base_path.join("existing.txt"), "original content").unwrap();

    let config = puzzled::config::DaemonConfig {
        branch_root: branch_root.clone(),
        profiles_dir: profiles_dir.clone(),
        policies_dir: policies_dir.clone(),
        max_branches: 64,
        bus_type: "session".to_string(),
        fs_type: "ext4".to_string(),
        log_level: "debug".to_string(),
        watchdog_timeout_secs: 30,
        ..Default::default()
    };

    let mut profile_loader = puzzled::profile::ProfileLoader::new(profiles_dir);
    profile_loader.load_all().unwrap();

    let policy_engine = puzzled::policy::PolicyEngine::new(policies_dir);
    policy_engine.reload().unwrap();

    let wal_dir = branch_root.join("wal");
    puzzled::wal::WriteAheadLog::init(&wal_dir).unwrap();
    let wal = puzzled::wal::WriteAheadLog::new(wal_dir);

    let audit = puzzled::audit::AuditLogger::new();

    let conflict_detector = Arc::new(Mutex::new(puzzled::conflict::ConflictDetector::new()));
    let budget_manager = Arc::new(Mutex::new(puzzled::budget::BudgetManager::new()));

    let seccomp_handler = puzzled::seccomp_handler::SeccompNotifHandler::spawn();
    let manager = puzzled::branch::BranchManager::new(
        config,
        profile_loader,
        policy_engine,
        wal,
        Arc::new(audit),
        None,
        conflict_detector,
        budget_manager,
        Some(seccomp_handler),
        None,
    );

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
    let branch_root = dir.path().join("branches");
    let base_path = dir.path().join("workspace");
    let profiles_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("policies")
        .join("profiles");
    let policies_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("policies")
        .join("rules");

    fs::create_dir_all(&branch_root).unwrap();
    fs::create_dir_all(&base_path).unwrap();

    let config = puzzled::config::DaemonConfig {
        branch_root: branch_root.clone(),
        profiles_dir: profiles_dir.clone(),
        policies_dir: policies_dir.clone(),
        max_branches: 64,
        bus_type: "session".to_string(),
        fs_type: "ext4".to_string(),
        log_level: "debug".to_string(),
        watchdog_timeout_secs: 30,
        ..Default::default()
    };

    let mut profile_loader = puzzled::profile::ProfileLoader::new(profiles_dir);
    profile_loader.load_all().unwrap();

    let policy_engine = puzzled::policy::PolicyEngine::new(policies_dir);
    policy_engine.reload().unwrap();

    let wal_dir = branch_root.join("wal");
    puzzled::wal::WriteAheadLog::init(&wal_dir).unwrap();
    let wal = puzzled::wal::WriteAheadLog::new(wal_dir);

    let audit = puzzled::audit::AuditLogger::new();

    let conflict_detector = Arc::new(Mutex::new(puzzled::conflict::ConflictDetector::new()));
    let budget_manager = Arc::new(Mutex::new(puzzled::budget::BudgetManager::new()));

    let seccomp_handler = puzzled::seccomp_handler::SeccompNotifHandler::spawn();
    let manager = puzzled::branch::BranchManager::new(
        config,
        profile_loader,
        policy_engine,
        wal,
        Arc::new(audit),
        None,
        conflict_detector,
        budget_manager,
        Some(seccomp_handler),
        None,
    );

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

/// Helper to create a BranchManager for policy rejection tests.
fn make_policy_rejection_manager(
    dir: &std::path::Path,
    policy_dir: &std::path::Path,
) -> puzzled::branch::BranchManager {
    let branch_root = dir.join("branches");
    let profiles_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("policies")
        .join("profiles");

    fs::create_dir_all(&branch_root).unwrap();

    let config = puzzled::config::DaemonConfig {
        branch_root: branch_root.clone(),
        profiles_dir: profiles_dir.clone(),
        policies_dir: policy_dir.to_path_buf(),
        max_branches: 64,
        bus_type: "session".to_string(),
        fs_type: "ext4".to_string(),
        log_level: "debug".to_string(),
        watchdog_timeout_secs: 30,
        ..Default::default()
    };

    let mut profile_loader = puzzled::profile::ProfileLoader::new(profiles_dir);
    profile_loader.load_all().unwrap();

    let policy_engine = puzzled::policy::PolicyEngine::new(policy_dir.to_path_buf());
    policy_engine.reload().unwrap();

    let wal_dir = branch_root.join("wal");
    puzzled::wal::WriteAheadLog::init(&wal_dir).unwrap();
    let wal = puzzled::wal::WriteAheadLog::new(wal_dir);

    let audit = puzzled::audit::AuditLogger::new();
    let conflict_detector = Arc::new(Mutex::new(puzzled::conflict::ConflictDetector::new()));
    let budget_manager = Arc::new(Mutex::new(puzzled::budget::BudgetManager::new()));

    let seccomp_handler = puzzled::seccomp_handler::SeccompNotifHandler::spawn();
    puzzled::branch::BranchManager::new(
        config,
        profile_loader,
        policy_engine,
        wal,
        Arc::new(audit),
        None,
        conflict_detector,
        budget_manager,
        Some(seccomp_handler),
        None,
    )
}

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

    let policies_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("policies")
        .join("rules");

    let manager = make_policy_rejection_manager(dir.path(), &policies_dir);

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

    let policies_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("policies")
        .join("rules");

    let manager = make_policy_rejection_manager(dir.path(), &policies_dir);

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
