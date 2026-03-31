// SPDX-License-Identifier: Apache-2.0
//! Integration test: Concurrent branch operations (Linux-only).
//!
//! Tests multiple simultaneous branches to verify isolation
//! and correct state management.

#![cfg(target_os = "linux")]

use std::fs;

use puzzled_types::BranchState;

mod common;

/// Multiple branches can exist simultaneously
#[test]
#[ignore] // Requires root on Linux
fn test_multiple_concurrent_branches() {
    let dir = tempfile::tempdir().unwrap();
    let base_path = dir.path().join("workspace");
    fs::create_dir_all(&base_path).unwrap();

    let manager = common::make_manager(dir.path());

    // Create 3 branches
    let b1 = manager
        .create("standard", &base_path, 1000, vec![])
        .unwrap();
    let b2 = manager
        .create("standard", &base_path, 1001, vec![])
        .unwrap();
    let b3 = manager
        .create("restricted", &base_path, 1002, vec![])
        .unwrap();

    // All should be active
    assert_eq!(b1.state, BranchState::Active);
    assert_eq!(b2.state, BranchState::Active);
    assert_eq!(b3.state, BranchState::Active);

    // List should show all 3
    let branches = manager.list();
    assert_eq!(branches.len(), 3);

    // Write different files in each branch
    fs::write(b1.upper_dir.join("from_b1.txt"), "branch 1").unwrap();
    fs::write(b2.upper_dir.join("from_b2.txt"), "branch 2").unwrap();
    fs::write(b3.upper_dir.join("from_b3.txt"), "branch 3").unwrap();

    // Commit b1, rollback b2, leave b3 active
    let r1 = manager.commit(&b1.id).unwrap();
    assert_eq!(r1.files_committed, 1);

    manager.rollback("test rollback", &b2.id).unwrap();

    // Verify isolation: only b1's file should be in base
    assert!(base_path.join("from_b1.txt").exists());
    assert!(!base_path.join("from_b2.txt").exists());
    assert!(!base_path.join("from_b3.txt").exists());

    // b3 should still be active
    let b3_info = manager.inspect(&b3.id).unwrap();
    assert_eq!(b3_info.state, BranchState::Active);
}

/// Maximum branch limit is enforced
#[test]
#[ignore] // Requires root on Linux
fn test_max_branches_enforced() {
    use std::sync::{Arc, Mutex};

    let dir = tempfile::tempdir().unwrap();
    let branch_root = dir.path().join("branches");
    let base_path = dir.path().join("workspace");
    let profiles_dir = common::profiles_dir();
    let policies_dir = common::policies_dir();

    fs::create_dir_all(&branch_root).unwrap();
    fs::create_dir_all(&base_path).unwrap();

    let config = puzzled::config::DaemonConfig {
        branch_root: branch_root.clone(),
        profiles_dir: profiles_dir.clone(),
        policies_dir: policies_dir.clone(),
        max_branches: 2, // Small limit for testing
        bus_type: puzzled::config::BusType::Session,
        fs_type: puzzled::config::FsType::Ext4,
        log_level: puzzled::config::LogLevel::Debug,
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

    // First two should succeed
    let _b1 = manager
        .create("standard", &base_path, 1000, vec![])
        .unwrap();
    let _b2 = manager
        .create("standard", &base_path, 1001, vec![])
        .unwrap();

    // Third should fail
    let result = manager.create("standard", &base_path, 1002, vec![]);
    assert!(result.is_err());
}
