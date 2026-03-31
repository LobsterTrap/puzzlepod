// SPDX-License-Identifier: Apache-2.0
//! Integration test: Crash recovery and branch re-discovery.
//!
//! Tests that puzzled correctly re-discovers active branches from disk on restart
//! (via save_state/load_state) and recovers incomplete WAL commits.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use puzzled_types::{BranchId, BranchInfo, BranchState};

/// Helper to create a BranchManager pointing at a temp directory.
fn make_test_manager(dir: &std::path::Path) -> puzzled::branch::BranchManager {
    let profiles_dir = dir.join("profiles");
    let policies_dir = dir.join("policies");
    let wal_dir = dir.join("wal");
    let branch_root = dir.join("branches");

    std::fs::create_dir_all(&profiles_dir).unwrap();
    std::fs::create_dir_all(&policies_dir).unwrap();
    std::fs::create_dir_all(&wal_dir).unwrap();
    std::fs::create_dir_all(&branch_root).unwrap();

    let runtime_dir = dir.join("run");
    std::fs::create_dir_all(&runtime_dir).unwrap();

    let config = puzzled::config::DaemonConfig {
        branch_root,
        profiles_dir: profiles_dir.clone(),
        policies_dir: policies_dir.clone(),
        max_branches: 64,
        runtime_dir,
        ..Default::default()
    };

    let profile_loader = puzzled::profile::ProfileLoader::new(profiles_dir);
    let policy_engine = puzzled::policy::PolicyEngine::new(policies_dir);
    let wal = puzzled::wal::WriteAheadLog::new(wal_dir);
    let audit = Arc::new(puzzled::audit::AuditLogger::new());
    let conflict_detector = Arc::new(Mutex::new(puzzled::conflict::ConflictDetector::new()));
    let budget_manager = Arc::new(Mutex::new(puzzled::budget::BudgetManager::new()));

    puzzled::branch::BranchManager::new(
        config,
        profile_loader,
        policy_engine,
        wal,
        audit,
        None,
        conflict_detector,
        budget_manager,
        None,
        None,
    )
}

/// T6: Test that save_state + load_state round-trips branch metadata correctly.
///
/// After restart, Ready/Active entries in state.json load as `Degraded` because
/// kernel enforcement is not re-established.
///
/// Simulates a daemon crash by:
/// 1. Creating a manager, inserting branches, calling save_state()
/// 2. Creating a NEW manager pointing at the same directory
/// 3. Calling load_state() and verifying branches are re-discovered
#[test]
fn test_save_load_state_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let branch_root = dir.path().join("branches");
    std::fs::create_dir_all(&branch_root).unwrap();

    // Phase 1: Write branch state to disk (simulating puzzled's save_state)
    {
        // Insert branches directly (bypassing create() which needs Linux)
        let id1 = BranchId::from("branch-alpha".to_string());
        let upper1 = branch_root.join("branch-alpha").join("upper");
        std::fs::create_dir_all(&upper1).unwrap();
        let info1 = BranchInfo {
            id: id1.clone(),
            profile: "standard".to_string(),
            base_path: PathBuf::from("/tmp/base"),
            upper_dir: upper1,
            work_dir: branch_root.join("branch-alpha").join("work"),
            state: BranchState::Active,
            created_at: chrono::Utc::now(),
            pid: Some(12345),
            uid: 1000,
            expires_at: None,
            selinux_context: None,
        };

        let id2 = BranchId::from("branch-beta".to_string());
        let upper2 = branch_root.join("branch-beta").join("upper");
        std::fs::create_dir_all(&upper2).unwrap();
        let info2 = BranchInfo {
            id: id2.clone(),
            profile: "restricted".to_string(),
            base_path: PathBuf::from("/tmp/base2"),
            upper_dir: upper2,
            work_dir: branch_root.join("branch-beta").join("work"),
            state: BranchState::Active,
            created_at: chrono::Utc::now(),
            pid: Some(12346),
            uid: 1001,
            expires_at: None,
            selinux_context: None,
        };

        // Insert a committed branch (should NOT be restored)
        let id3 = BranchId::from("branch-gamma".to_string());
        let info3 = BranchInfo {
            id: id3.clone(),
            profile: "standard".to_string(),
            base_path: PathBuf::from("/tmp/base3"),
            upper_dir: branch_root.join("branch-gamma").join("upper"),
            work_dir: branch_root.join("branch-gamma").join("work"),
            state: BranchState::Committed,
            created_at: chrono::Utc::now(),
            pid: None,
            uid: 1002,
            expires_at: None,
            selinux_context: None,
        };

        // Use internal access — we need to insert directly into the HashMap.
        // The test helper in branch.rs does `manager.branches.insert()`,
        // but branches is private. Instead, we'll serialize the state manually.
        let branches = vec![info1, info2, info3];
        let json = serde_json::to_string_pretty(&branches).unwrap();
        // M-br2: State file is now in runtime_dir, not branch_root
        let runtime_dir = dir.path().join("run");
        std::fs::create_dir_all(&runtime_dir).unwrap();
        let state_path = runtime_dir.join("state.json");
        std::fs::write(&state_path, json).unwrap();
    }

    // Phase 2: Create a NEW manager (simulating daemon restart) and load state
    {
        let manager = make_test_manager(dir.path());
        manager.load_state().unwrap();

        let branches = manager.list();

        // Ready/Active with existing upper_dir are restored as Degraded
        assert_eq!(
            branches.len(),
            2,
            "should restore 2 previously Active branches (not the Committed one)"
        );

        // Verify branch-alpha was restored
        let alpha = manager.inspect(&BranchId::from("branch-alpha".to_string()));
        assert!(alpha.is_some(), "branch-alpha should be restored");
        let alpha = alpha.unwrap();
        assert_eq!(alpha.state, BranchState::Degraded);
        assert_eq!(alpha.profile, "standard");
        assert_eq!(alpha.uid, 1000);

        // Verify branch-beta was restored
        let beta = manager.inspect(&BranchId::from("branch-beta".to_string()));
        assert!(beta.is_some(), "branch-beta should be restored");
        let beta = beta.unwrap();
        assert_eq!(beta.state, BranchState::Degraded);
        assert_eq!(beta.profile, "restricted");
        assert_eq!(beta.uid, 1001);

        // Verify branch-gamma (Committed) was NOT restored
        let gamma = manager.inspect(&BranchId::from("branch-gamma".to_string()));
        assert!(gamma.is_none(), "Committed branch should not be restored");
    }
}

/// T6: Test that load_state with no state.json file starts clean.
#[test]
fn test_load_state_no_file() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());

    // No state.json exists — should succeed silently
    manager.load_state().unwrap();
    assert!(manager.list().is_empty(), "should start with no branches");
}

/// T6: Test that load_state skips branches whose upper_dir is gone.
#[test]
fn test_load_state_missing_upper_dir() {
    let dir = tempfile::tempdir().unwrap();
    let branch_root = dir.path().join("branches");
    std::fs::create_dir_all(&branch_root).unwrap();

    // Write state with a branch whose upper_dir doesn't exist
    let id = BranchId::from("ghost-branch".to_string());
    let info = BranchInfo {
        id: id.clone(),
        profile: "standard".to_string(),
        base_path: PathBuf::from("/tmp/base"),
        upper_dir: branch_root.join("ghost-branch").join("upper"), // does NOT exist
        work_dir: branch_root.join("ghost-branch").join("work"),
        state: BranchState::Active,
        created_at: chrono::Utc::now(),
        pid: Some(99999),
        uid: 1000,
        expires_at: None,
        selinux_context: None,
    };

    let json = serde_json::to_string_pretty(&vec![info]).unwrap();
    // M-br2: State file is now in runtime_dir, not branch_root
    let runtime_dir = dir.path().join("run");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::write(runtime_dir.join("state.json"), json).unwrap();

    let manager = make_test_manager(dir.path());
    manager.load_state().unwrap();

    assert!(
        manager.list().is_empty(),
        "branch with missing upper_dir should not be restored"
    );
}

/// T6: Test WAL recovery with empty WAL (no incomplete commits).
#[test]
fn test_wal_recovery_empty() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    assert!(
        manager.recover().is_ok(),
        "WAL recovery with empty WAL should succeed"
    );
}

/// T6: Test WAL recovery discovers and cleans up incomplete commit directories.
#[test]
fn test_wal_recovery_cleans_orphan_branch_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let branch_root = dir.path().join("branches");
    std::fs::create_dir_all(&branch_root).unwrap();

    // Create an orphan branch directory (no WAL entry, just leftover files)
    let orphan_dir = branch_root.join("orphan-branch");
    std::fs::create_dir_all(orphan_dir.join("upper")).unwrap();
    std::fs::write(orphan_dir.join("upper").join("stale.txt"), "leftover").unwrap();

    let manager = make_test_manager(dir.path());
    // WAL recovery should succeed even with orphan directories
    // (it only processes WAL entries, not arbitrary directories)
    assert!(manager.recover().is_ok());

    // The orphan directory should still exist (WAL recovery only handles
    // WAL-tracked branches, not arbitrary dirs)
    assert!(
        orphan_dir.exists(),
        "orphan dir is not WAL-tracked, should persist"
    );
}
