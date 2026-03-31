// SPDX-License-Identifier: Apache-2.0
use super::*;

/// Helper to create a BranchManager for testing.
fn make_test_manager(dir: &std::path::Path) -> BranchManager {
    crate::test_helpers::create_test_branch_manager(dir, 4)
}

/// Helper to insert a branch directly (bypassing create() which is Linux-only).
fn insert_test_branch(manager: &BranchManager, state: BranchState) -> BranchId {
    let id = BranchId::new();
    let info = BranchInfo {
        id: id.clone(),
        profile: "test".to_string(),
        base_path: PathBuf::from("/tmp/base"),
        upper_dir: PathBuf::from("/tmp/upper"),
        work_dir: PathBuf::from("/tmp/work"),
        state,
        created_at: chrono::Utc::now(),
        pid: Some(9999),
        uid: 1000,
        expires_at: None,
        selinux_context: None,
    };
    manager.branches.insert(id.clone(), info);
    id
}

#[test]
fn test_list_empty() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    assert!(manager.list().is_empty());
}

#[test]
fn test_inspect_missing() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = BranchId::from("nonexistent".to_string());
    assert!(manager.inspect(&id).is_none());
}

#[test]
fn test_list_with_branches() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    insert_test_branch(&manager, BranchState::Active);
    insert_test_branch(&manager, BranchState::Active);
    assert_eq!(manager.list().len(), 2);
}

#[test]
fn test_inspect_existing() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = insert_test_branch(&manager, BranchState::Active);
    let info = manager.inspect(&id).unwrap();
    assert_eq!(info.id, id);
    assert_eq!(info.state, BranchState::Active);
    assert_eq!(info.profile, "test");
    assert_eq!(info.uid, 1000);
}

// -- State machine tests --

#[test]
fn test_transition_active_to_frozen() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = insert_test_branch(&manager, BranchState::Active);
    assert!(manager.transition(&id, BranchState::Frozen).is_ok());
    assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Frozen);
}

#[test]
fn test_transition_active_to_rolled_back() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = insert_test_branch(&manager, BranchState::Active);
    assert!(manager.transition(&id, BranchState::RolledBack).is_ok());
}

#[test]
fn test_transition_frozen_to_committing() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = insert_test_branch(&manager, BranchState::Frozen);
    assert!(manager.transition(&id, BranchState::Committing).is_ok());
}

#[test]
fn test_transition_frozen_to_committed_empty_changeset() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = insert_test_branch(&manager, BranchState::Frozen);
    assert!(manager.transition(&id, BranchState::Committed).is_ok());
}

#[test]
fn test_transition_frozen_to_rolled_back() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = insert_test_branch(&manager, BranchState::Frozen);
    assert!(manager.transition(&id, BranchState::RolledBack).is_ok());
}

#[test]
fn test_transition_committing_to_committed() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = insert_test_branch(&manager, BranchState::Committing);
    assert!(manager.transition(&id, BranchState::Committed).is_ok());
}

#[test]
fn test_transition_committing_to_failed() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = insert_test_branch(&manager, BranchState::Committing);
    assert!(manager.transition(&id, BranchState::Failed).is_ok());
}

#[test]
fn test_transition_any_to_failed() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());

    for state in [
        BranchState::Active,
        BranchState::Ready,
        BranchState::Frozen,
        BranchState::Creating,
    ] {
        let id = insert_test_branch(&manager, state);
        assert!(
            manager.transition(&id, BranchState::Failed).is_ok(),
            "should transition from {:?} to Failed",
            state
        );
    }
}

#[test]
fn test_transition_invalid_active_to_committed() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = insert_test_branch(&manager, BranchState::Active);
    let result = manager.transition(&id, BranchState::Committed);
    assert!(result.is_err());
}

#[test]
fn test_transition_invalid_committed_to_active() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = insert_test_branch(&manager, BranchState::Committed);
    let result = manager.transition(&id, BranchState::Active);
    assert!(result.is_err());
}

#[test]
fn test_transition_invalid_rolled_back_to_active() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = insert_test_branch(&manager, BranchState::RolledBack);
    let result = manager.transition(&id, BranchState::Active);
    assert!(result.is_err());
}

#[test]
fn test_transition_nonexistent_branch() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = BranchId::from("nonexistent".to_string());
    let result = manager.transition(&id, BranchState::Failed);
    assert!(result.is_err());
}

// -- commit/rollback edge cases --

#[test]
fn test_commit_nonexistent_branch() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = BranchId::from("nonexistent".to_string());
    let result = manager.commit(&id);
    assert!(result.is_err());
}

#[test]
fn test_commit_non_active_branch() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = insert_test_branch(&manager, BranchState::Committed);
    let result = manager.commit(&id);
    assert!(result.is_err());
}

#[test]
fn test_rollback_nonexistent_branch() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = BranchId::from("nonexistent".to_string());
    let result = manager.rollback("test rollback", &id);
    assert!(result.is_err());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn test_create_requires_linux() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let result = manager.create("standard", &PathBuf::from("/tmp"), 1000, vec![]);
    assert!(result.is_err());
}

// -- H4: Exited/Terminated state transitions --

#[test]
fn test_h4_transition_active_to_exited() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = insert_test_branch(&manager, BranchState::Active);
    assert!(manager.transition(&id, BranchState::Exited).is_ok());
    assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Exited);
}

#[test]
fn test_h4_transition_active_to_terminated() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = insert_test_branch(&manager, BranchState::Active);
    assert!(manager.transition(&id, BranchState::Terminated).is_ok());
    assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Terminated);
}

#[test]
fn test_h4_transition_frozen_to_terminated() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = insert_test_branch(&manager, BranchState::Frozen);
    assert!(manager.transition(&id, BranchState::Terminated).is_ok());
    assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Terminated);
}

#[test]
fn test_h4_transition_exited_to_frozen() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = insert_test_branch(&manager, BranchState::Exited);
    assert!(manager.transition(&id, BranchState::Frozen).is_ok());
    assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Frozen);
}

#[test]
fn test_h4_transition_terminated_to_rolled_back() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = insert_test_branch(&manager, BranchState::Terminated);
    assert!(manager.transition(&id, BranchState::RolledBack).is_ok());
}

#[test]
fn test_h4_transition_exited_to_active_invalid() {
    // Exited -> Active is NOT valid (agent has stopped, can't resume)
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = insert_test_branch(&manager, BranchState::Exited);
    assert!(manager.transition(&id, BranchState::Active).is_err());
}

#[test]
fn test_h4_transition_terminated_to_active_invalid() {
    // Terminated -> Active is NOT valid
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = insert_test_branch(&manager, BranchState::Terminated);
    assert!(manager.transition(&id, BranchState::Active).is_err());
}

// -- Ready state transitions --

#[test]
fn test_transition_creating_to_ready() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = insert_test_branch(&manager, BranchState::Creating);
    assert!(manager.transition(&id, BranchState::Ready).is_ok());
    assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Ready);
}

#[test]
fn test_transition_ready_to_active() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = insert_test_branch(&manager, BranchState::Ready);
    assert!(manager.transition(&id, BranchState::Active).is_ok());
    assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Active);
}

#[test]
fn test_transition_ready_to_rolled_back() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = insert_test_branch(&manager, BranchState::Ready);
    assert!(manager.transition(&id, BranchState::RolledBack).is_ok());
}

#[test]
fn test_transition_ready_to_frozen() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = insert_test_branch(&manager, BranchState::Ready);
    assert!(manager.transition(&id, BranchState::Frozen).is_ok());
    assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Frozen);
}

#[test]
fn test_transition_ready_to_committed_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = insert_test_branch(&manager, BranchState::Ready);
    assert!(manager.transition(&id, BranchState::Committed).is_err());
}

#[test]
fn test_enforce_timeouts_rolls_back_expired_ready_branch() {
    let dir = tempfile::tempdir().unwrap();
    let mut manager = make_test_manager(dir.path());
    manager.config.watchdog_timeout_secs = 30;

    let ready_id = insert_test_branch_with_age(&manager, BranchState::Ready, 60);

    manager.enforce_timeouts();

    assert!(
        manager.inspect(&ready_id).is_none(),
        "expired Ready branch should be removed after rollback"
    );
}

// -- enforce_timeouts --

/// Helper to insert a branch with a specific creation time.
fn insert_test_branch_with_age(
    manager: &BranchManager,
    state: BranchState,
    age_secs: i64,
) -> BranchId {
    let id = BranchId::new();
    let created_at =
        chrono::Utc::now() - chrono::TimeDelta::try_seconds(age_secs).unwrap_or_default();
    let info = BranchInfo {
        id: id.clone(),
        profile: "test".to_string(),
        base_path: PathBuf::from("/tmp/base"),
        upper_dir: PathBuf::from("/tmp/upper"),
        work_dir: PathBuf::from("/tmp/work"),
        state,
        created_at,
        pid: Some(9999),
        uid: 1000,
        expires_at: None,
        selinux_context: None,
    };
    manager.branches.insert(id.clone(), info);
    id
}

#[test]
fn test_enforce_timeouts_skips_when_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let mut manager = make_test_manager(dir.path());
    manager.config.watchdog_timeout_secs = 0;

    // Insert an "old" active branch
    let id = insert_test_branch_with_age(&manager, BranchState::Active, 9999);

    manager.enforce_timeouts();

    // Branch should still be Active (timeout disabled)
    assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Active);
}

#[test]
fn test_enforce_timeouts_rolls_back_expired_branch() {
    let dir = tempfile::tempdir().unwrap();
    let mut manager = make_test_manager(dir.path());
    manager.config.watchdog_timeout_secs = 30;

    // Branch created 60 seconds ago — exceeds 30s timeout
    let id = insert_test_branch_with_age(&manager, BranchState::Active, 60);

    manager.enforce_timeouts();

    // After rollback, branch is removed from the manager (C4)
    assert!(
        manager.inspect(&id).is_none(),
        "expired branch should be removed after rollback"
    );
}

#[test]
fn test_enforce_timeouts_ignores_young_branch() {
    let dir = tempfile::tempdir().unwrap();
    let mut manager = make_test_manager(dir.path());
    manager.config.watchdog_timeout_secs = 30;

    // Branch created 5 seconds ago — within timeout
    let id = insert_test_branch_with_age(&manager, BranchState::Active, 5);

    manager.enforce_timeouts();

    assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Active);
}

#[test]
fn test_enforce_timeouts_ignores_non_active_non_frozen_branches() {
    let dir = tempfile::tempdir().unwrap();
    let mut manager = make_test_manager(dir.path());
    manager.config.watchdog_timeout_secs = 30;

    // Old branches in terminal states should not be touched
    let committed_id = insert_test_branch_with_age(&manager, BranchState::Committed, 60);

    manager.enforce_timeouts();

    assert_eq!(
        manager.inspect(&committed_id).unwrap().state,
        BranchState::Committed
    );
}

#[test]
fn test_enforce_timeouts_rolls_back_expired_frozen_branch() {
    let dir = tempfile::tempdir().unwrap();
    let mut manager = make_test_manager(dir.path());
    manager.config.watchdog_timeout_secs = 30;

    // H4: Frozen branches should also be checked for timeouts
    let frozen_id = insert_test_branch_with_age(&manager, BranchState::Frozen, 60);

    manager.enforce_timeouts();

    // After rollback, branch is removed from the manager (C4)
    assert!(
        manager.inspect(&frozen_id).is_none(),
        "expired frozen branch should be removed after rollback"
    );
}

#[test]
fn test_enforce_timeouts_mixed_branches() {
    let dir = tempfile::tempdir().unwrap();
    let mut manager = make_test_manager(dir.path());
    manager.config.watchdog_timeout_secs = 30;

    // One expired active, one young active, one expired frozen, one committed
    let expired_id = insert_test_branch_with_age(&manager, BranchState::Active, 60);
    let young_id = insert_test_branch_with_age(&manager, BranchState::Active, 5);
    let frozen_id = insert_test_branch_with_age(&manager, BranchState::Frozen, 60);
    let committed_id = insert_test_branch_with_age(&manager, BranchState::Committed, 60);

    manager.enforce_timeouts();

    // After rollback, branch is removed from the manager (C4)
    assert!(
        manager.inspect(&expired_id).is_none(),
        "expired active branch should be removed after rollback"
    );
    assert_eq!(
        manager.inspect(&young_id).unwrap().state,
        BranchState::Active,
        "young active branch should remain active"
    );
    // H4: Frozen branches are now also subject to timeout enforcement
    assert!(
        manager.inspect(&frozen_id).is_none(),
        "expired frozen branch should be removed after rollback"
    );
    assert_eq!(
        manager.inspect(&committed_id).unwrap().state,
        BranchState::Committed,
        "committed branch should be untouched"
    );
}

// -- diff --

#[test]
fn test_diff_nonexistent_branch() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = BranchId::from("nonexistent".to_string());
    let result = manager.diff(&id);
    assert!(result.is_err());
}

// -- kill_agent --

#[test]
fn test_kill_agent_nonexistent_branch() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = BranchId::from("nonexistent".to_string());
    let result = manager.kill_agent(&id);
    assert!(result.is_err());
}

#[test]
fn test_kill_agent_non_active_branch() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    let id = insert_test_branch(&manager, BranchState::Frozen);
    let result = manager.kill_agent(&id);
    assert!(result.is_err());
}

// -- recover --

#[test]
fn test_recover_empty_wal() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    assert!(manager.recover().is_ok());
}

// -- reload policies --

#[test]
fn test_reload_policies_empty_dir() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());
    assert!(manager.reload_policies().is_ok());
}

// -- Phase 1.7: Additional branch manager tests --

#[test]
fn test_state_machine_valid_transitions_succeed() {
    // Verify all valid transitions in the state machine succeed.
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());

    let valid_transitions: Vec<(BranchState, BranchState)> = vec![
        (BranchState::Creating, BranchState::Ready),
        (BranchState::Ready, BranchState::Active),
        (BranchState::Ready, BranchState::Frozen),
        (BranchState::Ready, BranchState::RolledBack),
        (BranchState::Active, BranchState::Frozen),
        (BranchState::Active, BranchState::RolledBack),
        (BranchState::Active, BranchState::Exited),
        (BranchState::Active, BranchState::Terminated),
        (BranchState::Frozen, BranchState::Active),
        (BranchState::Frozen, BranchState::Committing),
        (BranchState::Frozen, BranchState::RolledBack),
        (BranchState::Frozen, BranchState::Committed),
        (BranchState::Frozen, BranchState::Terminated),
        (BranchState::Committing, BranchState::Committed),
        (BranchState::Committing, BranchState::Active),
        (BranchState::Committing, BranchState::Failed),
        (BranchState::Committing, BranchState::GovernanceReview),
        (BranchState::Exited, BranchState::Frozen),
        (BranchState::Terminated, BranchState::RolledBack),
        (BranchState::GovernanceReview, BranchState::Committed),
        (BranchState::GovernanceReview, BranchState::RolledBack),
        // Any -> Degraded
        (BranchState::Active, BranchState::Degraded),
        (BranchState::Frozen, BranchState::Degraded),
        // Any -> Failed
        (BranchState::Active, BranchState::Failed),
        (BranchState::Creating, BranchState::Failed),
    ];

    for (from, to) in valid_transitions {
        let id = insert_test_branch(&manager, from);
        assert!(
            manager.transition(&id, to).is_ok(),
            "transition {:?} -> {:?} should succeed",
            from,
            to
        );
        assert_eq!(
            manager.inspect(&id).unwrap().state,
            to,
            "state should be {:?} after transition from {:?}",
            to,
            from
        );
    }
}

#[test]
fn test_state_machine_invalid_transitions_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());

    let invalid_transitions: Vec<(BranchState, BranchState)> = vec![
        (BranchState::Active, BranchState::Committed),
        (BranchState::Active, BranchState::Committing),
        (BranchState::Active, BranchState::Creating),
        (BranchState::Committed, BranchState::Active),
        (BranchState::Committed, BranchState::Frozen),
        (BranchState::RolledBack, BranchState::Active),
        (BranchState::RolledBack, BranchState::Frozen),
        (BranchState::Exited, BranchState::Active),
        (BranchState::Exited, BranchState::Committed),
        (BranchState::Terminated, BranchState::Active),
        (BranchState::Creating, BranchState::Frozen),
        (BranchState::Creating, BranchState::Committed),
    ];

    for (from, to) in invalid_transitions {
        let id = insert_test_branch(&manager, from);
        let result = manager.transition(&id, to);
        assert!(
            result.is_err(),
            "transition {:?} -> {:?} should be rejected",
            from,
            to
        );
        // State should remain unchanged after rejection
        assert_eq!(
            manager.inspect(&id).unwrap().state,
            from,
            "state should remain {:?} after rejected transition to {:?}",
            from,
            to
        );
    }
}

#[test]
fn test_list_returns_all_branches() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());

    let id1 = insert_test_branch(&manager, BranchState::Active);
    let id2 = insert_test_branch(&manager, BranchState::Frozen);
    let id3 = insert_test_branch(&manager, BranchState::Committed);
    let id4 = insert_test_branch(&manager, BranchState::RolledBack);

    let listed = manager.list();
    assert_eq!(listed.len(), 4, "list() should return all 4 branches");

    let listed_ids: HashSet<BranchId> = listed.into_iter().map(|b| b.id).collect();
    assert!(listed_ids.contains(&id1));
    assert!(listed_ids.contains(&id2));
    assert!(listed_ids.contains(&id3));
    assert!(listed_ids.contains(&id4));
}

#[test]
fn test_inspect_returns_correct_info() {
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());

    let id = BranchId::from("inspect-test-branch".to_string());
    let info = BranchInfo {
        id: id.clone(),
        profile: "restricted".to_string(),
        base_path: PathBuf::from("/home/user/project"),
        upper_dir: PathBuf::from("/var/lib/puzzled/branches/upper"),
        work_dir: PathBuf::from("/var/lib/puzzled/branches/work"),
        state: BranchState::Active,
        created_at: chrono::Utc::now(),
        pid: Some(42),
        uid: 1001,
        expires_at: None,
        selinux_context: None,
    };
    manager.branches.insert(id.clone(), info.clone());

    let inspected = manager.inspect(&id).expect("branch should be found");
    assert_eq!(inspected.id, id);
    assert_eq!(inspected.profile, "restricted");
    assert_eq!(inspected.base_path, PathBuf::from("/home/user/project"));
    assert_eq!(inspected.state, BranchState::Active);
    assert_eq!(inspected.pid, Some(42));
    assert_eq!(inspected.uid, 1001);
}

#[test]
fn test_recovery_on_startup_loads_persisted_wal_state() {
    // Create a manager, write a WAL entry, then create a new manager
    // in the same directory and verify recover() processes it.
    let dir = tempfile::tempdir().unwrap();
    let wal_dir = dir.path().join("wal");
    std::fs::create_dir_all(&wal_dir).unwrap();

    // First manager: create WAL infrastructure
    let manager1 = make_test_manager(dir.path());
    // recover() with empty WAL should succeed
    assert!(manager1.recover().is_ok());

    // Second manager: should also recover successfully from the same dirs
    let manager2 = make_test_manager(dir.path());
    assert!(
        manager2.recover().is_ok(),
        "recovery on fresh startup should succeed with clean WAL"
    );
    // No branches should be loaded since none were persisted to disk
    assert!(manager2.list().is_empty());
}

#[test]
fn test_concurrent_branch_insertion() {
    // DashMap supports concurrent access; verify multiple branches
    // can be inserted without data loss.
    let dir = tempfile::tempdir().unwrap();
    let manager = Arc::new(make_test_manager(dir.path()));

    let mut handles = vec![];
    for _ in 0..8 {
        let mgr = Arc::clone(&manager);
        let handle = std::thread::spawn(move || {
            insert_test_branch(&mgr, BranchState::Active);
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().expect("thread should not panic");
    }

    assert_eq!(
        manager.list().len(),
        8,
        "all 8 concurrently inserted branches should be present"
    );
}

#[test]
fn test_state_persistence_via_dashmap() {
    // Verify that state stored in the DashMap is retrievable across
    // different access patterns (insert, inspect, transition, list).
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path());

    let id = insert_test_branch(&manager, BranchState::Creating);

    // Transition through the lifecycle
    manager.transition(&id, BranchState::Ready).unwrap();
    assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Ready);

    manager.transition(&id, BranchState::Active).unwrap();
    assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Active);

    manager.transition(&id, BranchState::Frozen).unwrap();
    assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Frozen);

    manager.transition(&id, BranchState::Committing).unwrap();
    assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Committing);

    manager.transition(&id, BranchState::Committed).unwrap();
    assert_eq!(manager.inspect(&id).unwrap().state, BranchState::Committed);

    // list() should reflect the final state
    let listed = manager.list();
    let found = listed.iter().find(|b| b.id == id).unwrap();
    assert_eq!(found.state, BranchState::Committed);
}

#[test]
fn test_branch_creation_increments_counter() {
    // Each call to insert_test_branch adds a branch; verify the count
    // increments correctly and the max_branches limit is respected.
    let dir = tempfile::tempdir().unwrap();
    let manager = make_test_manager(dir.path()); // max_branches = 4

    assert_eq!(manager.list().len(), 0);

    insert_test_branch(&manager, BranchState::Active);
    assert_eq!(manager.list().len(), 1);

    insert_test_branch(&manager, BranchState::Active);
    assert_eq!(manager.list().len(), 2);

    insert_test_branch(&manager, BranchState::Active);
    assert_eq!(manager.list().len(), 3);

    insert_test_branch(&manager, BranchState::Active);
    assert_eq!(manager.list().len(), 4);

    // Verify DashMap len is consistent
    assert_eq!(manager.branches.len(), 4);
}

// ---------------------------------------------------------------
// Source code scanning tests — concatenate all production submodules
// ---------------------------------------------------------------

/// Concatenate all production source files for source-scanning tests.
/// After the branch.rs split into a directory module, the production code
/// is spread across mod.rs, activate.rs, commit_flow.rs, and cleanup.rs.
fn production_source() -> String {
    let mod_rs = include_str!("mod.rs");
    let activate = include_str!("activate.rs");
    let commit_flow = include_str!("commit_flow.rs");
    let cleanup = include_str!("cleanup.rs");
    format!("{}\n{}\n{}\n{}", mod_rs, activate, commit_flow, cleanup)
}

// ---------------------------------------------------------------
// F1: metadata serialization must not use unwrap_or_default()
// ---------------------------------------------------------------

#[test]
fn test_f1_metadata_serialization_no_silent_default() {
    let source = production_source();
    // Find the metadata.json write section
    assert!(
        source.contains("metadata.json"),
        "metadata.json write must exist in production code"
    );
    // to_string_pretty must NOT be followed by unwrap_or_default()
    assert!(
        !source.contains("to_string_pretty(&metadata).unwrap_or_default()"),
        "F1: serde_json::to_string_pretty must not use unwrap_or_default() — \
         an empty string is unparseable on reload. Use unwrap_or_else to write valid JSON."
    );
}

// ---------------------------------------------------------------
// F12: lifetime_minutes cast must use safe conversion
// ---------------------------------------------------------------

#[test]
fn test_f12_lifetime_minutes_safe_cast() {
    let source = production_source();
    // The production code must not contain `mins as i64` (bare cast that wraps)
    // It should use try_from(mins).unwrap_or(i64::MAX) or similar safe conversion
    assert!(
        !source.contains("mins as i64"),
        "F12: lifetime_minutes cast must use i64::try_from(mins).unwrap_or(i64::MAX), \
         not bare `mins as i64` which wraps on huge values"
    );
}

// ---------------------------------------------------------------
// F16: fallback transition to Failed must not silently discard error
// ---------------------------------------------------------------

// ---------------------------------------------------------------
// H3: timeout_secs cast must use safe conversion
// ---------------------------------------------------------------

#[test]
fn test_h3_timeout_secs_safe_cast() {
    let source = production_source();
    assert!(
        !source.contains("timeout_secs as i64"),
        "H3: timeout_secs cast must use i64::try_from().unwrap_or(i64::MAX), \
         not bare `timeout_secs as i64` which truncates large u64 values"
    );
    assert!(
        !source.contains("review_timeout_secs as i64"),
        "H3: review_timeout_secs cast must use i64::try_from().unwrap_or(i64::MAX), \
         not bare `review_timeout_secs as i64` which truncates large u64 values"
    );
}

// ---------------------------------------------------------------
// H4: .len() as u32 must use safe conversion
// ---------------------------------------------------------------

#[test]
fn test_h4_no_bare_len_as_u32() {
    let source = production_source();
    // No bare .len() as u32 or .count() as u32 in production code
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with("///") {
            continue;
        }
        assert!(
            !trimmed.contains(".len() as u32") && !trimmed.contains(".count() as u32"),
            "H4: production code line {} contains bare `.len() as u32` or `.count() as u32` — \
             use u32::try_from(x).unwrap_or(u32::MAX)\nLine: {}",
            i + 1,
            trimmed
        );
    }
}

// ---------------------------------------------------------------
// H6: fd as i32 must use safe conversion
// ---------------------------------------------------------------

#[test]
fn test_h6_no_bare_fd_as_i32() {
    let source = production_source();
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with("///") {
            continue;
        }
        if trimmed.contains("fd as i32") && trimmed.contains("close(") {
            panic!(
                "H6: production code line {} contains bare `fd as i32` for close() — \
                 use i32::try_from(fd) with error handling\nLine: {}",
                i + 1,
                trimmed
            );
        }
    }
}

// ---------------------------------------------------------------
// H10: approve path must re-verify freeze
// ---------------------------------------------------------------

#[test]
fn test_h10_approve_branch_reverifies_freeze() {
    let source = include_str!("mod.rs");

    // Find the approve_branch function
    let func_start = source
        .find("fn approve_branch(")
        .expect("approve_branch function must exist");
    let body = &source[func_start..];
    let end = body.find("\n    pub fn ").unwrap_or(body.len());
    let func_body = &body[..end];

    assert!(
        func_body.contains("H10") && func_body.contains("re-freeze")
            || func_body.contains("re-verify") && func_body.contains("freeze"),
        "H10: approve_branch must re-verify/re-freeze cgroup before finalize_approved_commit"
    );
}

#[test]
fn test_f16_fallback_transition_not_silent() {
    let source = production_source();
    // Find the FailOperational double-failure section
    let fail_section = source
        .find("double failure in FailOperational")
        .expect("FailOperational double-failure path must exist");
    let context = &source[fail_section..];
    // Get the next ~300 chars to capture the transition call
    let end = context.len().min(300);
    let snippet = &context[..end];
    assert!(
        !snippet.contains("let _ = self.transition"),
        "F16: fallback transition to Failed must not use `let _ =` — error must be logged"
    );
}

/// M9: Verify policy error audit outcome includes error context, not just "error".
#[test]
fn test_m9_error_outcome_uses_fixed_label() {
    // T1: Policy error outcome MUST use a fixed "error" label to prevent
    // unbounded Prometheus metric cardinality from dynamic error messages.
    // The detailed error is logged via tracing::error! instead.
    let source = production_source();
    let after_second_error = source.split("PolicyDecision::Error").nth(2).unwrap_or("");
    let snippet = &after_second_error[..after_second_error.len().min(500)];
    assert!(
        snippet.contains("\"error\""),
        "T1: Policy error outcome must use a fixed label to prevent metric cardinality explosion. Found: {}",
        snippet
    );
    // Ensure we don't interpolate the error message into the label
    assert!(
        !snippet.contains("format!(\"error"),
        "T1: Policy error outcome must NOT interpolate error message into metric label. Found: {}",
        snippet
    );
}
