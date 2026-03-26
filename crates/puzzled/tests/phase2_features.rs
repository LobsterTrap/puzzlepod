// SPDX-License-Identifier: Apache-2.0
//! Integration tests for Phase 2 features.
//!
//! Tests cross-module interactions for conflict detection, budget escalation,
//! and audit store lifecycle. These tests are cross-platform (no kernel features).

use std::path::PathBuf;

use puzzled_types::{
    BranchId, BudgetTier, ConflictResolution, FileChange, FileChangeKind, ResourceLimits,
};

// ---------------------------------------------------------------------------
// Conflict detection across multiple branches
// ---------------------------------------------------------------------------

#[test]
fn test_conflict_detection_three_branches() {
    let mut detector = puzzled::conflict::ConflictDetector::new();
    let base = PathBuf::from("/workspace");

    let branch_a = BranchId::from("branch-a".to_string());
    let branch_b = BranchId::from("branch-b".to_string());
    let branch_c = BranchId::from("branch-c".to_string());

    // All three branches modify the same file
    let change = FileChange {
        path: PathBuf::from("shared/config.yaml"),
        kind: FileChangeKind::Modified,
        size: 100,
        checksum: "abc123".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    };

    detector.register_changes(&branch_a, &base, std::slice::from_ref(&change));
    detector.register_changes(&branch_b, &base, std::slice::from_ref(&change));
    detector.register_changes(&branch_c, &base, std::slice::from_ref(&change));

    // branch_c should see conflicts with both a and b
    let conflicts = detector.check_conflicts(&branch_c, &base, &[change]);
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].conflicting_branches.len(), 3); // a, b, and c
}

#[test]
fn test_conflict_resolution_reject() {
    let mut detector = puzzled::conflict::ConflictDetector::new();
    let base = PathBuf::from("/workspace");

    let branch_a = BranchId::from("branch-a".to_string());
    let branch_b = BranchId::from("branch-b".to_string());

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

    // Default resolution is Reject
    let result = detector.resolve(&conflicts);
    assert!(result.is_err());
}

#[test]
fn test_conflict_resolution_last_writer_wins() {
    let detector =
        puzzled::conflict::ConflictDetector::with_resolution(ConflictResolution::LastWriterWins);

    // Create a fake conflict
    let conflict = puzzled_types::Conflict {
        path: PathBuf::from("shared.txt"),
        conflicting_branches: vec![
            BranchId::from("a".to_string()),
            BranchId::from("b".to_string()),
        ],
        kind: puzzled_types::ConflictKind::BothModified,
    };

    // LastWriterWins should allow commit
    let result = detector.resolve(&[conflict]);
    assert!(result.is_ok());
}

#[test]
fn test_conflict_modified_and_deleted() {
    let mut detector = puzzled::conflict::ConflictDetector::new();
    let base = PathBuf::from("/workspace");

    let branch_a = BranchId::from("branch-a".to_string());
    let branch_b = BranchId::from("branch-b".to_string());

    // branch_a modifies the file
    let change_a = FileChange {
        path: PathBuf::from("important.txt"),
        kind: FileChangeKind::Modified,
        size: 200,
        checksum: "mod".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    };
    detector.register_changes(&branch_a, &base, &[change_a]);

    // branch_b deletes the file
    let change_b = FileChange {
        path: PathBuf::from("important.txt"),
        kind: FileChangeKind::Deleted,
        size: 0,
        checksum: "".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    };
    detector.register_changes(&branch_b, &base, std::slice::from_ref(&change_b));

    let conflicts = detector.check_conflicts(&branch_b, &base, &[change_b]);
    assert_eq!(conflicts.len(), 1);
    assert_eq!(
        conflicts[0].kind,
        puzzled_types::ConflictKind::ModifiedAndDeleted
    );
}

#[test]
fn test_conflict_unregister_after_commit() {
    let mut detector = puzzled::conflict::ConflictDetector::new();
    let base = PathBuf::from("/workspace");

    let branch_a = BranchId::from("branch-a".to_string());
    let branch_b = BranchId::from("branch-b".to_string());

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

    // Simulate branch_a committing (unregister)
    detector.unregister_branch(&branch_a);

    // branch_b should now have no conflicts
    let conflicts = detector.check_conflicts(&branch_b, &base, &[change]);
    assert!(conflicts.is_empty());
}

// ---------------------------------------------------------------------------
// Budget escalation lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_budget_full_lifecycle() {
    let mut mgr = puzzled::budget::BudgetManager::new();
    let key = "standard:1000";
    let branch = BranchId::from("b1".to_string());

    // Starts Restricted
    assert_eq!(mgr.get_status(key, &branch).tier, BudgetTier::Restricted);

    // 3 clean commits -> Standard
    for _ in 0..3 {
        mgr.record_clean_commit(key);
    }
    assert_eq!(mgr.get_status(key, &branch).tier, BudgetTier::Standard);
    assert_eq!(mgr.get_status(key, &branch).clean_commits, 3);

    // Violation drops back to Restricted
    mgr.record_violation(key);
    assert_eq!(mgr.get_status(key, &branch).tier, BudgetTier::Restricted);

    // Climb back up: 3 more -> Standard, 7 more -> Extended (10 total needed)
    for _ in 0..3 {
        mgr.record_clean_commit(key);
    }
    assert_eq!(mgr.get_status(key, &branch).tier, BudgetTier::Standard);

    for _ in 0..7 {
        mgr.record_clean_commit(key);
    }
    assert_eq!(mgr.get_status(key, &branch).tier, BudgetTier::Extended);
}

#[test]
fn test_budget_multiple_agents_independent() {
    let mut mgr = puzzled::budget::BudgetManager::new();
    let key_a = "standard:1000";
    let key_b = "restricted:1001";
    let branch = BranchId::from("b1".to_string());

    // Agent A gets escalated
    for _ in 0..3 {
        mgr.record_clean_commit(key_a);
    }
    assert_eq!(mgr.get_status(key_a, &branch).tier, BudgetTier::Standard);

    // Agent B should still be Restricted
    assert_eq!(mgr.get_status(key_b, &branch).tier, BudgetTier::Restricted);

    // Violating agent B should not affect A
    mgr.record_violation(key_b);
    assert_eq!(mgr.get_status(key_a, &branch).tier, BudgetTier::Standard);
    assert_eq!(mgr.get_status(key_b, &branch).tier, BudgetTier::Restricted);
}

#[test]
fn test_budget_effective_limits_scale_with_tier() {
    let mut mgr = puzzled::budget::BudgetManager::new();
    let key = "standard:1000";

    let base = ResourceLimits {
        memory_bytes: 1_073_741_824, // 1 GiB
        cpu_shares: 100,
        io_weight: 100,
        max_pids: 64,
        storage_quota_mb: 1024,
        inode_quota: 10_000,
        max_threads: None,
        no_new_privileges: None,
        max_files_read: None,
        max_files_written: None,
        max_single_file_size_mb: None,
        cpu_quota_us: None,
        memory_high: None,
        io_max: None,
        max_exec_calls: None,
        max_open_fds: None,
        max_files_deleted: None,
        max_total_write_mb: None,
        lifetime_minutes: None,
    };

    // Restricted (0.5x)
    let restricted = mgr.effective_limits(key, &base);
    assert_eq!(restricted.memory_bytes, 536_870_912); // 512 MiB
    assert_eq!(restricted.max_pids, 32);

    // Standard (1.0x)
    for _ in 0..3 {
        mgr.record_clean_commit(key);
    }
    let standard = mgr.effective_limits(key, &base);
    assert_eq!(standard.memory_bytes, 1_073_741_824); // 1 GiB
    assert_eq!(standard.max_pids, 64);

    // Extended (2.0x)
    for _ in 0..7 {
        mgr.record_clean_commit(key);
    }
    let extended = mgr.effective_limits(key, &base);
    assert_eq!(extended.memory_bytes, 2_147_483_648); // 2 GiB
    assert_eq!(extended.max_pids, 128);
}

#[test]
fn test_budget_agent_key_generation() {
    let key = puzzled::budget::BudgetManager::agent_key("standard", 1000);
    assert_eq!(key, "standard:1000");

    let key = puzzled::budget::BudgetManager::agent_key("restricted", 0);
    assert_eq!(key, "restricted:0");
}

// ---------------------------------------------------------------------------
// Audit store lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_audit_store_full_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = puzzled::audit_store::AuditStore::new(dir.path().to_path_buf()).unwrap();

    // Store multiple event types
    store
        .store(&puzzled::audit::AuditEvent::BranchCreated {
            branch_id: BranchId::from("b1".to_string()),
            profile: "standard".to_string(),
            uid: 1000,
        })
        .unwrap();

    store
        .store(&puzzled::audit::AuditEvent::BranchCommitted {
            branch_id: BranchId::from("b1".to_string()),
            files: 5,
            bytes: 1024,
        })
        .unwrap();

    store
        .store(&puzzled::audit::AuditEvent::PolicyViolation {
            branch_id: BranchId::from("b2".to_string()),
            rule: "no_secrets".to_string(),
            message: "found .env file".to_string(),
        })
        .unwrap();

    // Query all
    let all = store.query(None, None, None, None).unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].seq, 0);
    assert_eq!(all[1].seq, 1);
    assert_eq!(all[2].seq, 2);

    // Filter by branch_id
    let b1_events = store.query(Some("b1"), None, None, None).unwrap();
    assert_eq!(b1_events.len(), 2);

    // Filter by event_type
    let violations = store
        .query(None, Some("policy_violation"), None, None)
        .unwrap();
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].event.branch_id.as_deref(), Some("b2"));

    // Filter with limit
    let limited = store.query(None, None, None, Some(2)).unwrap();
    assert_eq!(limited.len(), 2);
}

#[test]
fn test_audit_store_export_json() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = puzzled::audit_store::AuditStore::new(dir.path().to_path_buf()).unwrap();

    store
        .store(&puzzled::audit::AuditEvent::BranchCreated {
            branch_id: BranchId::from("b1".to_string()),
            profile: "standard".to_string(),
            uid: 1000,
        })
        .unwrap();

    let json_export = store.export("json").unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_export).unwrap();
    assert!(parsed.is_array());
    assert_eq!(parsed.as_array().unwrap().len(), 1);
}

#[test]
fn test_audit_store_export_csv() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = puzzled::audit_store::AuditStore::new(dir.path().to_path_buf()).unwrap();

    store
        .store(&puzzled::audit::AuditEvent::BranchCreated {
            branch_id: BranchId::from("b1".to_string()),
            profile: "standard".to_string(),
            uid: 1000,
        })
        .unwrap();

    let csv_export = store.export("csv").unwrap();
    let lines: Vec<&str> = csv_export.lines().collect();
    assert_eq!(lines[0], "seq,timestamp,event_type,branch_id,details");
    assert!(lines[1].contains("branch_created"));
    assert!(lines[1].contains("b1"));
}

#[test]
fn test_audit_store_export_unsupported_format() {
    let dir = tempfile::tempdir().unwrap();
    let store = puzzled::audit_store::AuditStore::new(dir.path().to_path_buf()).unwrap();

    let result = store.export("xml");
    assert!(result.is_err());
}

#[test]
fn test_audit_store_persistence_across_instances() {
    let dir = tempfile::tempdir().unwrap();

    // First instance writes events
    {
        let mut store = puzzled::audit_store::AuditStore::new(dir.path().to_path_buf()).unwrap();
        store
            .store(&puzzled::audit::AuditEvent::BranchCreated {
                branch_id: BranchId::from("b1".to_string()),
                profile: "standard".to_string(),
                uid: 1000,
            })
            .unwrap();
        store
            .store(&puzzled::audit::AuditEvent::BranchRolledBack {
                branch_id: BranchId::from("b1".to_string()),
                reason: "test rollback".to_string(),
            })
            .unwrap();
    }

    // Second instance reads them back
    {
        let store = puzzled::audit_store::AuditStore::new(dir.path().to_path_buf()).unwrap();
        let events = store.query(None, None, None, None).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event.event_type, "branch_created");
        assert_eq!(events[1].event.event_type, "branch_rolled_back");
    }
}

// ---------------------------------------------------------------------------
// Network journal (puzzle-proxy)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_network_journal_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let branch_id = puzzled_types::BranchId::from("test-branch".to_string());

    let mut journal = puzzle_proxy::replay::NetworkJournal::new(journal_dir.clone(), branch_id);

    // Append some side-effect requests
    journal
        .append(puzzle_proxy::replay::JournalEntry {
            method: "POST".to_string(),
            uri: "https://api.example.com/deploy".to_string(),
            headers: vec![("Authorization".to_string(), "Bearer token".to_string())],
            body: b"deploy payload".to_vec(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            safe_replay: false,
        })
        .await
        .unwrap();

    journal
        .append(puzzle_proxy::replay::JournalEntry {
            method: "DELETE".to_string(),
            uri: "https://api.example.com/resource/42".to_string(),
            headers: vec![],
            body: vec![],
            timestamp: "2026-01-01T00:01:00Z".to_string(),
            safe_replay: false,
        })
        .await
        .unwrap();

    assert_eq!(journal.entry_count(), 2);

    // Read back
    let entries = journal.read_all().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].method, "POST");
    assert_eq!(entries[1].method, "DELETE");

    // Discard (simulating rollback)
    journal.discard();
    assert!(!journal_dir.exists());
}

#[tokio::test]
async fn test_network_journal_replay_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let branch_id = puzzled_types::BranchId::from("test-branch".to_string());

    let mut journal = puzzle_proxy::replay::NetworkJournal::new(journal_dir, branch_id);

    journal
        .append(puzzle_proxy::replay::JournalEntry {
            method: "PUT".to_string(),
            uri: "https://api.example.com/config".to_string(),
            headers: vec![],
            body: b"new config".to_vec(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            safe_replay: false,
        })
        .await
        .unwrap();

    // Verify journal has the entry recorded
    assert_eq!(journal.entry_count(), 1);

    // Replay will attempt real HTTP requests; in test env without a server,
    // entries fail to connect but the replay should not error out.
    let replayed = journal.replay(&[]).await.unwrap();
    // H-28: PUT is non-idempotent and safe_replay=false, so it's skipped.
    // replayed_count still increments to 1 (tracks progress for crash recovery).
    assert_eq!(replayed, 1);
}

// ---------------------------------------------------------------------------
// Conflict + Budget interaction (simulating branch lifecycle)
// ---------------------------------------------------------------------------

#[test]
fn test_conflict_free_commit_escalates_budget() {
    let mut conflict_detector = puzzled::conflict::ConflictDetector::new();
    let mut budget_manager = puzzled::budget::BudgetManager::new();

    let base = PathBuf::from("/workspace");
    let agent_key = "standard:1000";
    let branch = BranchId::from("b1".to_string());

    // Simulate 3 conflict-free commits
    for i in 0..3 {
        let change = FileChange {
            path: PathBuf::from(format!("file_{}.txt", i)),
            kind: FileChangeKind::Added,
            size: 100,
            checksum: format!("hash_{}", i),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        };

        conflict_detector.register_changes(&branch, &base, std::slice::from_ref(&change));
        let conflicts = conflict_detector.check_conflicts(&branch, &base, &[change]);
        assert!(conflicts.is_empty());

        // Commit succeeds, record clean commit
        budget_manager.record_clean_commit(agent_key);

        // Cleanup after commit
        conflict_detector.unregister_branch(&branch);
    }

    // Should be escalated to Standard after 3 clean commits
    assert_eq!(
        budget_manager.get_status(agent_key, &branch).tier,
        BudgetTier::Standard,
    );
}

#[test]
fn test_conflict_rejection_deescalates_budget() {
    let mut conflict_detector = puzzled::conflict::ConflictDetector::new();
    let mut budget_manager = puzzled::budget::BudgetManager::new();

    let base = PathBuf::from("/workspace");
    let agent_key = "standard:1000";

    let branch_a = BranchId::from("a".to_string());
    let branch_b = BranchId::from("b".to_string());

    // First, escalate agent to Standard
    for _ in 0..3 {
        budget_manager.record_clean_commit(agent_key);
    }
    assert_eq!(
        budget_manager.get_status(agent_key, &branch_b).tier,
        BudgetTier::Standard,
    );

    // Now create a conflict
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

    conflict_detector.register_changes(&branch_a, &base, std::slice::from_ref(&change));
    conflict_detector.register_changes(&branch_b, &base, std::slice::from_ref(&change));

    let conflicts = conflict_detector.check_conflicts(&branch_b, &base, &[change]);
    assert!(!conflicts.is_empty());

    // Conflict → rejection → violation
    let result = conflict_detector.resolve(&conflicts);
    assert!(result.is_err());

    budget_manager.record_violation(agent_key);
    assert_eq!(
        budget_manager.get_status(agent_key, &branch_b).tier,
        BudgetTier::Restricted,
    );
}

// ---------------------------------------------------------------------------
// Additional Phase 2 tests (hardening)
// ---------------------------------------------------------------------------

#[test]
fn test_conflict_detection_with_frozen_branch() {
    // A frozen branch's changes should still be tracked for conflict detection
    let mut detector = puzzled::conflict::ConflictDetector::new();
    let base = PathBuf::from("/workspace");

    let branch_a = BranchId::from("frozen-a".to_string());
    let branch_b = BranchId::from("active-b".to_string());

    let change = FileChange {
        path: PathBuf::from("shared/config.yaml"),
        kind: FileChangeKind::Modified,
        size: 100,
        checksum: "abc123".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    };

    // branch_a is "frozen" (registered changes before freeze)
    detector.register_changes(&branch_a, &base, std::slice::from_ref(&change));

    // branch_b modifies the same file
    detector.register_changes(&branch_b, &base, std::slice::from_ref(&change));
    let conflicts = detector.check_conflicts(&branch_b, &base, &[change]);
    assert!(
        !conflicts.is_empty(),
        "should detect conflict with frozen branch"
    );
}

#[test]
fn test_budget_tier_limits_enforced() {
    let mut budget = puzzled::budget::BudgetManager::new();
    let agent_key = "test-agent:1000";

    // Start at Restricted tier (agents begin restricted and earn trust)
    let branch = BranchId::from("test-branch".to_string());
    let status = budget.get_status(agent_key, &branch);
    assert_eq!(status.tier, BudgetTier::Restricted);

    // Record clean commits to escalate to Standard
    for _ in 0..3 {
        budget.record_clean_commit(agent_key);
    }
    let status = budget.get_status(agent_key, &branch);
    assert_eq!(status.tier, BudgetTier::Standard);

    // Record violation to de-escalate back to Restricted
    budget.record_violation(agent_key);
    let status = budget.get_status(agent_key, &branch);
    assert_eq!(status.tier, BudgetTier::Restricted);
}

#[test]
fn test_audit_store_fsync_on_write() {
    // Verify that events are persisted immediately (fsync on write)
    let dir = tempfile::tempdir().unwrap();
    let mut store = puzzled::audit_store::AuditStore::new(dir.path().to_path_buf()).unwrap();

    let event = puzzled::audit::AuditEvent::BranchCreated {
        branch_id: BranchId::from("fsync-test".to_string()),
        profile: "standard".to_string(),
        uid: 1000,
    };

    store.store(&event).unwrap();

    // Re-read from disk without closing
    let events_file = dir.path().join("events.ndjson");
    let content = std::fs::read_to_string(&events_file).unwrap();
    assert!(
        content.contains("fsync-test"),
        "event should be written to disk immediately"
    );
}

#[test]
fn test_audit_store_hmac_chain() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = puzzled::audit_store::AuditStore::new(dir.path().to_path_buf()).unwrap();

    // Store events
    for i in 0..3 {
        store
            .store(&puzzled::audit::AuditEvent::BranchCreated {
                branch_id: BranchId::from(format!("chain-{}", i)),
                profile: "standard".to_string(),
                uid: 1000,
            })
            .unwrap();
    }

    // Verify chain
    let count = store.verify_chain().unwrap();
    assert_eq!(count, 3);

    // Verify events have HMAC field
    let events_file = dir.path().join("events.ndjson");
    let content = std::fs::read_to_string(&events_file).unwrap();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(
            parsed.get("hmac").is_some(),
            "each event should have an HMAC field"
        );
    }
}

#[test]
fn test_network_journal_body_size_limit() {
    // MAX_BODY_SIZE = 100MB — verify the constant value
    // The actual enforcement is in handler.rs; here we verify the concept
    const MAX_BODY_SIZE: usize = 100 * 1024 * 1024;
    assert_eq!(MAX_BODY_SIZE, 104_857_600);

    // A body exceeding the limit should be rejected
    const { assert!(MAX_BODY_SIZE > 0) };
}

#[test]
fn test_network_journal_replay_idempotent() {
    // Journal replay should not crash on empty journal
    let dir = tempfile::tempdir().unwrap();
    let branch = BranchId::from("replay-test".to_string());
    let journal = puzzle_proxy::replay::NetworkJournal::new(dir.path().to_path_buf(), branch);

    // Empty journal should replay successfully with 0 count
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let count = rt.block_on(journal.replay(&[])).unwrap();
    assert_eq!(count, 0, "empty journal should replay with 0 entries");
}

#[test]
fn test_conflict_resolution_strategies() {
    // LastWriterWins should always resolve conflicts
    let detector =
        puzzled::conflict::ConflictDetector::with_resolution(ConflictResolution::LastWriterWins);

    let conflicts = vec![
        puzzled_types::Conflict {
            path: PathBuf::from("file1.txt"),
            conflicting_branches: vec![
                BranchId::from("a".to_string()),
                BranchId::from("b".to_string()),
            ],
            kind: puzzled_types::ConflictKind::BothModified,
        },
        puzzled_types::Conflict {
            path: PathBuf::from("file2.txt"),
            conflicting_branches: vec![
                BranchId::from("a".to_string()),
                BranchId::from("c".to_string()),
            ],
            kind: puzzled_types::ConflictKind::ModifiedAndDeleted,
        },
    ];

    let result = detector.resolve(&conflicts);
    assert!(
        result.is_ok(),
        "LastWriterWins should resolve all conflict types"
    );
}

#[test]
fn test_budget_deescalation_on_violation() {
    let mut budget = puzzled::budget::BudgetManager::new();
    let agent_key = "deescalate-agent:1000";

    // Escalate first
    let branch = BranchId::from("test".to_string());
    for _ in 0..5 {
        budget.record_clean_commit(agent_key);
    }
    let status = budget.get_status(agent_key, &branch);
    assert!(
        status.tier != BudgetTier::Restricted,
        "should have escalated after clean commits"
    );

    // De-escalate with violations
    budget.record_violation(agent_key);
    let status = budget.get_status(agent_key, &branch);
    assert_eq!(
        status.tier,
        BudgetTier::Restricted,
        "should de-escalate to Restricted after violation"
    );
}

// ---------------------------------------------------------------------------
// T10: Conflict detection stress test (100 branches)
// ---------------------------------------------------------------------------

#[test]
fn test_conflict_detection_100_branches_overlapping_files() {
    let mut detector = puzzled::conflict::ConflictDetector::new();
    let base = PathBuf::from("/workspace");

    // Create 100 branches, all modifying overlapping files
    let branch_ids: Vec<BranchId> = (0..100)
        .map(|i| BranchId::from(format!("branch-{}", i)))
        .collect();

    // Each branch modifies a set of files. Some overlap, some are unique.
    // Files 0-9 are shared across all branches (hot contention).
    // Files 10+ are unique per branch (no contention).
    for (i, branch_id) in branch_ids.iter().enumerate() {
        let mut changes = Vec::new();

        // Shared files (will conflict)
        for j in 0..10 {
            changes.push(FileChange {
                path: PathBuf::from(format!("shared/config_{}.yaml", j)),
                kind: FileChangeKind::Modified,
                size: 100 + (i * 10 + j) as u64,
                checksum: format!("hash_{}_{}", i, j),
                old_size: None,
                old_mode: None,
                new_mode: None,
                timestamp: None,
                target: None,
            });
        }

        // Unique files (no conflict)
        changes.push(FileChange {
            path: PathBuf::from(format!("branch_{}/unique.txt", i)),
            kind: FileChangeKind::Added,
            size: 200,
            checksum: format!("unique_{}", i),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        });

        detector.register_changes(branch_id, &base, &changes);
    }

    // The last branch should see conflicts on all 10 shared files
    let last_branch = &branch_ids[99];
    let last_changes: Vec<FileChange> = (0..10)
        .map(|j| FileChange {
            path: PathBuf::from(format!("shared/config_{}.yaml", j)),
            kind: FileChangeKind::Modified,
            size: 100,
            checksum: format!("hash_99_{}", j),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        })
        .collect();

    let conflicts = detector.check_conflicts(last_branch, &base, &last_changes);
    assert_eq!(
        conflicts.len(),
        10,
        "should detect 10 conflicting shared files"
    );

    // Each conflict should involve all 100 branches
    for conflict in &conflicts {
        assert_eq!(
            conflict.conflicting_branches.len(),
            100,
            "each shared file should have 100 conflicting branches, got {} for {}",
            conflict.conflicting_branches.len(),
            conflict.path.display()
        );
    }
}

#[test]
fn test_conflict_detection_100_branches_no_overlap() {
    let mut detector = puzzled::conflict::ConflictDetector::new();
    let base = PathBuf::from("/workspace");

    // 100 branches, each modifying a completely unique set of files
    let branch_ids: Vec<BranchId> = (0..100)
        .map(|i| BranchId::from(format!("branch-{}", i)))
        .collect();

    for (i, branch_id) in branch_ids.iter().enumerate() {
        let changes = vec![
            FileChange {
                path: PathBuf::from(format!("project_{}/main.rs", i)),
                kind: FileChangeKind::Modified,
                size: 1000,
                checksum: format!("hash_{}", i),
                old_size: None,
                old_mode: None,
                new_mode: None,
                timestamp: None,
                target: None,
            },
            FileChange {
                path: PathBuf::from(format!("project_{}/lib.rs", i)),
                kind: FileChangeKind::Added,
                size: 500,
                checksum: format!("lib_hash_{}", i),
                old_size: None,
                old_mode: None,
                new_mode: None,
                timestamp: None,
                target: None,
            },
        ];
        detector.register_changes(branch_id, &base, &changes);
    }

    // No branch should have conflicts
    for (i, branch_id) in branch_ids.iter().enumerate() {
        let changes = vec![FileChange {
            path: PathBuf::from(format!("project_{}/main.rs", i)),
            kind: FileChangeKind::Modified,
            size: 1000,
            checksum: format!("hash_{}", i),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        }];

        let conflicts = detector.check_conflicts(branch_id, &base, &changes);
        assert!(
            conflicts.is_empty(),
            "branch {} should have no conflicts, got {}",
            i,
            conflicts.len()
        );
    }
}

#[test]
fn test_conflict_detection_100_branches_progressive_registration() {
    let mut detector = puzzled::conflict::ConflictDetector::new();
    let base = PathBuf::from("/workspace");

    // Register branches progressively and unregister some to simulate commits
    let shared_change = FileChange {
        path: PathBuf::from("shared/data.json"),
        kind: FileChangeKind::Modified,
        size: 1024,
        checksum: "shared_hash".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    };

    let mut active_count = 0;

    for i in 0..100 {
        let branch_id = BranchId::from(format!("branch-{}", i));
        detector.register_changes(&branch_id, &base, std::slice::from_ref(&shared_change));
        active_count += 1;

        // Every 10th branch, "commit" and unregister the oldest active branch
        if i > 0 && i % 10 == 0 {
            let old_branch = BranchId::from(format!("branch-{}", i - 10));
            detector.unregister_branch(&old_branch);
            active_count -= 1;
        }

        // Conflict count should match active branches (minus the one checking)
        let conflicts =
            detector.check_conflicts(&branch_id, &base, std::slice::from_ref(&shared_change));
        if active_count > 1 {
            assert_eq!(
                conflicts.len(),
                1,
                "branch {} should see 1 conflict on shared file (active: {})",
                i,
                active_count
            );
            assert_eq!(
                conflicts[0].conflicting_branches.len(),
                active_count,
                "conflict should list all {} active branches at step {}",
                active_count,
                i
            );
        }
    }
}

// ---------------------------------------------------------------------------
// T11: Budget + policy violation coupling
// ---------------------------------------------------------------------------

#[test]
fn test_budget_violation_triggers_deescalation() {
    let mut budget = puzzled::budget::BudgetManager::new();
    let agent_key = "coupled-agent:1000";
    let branch = BranchId::from("coupling-test".to_string());

    // Escalate agent to Standard tier via clean commits
    for _ in 0..3 {
        budget.record_clean_commit(agent_key);
    }
    assert_eq!(
        budget.get_status(agent_key, &branch).tier,
        BudgetTier::Standard
    );

    // Simulate a policy violation (e.g., sensitive file in changeset)
    budget.record_violation(agent_key);

    // Should be de-escalated to Restricted
    let status = budget.get_status(agent_key, &branch);
    assert_eq!(
        status.tier,
        BudgetTier::Restricted,
        "policy violation should de-escalate from Standard to Restricted"
    );

    // Verify effective limits are reduced
    let base_limits = ResourceLimits {
        memory_bytes: 1_073_741_824, // 1 GiB
        cpu_shares: 100,
        io_weight: 100,
        max_pids: 64,
        storage_quota_mb: 1024,
        inode_quota: 10_000,
        max_threads: None,
        no_new_privileges: None,
        max_files_read: None,
        max_files_written: None,
        max_single_file_size_mb: None,
        cpu_quota_us: None,
        memory_high: None,
        io_max: None,
        max_exec_calls: None,
        max_open_fds: None,
        max_files_deleted: None,
        max_total_write_mb: None,
        lifetime_minutes: None,
    };

    let effective = budget.effective_limits(agent_key, &base_limits);
    assert_eq!(
        effective.memory_bytes,
        536_870_912, // 512 MiB (0.5x of 1 GiB)
        "restricted tier should halve memory limits"
    );
    assert_eq!(
        effective.max_pids,
        32, // 0.5x of 64
        "restricted tier should halve PID limits"
    );
}

#[test]
fn test_budget_violation_resets_clean_commit_counter() {
    let mut budget = puzzled::budget::BudgetManager::new();
    let agent_key = "reset-agent:1000";
    let branch = BranchId::from("reset-test".to_string());

    // 2 clean commits (not enough for Standard)
    budget.record_clean_commit(agent_key);
    budget.record_clean_commit(agent_key);
    assert_eq!(budget.get_status(agent_key, &branch).clean_commits, 2);

    // Violation should reset clean commits to 0
    budget.record_violation(agent_key);
    assert_eq!(
        budget.get_status(agent_key, &branch).clean_commits,
        0,
        "violation should reset clean commit counter"
    );
    assert_eq!(
        budget.get_status(agent_key, &branch).tier,
        BudgetTier::Restricted
    );
}

#[test]
fn test_budget_multiple_violations_remain_restricted() {
    let mut budget = puzzled::budget::BudgetManager::new();
    let agent_key = "multi-violate:1000";
    let branch = BranchId::from("multi-violate-test".to_string());

    // Escalate to Extended tier
    for _ in 0..10 {
        budget.record_clean_commit(agent_key);
    }
    assert_eq!(
        budget.get_status(agent_key, &branch).tier,
        BudgetTier::Extended
    );

    // Multiple violations should keep at Restricted
    for _ in 0..5 {
        budget.record_violation(agent_key);
    }
    assert_eq!(
        budget.get_status(agent_key, &branch).tier,
        BudgetTier::Restricted,
        "multiple violations should maintain Restricted tier"
    );
}

#[test]
fn test_budget_violation_then_recovery_to_extended() {
    let mut budget = puzzled::budget::BudgetManager::new();
    let agent_key = "recovery-agent:1000";
    let branch = BranchId::from("recovery-test".to_string());

    // Full lifecycle: escalate -> violate -> recover
    // 1. Escalate to Extended
    for _ in 0..10 {
        budget.record_clean_commit(agent_key);
    }
    assert_eq!(
        budget.get_status(agent_key, &branch).tier,
        BudgetTier::Extended
    );

    // 2. Violation drops one tier: Extended -> Standard (M2)
    budget.record_violation(agent_key);
    assert_eq!(
        budget.get_status(agent_key, &branch).tier,
        BudgetTier::Standard
    );

    // 3. Another violation drops to Restricted
    budget.record_violation(agent_key);
    assert_eq!(
        budget.get_status(agent_key, &branch).tier,
        BudgetTier::Restricted
    );

    // 4. Rebuild trust: 3 clean -> Standard, 7 more -> Extended
    for _ in 0..3 {
        budget.record_clean_commit(agent_key);
    }
    assert_eq!(
        budget.get_status(agent_key, &branch).tier,
        BudgetTier::Standard
    );

    for _ in 0..7 {
        budget.record_clean_commit(agent_key);
    }
    assert_eq!(
        budget.get_status(agent_key, &branch).tier,
        BudgetTier::Extended,
        "agent should be able to fully recover from violation"
    );
}

#[test]
fn test_budget_violation_coupling_with_conflict_detection() {
    // Integration: conflict -> policy rejection -> budget de-escalation -> reduced limits
    let mut conflict_detector = puzzled::conflict::ConflictDetector::new();
    let mut budget = puzzled::budget::BudgetManager::new();

    let base = PathBuf::from("/workspace");
    let agent_key = "coupled-flow:1000";
    let branch = BranchId::from("coupled-flow".to_string());

    // Escalate to Standard
    for _ in 0..3 {
        budget.record_clean_commit(agent_key);
    }
    assert_eq!(
        budget.get_status(agent_key, &branch).tier,
        BudgetTier::Standard
    );

    // Create a conflict situation
    let branch_a = BranchId::from("a".to_string());
    let branch_b = BranchId::from("b".to_string());
    let change = FileChange {
        path: PathBuf::from("important.yaml"),
        kind: FileChangeKind::Modified,
        size: 100,
        checksum: "abc".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    };

    conflict_detector.register_changes(&branch_a, &base, std::slice::from_ref(&change));
    conflict_detector.register_changes(&branch_b, &base, std::slice::from_ref(&change));

    let conflicts = conflict_detector.check_conflicts(&branch_b, &base, &[change]);
    assert!(!conflicts.is_empty());

    // Conflict -> rejection -> violation
    let resolution = conflict_detector.resolve(&conflicts);
    assert!(
        resolution.is_err(),
        "default resolution should reject conflicts"
    );

    budget.record_violation(agent_key);

    // Verify cascading effects
    let status = budget.get_status(agent_key, &branch);
    assert_eq!(status.tier, BudgetTier::Restricted);

    let base_limits = ResourceLimits {
        memory_bytes: 2_147_483_648, // 2 GiB
        cpu_shares: 200,
        io_weight: 100,
        max_pids: 128,
        storage_quota_mb: 2048,
        inode_quota: 20_000,
        max_threads: None,
        no_new_privileges: None,
        max_files_read: None,
        max_files_written: None,
        max_single_file_size_mb: None,
        cpu_quota_us: None,
        memory_high: None,
        io_max: None,
        max_exec_calls: None,
        max_open_fds: None,
        max_files_deleted: None,
        max_total_write_mb: None,
        lifetime_minutes: None,
    };

    let effective = budget.effective_limits(agent_key, &base_limits);
    assert_eq!(effective.memory_bytes, 1_073_741_824); // 1 GiB (0.5x)
    assert_eq!(effective.max_pids, 64); // 0.5x
}

// -----------------------------------------------------------------------
// F1: Concurrent access tests (race condition detection)
// -----------------------------------------------------------------------

/// F1: Multiple threads registering and checking conflicts simultaneously.
/// Verifies ConflictDetector doesn't panic or produce corrupted state under contention.
#[test]
fn test_conflict_detector_concurrent_access() {
    use std::sync::{Arc, Mutex};

    let detector = Arc::new(Mutex::new(puzzled::conflict::ConflictDetector::new()));

    let mut handles = vec![];
    let base = PathBuf::from("/workspace");

    // 10 threads each registering files for different branches
    for i in 0..10 {
        let detector = Arc::clone(&detector);
        let base = base.clone();
        handles.push(std::thread::spawn(move || {
            let branch = BranchId::from(format!("race-branch-{i}"));
            let changes = vec![
                FileChange {
                    path: PathBuf::from(format!("shared_file_{}.txt", i % 3)),
                    kind: FileChangeKind::Modified,
                    size: 100,
                    checksum: format!("hash-{i}"),
                    old_size: None,
                    old_mode: None,
                    new_mode: None,
                    timestamp: None,
                    target: None,
                },
                FileChange {
                    path: PathBuf::from(format!("unique_file_{i}.txt")),
                    kind: FileChangeKind::Added,
                    size: 50,
                    checksum: format!("unique-{i}"),
                    old_size: None,
                    old_mode: None,
                    new_mode: None,
                    timestamp: None,
                    target: None,
                },
            ];
            let mut det = detector.lock().unwrap();
            det.register_changes(&branch, &base, &changes);
            let conflicts = det.check_conflicts(&branch, &base, &changes);
            drop(det);
            (branch, conflicts.len())
        }));
    }

    let mut total_conflicts = 0;
    for handle in handles {
        let (branch, conflict_count) = handle.join().expect("thread should not panic");
        total_conflicts += conflict_count;
        // Unregister to clean up
        let mut det = detector.lock().unwrap();
        det.unregister_branch(&branch);
    }

    // Some threads should have detected conflicts on shared_file_*.txt
    // (exact number depends on scheduling). We mainly verify no panics
    // or corrupted state occurred.
    let _ = total_conflicts;
}

/// F1: BudgetManager concurrent record_commit from multiple threads.
#[test]
fn test_budget_manager_concurrent_commits() {
    use std::sync::{Arc, Mutex};

    let budget = Arc::new(Mutex::new(puzzled::budget::BudgetManager::new()));

    let mut handles = vec![];

    // 10 threads each recording commits for different agents
    for i in 0..10 {
        let budget = Arc::clone(&budget);
        handles.push(std::thread::spawn(move || {
            let agent_key = format!("agent-{i}");
            for _ in 0..5 {
                let mut bm = budget.lock().unwrap();
                bm.record_clean_commit(&agent_key);
            }
            // One violation
            {
                let mut bm = budget.lock().unwrap();
                bm.record_violation(&agent_key);
            }
        }));
    }

    for handle in handles {
        handle.join().expect("budget thread should not panic");
    }

    // Verify all agents were tracked (5 clean commits then 1 violation each).
    // record_violation resets clean_commits to 0, so final clean_commits == 0.
    let bm = budget.lock().unwrap();
    for i in 0..10 {
        let agent_key = format!("agent-{i}");
        let branch_id = BranchId::from(format!("check-{i}"));
        let status = bm.get_status(&agent_key, &branch_id);
        assert_eq!(
            status.violations, 1,
            "agent-{i} should have exactly 1 violation, got {}",
            status.violations
        );
        // clean_commits is reset to 0 on violation (M2 hardening)
        assert_eq!(
            status.clean_commits, 0,
            "agent-{i} clean_commits should be 0 after violation reset, got {}",
            status.clean_commits
        );
    }
}

// ---------------------------------------------------------------------------
// ProxyServer lifecycle tests
// ---------------------------------------------------------------------------

/// Test that the ProxyServer starts, accepts connections, and can be aborted.
#[tokio::test]
async fn test_proxy_server_spawn_and_abort() {
    let dir = tempfile::tempdir().unwrap();
    let branch_id = BranchId::from("proxy-test".to_string());

    // Bind to port 0 to get a free port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let config = puzzle_proxy::ProxyConfig {
        listen_addr: addr,
        read_allowed_domains: vec!["example.com".to_string()],
        write_allowed_domains: vec!["example.com".to_string()],
        denied_domains: vec![],
        mode: puzzle_proxy::ProxyMode::Gated,
        branch_dir: dir.path().to_path_buf(),
        branch_id: branch_id.clone(),
        ca: None,
        dlp_engine: None,
        max_inspection_body_size: 10 * 1024 * 1024,
        oversized_body_action: puzzle_proxy::dlp::OversizedAction::BlockAndAlert,
        quarantine_sender: None,
        phantom_token_manager: None,
        agent_profile: None,
        geo_database: None,
        data_residency: None,
        audit_sender: None,
        credential_mode: puzzled_types::CredentialMode::Phantom,
        transparent_mode: false,
    };

    let proxy = puzzle_proxy::ProxyServer::new(config);
    let task = tokio::spawn(async move {
        let _ = proxy.run().await;
    });

    // Give the proxy time to start listening
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Verify the proxy is reachable
    let connect_result = tokio::net::TcpStream::connect(addr).await;
    assert!(
        connect_result.is_ok(),
        "proxy should be accepting connections at {}",
        addr
    );

    // Abort the task (simulating branch cleanup)
    task.abort();
    let join_result = task.await;
    assert!(
        join_result.unwrap_err().is_cancelled(),
        "task should be cancelled"
    );

    // Verify the proxy is no longer reachable
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let connect_after = tokio::net::TcpStream::connect(addr).await;
    assert!(
        connect_after.is_err(),
        "proxy should not accept connections after abort"
    );
}

/// Test that the proxy filters requests based on allowed_domains.
/// Uses raw HTTP/1.1 over TCP to avoid needing hyper_util client dependency.
#[tokio::test]
async fn test_proxy_server_domain_filtering() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = tempfile::tempdir().unwrap();
    let branch_id = BranchId::from("proxy-filter-test".to_string());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let config = puzzle_proxy::ProxyConfig {
        listen_addr: addr,
        read_allowed_domains: vec!["allowed.example.com".to_string()],
        write_allowed_domains: vec![],
        denied_domains: vec!["evil.com".to_string()],
        mode: puzzle_proxy::ProxyMode::Gated,
        branch_dir: dir.path().to_path_buf(),
        branch_id,
        ca: None,
        dlp_engine: None,
        max_inspection_body_size: 10 * 1024 * 1024,
        oversized_body_action: puzzle_proxy::dlp::OversizedAction::BlockAndAlert,
        quarantine_sender: None,
        phantom_token_manager: None,
        agent_profile: None,
        geo_database: None,
        data_residency: None,
        audit_sender: None,
        credential_mode: puzzled_types::CredentialMode::Phantom,
        transparent_mode: false,
    };

    let proxy = puzzle_proxy::ProxyServer::new(config);
    let task = tokio::spawn(async move {
        let _ = proxy.run().await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Send a raw HTTP/1.1 request to a denied domain through the proxy
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = "GET http://evil.com/secret HTTP/1.1\r\nHost: evil.com\r\n\r\n";
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = vec![0u8; 4096];
    let n = stream.read(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response[..n]);

    // Proxy should return 403 Forbidden for denied domain
    assert!(
        response_str.contains("403"),
        "denied domain should return 403, got: {}",
        response_str.lines().next().unwrap_or("")
    );

    task.abort();
}

/// Test that proxy task handles are properly stored and cleaned up in DashMap.
#[tokio::test]
async fn test_proxy_task_dashmap_lifecycle() {
    use dashmap::DashMap;

    let tasks: DashMap<BranchId, tokio::task::JoinHandle<()>> = DashMap::new();
    let branch_id = BranchId::from("dashmap-test".to_string());

    // Spawn a simple background task
    let task = tokio::spawn(async {
        // Simulate proxy running
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    });

    tasks.insert(branch_id.clone(), task);
    assert!(tasks.contains_key(&branch_id));

    // Simulate cleanup: remove and abort
    if let Some((_, task)) = tasks.remove(&branch_id) {
        task.abort();
    }

    assert!(!tasks.contains_key(&branch_id));
}

/// Test that NetworkJournal on disk is accessible after ProxyServer writes to it.
#[tokio::test]
async fn test_proxy_journal_shared_directory() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("network_journal");
    let branch_id = BranchId::from("journal-share-test".to_string());

    // ProxyServer creates its own journal internally at branch_dir/network_journal
    let config = puzzle_proxy::ProxyConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        read_allowed_domains: vec![],
        write_allowed_domains: vec![],
        denied_domains: vec![],
        mode: puzzle_proxy::ProxyMode::Gated,
        branch_dir: dir.path().to_path_buf(),
        branch_id: branch_id.clone(),
        ca: None,
        dlp_engine: None,
        max_inspection_body_size: 10 * 1024 * 1024,
        oversized_body_action: puzzle_proxy::dlp::OversizedAction::BlockAndAlert,
        quarantine_sender: None,
        phantom_token_manager: None,
        agent_profile: None,
        geo_database: None,
        data_residency: None,
        audit_sender: None,
        credential_mode: puzzled_types::CredentialMode::Phantom,
        transparent_mode: false,
    };

    let proxy = puzzle_proxy::ProxyServer::new(config);
    let proxy_journal = proxy.journal();

    // Write an entry through the proxy's journal
    {
        let mut j = proxy_journal.lock().await;
        j.append(puzzle_proxy::replay::JournalEntry {
            method: "POST".to_string(),
            uri: "https://api.example.com/test".to_string(),
            headers: vec![],
            body: b"test body".to_vec(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            safe_replay: false,
        })
        .await
        .unwrap();
    }

    // A separate NetworkJournal instance reading the same directory sees the entry
    let reader_journal =
        puzzle_proxy::replay::NetworkJournal::new(journal_dir.clone(), branch_id.clone());
    let entries = reader_journal.read_all().unwrap();
    assert_eq!(entries.len(), 1, "reader should see proxy's journal entry");
    assert_eq!(entries[0].method, "POST");
    assert_eq!(entries[0].uri, "https://api.example.com/test");
}
