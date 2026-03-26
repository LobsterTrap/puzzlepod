// SPDX-License-Identifier: Apache-2.0
//! Cross-module integration tests for §4.1 (Trust), §4.3 (Provenance), §4.5 (Identity).
//!
//! These tests validate that TrustManager, ProvenanceStore, and IdentityManager
//! work correctly when composed together — the wiring that happens in the commit
//! path and D-Bus handlers. No live daemon or Linux kernel primitives required.
//!
//! Run with:
//!   cargo test -p puzzled --test cross_module_integration

use tempfile::TempDir;

use puzzled_types::{FileChangeKind, ProvenanceRecord, ProvenanceType, ScoringRule, TrustLevel};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_scoring_rules() -> Vec<ScoringRule> {
    vec![
        ScoringRule {
            event: "commit_approved".to_string(),
            delta: 2,
            max_increase_per_day: Some(10),
            description: Some("Successful commit".to_string()),
        },
        ScoringRule {
            event: "policy_violation".to_string(),
            delta: -10,
            max_increase_per_day: None,
            description: Some("Policy violation".to_string()),
        },
        ScoringRule {
            event: "commit_rejected".to_string(),
            delta: -5,
            max_increase_per_day: None,
            description: Some("Commit rejected".to_string()),
        },
        ScoringRule {
            event: "behavioral_trigger_warning".to_string(),
            delta: -5,
            max_increase_per_day: None,
            description: Some("Behavioral warning".to_string()),
        },
        ScoringRule {
            event: "behavioral_trigger_critical".to_string(),
            delta: -15,
            max_increase_per_day: None,
            description: Some("Behavioral critical".to_string()),
        },
        ScoringRule {
            event: "containment_violation".to_string(),
            delta: -25,
            max_increase_per_day: None,
            description: Some("Containment violation".to_string()),
        },
    ]
}

fn make_trust_manager(dir: &std::path::Path) -> puzzled::trust::TrustManager {
    puzzled::trust::TrustManager::new(dir.to_path_buf(), default_scoring_rules())
}

fn make_provenance_store(dir: &std::path::Path) -> puzzled::provenance::ProvenanceStore {
    puzzled::provenance::ProvenanceStore::new(dir.to_path_buf())
}

fn make_provenance_record(branch_id: &str, record_type: ProvenanceType) -> ProvenanceRecord {
    ProvenanceRecord {
        id: uuid::Uuid::new_v4().to_string(),
        record_type,
        branch_id: branch_id.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    }
}

// ---------------------------------------------------------------------------
// §4.1 + §4.5: Trust score populates JWT-SVID claims
// ---------------------------------------------------------------------------

#[cfg(feature = "ima")]
mod trust_identity {
    use super::*;
    use puzzled::identity::IdentityManager;
    use ed25519_dalek::SigningKey;

    fn test_signing_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        SigningKey::from_bytes(&bytes)
    }

    /// JWT-SVID should carry the real trust score from TrustManager.
    #[test]
    fn jwt_svid_reflects_live_trust_score() {
        let dir = TempDir::new().unwrap();
        let mut trust = make_trust_manager(dir.path());

        // Register UID 1000 with "standard" profile → initial score ~25
        trust.register_uid(1000, "standard");
        let state = trust.get_score(1000).expect("UID should exist");
        let score = state.score;
        let level = state.level.as_str().to_string();

        // Issue JWT-SVID with the live trust data
        let mgr = IdentityManager::new(
            test_signing_key(),
            "test.example.com".to_string(),
            3600,
            true,
            false,
        );

        let token = mgr
            .issue_jwt_svid(
                "branch-100",
                "standard",
                &level,
                score,
                &["service-a".to_string()],
                &["landlock".to_string(), "seccomp".to_string()],
                "v1.0",
                None,
                0,
            )
            .expect("issue should succeed");

        let claims = mgr
            .verify_jwt_svid(&token, None)
            .expect("verify should succeed");

        assert_eq!(claims.trust_score, score);
        assert_eq!(claims.trust_level, level);
    }

    /// After a trust score change, the next JWT-SVID should reflect the new score.
    #[test]
    fn jwt_svid_updates_after_trust_change() {
        let dir = TempDir::new().unwrap();
        let mut trust = make_trust_manager(dir.path());
        trust.register_uid(1000, "standard");

        // Apply positive events to raise score
        for _ in 0..3 {
            trust.on_audit_event("commit_approved", 1000, None);
        }

        let state = trust.get_score(1000).unwrap();
        let new_score = state.score;
        let new_level = state.level.as_str().to_string();

        // Score should have increased from initial
        assert!(new_score > 25, "score should increase after commits");

        let mgr = IdentityManager::new(
            test_signing_key(),
            "test.example.com".to_string(),
            3600,
            true,
            false,
        );

        let token = mgr
            .issue_jwt_svid(
                "branch-101",
                "standard",
                &new_level,
                new_score,
                &["svc".to_string()],
                &["landlock".to_string()],
                "v1.0",
                None,
                0,
            )
            .expect("issue should succeed");

        let claims = mgr
            .verify_jwt_svid(&token, None)
            .expect("verify should succeed");

        assert_eq!(claims.trust_score, new_score);
    }

    /// After a policy violation, trust drops and JWT-SVID reflects the lower score.
    #[test]
    fn jwt_svid_reflects_trust_drop_after_violation() {
        let dir = TempDir::new().unwrap();
        let mut trust = make_trust_manager(dir.path());
        trust.register_uid(1000, "standard");

        let initial_score = trust.get_score(1000).unwrap().score;

        // Apply a policy violation → score drops by 10
        trust.on_audit_event("policy_violation", 1000, Some("branch-bad"));

        let state = trust.get_score(1000).unwrap();
        assert!(
            state.score < initial_score,
            "score should drop: {} should be < {}",
            state.score,
            initial_score
        );

        let mgr = IdentityManager::new(
            test_signing_key(),
            "test.example.com".to_string(),
            3600,
            true,
            false,
        );

        let token = mgr
            .issue_jwt_svid(
                "branch-102",
                "standard",
                state.level.as_str(),
                state.score,
                &["svc".to_string()],
                &[],
                "v1.0",
                None,
                0,
            )
            .unwrap();

        let claims = mgr.verify_jwt_svid(&token, None).unwrap();
        assert_eq!(claims.trust_score, state.score);
        assert!(claims.trust_score < initial_score);
    }
}

// ---------------------------------------------------------------------------
// §4.1 + §4.3: Commit events update trust AND write provenance
// ---------------------------------------------------------------------------

/// Simulates the commit path: trust score update + provenance records written.
/// This is the wiring that commit_branch() in dbus.rs should perform.
#[test]
fn commit_path_updates_trust_and_writes_provenance() {
    let dir = TempDir::new().unwrap();
    let trust_dir = dir.path().join("trust");
    let prov_dir = dir.path().join("provenance");
    std::fs::create_dir_all(&trust_dir).unwrap();
    std::fs::create_dir_all(&prov_dir).unwrap();

    let mut trust = make_trust_manager(&trust_dir);
    let prov = make_provenance_store(&prov_dir);

    let uid = 1000u32;
    let branch_id = "branch-commit-test";

    trust.register_uid(uid, "standard");
    let initial_score = trust.get_score(uid).unwrap().score;

    // --- Simulate commit path ---

    // 1. Write FileChange provenance records (from diff engine)
    let file_change_record = make_provenance_record(
        branch_id,
        ProvenanceType::FileChange {
            change_id: "chg-001".to_string(),
            invocation_id: Some("inv-001".to_string()),
            path: "src/main.rs".to_string(),
            kind: FileChangeKind::Modified,
            size: 1024,
            checksum: "sha256:abcdef".to_string(),
        },
    );
    prov.record(&file_change_record)
        .expect("provenance record should succeed");

    // 2. Write Governance provenance record (from policy evaluation)
    let governance_record = make_provenance_record(
        branch_id,
        ProvenanceType::Governance {
            decision_id: "gov-001".to_string(),
            change_ids: vec!["chg-001".to_string()],
            policy_version: "sha256:policy123".to_string(),
            result: "approved".to_string(),
            violations: vec![],
            manifest_hash: Some("sha256:manifest456".to_string()),
        },
    );
    prov.record(&governance_record)
        .expect("governance provenance should succeed");

    // 3. Update trust score (commit approved)
    let _transition = trust.on_audit_event("commit_approved", uid, Some(branch_id));

    // --- Verify results ---

    // Trust score should have increased
    let new_score = trust.get_score(uid).unwrap().score;
    assert!(
        new_score > initial_score,
        "score should increase after commit: {} > {}",
        new_score,
        initial_score
    );

    // Provenance records should exist
    let records = prov
        .get_records(branch_id)
        .expect("get_records should succeed");
    assert_eq!(
        records.len(),
        2,
        "should have FileChange + Governance records"
    );

    // Provenance chain should be queryable
    let chain = prov.get_chain(branch_id).expect("get_chain should succeed");
    assert_eq!(chain.file_changes.len(), 1);
    assert_eq!(chain.governance.len(), 1);
    assert!(chain.requests.is_empty());
    assert!(chain.inferences.is_empty());
}

/// Rejected commit should decrease trust and write provenance with violations.
#[test]
fn rejected_commit_decreases_trust_writes_rejection_provenance() {
    let dir = TempDir::new().unwrap();
    let trust_dir = dir.path().join("trust");
    let prov_dir = dir.path().join("provenance");
    std::fs::create_dir_all(&trust_dir).unwrap();
    std::fs::create_dir_all(&prov_dir).unwrap();

    let mut trust = make_trust_manager(&trust_dir);
    let prov = make_provenance_store(&prov_dir);

    let uid = 1000u32;
    let branch_id = "branch-reject-test";
    trust.register_uid(uid, "standard");
    let initial_score = trust.get_score(uid).unwrap().score;

    // Write rejection provenance
    let governance_record = make_provenance_record(
        branch_id,
        ProvenanceType::Governance {
            decision_id: "gov-reject-001".to_string(),
            change_ids: vec!["chg-002".to_string()],
            policy_version: "sha256:policy123".to_string(),
            result: "rejected".to_string(),
            violations: vec!["sensitive file .env in changeset".to_string()],
            manifest_hash: None,
        },
    );
    prov.record(&governance_record).unwrap();

    // Update trust (commit rejected)
    trust.on_audit_event("commit_rejected", uid, Some(branch_id));

    let new_score = trust.get_score(uid).unwrap().score;
    assert!(
        new_score < initial_score,
        "score should decrease after rejection: {} < {}",
        new_score,
        initial_score
    );

    let chain = prov.get_chain(branch_id).unwrap();
    assert_eq!(chain.governance.len(), 1);
    if let ProvenanceType::Governance {
        result, violations, ..
    } = &chain.governance[0].record_type
    {
        assert_eq!(result, "rejected");
        assert_eq!(violations.len(), 1);
    } else {
        panic!("expected Governance record");
    }
}

// ---------------------------------------------------------------------------
// §4.3: Full provenance chain (SDK mode simulation)
// ---------------------------------------------------------------------------

/// Simulate a full SDK-mode provenance chain: Request → Inference → ToolInvocation → FileChange → Governance.
#[test]
fn full_provenance_chain_sdk_mode() {
    let dir = TempDir::new().unwrap();
    let prov = make_provenance_store(dir.path());
    let branch_id = "branch-sdk-full";

    let request_id = "req-001";
    let inference_id = "inf-001";
    let invocation_id = "inv-001";
    let change_id = "chg-001";
    let decision_id = "gov-001";

    let records = vec![
        make_provenance_record(
            branch_id,
            ProvenanceType::Request {
                request_id: request_id.to_string(),
                user_uid: 1000,
                prompt_hash: "sha256:prompthash".to_string(),
            },
        ),
        make_provenance_record(
            branch_id,
            ProvenanceType::Inference {
                inference_id: inference_id.to_string(),
                request_id: request_id.to_string(),
                model: "claude-sonnet-4-20250514".to_string(),
                token_count: 350,
                tool_calls: vec!["write_file".to_string()],
            },
        ),
        make_provenance_record(
            branch_id,
            ProvenanceType::ToolInvocation {
                invocation_id: invocation_id.to_string(),
                inference_id: Some(inference_id.to_string()),
                tool_path: "/usr/bin/python3".to_string(),
                arguments_hash: Some("sha256:args".to_string()),
                pid: 12345,
                exit_code: Some(0),
                started_at: None,
                exited_at: None,
            },
        ),
        make_provenance_record(
            branch_id,
            ProvenanceType::FileChange {
                change_id: change_id.to_string(),
                invocation_id: Some(invocation_id.to_string()),
                path: "src/main.rs".to_string(),
                kind: FileChangeKind::Modified,
                size: 2048,
                checksum: "sha256:filehash".to_string(),
            },
        ),
        make_provenance_record(
            branch_id,
            ProvenanceType::Governance {
                decision_id: decision_id.to_string(),
                change_ids: vec![change_id.to_string()],
                policy_version: "sha256:policyver".to_string(),
                result: "approved".to_string(),
                violations: vec![],
                manifest_hash: Some("sha256:manifest".to_string()),
            },
        ),
    ];

    // Write all records in batch
    prov.record_batch(branch_id, &records)
        .expect("batch write should succeed");

    // Verify chain structure
    let chain = prov.get_chain(branch_id).unwrap();
    assert_eq!(chain.requests.len(), 1);
    assert_eq!(chain.inferences.len(), 1);
    assert_eq!(chain.tool_invocations.len(), 1);
    assert_eq!(chain.file_changes.len(), 1);
    assert_eq!(chain.governance.len(), 1);

    // Verify trace_chain from file path
    let trace = prov.trace_chain(branch_id, "src/main.rs").unwrap();
    assert!(
        !trace.is_empty(),
        "trace_chain should return records for src/main.rs"
    );
    // Trace should include FileChange and its upstream Governance
    let has_file_change = trace
        .iter()
        .any(|r| matches!(&r.record_type, ProvenanceType::FileChange { path, .. } if path == "src/main.rs"));
    assert!(
        has_file_change,
        "trace should include the FileChange record"
    );
}

// ---------------------------------------------------------------------------
// §4.1 + §4.3: Behavioral anomaly triggers trust drop + provenance
// ---------------------------------------------------------------------------

#[test]
fn behavioral_anomaly_triggers_trust_drop() {
    let dir = TempDir::new().unwrap();
    let mut trust = make_trust_manager(dir.path());
    trust.register_uid(1000, "standard");
    let initial_score = trust.get_score(1000).unwrap().score;

    // Simulate behavioral trigger (warning severity → -5)
    trust.on_audit_event("behavioral_trigger_warning", 1000, Some("branch-anom"));

    let score_after_warning = trust.get_score(1000).unwrap().score;
    assert_eq!(
        score_after_warning,
        initial_score.saturating_sub(5),
        "warning should decrease score by 5"
    );

    // Simulate critical behavioral trigger → -15
    trust.on_audit_event("behavioral_trigger_critical", 1000, Some("branch-anom"));

    let score_after_critical = trust.get_score(1000).unwrap().score;
    assert_eq!(
        score_after_critical,
        score_after_warning.saturating_sub(15),
        "critical should decrease score by 15"
    );
}

/// Containment violation should cause severe trust drop.
#[test]
fn containment_violation_severe_trust_drop() {
    let dir = TempDir::new().unwrap();
    let mut trust = make_trust_manager(dir.path());

    // Start at standard level with some trust built up
    trust.register_uid(1000, "privileged");
    // Add a few clean commits first
    for _ in 0..5 {
        trust.on_audit_event("commit_approved", 1000, None);
    }
    let score_before = trust.get_score(1000).unwrap().score;

    // Containment violation → -25
    trust.on_audit_event("containment_violation", 1000, Some("branch-escape"));

    let score_after = trust.get_score(1000).unwrap().score;
    assert!(
        score_before - score_after >= 25,
        "containment violation should drop score by at least 25: {} → {}",
        score_before,
        score_after
    );
}

// ---------------------------------------------------------------------------
// §4.1: Trust tier transitions
// ---------------------------------------------------------------------------

#[test]
fn trust_tier_transition_detection() {
    let dir = TempDir::new().unwrap();
    let mut trust = make_trust_manager(dir.path());

    // Start UID at score 25 (Restricted tier, range 20-39)
    trust.register_uid(1000, "standard");
    assert_eq!(trust.get_score(1000).unwrap().level, TrustLevel::Restricted);

    // Each commit_approved gives +2, but max_increase_per_day caps at +10.
    // So 5 commits = +10, score = 35 (still Restricted).
    // To cross into Standard (40+), we need to verify the daily cap behavior.
    //
    // With max_increase_per_day=10 and delta=+2:
    //   commits 1-5: score 27, 29, 31, 33, 35 (+10 total, capped)
    //   commits 6+: no change (daily cap reached)
    //
    // So with the default rules, crossing 40 requires multiple days.
    // Let's verify the cap is working correctly.
    let mut last_transition = None;
    for _ in 0..8 {
        let result = trust.on_audit_event("commit_approved", 1000, None);
        if result.is_some() {
            last_transition = result;
        }
    }

    let state = trust.get_score(1000).unwrap();
    // With max_increase_per_day=10 and initial=25, score should be 35
    assert_eq!(
        state.score, 35,
        "score should be 35 (25 + 10 daily cap): {}",
        state.score
    );
    assert_eq!(
        state.level,
        TrustLevel::Restricted,
        "still Restricted at score 35"
    );

    // No tier transition should have occurred (35 is still Restricted 20-39)
    assert!(
        last_transition.is_none(),
        "no tier transition expected within daily cap"
    );
}

// ---------------------------------------------------------------------------
// §4.1: Override mechanics
// ---------------------------------------------------------------------------

#[test]
fn trust_override_reflected_in_state() {
    let dir = TempDir::new().unwrap();
    let mut trust = make_trust_manager(dir.path());
    trust.register_uid(1000, "standard");

    trust
        .set_override(1000, TrustLevel::Elevated, 24)
        .expect("set_override should succeed");

    let state = trust.get_score(1000).unwrap();
    assert!(state.override_active);
    assert_eq!(state.override_level, Some(TrustLevel::Elevated));
    assert!(state.override_expires.is_some());
}

// ---------------------------------------------------------------------------
// §4.1: History persistence and retrieval
// ---------------------------------------------------------------------------

#[test]
fn trust_history_persists_and_queries() {
    let dir = TempDir::new().unwrap();
    let mut trust = make_trust_manager(dir.path());
    trust.register_uid(1000, "standard");

    // Generate some history
    trust.on_audit_event("commit_approved", 1000, Some("b1"));
    trust.on_audit_event("commit_approved", 1000, Some("b2"));
    trust.on_audit_event("policy_violation", 1000, Some("b3"));

    let history = trust
        .get_history(1000, 10)
        .expect("get_history should succeed");
    assert_eq!(history.len(), 3, "should have 3 history entries");

    // Verify ordering (most recent first or chronological)
    // and that event_type field is populated
    for event in &history {
        assert!(!event.event_type.is_empty(), "event_type should be set");
        assert_eq!(event.uid, 1000);
    }

    // History should survive reload
    let trust2 = make_trust_manager(dir.path());
    let history2 = trust2.get_history(1000, 10).unwrap();
    assert_eq!(
        history2.len(),
        history.len(),
        "history should survive reload"
    );
}

// ---------------------------------------------------------------------------
// §4.3: Provenance cleanup on branch rollback
// ---------------------------------------------------------------------------

#[test]
fn provenance_cleanup_on_rollback() {
    let dir = TempDir::new().unwrap();
    let prov = make_provenance_store(dir.path());
    let branch_id = "branch-rollback";

    // Write some records
    let record = make_provenance_record(
        branch_id,
        ProvenanceType::Request {
            request_id: "req-cleanup".to_string(),
            user_uid: 1000,
            prompt_hash: "sha256:hash".to_string(),
        },
    );
    prov.record(&record).unwrap();
    assert!(!prov.get_records(branch_id).unwrap().is_empty());

    // Cleanup (simulates rollback)
    prov.cleanup_branch(branch_id).unwrap();

    // Records should be gone
    let records = prov.get_records(branch_id).unwrap();
    assert!(
        records.is_empty(),
        "records should be cleaned up after rollback"
    );
}

// ---------------------------------------------------------------------------
// §4.1 + §4.3 + §4.5: Full commit-path integration
// ---------------------------------------------------------------------------

#[cfg(feature = "ima")]
#[test]
fn full_commit_path_trust_provenance_identity() {
    use puzzled::identity::IdentityManager;
    use ed25519_dalek::SigningKey;

    let dir = TempDir::new().unwrap();
    let trust_dir = dir.path().join("trust");
    let prov_dir = dir.path().join("provenance");
    std::fs::create_dir_all(&trust_dir).unwrap();
    std::fs::create_dir_all(&prov_dir).unwrap();

    let mut trust = make_trust_manager(&trust_dir);
    let prov = make_provenance_store(&prov_dir);

    let uid = 1000u32;
    let branch_id = "branch-full-integration";
    trust.register_uid(uid, "standard");

    // --- Step 1: Write provenance (FileChange + Governance) ---
    let records = vec![
        make_provenance_record(
            branch_id,
            ProvenanceType::FileChange {
                change_id: "chg-full-001".to_string(),
                invocation_id: None,
                path: "README.md".to_string(),
                kind: FileChangeKind::Added,
                size: 512,
                checksum: "sha256:readme".to_string(),
            },
        ),
        make_provenance_record(
            branch_id,
            ProvenanceType::Governance {
                decision_id: "gov-full-001".to_string(),
                change_ids: vec!["chg-full-001".to_string()],
                policy_version: "sha256:pol".to_string(),
                result: "approved".to_string(),
                violations: vec![],
                manifest_hash: None,
            },
        ),
    ];
    prov.record_batch(branch_id, &records).unwrap();

    // --- Step 2: Update trust ---
    trust.on_audit_event("commit_approved", uid, Some(branch_id));

    // --- Step 3: Issue JWT-SVID with live trust data ---
    let state = trust.get_score(uid).unwrap();
    let mut key_bytes = [0u8; 32];
    for (i, b) in key_bytes.iter_mut().enumerate() {
        *b = i as u8;
    }
    let mgr = IdentityManager::new(
        SigningKey::from_bytes(&key_bytes),
        "integration.test".to_string(),
        3600,
        true,
        false,
    );

    let token = mgr
        .issue_jwt_svid(
            branch_id,
            "standard",
            state.level.as_str(),
            state.score,
            &["api.example.com".to_string()],
            &[
                "landlock".to_string(),
                "seccomp".to_string(),
                "pid_ns".to_string(),
            ],
            "sha256:pol",
            None,
            0,
        )
        .unwrap();

    let claims = mgr
        .verify_jwt_svid(&token, Some("api.example.com"))
        .unwrap();

    // --- Verify all three modules are consistent ---
    assert_eq!(claims.trust_score, state.score);
    assert_eq!(claims.trust_level, state.level.as_str());
    assert_eq!(claims.branch_id, branch_id);
    assert_eq!(claims.agent_profile, "standard");
    assert_eq!(claims.governance.policy_version, "sha256:pol");

    let chain = prov.get_chain(branch_id).unwrap();
    assert_eq!(chain.file_changes.len(), 1);
    assert_eq!(chain.governance.len(), 1);
}

// ---------------------------------------------------------------------------
// §4.1: Baseline anomaly detection feeds into trust scoring
// ---------------------------------------------------------------------------

#[test]
fn baseline_anomaly_feeds_trust_scoring() {
    let dir = TempDir::new().unwrap();
    let mut trust = make_trust_manager(dir.path());
    trust.register_uid(1000, "standard");

    // Establish a baseline with normal observations
    for i in 0..15 {
        trust.observe_metric(1000, "exec_rate", 10.0 + (i as f64 * 0.1));
    }

    let score_before = trust.get_score(1000).unwrap().score;

    // Inject an anomalous observation (way above normal)
    let anomaly = trust.observe_metric(1000, "exec_rate", 1000.0);

    // observe_metric returns the anomaly severity but does NOT auto-apply
    // the trust delta — the caller (D-Bus handler / commit path) maps the
    // severity to the appropriate scoring event. This is the cross-module
    // wiring that should happen in puzzled's event pipeline.
    // J86: Use expect() instead of if-let to ensure the anomaly is detected.
    let severity = anomaly.expect("J86: 1000.0 should trigger anomaly after baseline of ~10.0");
    // Map severity to the corresponding scoring event
    let event_type = match severity {
        puzzled_types::BaselineSeverity::Warning => "behavioral_trigger_warning",
        puzzled_types::BaselineSeverity::Critical => "behavioral_trigger_critical",
        puzzled_types::BaselineSeverity::Fatal => "behavioral_trigger_fatal",
    };
    trust.on_audit_event(event_type, 1000, Some("branch-anom"));

    let score_after = trust.get_score(1000).unwrap().score;
    assert!(
        score_after < score_before,
        "anomaly + scoring event should decrease trust: {} < {}",
        score_after,
        score_before
    );
}
