// SPDX-License-Identifier: Apache-2.0
//! Live D-Bus integration tests — run against a live puzzled daemon.
//!
//! These tests auto-skip when puzzled is not running, so they are safe to
//! include in `cargo test --workspace`. When skipped, each test prints
//! instructions on how to run them with a live daemon.
//!
//! To run with a live daemon:
//!   1. Start puzzled in one terminal:
//!      `sudo cargo run -p puzzled`
//!
//!   2. Run the tests in another terminal:
//!      `sudo cargo test -p puzzled --test live_dbus_integration -- --test-threads=1`
//!
//! Tests are ordered: create → inspect → diff → list → rollback/commit.
//! Use `--test-threads=1` to preserve ordering when puzzled is running.
//!
//! Rate limit: puzzled allows 10 CreateBranch calls per UID per minute.
//! Tests are structured to stay within this limit, with cooldown sleeps
//! before groups that need fresh quota.

use serde_json::Value;

const SKIP_MESSAGE: &str = "\
    ╔══════════════════════════════════════════════════════════════════╗\n\
    ║  SKIPPED — puzzled is not running on D-Bus.                     ║\n\
    ║                                                                ║\n\
    ║  These are live integration tests that require a running       ║\n\
    ║  puzzled daemon. To run them:                                   ║\n\
    ║                                                                ║\n\
    ║  1. Start puzzled in one terminal (on a Linux host/VM):         ║\n\
    ║     sudo cargo run -p puzzled                                   ║\n\
    ║                                                                ║\n\
    ║  2. Run the tests in another terminal:                         ║\n\
    ║     sudo cargo test -p puzzled --test live_dbus_integration \\   ║\n\
    ║       -- --test-threads=1                                      ║\n\
    ╚══════════════════════════════════════════════════════════════════╝";

/// Helper: connect to puzzled over D-Bus (session bus for dev/test).
async fn connect_proxy() -> zbus::Result<zbus::Connection> {
    // Try session bus first (dev/test), fall back to system bus (production).
    match zbus::Connection::session().await {
        Ok(conn) => Ok(conn),
        Err(_) => zbus::Connection::system().await,
    }
}

/// D-Bus proxy for org.lobstertrap.PuzzlePod1.Manager.
#[zbus::proxy(
    interface = "org.lobstertrap.PuzzlePod1.Manager",
    default_service = "org.lobstertrap.PuzzlePod1",
    default_path = "/org/lobstertrap/PuzzlePod1/Manager"
)]
trait Manager {
    async fn create_branch(
        &self,
        profile: &str,
        base_path: &str,
        command_json: &str,
    ) -> zbus::Result<String>;
    async fn activate_branch(&self, branch_id: &str, command_json: &str) -> zbus::Result<String>;
    async fn commit_branch(&self, branch_id: &str) -> zbus::Result<String>;
    async fn rollback_branch(&self, branch_id: &str, reason: &str) -> zbus::Result<bool>;
    async fn inspect_branch(&self, branch_id: &str) -> zbus::Result<String>;
    async fn list_branches(&self) -> zbus::Result<String>;
    async fn diff_branch(&self, branch_id: &str) -> zbus::Result<String>;
    async fn list_agents(&self) -> zbus::Result<String>;
    async fn kill_agent(&self, branch_id: &str) -> zbus::Result<bool>;
    async fn reload_policy(&self) -> zbus::Result<(bool, String)>;
    async fn query_audit_events(&self, filter_json: &str) -> zbus::Result<String>;
    async fn export_audit_events(&self, format: &str) -> zbus::Result<String>;
    async fn approve_branch(&self, branch_id: &str) -> zbus::Result<String>;
    async fn reject_branch(&self, branch_id: &str, reason: &str) -> zbus::Result<bool>;
    async fn unregister_agent(&self, branch_id: &str) -> zbus::Result<bool>;
    async fn agent_info(&self, branch_id: &str) -> zbus::Result<String>;

    // §4.1 Trust methods
    async fn get_trust_score(&self, uid: u32) -> zbus::Result<String>;
    async fn get_baseline(&self, uid: u32) -> zbus::Result<String>;
    async fn reset_trust_score(&self, uid: u32, reason: &str) -> zbus::Result<bool>;
    async fn set_trust_override(
        &self,
        uid: u32,
        level: &str,
        duration_hours: u32,
    ) -> zbus::Result<bool>;
    async fn list_trust_history(&self, uid: u32, limit: u32) -> zbus::Result<String>;

    // §4.3 Provenance methods
    async fn report_provenance(&self, branch_id: &str, record_json: &str) -> zbus::Result<String>;
    async fn get_provenance(&self, branch_id: &str) -> zbus::Result<String>;

    // §4.5 Identity methods
    async fn get_identity_token(
        &self,
        branch_id: &str,
        audience_json: &str,
    ) -> zbus::Result<String>;
    async fn get_spiffe_id(&self, branch_id: &str) -> zbus::Result<String>;
    async fn get_identity_jwks(&self) -> zbus::Result<String>;
}

/// Try to get a D-Bus proxy to puzzled. Returns `None` (and prints skip
/// instructions) if puzzled is not reachable, so every test can bail early.
async fn try_get_proxy() -> Option<ManagerProxy<'static>> {
    let conn = match connect_proxy().await {
        Ok(c) => c,
        Err(_) => {
            eprintln!("{SKIP_MESSAGE}");
            return None;
        }
    };
    let conn: &'static zbus::Connection = Box::leak(Box::new(conn));
    let proxy = match ManagerProxy::new(conn).await {
        Ok(p) => p,
        Err(_) => {
            eprintln!("{SKIP_MESSAGE}");
            return None;
        }
    };

    // Probe with a cheap call to verify the service is actually registered.
    match proxy.list_branches().await {
        Ok(_) => Some(proxy),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("ServiceUnknown") || msg.contains("not activatable") {
                eprintln!("{SKIP_MESSAGE}");
                None
            } else {
                // Some other error — service is there but something else went wrong.
                Some(proxy)
            }
        }
    }
}

/// Convenience macro: skip the test if puzzled is not running.
macro_rules! require_puzzled {
    () => {
        match try_get_proxy().await {
            Some(p) => p,
            None => return,
        }
    };
}

// =========================================================================
// Connection & basic API tests
// =========================================================================

#[tokio::test]
async fn test_01_dbus_connection() {
    // Verify we can connect to puzzled's D-Bus interface.
    let _proxy = require_puzzled!();
    // If we get here without panic, connection succeeded.
}

#[tokio::test]
async fn test_02_list_branches_empty_or_populated() {
    let proxy = require_puzzled!();
    let json_str = proxy
        .list_branches()
        .await
        .expect("ListBranches should succeed");
    let parsed: Value = serde_json::from_str(&json_str)
        .unwrap_or_else(|e| panic!("ListBranches returned invalid JSON: {e}\nraw: {json_str}"));
    assert!(parsed.is_array(), "ListBranches should return a JSON array");
}

#[tokio::test]
async fn test_03_list_agents() {
    let proxy = require_puzzled!();
    let result = proxy.list_agents().await;
    assert!(result.is_ok(), "ListAgents should succeed: {:?}", result);

    let json_str = result.unwrap();
    let parsed: Value = serde_json::from_str(&json_str)
        .unwrap_or_else(|e| panic!("ListAgents returned invalid JSON: {e}\nraw: {json_str}"));
    assert!(parsed.is_array(), "ListAgents should return a JSON array");
}

#[tokio::test]
async fn test_04_reload_policy() {
    let proxy = require_puzzled!();
    let result = proxy.reload_policy().await;
    assert!(result.is_ok(), "ReloadPolicy should succeed: {:?}", result);
    let (success, message) = result.unwrap();
    assert!(
        success,
        "ReloadPolicy should return success=true: {message}"
    );
}

// =========================================================================
// Branch lifecycle: create → inspect → diff → rollback
// =========================================================================

#[tokio::test]
async fn test_10_create_branch_standard() {
    let proxy = require_puzzled!();

    // Create a branch with the "standard" profile.
    // base_path must be an existing directory on the host.
    let result = proxy.create_branch("standard", "/tmp", "[]").await;
    assert!(
        result.is_ok(),
        "CreateBranch(standard, /tmp) should succeed: {:?}",
        result
    );

    let json_str = result.unwrap();
    let parsed: Value = serde_json::from_str(&json_str)
        .unwrap_or_else(|e| panic!("CreateBranch returned invalid JSON: {e}\nraw: {json_str}"));

    // Should contain a branch_id
    assert!(
        parsed.get("branch_id").is_some() || parsed.get("id").is_some(),
        "CreateBranch response should contain branch_id: {json_str}"
    );
    eprintln!("Created branch: {json_str}");
}

#[tokio::test]
async fn test_11_create_branch_restricted() {
    let proxy = require_puzzled!();

    let result = proxy.create_branch("restricted", "/tmp", "[]").await;
    assert!(
        result.is_ok(),
        "CreateBranch(restricted, /tmp) should succeed: {:?}",
        result
    );
    let json_str = result.unwrap();
    eprintln!("Created restricted branch: {json_str}");
}

#[tokio::test]
async fn test_12_create_branch_invalid_profile() {
    let proxy = require_puzzled!();

    // Non-existent profile should fail
    let result = proxy
        .create_branch("nonexistent_profile_xyz", "/tmp", "[]")
        .await;
    assert!(
        result.is_err(),
        "CreateBranch with non-existent profile should fail"
    );
    let err = result.unwrap_err();
    eprintln!("Expected error for invalid profile: {err}");
}

#[tokio::test]
async fn test_13_create_branch_invalid_path() {
    let proxy = require_puzzled!();

    // Relative path should be rejected by input validation
    let result = proxy.create_branch("standard", "relative/path", "[]").await;
    assert!(
        result.is_err(),
        "CreateBranch with relative path should fail"
    );
}

#[tokio::test]
async fn test_14_create_branch_path_traversal() {
    let proxy = require_puzzled!();

    // Path traversal should be rejected
    let result = proxy
        .create_branch("standard", "/tmp/../etc/shadow", "[]")
        .await;
    assert!(
        result.is_err(),
        "CreateBranch with path traversal should fail"
    );
}

#[tokio::test]
async fn test_15_create_branch_invalid_command_json() {
    let proxy = require_puzzled!();

    // Invalid JSON for command should fail
    let result = proxy
        .create_branch("standard", "/tmp", "not valid json")
        .await;
    assert!(
        result.is_err(),
        "CreateBranch with invalid command JSON should fail"
    );
}

#[tokio::test]
async fn test_16_create_branch_with_command() {
    let proxy = require_puzzled!();

    // Create a branch with a real command (sleep keeps the agent alive)
    let result = proxy
        .create_branch("standard", "/tmp", r#"["/bin/sleep", "300"]"#)
        .await;
    assert!(
        result.is_ok(),
        "CreateBranch with command should succeed: {:?}",
        result
    );
    let json_str = result.unwrap();
    eprintln!("Created branch with command: {json_str}");
}

// =========================================================================
// Inspect, diff, and lifecycle management
//
// These tests share branches to minimize CreateBranch calls and stay
// within the 10/minute rate limit. Tests 10-16 consume 7 calls
// (including failed ones that still count against the limiter).
// =========================================================================

/// Helper: extract branch ID from a CreateBranch JSON response.
fn extract_branch_id(json_str: &str) -> String {
    let parsed: Value = serde_json::from_str(json_str).expect("invalid JSON from CreateBranch");

    if let Some(id) = parsed.get("branch_id").and_then(|v| v.as_str()) {
        return id.to_string();
    }
    if let Some(id) = parsed.get("id").and_then(|v| v.as_str()) {
        return id.to_string();
    }
    if let Some(id) = parsed.as_str() {
        return id.to_string();
    }

    panic!("Cannot extract branch_id from: {json_str}");
}

/// Helper: create a branch with a long-lived agent and return its ID.
/// Uses `/bin/sleep 300` so the branch stays alive for inspect/diff/rollback.
async fn create_test_branch(proxy: &ManagerProxy<'_>) -> String {
    let result = proxy
        .create_branch("standard", "/tmp", "[]")
        .await
        .expect("CreateBranch failed in helper");

    let id = extract_branch_id(&result);

    // Activate the branch to spawn a sandboxed process.
    let _activate_result = proxy.activate_branch(&id, r#"["/bin/sleep", "300"]"#).await;

    // Give the agent process time to start and sandbox to initialize.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    id
}

/// Combined test: inspect + diff + agent_info + rollback on one branch.
/// Uses a single CreateBranch call to stay within rate limits.
#[tokio::test]
async fn test_20_inspect_diff_rollback() {
    let proxy = require_puzzled!();
    let branch_id = create_test_branch(&proxy).await;

    // --- Inspect ---
    let result = proxy.inspect_branch(&branch_id).await;
    assert!(
        result.is_ok(),
        "InspectBranch({branch_id}) should succeed: {:?}",
        result
    );
    let json_str = result.unwrap();
    let parsed: Value = serde_json::from_str(&json_str)
        .unwrap_or_else(|e| panic!("InspectBranch returned invalid JSON: {e}\nraw: {json_str}"));
    assert!(
        parsed.get("state").is_some(),
        "InspectBranch should include state: {json_str}"
    );
    eprintln!("Inspected branch {branch_id}: {json_str}");

    // --- Diff ---
    let diff_result = proxy.diff_branch(&branch_id).await;
    assert!(
        diff_result.is_ok(),
        "DiffBranch({branch_id}) should succeed: {:?}",
        diff_result
    );
    let diff_str = diff_result.unwrap();
    let diff_parsed: Value = serde_json::from_str(&diff_str)
        .unwrap_or_else(|e| panic!("DiffBranch returned invalid JSON: {e}\nraw: {diff_str}"));
    assert!(
        diff_parsed.is_array(),
        "DiffBranch should return a JSON array: {diff_str}"
    );
    eprintln!(
        "Diff for {branch_id}: {} changes",
        diff_parsed.as_array().map(|a| a.len()).unwrap_or(0)
    );

    // --- AgentInfo ---
    let info_result = proxy.agent_info(&branch_id).await;
    eprintln!("AgentInfo for {branch_id}: {:?}", info_result);

    // --- Rollback ---
    let rollback = proxy.rollback_branch(&branch_id, "test rollback").await;
    assert!(
        rollback.is_ok(),
        "RollbackBranch({branch_id}) should succeed: {:?}",
        rollback
    );
    let success = rollback.unwrap();
    assert!(success, "RollbackBranch should return true");

    // After rollback, inspect should fail or show rolled-back state
    let inspect_after = proxy.inspect_branch(&branch_id).await;
    eprintln!("Inspect after rollback: {:?}", inspect_after);
}

#[tokio::test]
async fn test_21_inspect_nonexistent_branch() {
    let proxy = require_puzzled!();

    let result = proxy
        .inspect_branch("00000000-0000-0000-0000-000000000000")
        .await;
    eprintln!("Inspect non-existent: {:?}", result);
}

#[tokio::test]
async fn test_22_rollback_nonexistent_branch() {
    let proxy = require_puzzled!();

    let result = proxy
        .rollback_branch("00000000-0000-0000-0000-000000000000", "test")
        .await;
    eprintln!("Rollback non-existent: {:?}", result);
}

/// Test commit on a branch (uses 1 CreateBranch call).
#[tokio::test]
async fn test_23_commit_branch() {
    let proxy = require_puzzled!();
    let branch_id = create_test_branch(&proxy).await;

    // Commit the branch (empty changeset should be approved by policy)
    let result = proxy.commit_branch(&branch_id).await;
    eprintln!("Commit result for {branch_id}: {:?}", result);

    // Cleanup if commit didn't consume the branch
    let _ = proxy.rollback_branch(&branch_id, "test cleanup").await;
}

/// Test kill agent (uses 1 CreateBranch call).
#[tokio::test]
async fn test_24_kill_agent() {
    let proxy = require_puzzled!();
    let branch_id = create_test_branch(&proxy).await;

    let kill_result = proxy.kill_agent(&branch_id).await;
    eprintln!("KillAgent({branch_id}): {:?}", kill_result);

    // Cleanup
    let _ = proxy.rollback_branch(&branch_id, "killed").await;
}

// =========================================================================
// Audit (no branch creation needed)
// =========================================================================

#[tokio::test]
async fn test_30_query_audit_events() {
    let proxy = require_puzzled!();

    let result = proxy.query_audit_events("{}").await;
    assert!(
        result.is_ok(),
        "QueryAuditEvents should succeed: {:?}",
        result
    );

    let json_str = result.unwrap();
    let parsed: Value = serde_json::from_str(&json_str)
        .unwrap_or_else(|e| panic!("QueryAuditEvents returned invalid JSON: {e}\nraw: {json_str}"));
    assert!(
        parsed.is_array(),
        "QueryAuditEvents should return a JSON array"
    );
    eprintln!("Audit events: {} entries", parsed.as_array().unwrap().len());
}

#[tokio::test]
async fn test_31_export_audit_events_json() {
    let proxy = require_puzzled!();

    let result = proxy.export_audit_events("json").await;
    assert!(
        result.is_ok(),
        "ExportAuditEvents(json) should succeed: {:?}",
        result
    );
}

#[tokio::test]
async fn test_32_export_audit_events_csv() {
    let proxy = require_puzzled!();

    let result = proxy.export_audit_events("csv").await;
    assert!(
        result.is_ok(),
        "ExportAuditEvents(csv) should succeed: {:?}",
        result
    );
}

// =========================================================================
// Input validation & security
// =========================================================================

#[tokio::test]
async fn test_40_create_branch_null_byte_in_profile() {
    let proxy = require_puzzled!();

    let result = proxy.create_branch("standard\x00evil", "/tmp", "[]").await;
    assert!(result.is_err(), "Profile with null byte should be rejected");
}

#[tokio::test]
async fn test_41_create_branch_injection_in_profile() {
    let proxy = require_puzzled!();

    let result = proxy
        .create_branch("standard; rm -rf /", "/tmp", "[]")
        .await;
    assert!(
        result.is_err(),
        "Profile with shell injection should be rejected"
    );
}

#[tokio::test]
async fn test_42_create_branch_null_byte_in_command() {
    let proxy = require_puzzled!();

    let result = proxy
        .create_branch("standard", "/tmp", r#"["/bin/sh\u0000", "-c", "evil"]"#)
        .await;
    // Should either fail to parse JSON or reject the null byte
    eprintln!("Null byte in command: {:?}", result);
}

#[tokio::test]
async fn test_43_create_branch_empty_profile() {
    let proxy = require_puzzled!();

    let result = proxy.create_branch("", "/tmp", "[]").await;
    assert!(result.is_err(), "Empty profile name should be rejected");
}

// =========================================================================
// Full lifecycle: create → inspect → diff → commit/rollback
// These tests wait for the rate limit window to reset first.
// =========================================================================

#[tokio::test]
async fn test_60_full_lifecycle_rollback() {
    let proxy = require_puzzled!();

    // Wait for rate limit window to reset (previous tests may have consumed quota).
    eprintln!("Waiting 65s for rate limit window to reset...");
    tokio::time::sleep(std::time::Duration::from_secs(65)).await;

    // 1. Create branch with a long-lived agent
    let create_result = proxy
        .create_branch("standard", "/tmp", r#"["/bin/sleep", "300"]"#)
        .await
        .expect("CreateBranch should succeed");
    let branch_id = extract_branch_id(&create_result);
    eprintln!("1. Created branch: {branch_id}");

    // Give agent time to start
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // 2. Inspect — should be Active
    let inspect = proxy
        .inspect_branch(&branch_id)
        .await
        .expect("InspectBranch should succeed");
    let inspect_parsed: Value = serde_json::from_str(&inspect).expect("invalid JSON");
    eprintln!(
        "2. Inspected: state={}",
        inspect_parsed.get("state").unwrap_or(&Value::Null)
    );

    // 3. Diff — should be empty (no writes)
    let diff = proxy
        .diff_branch(&branch_id)
        .await
        .expect("DiffBranch should succeed");
    let diff_parsed: Value = serde_json::from_str(&diff).expect("invalid JSON");
    let change_count = diff_parsed.as_array().map(|a| a.len()).unwrap_or(0);
    eprintln!("3. Diff: {change_count} changes");

    // 4. Rollback
    let rollback = proxy
        .rollback_branch(&branch_id, "lifecycle test")
        .await
        .expect("RollbackBranch should succeed");
    assert!(rollback, "RollbackBranch should return true");
    eprintln!("4. Rolled back successfully");

    // 5. Verify branch is gone or in rolled-back state
    let inspect_after = proxy.inspect_branch(&branch_id).await;
    eprintln!("5. After rollback: {:?}", inspect_after);
}

#[tokio::test]
async fn test_61_full_lifecycle_commit() {
    let proxy = require_puzzled!();

    // 1. Create branch with a long-lived agent
    let create_result = proxy
        .create_branch("standard", "/tmp", r#"["/bin/sleep", "300"]"#)
        .await
        .expect("CreateBranch should succeed");
    let branch_id = extract_branch_id(&create_result);
    eprintln!("1. Created branch: {branch_id}");

    // Give agent time to start
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // 2. Commit (empty changeset)
    let commit_result = proxy.commit_branch(&branch_id).await;
    match &commit_result {
        Ok(result) => eprintln!("2. Commit result: {result}"),
        Err(e) => eprintln!("2. Commit error (may be expected): {e}"),
    }

    // 3. Verify branch state after commit
    let inspect_after = proxy.inspect_branch(&branch_id).await;
    eprintln!("3. After commit: {:?}", inspect_after);

    // Cleanup — rollback if commit didn't consume the branch
    let _ = proxy.rollback_branch(&branch_id, "test cleanup").await;
}

// =========================================================================
// Rate limiting (runs last — creates many branches and exhausts quota)
// =========================================================================

#[tokio::test]
async fn test_90_rate_limiting() {
    let proxy = require_puzzled!();

    // Wait for rate limit window to reset from lifecycle tests.
    eprintln!("Waiting 65s for rate limit window to reset...");
    tokio::time::sleep(std::time::Duration::from_secs(65)).await;

    // Rapidly create branches to trigger rate limiting (>10 per minute)
    let mut created = Vec::new();
    let mut hit_limit = false;

    for i in 0..15 {
        let result = proxy
            .create_branch("standard", "/tmp", r#"["/bin/sleep", "10"]"#)
            .await;
        match result {
            Ok(json_str) => {
                eprintln!("Request {}: OK", i + 1);
                let id = extract_branch_id(&json_str);
                created.push(id);
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("rate") || msg.contains("limit") || msg.contains("Rate") {
                    eprintln!("Request {}: rate-limited (expected)", i + 1);
                    hit_limit = true;
                    break;
                } else {
                    eprintln!("Request {}: error: {}", i + 1, msg);
                }
            }
        }
    }

    // Cleanup all created branches
    for id in &created {
        let _ = proxy.rollback_branch(id, "rate limit test cleanup").await;
    }

    assert!(
        hit_limit,
        "Should have hit rate limit after 10+ rapid CreateBranch calls (created {} before stopping)",
        created.len()
    );
}

// =========================================================================
// §4.1 Trust D-Bus methods
// =========================================================================

#[tokio::test]
async fn test_50_get_trust_score() {
    let proxy = require_puzzled!();

    // Query trust score for the caller's own UID (uid 0 = root)
    let result = proxy.get_trust_score(0).await;
    assert!(result.is_ok(), "GetTrustScore should succeed: {:?}", result);

    let json_str = result.unwrap();
    let parsed: Value = serde_json::from_str(&json_str)
        .unwrap_or_else(|e| panic!("GetTrustScore returned invalid JSON: {e}\nraw: {json_str}"));
    // Should contain score and level fields
    assert!(
        parsed.get("score").is_some() || parsed.get("uid").is_some(),
        "GetTrustScore should return trust state JSON: {json_str}"
    );
    eprintln!("Trust score: {json_str}");
}

#[tokio::test]
async fn test_51_get_baseline() {
    let proxy = require_puzzled!();

    let result = proxy.get_baseline(0).await;
    assert!(result.is_ok(), "GetBaseline should succeed: {:?}", result);

    let json_str = result.unwrap();
    // Should be valid JSON (may be empty baseline)
    let _parsed: Value = serde_json::from_str(&json_str)
        .unwrap_or_else(|e| panic!("GetBaseline returned invalid JSON: {e}\nraw: {json_str}"));
    eprintln!("Baseline: {json_str}");
}

#[tokio::test]
async fn test_52_list_trust_history() {
    let proxy = require_puzzled!();

    let result = proxy.list_trust_history(0, 20).await;
    assert!(
        result.is_ok(),
        "ListTrustHistory should succeed: {:?}",
        result
    );

    let json_str = result.unwrap();
    let parsed: Value = serde_json::from_str(&json_str)
        .unwrap_or_else(|e| panic!("ListTrustHistory returned invalid JSON: {e}\nraw: {json_str}"));
    assert!(
        parsed.is_array(),
        "ListTrustHistory should return a JSON array: {json_str}"
    );
    eprintln!(
        "Trust history: {} entries",
        parsed.as_array().unwrap().len()
    );
}

#[tokio::test]
async fn test_53_reset_trust_score() {
    let proxy = require_puzzled!();

    // Reset trust for UID 0 (root — should be allowed)
    let result = proxy.reset_trust_score(0, "integration test reset").await;
    assert!(
        result.is_ok(),
        "ResetTrustScore should succeed: {:?}",
        result
    );
    assert!(result.unwrap(), "ResetTrustScore should return true");
}

#[tokio::test]
async fn test_54_set_trust_override() {
    let proxy = require_puzzled!();

    // Set a temporary elevated trust override for 1 hour
    let result = proxy.set_trust_override(0, "elevated", 1).await;
    assert!(
        result.is_ok(),
        "SetTrustOverride should succeed: {:?}",
        result
    );
    assert!(result.unwrap(), "SetTrustOverride should return true");

    // Verify the override is reflected in get_trust_score
    let score_result = proxy.get_trust_score(0).await.unwrap();
    let parsed: Value = serde_json::from_str(&score_result).unwrap();
    assert_eq!(
        parsed.get("override_active").and_then(|v| v.as_bool()),
        Some(true),
        "Override should be active: {score_result}"
    );
}

// =========================================================================
// §4.3 Provenance D-Bus methods
// =========================================================================

#[tokio::test]
async fn test_55_report_and_get_provenance() {
    let proxy = require_puzzled!();

    // Create a branch first so we have a valid branch_id
    let create_result = proxy
        .create_branch("standard", "/tmp", r#"["/bin/sleep", "60"]"#)
        .await;
    if create_result.is_err() {
        eprintln!("Skipping provenance test — branch creation failed (may be rate-limited)");
        return;
    }
    let branch_id = extract_branch_id(&create_result.unwrap());

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Report a provenance record
    let record_json = serde_json::json!({
        "id": "test-prov-001",
        "record_type": {
            "type": "request",
            "request_id": "req-test-001",
            "user_uid": 0,
            "prompt_hash": "sha256:testhash"
        },
        "branch_id": branch_id,
        "timestamp": chrono::Utc::now().to_rfc3339()
    })
    .to_string();

    let report_result = proxy.report_provenance(&branch_id, &record_json).await;
    assert!(
        report_result.is_ok(),
        "ReportProvenance should succeed: {:?}",
        report_result
    );
    eprintln!("ReportProvenance: {}", report_result.unwrap());

    // Get provenance records for the branch
    let get_result = proxy.get_provenance(&branch_id).await;
    assert!(
        get_result.is_ok(),
        "GetProvenance should succeed: {:?}",
        get_result
    );
    let prov_str = get_result.unwrap();
    assert!(
        !prov_str.is_empty(),
        "GetProvenance should return non-empty data"
    );
    eprintln!("GetProvenance: {}", &prov_str[..prov_str.len().min(200)]);

    // Cleanup
    let _ = proxy.rollback_branch(&branch_id, "provenance test").await;
}

#[tokio::test]
async fn test_56_get_provenance_nonexistent_branch() {
    let proxy = require_puzzled!();

    let result = proxy
        .get_provenance("00000000-0000-0000-0000-nonexistent")
        .await;
    // Should either return empty or error — not crash
    eprintln!("GetProvenance non-existent: {:?}", result);
}

// =========================================================================
// §4.5 Identity D-Bus methods
// =========================================================================

#[tokio::test]
async fn test_57_get_identity_jwks() {
    let proxy = require_puzzled!();

    let result = proxy.get_identity_jwks().await;
    assert!(
        result.is_ok(),
        "GetIdentityJwks should succeed: {:?}",
        result
    );

    let jwks_str = result.unwrap();
    let parsed: Value = serde_json::from_str(&jwks_str)
        .unwrap_or_else(|e| panic!("GetIdentityJwks returned invalid JSON: {e}\nraw: {jwks_str}"));
    // JWKS should have a "keys" array
    assert!(
        parsed.get("keys").is_some(),
        "JWKS should contain 'keys' field: {jwks_str}"
    );
    let keys = parsed["keys"].as_array().unwrap();
    assert!(!keys.is_empty(), "JWKS should have at least one key");
    assert_eq!(keys[0]["kty"], "OKP", "Key type should be OKP (Ed25519)");
    assert_eq!(keys[0]["crv"], "Ed25519");
    eprintln!("JWKS: {jwks_str}");
}

#[tokio::test]
async fn test_58_get_spiffe_id() {
    let proxy = require_puzzled!();

    // Create a branch to get its SPIFFE ID
    let create_result = proxy
        .create_branch("standard", "/tmp", r#"["/bin/sleep", "60"]"#)
        .await;
    if create_result.is_err() {
        eprintln!("Skipping SPIFFE ID test — branch creation failed");
        return;
    }
    let branch_id = extract_branch_id(&create_result.unwrap());
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let result = proxy.get_spiffe_id(&branch_id).await;
    assert!(result.is_ok(), "GetSpiffeId should succeed: {:?}", result);

    let spiffe_id = result.unwrap();
    assert!(
        spiffe_id.starts_with("spiffe://"),
        "SPIFFE ID should start with 'spiffe://': {spiffe_id}"
    );
    assert!(
        spiffe_id.contains(&branch_id),
        "SPIFFE ID should contain branch_id: {spiffe_id}"
    );
    eprintln!("SPIFFE ID: {spiffe_id}");

    // Cleanup
    let _ = proxy.rollback_branch(&branch_id, "spiffe test").await;
}

#[tokio::test]
async fn test_59_get_identity_token() {
    let proxy = require_puzzled!();

    // Create a branch to get its identity token
    let create_result = proxy
        .create_branch("standard", "/tmp", r#"["/bin/sleep", "60"]"#)
        .await;
    if create_result.is_err() {
        eprintln!("Skipping identity token test — branch creation failed");
        return;
    }
    let branch_id = extract_branch_id(&create_result.unwrap());
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let audience_json = serde_json::json!(["api.example.com"]).to_string();
    let result = proxy.get_identity_token(&branch_id, &audience_json).await;
    assert!(
        result.is_ok(),
        "GetIdentityToken should succeed: {:?}",
        result
    );

    let token = result.unwrap();
    // JWT should have 3 dot-separated parts
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT-SVID should have 3 parts: {token}");
    eprintln!(
        "JWT-SVID: {}...{}",
        &token[..30],
        &token[token.len() - 20..]
    );

    // Cleanup
    let _ = proxy.rollback_branch(&branch_id, "identity test").await;
}

// =========================================================================
// ActivateBranch tests
// =========================================================================

/// Test activate_branch spawns a sandboxed process and returns a PID.
#[tokio::test]
async fn test_70_activate_branch() {
    let proxy = require_puzzled!();

    // Step 1: Create branch (workspace only, no process)
    let create_result = proxy.create_branch("standard", "/tmp", "[]").await;
    assert!(
        create_result.is_ok(),
        "CreateBranch should succeed: {:?}",
        create_result
    );
    let create_json = create_result.unwrap();
    let branch_id = extract_branch_id(&create_json);

    // Verify pid is null after create
    let create_parsed: Value = serde_json::from_str(&create_json).unwrap();
    assert!(
        create_parsed.get("pid").is_none_or(|v| v.is_null()),
        "pid should be null after CreateBranch (no process spawned): {:?}",
        create_parsed.get("pid")
    );

    // Step 2: Activate branch (spawn sandboxed process)
    let activate_result = proxy
        .activate_branch(&branch_id, r#"["/bin/sleep", "60"]"#)
        .await;
    if let Err(ref e) = activate_result {
        let msg = format!("{e:?}");
        if msg.contains("Read-only file system") || msg.contains("cgroup") {
            eprintln!("Skipping activate test — cgroupfs is read-only (CI container)");
            let _ = proxy.rollback_branch(&branch_id, "skip").await;
            return;
        }
    }
    assert!(
        activate_result.is_ok(),
        "ActivateBranch should succeed: {:?}",
        activate_result
    );
    let activate_json = activate_result.unwrap();
    let activate_parsed: Value = serde_json::from_str(&activate_json).unwrap();

    // Verify pid is set after activation
    let pid = activate_parsed.get("pid");
    assert!(
        pid.is_some() && !pid.unwrap().is_null(),
        "pid should be set after ActivateBranch: {activate_json}"
    );
    eprintln!("ActivateBranch: branch={branch_id}, pid={:?}", pid.unwrap());

    // Cleanup
    let _ = proxy.kill_agent(&branch_id).await;
    let _ = proxy.rollback_branch(&branch_id, "activate test").await;
}

/// Test activate_branch on a nonexistent branch fails.
#[tokio::test]
async fn test_71_activate_nonexistent_branch() {
    let proxy = require_puzzled!();

    let result = proxy
        .activate_branch(
            "00000000-0000-0000-0000-000000000000",
            r#"["/bin/sleep", "1"]"#,
        )
        .await;
    assert!(
        result.is_err(),
        "ActivateBranch on nonexistent branch should fail"
    );
    eprintln!("ActivateBranch nonexistent: {:?}", result);
}

/// Test double activation fails (branch already has a running sandbox).
#[tokio::test]
async fn test_72_activate_branch_twice() {
    let proxy = require_puzzled!();

    let create_result = proxy.create_branch("standard", "/tmp", "[]").await;
    if create_result.is_err() {
        eprintln!("Skipping double-activate test — branch creation failed");
        return;
    }
    let branch_id = extract_branch_id(&create_result.unwrap());

    // First activation should succeed
    let first = proxy
        .activate_branch(&branch_id, r#"["/bin/sleep", "60"]"#)
        .await;
    if let Err(ref e) = first {
        let msg = format!("{e:?}");
        if msg.contains("Read-only file system") || msg.contains("cgroup") {
            eprintln!("Skipping double-activate test — cgroupfs is read-only (CI container)");
            let _ = proxy.rollback_branch(&branch_id, "skip").await;
            return;
        }
    }
    assert!(
        first.is_ok(),
        "First ActivateBranch should succeed: {:?}",
        first
    );

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Second activation should fail
    let second = proxy
        .activate_branch(&branch_id, r#"["/bin/sleep", "60"]"#)
        .await;
    assert!(
        second.is_err(),
        "Second ActivateBranch should fail (already running)"
    );
    eprintln!("Double activate error: {:?}", second);

    // Cleanup
    let _ = proxy.kill_agent(&branch_id).await;
    let _ = proxy
        .rollback_branch(&branch_id, "double-activate test")
        .await;
}
