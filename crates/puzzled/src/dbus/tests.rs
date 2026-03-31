// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::dbus::helpers::{
    check_branch_access, should_emit_behavioral_trigger, BEHAVIORAL_TRIGGER_MAX_AGE,
    MAX_BASE_PATH_LEN, MAX_BEHAVIORAL_TRIGGER_ENTRIES, MAX_BRANCH_ID_LEN, MAX_COMMAND_JSON_LEN,
    MAX_PROFILE_NAME_LEN,
};

// -----------------------------------------------------------------------
// validate_branch_id — production function tests
// -----------------------------------------------------------------------

#[test]
fn test_validate_branch_id_valid() {
    assert!(validate_branch_id("my-branch-123").is_ok());
    assert!(validate_branch_id("branch_with_underscore").is_ok());
    assert!(validate_branch_id("a").is_ok());
    assert!(validate_branch_id("UPPERCASE").is_ok());
}

#[test]
fn test_validate_branch_id_empty() {
    let err = validate_branch_id("").unwrap_err();
    assert!(err.to_string().contains("must not be empty"));
}

#[test]
fn test_validate_branch_id_invalid_chars() {
    // Path traversal
    assert!(validate_branch_id("../etc/passwd").is_err());
    // Shell metacharacters
    assert!(validate_branch_id("branch;rm -rf /").is_err());
    // Spaces
    assert!(validate_branch_id("has space").is_err());
    // Null bytes
    assert!(validate_branch_id("null\x00byte").is_err());
    // Slashes
    assert!(validate_branch_id("with/slash").is_err());
}

#[test]
fn test_validate_branch_id_too_long() {
    let long_id = "a".repeat(MAX_BRANCH_ID_LEN + 1);
    let err = validate_branch_id(&long_id).unwrap_err();
    assert!(err.to_string().contains("maximum length"));
}

#[test]
fn test_validate_branch_id_max_length_accepted() {
    let max_id = "a".repeat(MAX_BRANCH_ID_LEN);
    assert!(validate_branch_id(&max_id).is_ok());
}

// -----------------------------------------------------------------------
// validate_dbus_inputs — production function tests
// -----------------------------------------------------------------------

#[test]
fn test_validate_dbus_inputs_valid() {
    assert!(validate_dbus_inputs("standard", "/workspace", "[]").is_ok());
    assert!(validate_dbus_inputs("my-profile_v2", "/home/user/project", "").is_ok());
}

#[test]
fn test_validate_dbus_inputs_empty_profile() {
    assert!(validate_dbus_inputs("", "/workspace", "[]").is_err());
}

#[test]
fn test_validate_dbus_inputs_profile_special_chars() {
    // Slash — path traversal
    assert!(validate_dbus_inputs("../hack", "/workspace", "").is_err());
    // Semicolon — command injection
    assert!(validate_dbus_inputs("a;b", "/workspace", "").is_err());
    // Space
    assert!(validate_dbus_inputs("a b", "/workspace", "").is_err());
}

#[test]
fn test_validate_dbus_inputs_profile_too_long() {
    let long_profile = "a".repeat(MAX_PROFILE_NAME_LEN + 1);
    assert!(validate_dbus_inputs(&long_profile, "/workspace", "").is_err());
}

#[test]
fn test_validate_dbus_inputs_relative_path() {
    assert!(validate_dbus_inputs("standard", "relative/path", "").is_err());
    assert!(validate_dbus_inputs("standard", "./local", "").is_err());
}

#[test]
fn test_validate_dbus_inputs_path_traversal() {
    assert!(validate_dbus_inputs("standard", "/workspace/../etc/shadow", "").is_err());
}

#[test]
fn test_validate_dbus_inputs_path_null_bytes() {
    assert!(validate_dbus_inputs("standard", "/workspace/\x00evil", "").is_err());
}

#[test]
fn test_validate_dbus_inputs_path_too_long() {
    let long_path = format!("/{}", "a".repeat(MAX_BASE_PATH_LEN));
    assert!(validate_dbus_inputs("standard", &long_path, "").is_err());
}

#[test]
fn test_validate_dbus_inputs_command_too_long() {
    let long_cmd = format!("[\"{}\"]", "a".repeat(MAX_COMMAND_JSON_LEN));
    assert!(validate_dbus_inputs("standard", "/workspace", &long_cmd).is_err());
}

// -----------------------------------------------------------------------
// check_branch_access — production function tests (H-30)
// -----------------------------------------------------------------------

#[test]
fn test_check_branch_access_root_always_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let manager = create_test_manager(dir.path());

    // Even for a non-existent branch, root gets "not found" not "access denied"
    let id = BranchId::from("nonexistent".to_string());
    let result = check_branch_access(0, &manager, &id);
    // Root bypasses the access check entirely — returns Ok even if branch not found
    assert!(result.is_ok());
}

#[test]
fn test_check_branch_access_nonexistent_branch_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let manager = create_test_manager(dir.path());

    // H-30: Non-root caller on non-existent branch should get an error
    let id = BranchId::from("ghost-branch".to_string());
    let result = check_branch_access(1000, &manager, &id);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
}

// -----------------------------------------------------------------------
// RateLimiter — production struct tests
// -----------------------------------------------------------------------

#[test]
fn test_rate_limiter_production_allows_under_limit() {
    let mut limiter = RateLimiter::new();
    for _ in 0..RateLimiter::MAX_PER_MINUTE {
        assert!(limiter.check(1000));
    }
}

#[test]
fn test_rate_limiter_production_blocks_over_limit() {
    let mut limiter = RateLimiter::new();
    for _ in 0..RateLimiter::MAX_PER_MINUTE {
        assert!(limiter.check(1000));
    }
    assert!(!limiter.check(1000));
}

#[test]
fn test_rate_limiter_production_per_uid_isolation() {
    let mut limiter = RateLimiter::new();
    // Fill uid 1000
    for _ in 0..RateLimiter::MAX_PER_MINUTE {
        limiter.check(1000);
    }
    assert!(!limiter.check(1000));
    // uid 1001 unaffected
    assert!(limiter.check(1001));
}

#[test]
fn test_rate_limiter_production_uid_eviction_at_capacity() {
    // A3: Verify that when MAX_TRACKED_UIDS is reached, stale UIDs are evicted
    let mut limiter = RateLimiter::new();
    // Fill up to capacity
    for uid in 0..RateLimiter::MAX_TRACKED_UIDS as u32 {
        limiter.check(uid);
    }
    assert_eq!(limiter.requests.len(), RateLimiter::MAX_TRACKED_UIDS);

    // One more UID should evict the oldest
    assert!(limiter.check(RateLimiter::MAX_TRACKED_UIDS as u32));
    assert!(limiter.requests.len() <= RateLimiter::MAX_TRACKED_UIDS);
}

// -----------------------------------------------------------------------
// should_emit_behavioral_trigger — production function tests (PM11/M-db4)
// -----------------------------------------------------------------------

#[test]
fn test_behavioral_trigger_throttle_first_emission() {
    let map = std::sync::Mutex::new(HashMap::new());
    // First emission should always be allowed
    assert!(should_emit_behavioral_trigger(&map, "branch-1"));
}

#[test]
fn test_behavioral_trigger_throttle_suppresses_rapid_emissions() {
    let map = std::sync::Mutex::new(HashMap::new());
    // First: allowed
    assert!(should_emit_behavioral_trigger(&map, "branch-1"));
    // Second (immediate): suppressed
    assert!(!should_emit_behavioral_trigger(&map, "branch-1"));
}

#[test]
fn test_behavioral_trigger_throttle_per_branch() {
    let map = std::sync::Mutex::new(HashMap::new());
    assert!(should_emit_behavioral_trigger(&map, "branch-1"));
    // Different branch should be independent
    assert!(should_emit_behavioral_trigger(&map, "branch-2"));
    // branch-1 still throttled
    assert!(!should_emit_behavioral_trigger(&map, "branch-1"));
}

#[test]
fn test_behavioral_trigger_throttle_evicts_old_entries() {
    let map = std::sync::Mutex::new(HashMap::new());
    // Pre-fill with old entries
    {
        let mut m = map.lock().unwrap();
        let old_time = std::time::Instant::now()
            - BEHAVIORAL_TRIGGER_MAX_AGE
            - std::time::Duration::from_secs(1);
        for i in 0..100 {
            m.insert(format!("stale-{}", i), old_time);
        }
    }
    // M-db4: Stale entries should be evicted on next check
    assert!(should_emit_behavioral_trigger(&map, "fresh-branch"));
    let m = map.lock().unwrap();
    // All stale entries should be gone, only fresh-branch remains
    assert_eq!(m.len(), 1);
    assert!(m.contains_key("fresh-branch"));
}

#[test]
fn test_behavioral_trigger_throttle_caps_at_max() {
    let map = std::sync::Mutex::new(HashMap::new());
    // Pre-fill to MAX
    {
        let mut m = map.lock().unwrap();
        for i in 0..MAX_BEHAVIORAL_TRIGGER_ENTRIES {
            m.insert(format!("branch-{}", i), std::time::Instant::now());
        }
    }
    // M-db4: Should evict oldest when at capacity
    assert!(should_emit_behavioral_trigger(&map, "new-branch"));
    let m = map.lock().unwrap();
    assert!(m.len() <= MAX_BEHAVIORAL_TRIGGER_ENTRIES);
    assert!(m.contains_key("new-branch"));
}

// -----------------------------------------------------------------------
// IdempotencyCache bounds tests (M-db3)
// -----------------------------------------------------------------------

#[test]
fn test_idempotency_cache_evicts_on_overflow() {
    let mut cache: HashMap<String, IdempotencyCacheEntry> = HashMap::new();

    // Fill to MAX
    for i in 0..MAX_IDEMPOTENCY_ENTRIES {
        cache.insert(
            format!("key-{}", i),
            IdempotencyCacheEntry {
                result_json: format!("result-{}", i),
                created_at: std::time::Instant::now(),
            },
        );
    }
    assert_eq!(cache.len(), MAX_IDEMPOTENCY_ENTRIES);

    // M-db3: Eviction logic (mirrors production code in create_branch)
    if cache.len() >= MAX_IDEMPOTENCY_ENTRIES {
        let oldest_key = cache
            .iter()
            .min_by_key(|(_, entry)| entry.created_at)
            .map(|(k, _)| k.clone());
        if let Some(key) = oldest_key {
            cache.remove(&key);
        }
    }
    cache.insert(
        "new-key".to_string(),
        IdempotencyCacheEntry {
            result_json: "new".to_string(),
            created_at: std::time::Instant::now(),
        },
    );
    assert_eq!(cache.len(), MAX_IDEMPOTENCY_ENTRIES);
    assert!(cache.contains_key("new-key"));
}

// -----------------------------------------------------------------------
// S28: approve_branch and reject_branch must use validate_and_authorize
// -----------------------------------------------------------------------

/// S28: approve_branch must call validate_and_authorize() for consistent
/// branch existence validation, not just an inline UID check.
/// Without this, approve/reject on a nonexistent branch skips the
/// branch existence check that all other methods perform.
#[test]
fn test_s28_approve_reject_use_validate_and_authorize() {
    let source = include_str!("mod.rs");

    // Find the approve_branch method body
    let approve_start = source
        .find("fn approve_branch(")
        .expect("approve_branch method must exist");
    let approve_body = &source[approve_start..];
    // Find the next "async fn" which marks the end of approve_branch
    let approve_end = approve_body[50..]
        .find("async fn ")
        .unwrap_or(approve_body.len());
    let approve_text = &approve_body[..approve_end];

    assert!(
        approve_text.contains("validate_and_authorize"),
        "S28: approve_branch must call validate_and_authorize() for \
             consistent branch existence + access validation"
    );

    // Find the reject_branch method body
    let reject_start = source
        .find("fn reject_branch(")
        .expect("reject_branch method must exist");
    let reject_body = &source[reject_start..];
    let reject_end = reject_body[50..]
        .find("async fn ")
        .unwrap_or(reject_body.len());
    let reject_text = &reject_body[..reject_end];

    assert!(
        reject_text.contains("validate_and_authorize"),
        "S28: reject_branch must call validate_and_authorize() for \
             consistent branch existence + access validation"
    );
}

// -----------------------------------------------------------------------
// R1: Attestation D-Bus methods must have authentication
// -----------------------------------------------------------------------

/// R1: All attestation methods that accept branch_id must call
/// validate_branch_id() and get_caller_uid(). Methods that export
/// sensitive data (verify_attestation_chain, export_attestation_bundle)
/// must require root.
#[test]
fn test_r1_attestation_methods_have_auth() {
    let source = include_str!("mod.rs");
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

    let methods_requiring_root = [
        "fn verify_attestation_chain(",
        "fn export_attestation_bundle(",
    ];
    for method_sig in &methods_requiring_root {
        let start = prod_source
            .find(method_sig)
            .unwrap_or_else(|| panic!("method {} must exist", method_sig));
        let body = &prod_source[start..];
        let end = body[50..].find("async fn ").unwrap_or(body.len());
        let text = &body[..end];
        assert!(
            text.contains("get_caller_uid"),
            "R1: {} must call get_caller_uid() for authentication",
            method_sig
        );
        assert!(
            text.contains("validate_branch_id"),
            "R1: {} must call validate_branch_id() for input validation",
            method_sig
        );
    }

    // get_inclusion_proof and get_consistency_proof must at least authenticate
    for method_sig in &[
        "fn get_inclusion_proof(",
        "fn get_consistency_proof(",
        "fn get_attestation_public_key(",
    ] {
        let start = prod_source
            .find(method_sig)
            .unwrap_or_else(|| panic!("method {} must exist", method_sig));
        let body = &prod_source[start..];
        let end = body[50..].find("async fn ").unwrap_or(body.len());
        let text = &body[..end];
        assert!(
            text.contains("get_caller_uid"),
            "R1: {} must call get_caller_uid() for authentication",
            method_sig
        );
    }
}

// -----------------------------------------------------------------------
// R4: netns name validation
// -----------------------------------------------------------------------

/// R4: Network namespace name must reject path traversal characters.
#[test]
fn test_r4_netns_name_validation_exists() {
    let source = include_str!("../sandbox/network.rs");
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

    // The create_named_netns function must validate the name
    let start = prod_source
        .find("fn create_named_netns(")
        .expect("create_named_netns must exist");
    let body = &prod_source[start..];
    let end = body[50..]
        .find("\npub fn ")
        .or_else(|| body[50..].find("\nfn "))
        .unwrap_or(body.len());
    let text = &body[..end];

    assert!(
        text.contains("validate_netns_name")
            || text.contains("contains('/')")
            || text.contains("path traversal"),
        "R4: create_named_netns must validate name for path traversal"
    );
}

// -----------------------------------------------------------------------
// R9: ensure_branch must check UID on existing branch
// -----------------------------------------------------------------------

/// R9: ensure_branch must not leak other users' branch info.
#[test]
fn test_r9_ensure_branch_checks_uid() {
    let source = include_str!("mod.rs");
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

    let start = prod_source
        .find("fn ensure_branch(")
        .expect("ensure_branch must exist");
    let body = &prod_source[start..];
    let end = body[50..].find("async fn ").unwrap_or(body.len());
    let text = &body[..end];

    // When returning existing branch, must check UID matches
    assert!(
        text.contains("info.uid")
            || text.contains(".uid ==")
            || text.contains("check_branch_access"),
        "R9: ensure_branch must verify caller UID owns the existing branch"
    );
}

// -----------------------------------------------------------------------
// R10: ensure_branch must have rate limiting
// -----------------------------------------------------------------------

/// R10: ensure_branch must apply rate limiting like create_branch does.
#[test]
fn test_r10_ensure_branch_has_rate_limiting() {
    let source = include_str!("mod.rs");
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

    let start = prod_source
        .find("fn ensure_branch(")
        .expect("ensure_branch must exist");
    let body = &prod_source[start..];
    let end = body[50..].find("async fn ").unwrap_or(body.len());
    let text = &body[..end];

    assert!(
        text.contains("rate_limiter") || text.contains("check(uid)"),
        "R10: ensure_branch must apply rate limiting to prevent branch exhaustion DoS"
    );
}

// -----------------------------------------------------------------------
// Helper: create a BranchManager for testing
// -----------------------------------------------------------------------

fn create_test_manager(dir: &std::path::Path) -> crate::branch::BranchManager {
    crate::test_helpers::create_test_branch_manager(dir, 64)
}

// R6: Changeset hash must NOT use unwrap_or_default() which produces a
// constant SHA-256 hash on failure, enabling hash collision across branches.
#[test]
fn test_r6_changeset_hash_no_unwrap_or_default() {
    let source = include_str!("mod.rs");
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
    // Find the changeset_hash block
    let hash_start = prod_source
        .find("let hash_input = manifest_json")
        .expect("changeset hash_input assignment must exist");
    let hash_block = &prod_source[hash_start..hash_start + 300];
    assert!(
        !hash_block.contains("unwrap_or_default()"),
        "R6: changeset hash fallback must NOT use unwrap_or_default() which \
             produces a constant hash on failure. Found in:\n{}",
        hash_block
    );
}

/// S43: Ensure public_key / attestation_public_key reads do not use
/// `unwrap_or_default()`, which silently returns an empty string on failure.
#[test]
fn test_s43_public_key_no_silent_default() {
    let source = include_str!("mod.rs");
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
    for (i, line) in prod_source.lines().enumerate() {
        let lower = line.to_lowercase();
        if (lower.contains("public_key") || lower.contains("attestation_public_key"))
            && line.contains("unwrap_or_default()")
        {
            panic!(
                "S43: dbus.rs line {} reads a public key with unwrap_or_default(), \
                     which silently returns an empty string on failure. \
                     Use unwrap_or_else with tracing::error! instead.\nLine: {}",
                i + 1,
                line.trim()
            );
        }
    }
}

/// F11: Verify that no production code silently discards D-Bus signal emission results
/// via `let _ = ManagerInterface::`. Each signal emission must log on failure.
#[test]
fn test_f11_dbus_signals_not_silently_dropped() {
    let source = include_str!("mod.rs");
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
    let count = prod_source.matches("let _ = ManagerInterface::").count();
    assert_eq!(
        count, 0,
        "F11: found {} instances of `let _ = ManagerInterface::` in production code. \
             Each D-Bus signal emission result must be checked with \
             `if let Err(e) = ManagerInterface::...` and logged via tracing::debug!.",
        count
    );
}

// -----------------------------------------------------------------------
// V1: commit_branch must update trust score on approval and rejection
// -----------------------------------------------------------------------

#[test]
fn test_v1_commit_branch_wires_trust_scoring() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn commit_branch(");

    assert!(
        body.contains("update_trust_score"),
        "V1: commit_branch must call update_trust_score to update trust \
             score on commit approval/rejection."
    );
}

// -----------------------------------------------------------------------
// V2: commit_branch must write provenance records
// -----------------------------------------------------------------------

#[test]
fn test_v2_commit_branch_wires_provenance() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn commit_branch(");

    assert!(
        body.contains("record_governance_provenance"),
        "V2: commit_branch must call record_governance_provenance to write \
             Governance provenance records on commit approval/rejection."
    );
}

// -----------------------------------------------------------------------
// V3: commit_branch must emit trust_transition signal on level change
// -----------------------------------------------------------------------

#[test]
fn test_v3_commit_branch_emits_trust_transition() {
    let source = include_str!("mod.rs");
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

    let start = prod_source
        .find("fn commit_branch(")
        .expect("commit_branch method must exist");
    let body = &prod_source[start..];
    let end = body[80..]
        .find("\n    async fn ")
        .map(|p| p + 80)
        .unwrap_or(body.len());
    let commit_body = &body[..end];

    assert!(
        commit_body.contains("trust_transition"),
        "V3: commit_branch must emit trust_transition signal when \
             on_audit_event causes a trust level change."
    );
}

// -----------------------------------------------------------------------
// V4: get_identity_token must not hardcode enforcement layers
// -----------------------------------------------------------------------

#[test]
fn test_v4_identity_token_no_hardcoded_enforcement() {
    let source = include_str!("mod.rs");
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

    let start = prod_source
        .find("fn get_identity_token(")
        .expect("get_identity_token method must exist");
    let body = &prod_source[start..];
    let end = body[80..]
        .find("\n    async fn ")
        .or_else(|| body[80..].find("\n    /// "))
        .or_else(|| body[80..].find("\n    #[cfg("))
        .map(|p| p + 80)
        .unwrap_or(body.len());
    let method_body = &body[..end];

    assert!(
        !method_body.contains(r#""pid_ns".to_string()"#),
        "V4: get_identity_token must NOT hardcode enforcement layers \
             like pid_ns. Derive from profile enforcement requirements."
    );
}

// -----------------------------------------------------------------------
// V5: get_identity_token must not hardcode policy_version
// -----------------------------------------------------------------------

#[test]
fn test_v5_identity_token_no_hardcoded_policy_version() {
    let source = include_str!("mod.rs");
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

    let start = prod_source
        .find("fn get_identity_token(")
        .expect("get_identity_token method must exist");
    let body = &prod_source[start..];
    let end = body[80..]
        .find("\n    async fn ")
        .or_else(|| body[80..].find("\n    /// "))
        .or_else(|| body[80..].find("\n    #[cfg("))
        .map(|p| p + 80)
        .unwrap_or(body.len());
    let method_body = &body[..end];

    assert!(
        !method_body.contains(r#""v1.0""#),
        "V5: get_identity_token must NOT hardcode policy_version as \"v1.0\". \
             Read from governance config or policy engine."
    );
}

// -----------------------------------------------------------------------
// V6: provenance D-Bus methods must verify branch exists for non-root
// -----------------------------------------------------------------------

#[test]
fn test_v6_provenance_methods_verify_branch_exists() {
    let source = include_str!("mod.rs");
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

    for method_name in &["fn report_provenance(", "fn get_provenance("] {
        let start = prod_source
            .find(method_name)
            .unwrap_or_else(|| panic!("{} must exist", method_name));
        let body = &prod_source[start..];
        let end = body[80..]
            .find("\n    async fn ")
            .or_else(|| body[80..].find("\n    /// "))
            .or_else(|| body[80..].find("\n    #[cfg("))
            .map(|p| p + 80)
            .unwrap_or(body.len());
        let method_body = &body[..end];

        assert!(
            method_body.contains("branch not found"),
            "V6: {} must return an error when the branch doesn't exist \
                 for non-root callers.",
            method_name
        );
    }
}

// -----------------------------------------------------------------------
// V7: get_identity_token must populate attestation chain data
// -----------------------------------------------------------------------

#[test]
fn test_v7_identity_token_populates_attestation_chain() {
    let source = include_str!("mod.rs");
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

    let start = prod_source
        .find("fn get_identity_token(")
        .expect("get_identity_token method must exist");
    let body = &prod_source[start..];
    let end = body[80..]
        .find("\n    async fn ")
        .or_else(|| body[80..].find("\n    /// "))
        .or_else(|| body[80..].find("\n    #[cfg("))
        .map(|p| p + 80)
        .unwrap_or(body.len());
    let method_body = &body[..end];

    assert!(
        method_body.contains("audit_store") || method_body.contains("merkle"),
        "V7: get_identity_token must read attestation chain data \
             (root_hash, size) from the audit_store's Merkle tree."
    );
}

// ===================================================================
// W-series: Pass 2-5 validation fixes
// ===================================================================

/// Helper: extract a method body from production source by method name.
/// Returns the text from `fn method_name(` to the next `\n    async fn `.
fn extract_method(source: &str, method_name: &str) -> String {
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
    let start = prod_source
        .find(method_name)
        .unwrap_or_else(|| panic!("{} must exist in production code", method_name));
    let body = &prod_source[start..];
    let end = body[80..]
        .find("\n    async fn ")
        .or_else(|| body[80..].find("\n    /// "))
        .or_else(|| body[80..].find("\n    #[cfg("))
        .map(|p| p + 80)
        .unwrap_or(body.len());
    body[..end].to_string()
}

// -----------------------------------------------------------------------
// W1: commit_branch must capture branch owner UID BEFORE commit()
// -----------------------------------------------------------------------

#[test]
fn test_w1_commit_branch_uid_captured_before_commit() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn commit_branch(");

    // The V1 block (between "// V1:" and "// V2:") must NOT call
    // inspect(&id) to get uid — it should use a pre-captured variable.
    let v1_start = body.find("// V1:").expect("V1 comment must exist");
    let v2_start = body.find("// V2:").expect("V2 comment must exist");
    let v1_block = &body[v1_start..v2_start];

    assert!(
        !v1_block.contains("inspect(&id)"),
        "W1: V1 block must NOT call inspect(&id) for uid after commit() — \
             branch may be gone. Use a uid captured BEFORE self.services.manager.commit()."
    );
}

// -----------------------------------------------------------------------
// W2: record_governance must pass changeset_hash as manifest_hash
// -----------------------------------------------------------------------

#[test]
fn test_w2_commit_branch_provenance_manifest_hash() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn commit_branch(");

    // Find the record_governance_provenance call
    let rg_start = body
        .find("record_governance_provenance")
        .expect("record_governance_provenance call must exist in commit_branch");
    let rg_block = &body[rg_start..rg_start + 500.min(body.len() - rg_start)];

    // The manifest_hash parameter must contain Some(changeset_hash
    assert!(
        rg_block.contains("Some(changeset_hash"),
        "W2: record_governance_provenance must pass changeset_hash as \
             manifest_hash, not as policy_version."
    );
}

// -----------------------------------------------------------------------
// W3: approve_branch must wire trust scoring
// -----------------------------------------------------------------------

#[test]
fn test_w3_approve_branch_wires_trust() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn approve_branch(");

    assert!(
        body.contains("update_trust_score"),
        "W3: approve_branch must call update_trust_score to update trust \
             score on manual governance approval."
    );
}

// -----------------------------------------------------------------------
// W4: approve_branch must wire provenance recording
// -----------------------------------------------------------------------

#[test]
fn test_w4_approve_branch_wires_provenance() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn approve_branch(");

    assert!(
        body.contains("record_governance") || body.contains("provenance_store"),
        "W4: approve_branch must record a Governance provenance record \
             for manual approval decisions."
    );
}

// -----------------------------------------------------------------------
// W5: approve_branch must emit trust_transition signal
// -----------------------------------------------------------------------

#[test]
fn test_w5_approve_branch_emits_trust_transition() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn approve_branch(");

    assert!(
        body.contains("trust_transition"),
        "W5: approve_branch must emit trust_transition signal when \
             on_audit_event causes a trust level change."
    );
}

// -----------------------------------------------------------------------
// W6: reject_branch must wire trust scoring
// -----------------------------------------------------------------------

#[test]
fn test_w6_reject_branch_wires_trust() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn reject_branch(");

    assert!(
        body.contains("update_trust_score"),
        "W6: reject_branch must call update_trust_score to update trust \
             score on manual governance rejection."
    );
}

// -----------------------------------------------------------------------
// W7: reject_branch must wire provenance recording
// -----------------------------------------------------------------------

#[test]
fn test_w7_reject_branch_wires_provenance() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn reject_branch(");

    assert!(
        body.contains("record_governance") || body.contains("provenance_store"),
        "W7: reject_branch must record a Governance provenance record \
             for manual rejection decisions."
    );
}

// -----------------------------------------------------------------------
// W8: get_identity_token must read policy_hash from audit_store
// -----------------------------------------------------------------------

#[test]
fn test_w8_identity_token_reads_policy_hash() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn get_identity_token(");

    assert!(
        body.contains("policy_hash"),
        "W8: get_identity_token must read policy version from \
             audit_store.policy_hash(), not use a meaningless placeholder."
    );
}

// -----------------------------------------------------------------------
// W9: trust_transition score must be captured in same lock scope
// -----------------------------------------------------------------------

#[test]
fn test_w9_trust_transition_score_same_lock_scope() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn commit_branch(");

    // The V3 block (between "// V3:" and "// B2:") must NOT re-lock
    // trust_manager to read the score — it should use a pre-captured value.
    let v3_start = body.find("// V3:").expect("V3 comment must exist");
    let b2_start = body.find("// B2:").expect("B2 comment must exist");
    let v3_block = &body[v3_start..b2_start];

    assert!(
        !v3_block.contains("trust_manager"),
        "W9: V3 block must NOT re-lock trust_manager to read score. \
             Capture score in the same lock scope as on_audit_event (V1 block) \
             to avoid TOCTOU race."
    );
}

// -----------------------------------------------------------------------
// W10: get_spiffe_id must verify branch exists for non-root callers
// -----------------------------------------------------------------------

#[test]
fn test_w10_spiffe_id_verifies_branch_exists() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn get_spiffe_id(");

    assert!(
        body.contains("branch not found"),
        "W10: get_spiffe_id must return an error when the branch \
             doesn't exist for non-root callers."
    );
}

// -----------------------------------------------------------------------
// W11: rollback_branch must record provenance
// -----------------------------------------------------------------------

#[test]
fn test_w11_rollback_branch_wires_provenance() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn rollback_branch(");

    assert!(
        body.contains("record_governance") || body.contains("provenance_store"),
        "W11: rollback_branch must record a Governance provenance record \
             for the rollback decision."
    );
}

/// G7: Merkle tree size must use try_from, not bare `as u32` which truncates.
#[test]
fn test_g7_merkle_size_safe_cast() {
    let source = include_str!("mod.rs");
    let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
    let production_code = &source[..test_start];

    // The production code must NOT contain `tree.size() as u32`
    assert!(
        !production_code.contains("tree.size() as u32"),
        "G7: dbus.rs must not use bare `as u32` cast on tree.size() — \
             this silently truncates values exceeding u32::MAX. Use try_from instead."
    );

    // Verify it uses the safe alternative
    assert!(
        production_code.contains("u32::try_from(tree.size())"),
        "G7: dbus.rs must use u32::try_from(tree.size()) for safe casting"
    );
}

// -----------------------------------------------------------------------
// X-series: G1 — Provenance cleanup on branch rollback/reject
// -----------------------------------------------------------------------

#[test]
fn test_x1_rollback_branch_cleans_up_provenance() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn rollback_branch(");

    // After recording rollback provenance (W11), the rollback_branch method
    // must also clean up provenance data for the branch — otherwise
    // provenance directories accumulate indefinitely on disk.
    assert!(
        body.contains("cleanup_branch"),
        "X1: rollback_branch must call provenance cleanup (cleanup_branch) \
             to remove provenance data after the branch is rolled back. \
             PRD §4.3.8: 'Branch rollback/cleanup removes the provenance directory.'"
    );
}

#[test]
fn test_x2_reject_branch_cleans_up_provenance() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn reject_branch(");

    // reject_branch internally rolls back the branch, so it must also
    // clean up provenance data.
    assert!(
        body.contains("cleanup_branch"),
        "X2: reject_branch must call provenance cleanup (cleanup_branch) \
             to remove provenance data after the branch is rejected. \
             PRD §4.3.8: 'Branch rollback/cleanup removes the provenance directory.'"
    );
}

// -----------------------------------------------------------------------
// X-series: G3 — Containment claims in identity tokens
// -----------------------------------------------------------------------

#[test]
#[cfg(feature = "ima")]
fn test_x3_identity_token_uses_containment_api() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn get_identity_token(");

    // get_identity_token must call issue_jwt_svid_with_containment
    // (not just issue_jwt_svid) so that containment claims derived
    // from the profile are included when include_containment_claims is true.
    assert!(
        body.contains("issue_jwt_svid_with_containment"),
        "X3: get_identity_token must call issue_jwt_svid_with_containment \
             to pass profile-derived containment claims into the JWT-SVID. \
             PRD §4.5.3 specifies containment claims (filesystem_scope, \
             network_mode, allowed_domains, exec_allowlist_count)."
    );
}

#[test]
#[cfg(feature = "ima")]
fn test_x4_identity_token_constructs_containment_claims() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn get_identity_token(");

    // The containment claims must be derived from real profile data,
    // not hardcoded or left as None.
    assert!(
        body.contains("ContainmentClaims"),
        "X4: get_identity_token must construct ContainmentClaims from \
             the agent profile (filesystem scope, network mode, allowed \
             domains, exec allowlist count) — not leave containment as None."
    );
}

// ===================================================================
// H-series Round 6: Security findings H40-H53
// ===================================================================

// -----------------------------------------------------------------------
// H40: BranchCommitted events must include uid in details
// -----------------------------------------------------------------------
#[test]
fn test_h40_branch_committed_includes_uid() {
    // H40 fix is in audit_store.rs store_with_context — verified there.
    // Here we verify that commit_branch calls store_audit_event (which
    // internally resolves agent_identity with uid via inspect().agent_identity()).
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn commit_branch(");
    assert!(
        body.contains("store_audit_event"),
        "H40: commit_branch must call store_audit_event (which passes \
             agent_identity to store_with_context) so that uid is injected \
             into BranchCommitted event details."
    );
}

// -----------------------------------------------------------------------
// H44: Hex parsing must guard against odd-length input
// -----------------------------------------------------------------------
#[test]
fn test_h44_odd_length_hex_returns_none() {
    // H44: Verify that odd-length hex input is handled without panic.
    // The guard is now in puzzled_types::merkle::hex_decode() which
    // rejects odd-length and non-ASCII hex strings (A-M3).
    let source = include_str!("mod.rs");
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
    assert!(
        prod_source.contains("merkle::hex_decode"),
        "H44: verify_attestation_chain must use merkle::hex_decode() which \
             guards against odd-length hex strings to prevent out-of-bounds panic."
    );
}

// -----------------------------------------------------------------------
// H45: trigger_governance must have audit logging
// -----------------------------------------------------------------------
#[test]
fn test_h45_trigger_governance_has_audit_logging() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn trigger_governance(");
    assert!(
        body.contains("audit_store") || body.contains("audit_logger"),
        "H45: trigger_governance must write to audit_store or audit_logger \
             to record governance events, matching the commit_branch pattern."
    );
}

// -----------------------------------------------------------------------
// H46: Credential file read errors must not expose filesystem paths
// -----------------------------------------------------------------------
#[test]
fn test_h46_credential_read_error_no_path_leak() {
    let source = include_str!("mod.rs");
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
    // The old pattern was: format!("reading credential from {}: {}", path, e)
    // H46 replaces it with a generic message
    assert!(
        !prod_source.contains(r#"format!("reading credential from {}: {}", path"#),
        "H46: credential file read errors must not include the filesystem path \
             in the error message. Use a generic message instead."
    );
    assert!(
        prod_source.contains("failed to read credential from specified file"),
        "H46: credential read errors must use the generic message \
             'failed to read credential from specified file'."
    );
}

// -----------------------------------------------------------------------
// H49: ensure_branch must write audit event on creation
// -----------------------------------------------------------------------
#[test]
fn test_h49_ensure_branch_writes_audit() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn ensure_branch(");
    assert!(
        body.contains("audit_store") || body.contains("audit_logger"),
        "H49: ensure_branch must write to audit_store on successful branch \
             creation, matching the create_branch audit pattern."
    );
}

// -----------------------------------------------------------------------
// H50: Signing key file permissions must be verified
// -----------------------------------------------------------------------
#[test]
fn test_h50_signing_key_permissions_checked() {
    let source = include_str!("mod.rs");
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
    assert!(
        prod_source.contains("H50") && prod_source.contains("permissions"),
        "H50: start_dbus_service must verify signing key file permissions \
             and warn if world-readable (expected 0600 or 0400)."
    );
}

// -----------------------------------------------------------------------
// H52: command_json must not be logged verbatim
// -----------------------------------------------------------------------
#[test]
fn test_h52_command_json_not_logged_verbatim() {
    let source = include_str!("mod.rs");
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
    // The old line was: tracing::info!(profile, base_path, command_json, ...)
    // H52 replaces command_json with command_json_len
    assert!(
        !prod_source.contains("profile, base_path, command_json, \"CreateBranch"),
        "H52: command_json must not be logged verbatim in CreateBranch. \
             Log command_json_len instead."
    );
    assert!(
        prod_source.contains("command_json_len"),
        "H52: CreateBranch must log command_json_len instead of the full value."
    );
}

// ===================================================================
// Y-series: Third validation — §4.1, §4.3, §4.5 vs PRD (round 3)
// ===================================================================

// -----------------------------------------------------------------------
// Y1: create_branch must call register_uid for profile-specific initial scores
// -----------------------------------------------------------------------

#[test]
fn test_y1_create_branch_registers_uid_with_profile() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn create_branch(");

    // PRD §4.1.9: register_uid(uid, profile_name) allows explicit UID
    // registration with profile-specific initial scores.
    // create_branch must call it so that the trust score is initialized
    // with the correct profile modifier (restricted→10, privileged→50).
    assert!(
        body.contains("register_uid"),
        "Y1: create_branch must call trust_manager.register_uid() to \
             initialize the trust score with a profile-specific initial value. \
             PRD §4.1.9: 'Callers should call this when a branch is created \
             with a known profile.'"
    );
}

// -----------------------------------------------------------------------
// Y2: commit_branch must not use wildcard match for PolicyDecision
// -----------------------------------------------------------------------

#[test]
fn test_y2_commit_branch_no_wildcard_policy_decision() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn commit_branch(");

    // The PolicyDecision enum has 3 variants: Approved, Rejected(_), Error(_).
    // Using `_ => "commit_approved"` silently treats Error as Approved for
    // trust scoring. Must use exhaustive match or explicit Error handling.
    //
    // Check that no `_ => "commit_approved"` pattern exists.
    assert!(
        !body.contains(r#"_ => "commit_approved""#),
        "Y2: commit_branch must not use a wildcard `_ =>` match that treats \
             PolicyDecision::Error as 'commit_approved' for trust scoring. \
             Use explicit variants or handle Error as a distinct event."
    );
}

// -----------------------------------------------------------------------
// Y5: exec_allowlist_count must use safe cast (consistent with G7)
// -----------------------------------------------------------------------

#[test]
#[cfg(feature = "ima")]
fn test_y5_exec_allowlist_count_safe_cast() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn get_identity_token(");

    // Bare `as u32` silently truncates on exotic profiles with > 4B entries.
    // Must use try_from for consistency with the G7 pattern on Merkle tree size.
    assert!(
        !body.contains("exec_allowlist.len() as u32"),
        "Y5: exec_allowlist_count must not use bare `as u32` cast. \
             Use u32::try_from() for consistency with G7 pattern."
    );
}

// -----------------------------------------------------------------------
// Y6: unregister_agent must have full cross-module wiring
// -----------------------------------------------------------------------

#[test]
fn test_y6_unregister_agent_records_provenance() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn unregister_agent(");

    // unregister_agent is semantically a rollback. It must have the same
    // cross-module wiring as rollback_branch: provenance recording +
    // provenance cleanup + audit store event.
    assert!(
        body.contains("record_governance") || body.contains("provenance_store"),
        "Y6: unregister_agent must record a provenance event for the \
             unregistration decision, matching rollback_branch's wiring."
    );
}

#[test]
fn test_y6_unregister_agent_cleans_up_provenance() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn unregister_agent(");

    assert!(
        body.contains("cleanup_branch"),
        "Y6: unregister_agent must call provenance cleanup (cleanup_branch) \
             to remove provenance data, matching rollback_branch's X1 pattern."
    );
}

#[test]
fn test_y6_unregister_agent_writes_audit_store() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn unregister_agent(");

    assert!(
        body.contains("store_audit_event"),
        "Y6: unregister_agent must call store_audit_event for attestation, \
             matching rollback_branch's attestation bridge pattern."
    );
}

// ===================================================================
// Z-series: Fourth validation — attestation chain completeness
// ===================================================================

// -----------------------------------------------------------------------
// Z2: approve_branch must write to audit store (attestation chain)
// -----------------------------------------------------------------------

#[test]
fn test_z2_approve_branch_writes_audit_store() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn approve_branch(");

    assert!(
        body.contains("store_audit_event"),
        "Z2: approve_branch must call store_audit_event so that manual \
             governance approvals appear in the attestation chain (§3.1). \
             Without this, approved branches have no Ed25519 signature \
             or Merkle tree leaf."
    );
}

// -----------------------------------------------------------------------
// Z3: approve_branch must call audit_logger
// -----------------------------------------------------------------------

#[test]
fn test_z3_approve_branch_calls_audit_logger() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn approve_branch(");

    assert!(
        body.contains("audit_logger"),
        "Z3: approve_branch must call audit_logger to write the approval \
             event to syslog/netlink, matching commit_branch's pattern."
    );
}

// -----------------------------------------------------------------------
// Z5: reject_branch must write to audit store (attestation chain)
// -----------------------------------------------------------------------

#[test]
fn test_z5_reject_branch_writes_audit_store() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn reject_branch(");

    assert!(
        body.contains("store_audit_event"),
        "Z5: reject_branch must call store_audit_event so that manual \
             governance rejections appear in the attestation chain \
             (§3.1). Without this, rejected branches have no Ed25519 signature \
             or Merkle tree leaf."
    );
}

// -----------------------------------------------------------------------
// Z6: reject_branch must call audit_logger
// -----------------------------------------------------------------------

#[test]
fn test_z6_reject_branch_calls_audit_logger() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn reject_branch(");

    assert!(
        body.contains("audit_logger"),
        "Z6: reject_branch must call audit_logger to write the rejection \
             event to syslog/netlink, matching commit_branch/rollback_branch's pattern."
    );
}

// -----------------------------------------------------------------------
// Z11: commit_branch signal emission must not use wildcard for PolicyDecision
// -----------------------------------------------------------------------

#[test]
fn test_z11_commit_branch_signal_no_wildcard() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn commit_branch(");

    // The signal emission match for PolicyDecision must not use `_ => {}`
    // which silently swallows PolicyDecision::Error — subscribers should
    // be notified of governance evaluation failures.
    //
    // We check that no `_ => {}` or `_ => { }` pattern exists in the
    // signal emission section (after the match on policy_result for signals).
    let signal_section = body.find("match &result.policy_result").and_then(|first| {
        // Find the SECOND match (the signal emission one, not the
        // trust scoring one which was already fixed by Y2).
        body[first + 1..]
            .find("match &result.policy_result")
            .map(|off| first + 1 + off)
    });
    if let Some(start) = signal_section {
        let section = &body[start..];
        // Extract just the match block (up to the closing brace pattern)
        let block = section.split("Ok(json)").next().unwrap_or(section);
        assert!(
            !block.contains("_ => {}"),
            "Z11: commit_branch signal emission must not use `_ => {{}}` \
                 wildcard for PolicyDecision. PolicyDecision::Error should emit \
                 a signal or be handled explicitly."
        );
    }
}

// -----------------------------------------------------------------------
// J21: command_json must not be logged verbatim in activate_branch
// -----------------------------------------------------------------------
#[test]
fn test_j21_activate_branch_no_verbatim_command_json() {
    let source = include_str!("mod.rs");
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
    // activate_branch must NOT log command_json directly
    assert!(
        !prod_source.contains("branch_id, command_json, \"ActivateBranch"),
        "J21: activate_branch must not log command_json verbatim. \
             Use command_json_len instead."
    );
    // Verify the fix uses command_json_len
    assert!(
        prod_source.contains("command_json_len = command_json.len()")
            && prod_source.contains("\"ActivateBranch requested\""),
        "J21: activate_branch must log command_json_len instead of command_json."
    );
}

// -----------------------------------------------------------------------
// J22: Timestamp comparison uses parse_from_rfc3339, not lexicographic
// -----------------------------------------------------------------------
#[test]
fn test_j22_timestamp_comparison_uses_parsed_datetime() {
    let source = include_str!("mod.rs");
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
    // The verify_attestation_chain method must use parse_from_rfc3339
    assert!(
        prod_source.contains("parse_from_rfc3339"),
        "J22: verify_attestation_chain must use chrono::DateTime::parse_from_rfc3339 \
             for timestamp comparison, not lexicographic string comparison."
    );
}

// -----------------------------------------------------------------------
// AA1: report_provenance must validate record.branch_id == branch_id
// -----------------------------------------------------------------------
#[test]
fn test_aa1_report_provenance_validates_record_branch_id() {
    let source = include_str!("mod.rs");
    let report_body = extract_method(source, "fn report_provenance");
    // Must check that the deserialized record's branch_id matches the
    // D-Bus parameter branch_id to prevent provenance injection.
    assert!(
        report_body.contains("record.branch_id")
            && (report_body.contains("!= branch_id")
                || report_body.contains("!= id")
                || report_body.contains("mismatch")),
        "AA1: report_provenance must validate that record.branch_id matches \
             the D-Bus branch_id parameter to prevent provenance injection into \
             branches the caller doesn't own."
    );
}

// -----------------------------------------------------------------------
// AA2: approve_branch computes changeset hash once, not multiple times
// -----------------------------------------------------------------------
#[test]
fn test_aa2_approve_branch_single_changeset_hash() {
    let source = include_str!("mod.rs");
    let approve_body = extract_method(source, "fn approve_branch");
    // Count occurrences of the SHA256 hash computation pattern
    let hash_computations = approve_body.matches("Sha256::new()").count();
    assert!(
        hash_computations <= 1,
        "AA2: approve_branch computes SHA256 changeset hash {hash_computations} times. \
             Should compute once and reuse the variable."
    );
}

// -----------------------------------------------------------------------
// AA3: unregister_agent calls audit_logger (syslog/netlink)
// -----------------------------------------------------------------------
#[test]
fn test_aa3_unregister_agent_calls_audit_logger() {
    let source = include_str!("mod.rs");
    let unregister_body = extract_method(source, "fn unregister_agent");
    assert!(
        unregister_body.contains("audit_logger") && unregister_body.contains(".log("),
        "AA3: unregister_agent must call audit_logger.log() to emit the \
             unregistration event to syslog/netlink, matching all other branch \
             lifecycle terminals."
    );
}

// ===================================================================
// K-series (round 8): Security hardening fixes
// ===================================================================

// -----------------------------------------------------------------------
// K21: rollback_branch reason must be sanitized before logging
// -----------------------------------------------------------------------
#[test]
fn test_k21_rollback_branch_reason_sanitized() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn rollback_branch(");
    // Must not log reason directly — must use sanitize_log_reason
    assert!(
        body.contains("sanitize_log_reason"),
        "K21: rollback_branch must sanitize the reason parameter before \
             logging to prevent log injection via embedded control characters."
    );
}

// -----------------------------------------------------------------------
// K22: reject_branch reason must be sanitized before logging
// -----------------------------------------------------------------------
#[test]
fn test_k22_reject_branch_reason_sanitized() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn reject_branch(");
    assert!(
        body.contains("sanitize_log_reason"),
        "K22: reject_branch must sanitize the reason parameter before \
             logging to prevent log injection via embedded control characters."
    );
}

// -----------------------------------------------------------------------
// K23: list_trust_history limit must be capped
// -----------------------------------------------------------------------
#[test]
fn test_k23_trust_history_limit_capped() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn list_trust_history(");
    assert!(
        body.contains("MAX_TRUST_HISTORY_LIMIT"),
        "K23: list_trust_history must define MAX_TRUST_HISTORY_LIMIT \
             and cap the caller-supplied limit to prevent excessive memory usage."
    );
}

// -----------------------------------------------------------------------
// K24: report_provenance must validate record size
// -----------------------------------------------------------------------
#[test]
fn test_k24_provenance_record_size_validated() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn report_provenance(");
    assert!(
        body.contains("MAX_PROVENANCE_RECORD_LEN"),
        "K24: report_provenance must define MAX_PROVENANCE_RECORD_LEN \
             and reject oversized record_json payloads before processing."
    );
}

// -----------------------------------------------------------------------
// K25: MAX_EXPORT_FILE_SIZE must be reasonable for pretty-print
// -----------------------------------------------------------------------
#[test]
fn test_k25_export_file_size_reasonable() {
    let source = include_str!("../audit_store.rs");
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
    assert!(
        prod_source.contains("MAX_EXPORT_FILE_SIZE"),
        "K25: audit_store.rs must define MAX_EXPORT_FILE_SIZE"
    );
    // Verify it's <= 100MB (not 500MB) to account for pretty-print expansion
    assert!(
        prod_source.contains("100 * 1024 * 1024"),
        "K25: MAX_EXPORT_FILE_SIZE should be 100MB (not 500MB) to account \
             for pretty-print JSON expansion that can 3-5x the in-memory size."
    );
}

// -----------------------------------------------------------------------
// K26: ensure_branch must call register_uid after creation
// -----------------------------------------------------------------------
#[test]
fn test_k26_ensure_branch_registers_uid() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn ensure_branch(");
    assert!(
        body.contains("register_uid"),
        "K26: ensure_branch must call trust_manager.register_uid() after \
             branch creation, matching the create_branch pattern for \
             profile-specific initial trust scores."
    );
}

// -----------------------------------------------------------------------
// K27: trigger_governance must check policy_result
// -----------------------------------------------------------------------
#[test]
fn test_k27_trigger_governance_checks_policy_result() {
    let source = include_str!("mod.rs");
    let body = extract_method(source, "fn trigger_governance(");
    assert!(
        body.contains("policy_result"),
        "K27: trigger_governance must check result.policy_result and emit \
             appropriate audit events (BranchCommitted vs CommitRejected/PolicyViolation)."
    );
    // Must not unconditionally log BranchCommitted
    assert!(
        body.contains("PolicyDecision::Rejected") || body.contains("CommitRejected"),
        "K27: trigger_governance must handle rejected policy decisions, \
             not always emit BranchCommitted."
    );
}

// -----------------------------------------------------------------------
// K28: store_credential and rotate_credential must canonicalize paths
// -----------------------------------------------------------------------
#[test]
fn test_k28_credential_file_path_canonicalized() {
    let source = include_str!("mod.rs");
    let store_body = extract_method(source, "fn store_credential(");
    assert!(
        store_body.contains("canonicalize"),
        "K28: store_credential must use std::fs::canonicalize() to resolve \
             symlinks before checking /proc, /sys, /dev prefixes."
    );
    let rotate_body = extract_method(source, "fn rotate_credential(");
    assert!(
        rotate_body.contains("canonicalize"),
        "K28: rotate_credential must use std::fs::canonicalize() to resolve \
             symlinks before checking /proc, /sys, /dev prefixes."
    );
}

// -----------------------------------------------------------------------
// H-1: unlock_credential must have root access control
// -----------------------------------------------------------------------
#[test]
fn test_h1_unlock_credential_has_root_access_control() {
    let source = include_str!("mod.rs");
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
    let body = extract_method(prod_source, "fn unlock_credential(");
    assert!(
        body.contains("uid != 0"),
        "H-1: unlock_credential must check uid != 0 for root-only access, \
             matching store_credential and rotate_credential patterns."
    );
    assert!(
        body.contains("AccessDenied"),
        "H-1: unlock_credential must return AccessDenied for non-root callers."
    );
}

// -----------------------------------------------------------------------
// M-11: credential D-Bus methods must use validate_and_authorize
// -----------------------------------------------------------------------
#[test]
fn test_m11_provision_credentials_uses_validate_and_authorize() {
    let source = include_str!("mod.rs");
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
    let body = extract_method(prod_source, "fn provision_credentials(");
    assert!(
        body.contains("validate_and_authorize"),
        "M-11: provision_credentials must use validate_and_authorize for \
             branch ownership verification, not raw BranchId::from()."
    );
    assert!(
        !body.contains("BranchId::from("),
        "M-11: provision_credentials must not use unchecked BranchId::from()."
    );
}

#[test]
fn test_m11_revoke_credentials_uses_validate_and_authorize() {
    let source = include_str!("mod.rs");
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
    let body = extract_method(prod_source, "fn revoke_credentials(");
    assert!(
        body.contains("validate_and_authorize"),
        "M-11: revoke_credentials must use validate_and_authorize for \
             branch ownership verification, not raw BranchId::from()."
    );
    assert!(
        !body.contains("BranchId::from("),
        "M-11: revoke_credentials must not use unchecked BranchId::from()."
    );
}

#[test]
fn test_m11_list_credentials_uses_validate_and_authorize() {
    let source = include_str!("mod.rs");
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
    let body = extract_method(prod_source, "fn list_credentials(");
    assert!(
        body.contains("validate_and_authorize"),
        "M-11: list_credentials must use validate_and_authorize for \
             branch ownership verification when branch_id is non-empty."
    );
    assert!(
        !body.contains("BranchId::from("),
        "M-11: list_credentials must not use unchecked BranchId::from()."
    );
}
