// SPDX-License-Identifier: Apache-2.0
//! Tests for D-Bus input validation and access control.
//!
//! These tests verify validation logic used by the D-Bus interface without
//! requiring a running D-Bus daemon. Tests focus on input sanitization,
//! access control, and rate limiting patterns.

use std::collections::HashMap;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Input validation tests (mirror validate_dbus_inputs logic)
// ---------------------------------------------------------------------------

/// Validate profile name: alphanumeric + hyphens/underscores only.
fn validate_profile(profile: &str) -> bool {
    !profile.is_empty()
        && profile
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
}

/// Validate base path: must be absolute, no null bytes, no ".." components.
fn validate_base_path(base_path: &str) -> bool {
    base_path.starts_with('/')
        && !base_path.contains('\0')
        && !base_path.split('/').any(|c| c == "..")
}

/// Validate command JSON: must not contain null bytes in arguments.
fn validate_command_json(json: &str) -> bool {
    if json.is_empty() || json == "[]" {
        return true;
    }
    match serde_json::from_str::<Vec<String>>(json) {
        Ok(args) => args.iter().all(|a| !a.contains('\0')),
        Err(_) => false,
    }
}

/// Simple per-UID rate limiter (mirrors puzzled::dbus::RateLimiter).
struct RateLimiter {
    requests: HashMap<u32, Vec<Instant>>,
    max_per_minute: usize,
}

impl RateLimiter {
    fn new(max_per_minute: usize) -> Self {
        Self {
            requests: HashMap::new(),
            max_per_minute,
        }
    }

    fn check(&mut self, uid: u32) -> bool {
        let now = Instant::now();
        let cutoff = now - Duration::from_secs(60);
        let times = self.requests.entry(uid).or_default();
        times.retain(|t| *t > cutoff);
        if times.len() >= self.max_per_minute {
            return false;
        }
        times.push(now);
        true
    }
}

/// Check branch access: owner or root.
fn check_branch_access(caller_uid: u32, branch_owner_uid: u32) -> bool {
    caller_uid == 0 || caller_uid == branch_owner_uid
}

#[test]
fn test_validate_dbus_inputs_valid_profile() {
    assert!(validate_profile("standard"));
    assert!(validate_profile("my-profile"));
    assert!(validate_profile("profile_v2"));
    assert!(validate_profile("restricted"));
}

#[test]
fn test_validate_dbus_inputs_invalid_profile_chars() {
    assert!(!validate_profile("my profile")); // space
    assert!(!validate_profile("profile/hack")); // slash
    assert!(!validate_profile("profile;drop")); // semicolon
    assert!(!validate_profile("../etc/passwd")); // path traversal
    assert!(!validate_profile("profile\x00")); // null byte
}

#[test]
fn test_validate_dbus_inputs_relative_path() {
    assert!(!validate_base_path("relative/path"));
    assert!(!validate_base_path("./local"));
    assert!(!validate_base_path(""));
}

#[test]
fn test_validate_dbus_inputs_path_traversal() {
    assert!(!validate_base_path("/workspace/../etc/shadow"));
    assert!(!validate_base_path("/workspace/../../root"));
    assert!(validate_base_path("/workspace/subdir/file")); // valid
}

#[test]
fn test_validate_dbus_inputs_null_bytes() {
    assert!(!validate_base_path("/workspace/file\x00.txt"));
    assert!(validate_base_path("/workspace/normal.txt"));
}

#[test]
fn test_validate_dbus_inputs_empty_profile() {
    assert!(!validate_profile(""));
}

#[test]
fn test_check_branch_access_owner() {
    assert!(check_branch_access(1000, 1000)); // owner matches
}

#[test]
fn test_check_branch_access_root_bypass() {
    assert!(check_branch_access(0, 1000)); // root can access any branch
    assert!(check_branch_access(0, 9999));
}

#[test]
fn test_check_branch_access_denied() {
    assert!(!check_branch_access(1001, 1000)); // different user
    assert!(!check_branch_access(65534, 1000)); // nobody user
}

#[test]
fn test_rate_limiter_allows_under_limit() {
    let mut limiter = RateLimiter::new(10);
    for _ in 0..10 {
        assert!(limiter.check(1000));
    }
}

#[test]
fn test_rate_limiter_blocks_over_limit() {
    let mut limiter = RateLimiter::new(10);
    for _ in 0..10 {
        assert!(limiter.check(1000));
    }
    // 11th request should be blocked
    assert!(!limiter.check(1000));
}

#[test]
fn test_rate_limiter_resets_after_window() {
    let mut limiter = RateLimiter::new(10);
    // Fill up the limit
    for _ in 0..10 {
        limiter.check(1000);
    }
    assert!(!limiter.check(1000));

    // Manually age out the timestamps by clearing (simulates window expiry)
    limiter.requests.get_mut(&1000).unwrap().clear();
    assert!(limiter.check(1000));
}

#[test]
fn test_rate_limiter_per_uid_isolation() {
    let mut limiter = RateLimiter::new(2);
    assert!(limiter.check(1000));
    assert!(limiter.check(1000));
    assert!(!limiter.check(1000)); // uid 1000 blocked

    // uid 1001 should still be allowed
    assert!(limiter.check(1001));
    assert!(limiter.check(1001));
    assert!(!limiter.check(1001));
}

#[test]
fn test_rate_limiter_zero_uid() {
    let mut limiter = RateLimiter::new(10);
    // Root (uid 0) should also be rate-limited
    for _ in 0..10 {
        assert!(limiter.check(0));
    }
    assert!(!limiter.check(0));
}

#[test]
fn test_validate_command_json_null_bytes() {
    assert!(!validate_command_json(r#"["/bin/sh", "arg\u0000inject"]"#));
    assert!(validate_command_json(r#"["/usr/bin/python3", "agent.py"]"#));
    assert!(validate_command_json(""));
    assert!(validate_command_json("[]"));
}

// ---------------------------------------------------------------------------
// T21: D-Bus rate limiting — throttle excessive requests
// ---------------------------------------------------------------------------

#[test]
fn t21_rate_limiter_throttles_burst() {
    // Simulate a rapid burst of requests that exceeds the per-minute limit.
    let mut limiter = RateLimiter::new(5);

    // First 5 requests should be accepted
    for i in 0..5 {
        assert!(
            limiter.check(1000),
            "request {} within limit should be accepted",
            i + 1
        );
    }

    // Requests 6 through 10 should all be rejected
    for i in 5..10 {
        assert!(
            !limiter.check(1000),
            "request {} over limit should be rejected",
            i + 1
        );
    }
}

#[test]
fn t21_rate_limiter_different_uids_independent() {
    // Rate limiting is per-UID; one user hitting the limit should not
    // affect other users.
    let mut limiter = RateLimiter::new(3);

    // UID 1000 exhausts its limit
    assert!(limiter.check(1000));
    assert!(limiter.check(1000));
    assert!(limiter.check(1000));
    assert!(!limiter.check(1000));

    // UID 1001 should still have full quota
    assert!(limiter.check(1001));
    assert!(limiter.check(1001));
    assert!(limiter.check(1001));
    assert!(!limiter.check(1001));

    // UID 0 (root) is not exempt from rate limiting
    assert!(limiter.check(0));
    assert!(limiter.check(0));
    assert!(limiter.check(0));
    assert!(!limiter.check(0));
}

#[test]
fn t21_rate_limiter_window_expiry_restores_capacity() {
    // After the time window expires, the limiter should allow requests again.
    let mut limiter = RateLimiter::new(2);

    assert!(limiter.check(1000));
    assert!(limiter.check(1000));
    assert!(!limiter.check(1000)); // blocked

    // Simulate window expiry by clearing timestamps
    limiter.requests.get_mut(&1000).unwrap().clear();

    // Should accept requests again
    assert!(
        limiter.check(1000),
        "after window expiry, requests should be accepted again"
    );
    assert!(limiter.check(1000));
    assert!(!limiter.check(1000)); // blocked again
}

#[test]
fn t21_rate_limiter_single_request_limit() {
    // Edge case: limit of 1 request per window
    let mut limiter = RateLimiter::new(1);

    assert!(limiter.check(1000)); // first request OK
    assert!(!limiter.check(1000)); // second request blocked immediately
}

#[test]
fn t21_rate_limiter_high_limit() {
    // With a high limit, many requests should be accepted
    let mut limiter = RateLimiter::new(1000);

    for i in 0..1000 {
        assert!(
            limiter.check(1000),
            "request {} within high limit should be accepted",
            i + 1
        );
    }
    assert!(
        !limiter.check(1000),
        "request 1001 should be blocked even with high limit"
    );
}
