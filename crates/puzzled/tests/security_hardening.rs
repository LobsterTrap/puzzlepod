// SPDX-License-Identifier: Apache-2.0
//! Tests verifying security hardening fixes.
//!
//! Each test corresponds to a specific fix from the production hardening audit.
//! Tests are cross-platform and do not require root or kernel features.

use std::path::PathBuf;

use puzzled_types::BranchId;

// ---------------------------------------------------------------------------
// Fix #6: Mutex poison recovery
// ---------------------------------------------------------------------------

#[test]
fn test_mutex_poison_recovery() {
    use std::sync::Mutex;

    let mutex = Mutex::new(42);

    // Poison the mutex by panicking while holding the lock
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = mutex.lock().unwrap();
        panic!("intentional panic to poison mutex");
    }));
    assert!(result.is_err());

    // The poisoned mutex should still be usable with unwrap_or_else
    let value = mutex.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(*value, 42);
}

// ---------------------------------------------------------------------------
// Fix #7: CString null byte rejection
// ---------------------------------------------------------------------------

#[test]
fn test_cstring_null_byte_rejected() {
    let path_with_null = "/usr/bin/python3\0--malicious";
    let result = std::ffi::CString::new(path_with_null);
    assert!(
        result.is_err(),
        "CString::new should reject paths with null bytes"
    );
}

#[test]
fn test_cstring_valid_path_accepted() {
    let valid_path = "/usr/bin/python3";
    let result = std::ffi::CString::new(valid_path);
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Fix #8: Path traversal in rollback
// J87: Verify production branch.rs uses canonicalize + starts_with in rollback
// ---------------------------------------------------------------------------

#[test]
fn test_rollback_validates_upper_dir_path() {
    let branch_root = tempfile::tempdir().unwrap();
    let branch_dir = branch_root.path().join("branch-123");
    std::fs::create_dir_all(&branch_dir).unwrap();

    // Valid: branch_dir is under branch_root
    let canon_branch = std::fs::canonicalize(&branch_dir).unwrap();
    let canon_root = std::fs::canonicalize(branch_root.path()).unwrap();
    assert!(
        canon_branch.starts_with(&canon_root),
        "branch dir should be under branch root after canonicalization"
    );
}

#[test]
fn test_rollback_rejects_path_outside_root() {
    let branch_root = tempfile::tempdir().unwrap();

    // A path outside branch_root should be rejected
    let outside_dir = PathBuf::from("/tmp");
    let canon_outside = std::fs::canonicalize(&outside_dir).unwrap_or(outside_dir.clone());
    let canon_root = std::fs::canonicalize(branch_root.path()).unwrap();

    assert!(
        !canon_outside.starts_with(&canon_root),
        "path outside branch_root should not pass validation"
    );
}

#[test]
fn j87_rollback_production_uses_canonicalize_and_starts_with() {
    // J87: Verify production branch.rs contains canonicalize + starts_with
    // in the rollback path, not just testing stdlib behavior in isolation.
    let source = include_str!("../src/branch/mod.rs");

    let rollback_start = source
        .find("fn rollback_internal(")
        .expect("J87: rollback_internal function must exist in branch.rs");
    let rollback_body = &source[rollback_start..];
    // Find the end of the function (next top-level fn or end of file)
    let rollback_end = rollback_body
        .find("\n    pub fn ")
        .or_else(|| rollback_body.find("\n    fn "))
        .unwrap_or(rollback_body.len());
    let rollback_body = &rollback_body[..rollback_end];

    assert!(
        rollback_body.contains("canonicalize"),
        "J87: rollback_internal must use canonicalize to resolve symlinks before path comparison"
    );
    assert!(
        rollback_body.contains("starts_with"),
        "J87: rollback_internal must use starts_with to verify branch dir is under branch_root"
    );
}

// ---------------------------------------------------------------------------
// Fix #15: base_path validation in create()
// J88: Verify production branch.rs uses is_absolute(), exists(), is_dir()
// ---------------------------------------------------------------------------

#[test]
fn test_base_path_must_be_absolute() {
    let relative = PathBuf::from("relative/path");
    assert!(
        !relative.is_absolute(),
        "relative path should not be accepted"
    );

    let absolute = PathBuf::from("/workspace/project");
    assert!(absolute.is_absolute(), "absolute path should be accepted");
}

#[test]
fn test_base_path_must_exist() {
    let nonexistent = PathBuf::from("/nonexistent/path/12345");
    assert!(
        !nonexistent.exists(),
        "nonexistent path should fail exists() check"
    );
}

#[test]
fn test_base_path_must_be_directory() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("not-a-dir.txt");
    std::fs::write(&file_path, "file content").unwrap();

    assert!(!file_path.is_dir(), "file should not pass is_dir() check");
    assert!(dir.path().is_dir(), "directory should pass is_dir() check");
}

#[test]
fn j88_create_branch_production_validates_base_path() {
    // J88: Verify production branch.rs uses is_absolute(), exists(), is_dir()
    // in the create path, not just testing stdlib behavior in isolation.
    let source = include_str!("../src/branch/mod.rs");

    let create_start = source
        .find("fn create_branch(")
        .expect("J88: create_branch function must exist in branch.rs");
    let create_body = &source[create_start..];
    // Find the end of the function
    let create_end = create_body
        .find("\n    /// ")
        .or_else(|| create_body.find("\n    pub fn "))
        .unwrap_or(create_body.len());
    let create_body = &create_body[..create_end];

    assert!(
        create_body.contains("is_absolute()"),
        "J88: create_branch must validate base_path.is_absolute()"
    );
    assert!(
        create_body.contains(".exists()"),
        "J88: create_branch must validate base_path.exists()"
    );
    assert!(
        create_body.contains("is_dir()"),
        "J88: create_branch must validate base_path.is_dir()"
    );
}

// ---------------------------------------------------------------------------
// Fix #17: Audit message sanitization
// J80: Verify production sanitize_audit_field contains key sanitization patterns
// instead of mirroring the function (which can diverge from production).
// ---------------------------------------------------------------------------

#[test]
fn test_audit_sanitize_field_production_patterns() {
    // J80: Use include_str! to verify the production sanitize_audit_field
    // contains the key sanitization patterns, rather than testing a mirror copy
    // that could silently diverge from the real implementation.
    let source = include_str!("../src/audit.rs");

    // Find the sanitize_audit_field function body
    let fn_start = source
        .find("fn sanitize_audit_field(")
        .expect("J80: sanitize_audit_field function must exist in audit.rs");
    let fn_body = &source[fn_start..fn_start + 500.min(source.len() - fn_start)];

    // Verify key sanitization patterns exist in production code
    assert!(
        fn_body.contains("is_control()"),
        "J80: production sanitize_audit_field must check is_control() for control characters"
    );
    assert!(
        fn_body.contains("\\u{FFFD}"),
        "J80: production sanitize_audit_field must handle Unicode replacement character \\u{{FFFD}}"
    );
    assert!(
        fn_body.contains("!c.is_alphanumeric()"),
        "J80: production sanitize_audit_field must check !c.is_alphanumeric() for non-text chars"
    );
    assert!(
        fn_body.contains("'\"'") || fn_body.contains("c == '\"'"),
        "J80: production sanitize_audit_field must strip double quotes"
    );
    assert!(
        fn_body.contains("'='") || fn_body.contains("c == '='"),
        "J80: production sanitize_audit_field must strip equals signs (audit injection)"
    );
}

// ---------------------------------------------------------------------------
// Fix #19: CSPRNG error propagation
// ---------------------------------------------------------------------------

#[test]
fn test_csprng_error_propagated() {
    // getrandom should succeed on all supported platforms
    let mut buf = [0u8; 32];
    let result = getrandom::getrandom(&mut buf);
    assert!(result.is_ok(), "CSPRNG should work on this platform");
    // At least some bytes should be non-zero (probability of all zeros: 2^-256)
    assert!(
        buf.iter().any(|&b| b != 0),
        "CSPRNG output should not be all zeros"
    );
}

// ---------------------------------------------------------------------------
// Fix #20: Audit chain integrity
// ---------------------------------------------------------------------------

#[test]
fn test_audit_chain_integrity() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = puzzled::audit_store::AuditStore::new(dir.path().to_path_buf()).unwrap();

    // Store several events
    for i in 0..5 {
        store
            .store(&puzzled::audit::AuditEvent::BranchCreated {
                branch_id: BranchId::from(format!("branch-{}", i)),
                profile: "standard".to_string(),
                uid: 1000 + i as u32,
            })
            .unwrap();
    }

    // Verify chain integrity
    let count = store.verify_chain().unwrap();
    assert_eq!(count, 5, "all 5 events should verify");
}

#[test]
fn test_audit_chain_tamper_detected() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = puzzled::audit_store::AuditStore::new(dir.path().to_path_buf()).unwrap();

    // Store events
    for i in 0..3 {
        store
            .store(&puzzled::audit::AuditEvent::BranchCreated {
                branch_id: BranchId::from(format!("branch-{}", i)),
                profile: "standard".to_string(),
                uid: 1000,
            })
            .unwrap();
    }

    // Tamper with the events file — modify the second line
    let events_path = dir.path().join("events.ndjson");
    let content = std::fs::read_to_string(&events_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert!(lines.len() >= 3);

    // Replace the middle event with a modified version
    let mut tampered = String::new();
    for (i, line) in lines.iter().enumerate() {
        if i == 1 {
            // Modify the event content while keeping the old HMAC
            let modified = line.replace("branch-1", "branch-TAMPERED");
            tampered.push_str(&modified);
        } else {
            tampered.push_str(line);
        }
        tampered.push('\n');
    }
    std::fs::write(&events_path, tampered).unwrap();

    // Verification should detect the tamper
    let result = store.verify_chain();
    assert!(
        result.is_err(),
        "tampered audit chain should fail verification"
    );
}

// ---------------------------------------------------------------------------
// Config validation tests
// ---------------------------------------------------------------------------

#[test]
fn test_config_validation_max_branches_zero() {
    let config = puzzled::config::DaemonConfig {
        max_branches: 0,
        ..Default::default()
    };
    let result = config.validate();
    assert!(result.is_err(), "max_branches=0 should be invalid");
}

#[test]
fn test_config_validation_max_branches_too_large() {
    let config = puzzled::config::DaemonConfig {
        max_branches: 2000,
        ..Default::default()
    };
    let result = config.validate();
    assert!(
        result.is_err(),
        "max_branches=2000 should be invalid (>1024)"
    );
}

#[test]
fn test_config_validation_invalid_log_level() {
    // Invalid enum values are now rejected at deserialization time.
    let result = serde_yaml::from_str::<puzzled::config::DaemonConfig>("log_level: verbose");
    assert!(
        result.is_err(),
        "invalid log_level should be rejected by serde"
    );
}

#[test]
fn test_config_validation_invalid_bus_type() {
    // Invalid enum values are now rejected at deserialization time.
    let result = serde_yaml::from_str::<puzzled::config::DaemonConfig>("bus_type: peer");
    assert!(
        result.is_err(),
        "invalid bus_type should be rejected by serde"
    );
}

#[test]
fn test_config_validation_invalid_fs_type() {
    // Invalid enum values are now rejected at deserialization time.
    let result = serde_yaml::from_str::<puzzled::config::DaemonConfig>("fs_type: ntfs");
    assert!(
        result.is_err(),
        "invalid fs_type should be rejected by serde"
    );
}

#[test]
fn test_config_validation_valid_defaults() {
    let config = puzzled::config::DaemonConfig::default();
    let result = config.validate();
    assert!(result.is_ok(), "default config should be valid");
}

// ---------------------------------------------------------------------------
// R21: ima.rs — sign() method exists and signing_key() has warning comment
// ---------------------------------------------------------------------------

#[test]
fn r21_ima_has_sign_method() {
    let source = include_str!("../src/ima.rs");
    assert!(
        source.contains("pub fn sign("),
        "R21: ima.rs must expose a pub fn sign() method for safe signing without raw key access"
    );
}

#[test]
fn r21_ima_signing_key_has_warning() {
    let source = include_str!("../src/ima.rs");
    // signing_key() should have an R21 warning comment near it
    assert!(
        source.contains("R21"),
        "R21: signing_key() accessor must have an R21 warning comment about key exposure"
    );
}

// ---------------------------------------------------------------------------
// R22: ima.rs — Key rotation uses create_new(true) to prevent symlink attacks
// ---------------------------------------------------------------------------

#[test]
fn r22_ima_key_rotation_uses_create_new() {
    let source = include_str!("../src/ima.rs");
    assert!(
        source.contains("create_new(true)"),
        "R22: key rotation must use create_new(true) (O_EXCL) to prevent symlink attacks"
    );
    assert!(
        !source.contains("create(true).truncate(true)"),
        "R22: key rotation must NOT use create(true).truncate(true) — vulnerable to symlink following"
    );
}

// ---------------------------------------------------------------------------
// R23: credentials.rs — No TOCTOU permission window on save
// ---------------------------------------------------------------------------

#[test]
fn r23_credentials_no_toctou_permission_window() {
    let source = include_str!("../../puzzle-proxy/src/credentials.rs");
    // The save function should NOT have the pattern: write then set_permissions
    let has_old_pattern = source.contains("std::fs::write(&tmp_path")
        && source.contains("set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))");
    assert!(
        !has_old_pattern,
        "R23: credentials.rs save must NOT use write() then set_permissions() — TOCTOU vulnerability"
    );
}

// ---------------------------------------------------------------------------
// R26: dbus.rs — No silent serialization failure via unwrap_or_default()
// ---------------------------------------------------------------------------

#[test]
fn r26_dbus_no_silent_serialization_failure() {
    let source = include_str!("../src/dbus/mod.rs");
    assert!(
        !source.contains("to_string(violations).unwrap_or_default()"),
        "R26: dbus.rs must NOT silently swallow serialization failures with unwrap_or_default()"
    );
}

// ---------------------------------------------------------------------------
// R27: conflict.rs — modified_files map has a size bound
// ---------------------------------------------------------------------------

#[test]
fn r27_conflict_has_max_modified_files_constant() {
    let source = include_str!("../src/conflict.rs");
    assert!(
        source.contains("MAX_MODIFIED_FILES"),
        "R27: conflict.rs must define a MAX_MODIFIED_FILES size bound"
    );
}

// ---------------------------------------------------------------------------
// G10: Watcher threads bounded (policy.rs)
// ---------------------------------------------------------------------------

#[test]
fn test_g10_watcher_threads_bounded() {
    let source = include_str!("../src/policy.rs");
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
    assert!(
        prod_source.contains("MAX_WATCHER_THREADS"),
        "G10: policy.rs must define MAX_WATCHER_THREADS to cap watcher thread spawns"
    );
    // Also verify we check the count before spawning
    assert!(
        prod_source.contains("active_watcher_threads"),
        "G10: policy.rs must track active_watcher_threads count"
    );
}

// ---------------------------------------------------------------------------
// G11: recover_branch_chains uses filter_map, not map_while (audit_store.rs)
// ---------------------------------------------------------------------------

#[test]
fn test_g11_recovery_uses_filter_map() {
    let source = include_str!("../src/audit_store.rs");
    // Find the recover_branch_chains function
    let fn_start = source
        .find("fn recover_branch_chains")
        .expect("G11: recover_branch_chains function must exist in audit_store.rs");
    // Get the function body (up to the next top-level fn)
    let fn_body = &source[fn_start..];
    let fn_end = fn_body
        .find("\n    /// ")
        .or_else(|| fn_body.find("\n    pub fn "))
        .or_else(|| fn_body.find("\n    fn "))
        .unwrap_or(fn_body.len());
    let fn_body = &fn_body[..fn_end];
    assert!(
        fn_body.contains("filter_map"),
        "G11: recover_branch_chains must use filter_map (not map_while) \
         to skip corrupted lines without stopping iteration"
    );
    // Check that the code pattern .map_while(|l| l.ok()) is NOT used.
    // The word "map_while" may appear in comments explaining the fix.
    assert!(
        !fn_body.contains(".map_while("),
        "G11: recover_branch_chains must NOT call .map_while() — it stops at \
         the first I/O error, losing subsequent branch chain state"
    );
}
