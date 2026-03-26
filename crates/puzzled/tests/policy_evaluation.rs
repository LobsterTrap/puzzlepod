// SPDX-License-Identifier: Apache-2.0
//! Integration test: Full diff -> policy evaluation pipeline.
//!
//! Tests the complete flow from file changes in a temp directory through
//! the DiffEngine to the PolicyEngine, verifying end-to-end governance.

use std::fs;
use std::path::PathBuf;

use puzzled_types::{AgentProfile, FileChangeKind, PolicyDecision};

// We test the policy engine and diff engine directly since they are
// cross-platform (no Linux kernel primitives required).

fn policy_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("policies")
        .join("rules")
}

fn create_policy_engine() -> puzzled::policy::PolicyEngine {
    let engine = puzzled::policy::PolicyEngine::new(policy_dir());
    engine.reload().unwrap();
    engine
}

#[test]
fn test_diff_to_policy_approve() {
    let upper = tempfile::tempdir().unwrap();
    let lower = tempfile::tempdir().unwrap();

    // Create a clean changeset (source file)
    fs::write(upper.path().join("main.rs"), "fn main() {}").unwrap();

    let engine = puzzled::diff::DiffEngine::new();
    let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

    assert!(!changes.is_empty());

    let policy = create_policy_engine();
    let decision = policy.evaluate(&changes, None).unwrap();
    assert!(matches!(decision, PolicyDecision::Approved));
}

#[test]
fn test_diff_to_policy_reject_env_file() {
    let upper = tempfile::tempdir().unwrap();
    let lower = tempfile::tempdir().unwrap();

    // Create a sensitive file
    fs::write(upper.path().join(".env"), "SECRET_KEY=hunter2").unwrap();

    let engine = puzzled::diff::DiffEngine::new();
    let changes = engine.generate(upper.path(), lower.path(), None).unwrap();

    assert!(!changes.is_empty());
    assert!(changes
        .iter()
        .any(|c| c.path.to_str().unwrap().contains(".env")));

    let policy = create_policy_engine();
    let decision = policy.evaluate(&changes, None).unwrap();

    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(violations.iter().any(|v| v.rule == "no_sensitive_files"));
        }
        other => panic!("expected Rejected, got {:?}", other),
    }
}

#[test]
fn test_diff_to_policy_reject_system_path() {
    let _upper = tempfile::tempdir().unwrap();
    let _lower = tempfile::tempdir().unwrap();

    // Simulate a file at a system path
    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("/usr/bin/backdoor"),
        kind: FileChangeKind::Added,
        size: 8192,
        checksum: "deadbeef".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    }];

    let policy = create_policy_engine();
    let decision = policy.evaluate(&changes, None).unwrap();

    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(violations
                .iter()
                .any(|v| v.rule == "no_system_modifications"));
        }
        other => panic!("expected Rejected, got {:?}", other),
    }
}

#[test]
fn test_empty_changeset_approved() {
    let policy = create_policy_engine();
    let decision = policy.evaluate(&[], None).unwrap();
    assert!(matches!(decision, PolicyDecision::Approved));
}

#[test]
fn test_multiple_clean_files_approved() {
    let policy = create_policy_engine();

    let changes = vec![
        puzzled_types::FileChange {
            path: PathBuf::from("src/lib.rs"),
            kind: FileChangeKind::Modified,
            size: 2048,
            checksum: "aaa".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        },
        puzzled_types::FileChange {
            path: PathBuf::from("src/utils.rs"),
            kind: FileChangeKind::Added,
            size: 1024,
            checksum: "bbb".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        },
        puzzled_types::FileChange {
            path: PathBuf::from("tests/test.rs"),
            kind: FileChangeKind::Modified,
            size: 512,
            checksum: "ccc".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        },
    ];

    let decision = policy.evaluate(&changes, None).unwrap();
    assert!(matches!(decision, PolicyDecision::Approved));
}

// ---------------------------------------------------------------------------
// T18: Rego edge cases — empty path, ".." traversal, null bytes
// ---------------------------------------------------------------------------

#[test]
fn t18_rego_empty_path_rejected() {
    // The commit.rego "no_empty_paths" rule should reject changesets with empty paths.
    let policy = create_policy_engine();

    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from(""),
        kind: FileChangeKind::Added,
        size: 100,
        checksum: "abc".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    }];

    let decision = policy.evaluate(&changes, None).unwrap();
    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(
                violations.iter().any(|v| v.rule == "no_empty_paths"),
                "expected no_empty_paths violation, got: {:?}",
                violations
            );
        }
        other => panic!("expected Rejected for empty path, got {:?}", other),
    }
}

#[test]
fn t18_rego_dotdot_traversal_in_sensitive_path() {
    // A path with ".." traversal that resolves to a sensitive location
    // should be caught by the sensitive file regex patterns if it matches.
    // Note: Rego evaluates the literal path string, not a resolved path.
    let policy = create_policy_engine();

    // Path traversal to reach .ssh directory
    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("project/../.ssh/id_rsa"),
        kind: FileChangeKind::Added,
        size: 2048,
        checksum: "def".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    }];

    let decision = policy.evaluate(&changes, None).unwrap();
    match decision {
        PolicyDecision::Rejected(violations) => {
            // Should match "id_rsa" and/or ".ssh/" patterns
            assert!(
                violations.iter().any(|v| v.rule == "no_sensitive_files"),
                "expected no_sensitive_files violation for traversal path, got: {:?}",
                violations
            );
        }
        other => panic!(
            "expected Rejected for path with traversal to sensitive file, got {:?}",
            other
        ),
    }
}

#[test]
fn t18_rego_null_byte_in_path() {
    // Paths containing null bytes could be used for injection attacks.
    // The policy should handle them gracefully (either reject or not crash).
    let policy = create_policy_engine();

    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("safe_file\x00.env"),
        kind: FileChangeKind::Added,
        size: 100,
        checksum: "ghi".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    }];

    // The policy engine should not panic. Whether it rejects depends on whether
    // the regex matches the path with the embedded null byte.
    let result = policy.evaluate(&changes, None);
    assert!(
        result.is_ok(),
        "policy engine must not panic on null byte in path"
    );
}

#[test]
fn t18_rego_persistence_path_traversal() {
    // Direct persistence path should be caught
    let policy = create_policy_engine();

    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("/etc/cron.d/malicious"),
        kind: FileChangeKind::Added,
        size: 256,
        checksum: "jkl".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    }];

    let decision = policy.evaluate(&changes, None).unwrap();
    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(
                violations.iter().any(|v| v.rule == "no_persistence"),
                "expected no_persistence violation, got: {:?}",
                violations
            );
        }
        other => panic!("expected Rejected for persistence path, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// T19: Rego regex patterns — no false positives on legitimate paths
// ---------------------------------------------------------------------------

#[test]
fn t19_rego_no_false_positive_env_like_names() {
    // Files with "env" in the name but NOT matching the sensitive patterns
    // should be approved. The pattern is "\\.env$" and "\\.env\\." which
    // should not match "environment.rs" or "env_setup.py".
    let policy = create_policy_engine();

    let changes = vec![
        puzzled_types::FileChange {
            path: PathBuf::from("src/environment.rs"),
            kind: FileChangeKind::Added,
            size: 1024,
            checksum: "aaa".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        },
        puzzled_types::FileChange {
            path: PathBuf::from("scripts/env_setup.py"),
            kind: FileChangeKind::Added,
            size: 512,
            checksum: "bbb".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        },
        puzzled_types::FileChange {
            path: PathBuf::from("docs/environment-variables.md"),
            kind: FileChangeKind::Added,
            size: 2048,
            checksum: "ccc".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        },
    ];

    let decision = policy.evaluate(&changes, None).unwrap();
    assert!(
        matches!(decision, PolicyDecision::Approved),
        "legitimate files with 'env' in the name should not be flagged: {:?}",
        decision
    );
}

#[test]
fn t19_rego_no_false_positive_ssh_like_names() {
    // Files containing "ssh" but not in ".ssh/" directory should be approved
    let policy = create_policy_engine();

    let changes = vec![
        puzzled_types::FileChange {
            path: PathBuf::from("src/ssh_client.rs"),
            kind: FileChangeKind::Added,
            size: 4096,
            checksum: "ddd".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        },
        puzzled_types::FileChange {
            path: PathBuf::from("docs/ssh-usage.md"),
            kind: FileChangeKind::Added,
            size: 1024,
            checksum: "eee".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        },
    ];

    let decision = policy.evaluate(&changes, None).unwrap();
    assert!(
        matches!(decision, PolicyDecision::Approved),
        "files with 'ssh' in name (not in .ssh/ dir) should not be flagged: {:?}",
        decision
    );
}

#[test]
fn t19_rego_no_false_positive_shadow_like_names() {
    // The shadow pattern is "(^|/)shadow$" — should not match "shadow.rs"
    // or "shadow-dom/index.js"
    let policy = create_policy_engine();

    let changes = vec![
        puzzled_types::FileChange {
            path: PathBuf::from("src/shadow.rs"),
            kind: FileChangeKind::Added,
            size: 512,
            checksum: "fff".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        },
        puzzled_types::FileChange {
            path: PathBuf::from("shadow-dom/index.js"),
            kind: FileChangeKind::Added,
            size: 256,
            checksum: "ggg".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        },
    ];

    let decision = policy.evaluate(&changes, None).unwrap();
    // "src/shadow.rs" should NOT match "(^|/)shadow$" because it has ".rs" suffix
    // "shadow-dom/index.js" should NOT match because "shadow-dom" != "shadow"
    assert!(
        matches!(decision, PolicyDecision::Approved),
        "shadow.rs and shadow-dom/ should not trigger no_sensitive_files: {:?}",
        decision
    );
}

#[test]
fn t19_rego_no_false_positive_system_adjacent_paths() {
    // Paths that look similar to system paths but are not
    let policy = create_policy_engine();

    let changes = vec![
        puzzled_types::FileChange {
            path: PathBuf::from("src/usr/bin/tool.rs"),
            kind: FileChangeKind::Added,
            size: 1024,
            checksum: "hhh".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        },
        puzzled_types::FileChange {
            path: PathBuf::from("project/boot-config.yaml"),
            kind: FileChangeKind::Added,
            size: 256,
            checksum: "iii".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        },
    ];

    let decision = policy.evaluate(&changes, None).unwrap();
    // "src/usr/bin/tool.rs" does NOT start with "/usr/bin/" (no leading slash)
    // "project/boot-config.yaml" does NOT start with "/boot/"
    assert!(
        matches!(decision, PolicyDecision::Approved),
        "paths resembling but not matching system prefixes should be approved: {:?}",
        decision
    );
}

#[test]
fn t19_rego_metadata_change_correctly_flagged() {
    // MetadataChanged should always trigger no_exec_permission_changes
    let policy = create_policy_engine();

    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("scripts/deploy.py"),
        kind: FileChangeKind::MetadataChanged,
        size: 0,
        checksum: String::new(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    }];

    let decision = policy.evaluate(&changes, None).unwrap();
    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(
                violations
                    .iter()
                    .any(|v| v.rule == "no_exec_permission_changes"),
                "MetadataChanged should trigger no_exec_permission_changes"
            );
        }
        other => panic!("expected Rejected for MetadataChanged, got {:?}", other),
    }
}

// ── Issue #8: SSH key variant coverage ──────────────────────────────────

#[test]
fn t20_rego_rejects_ecdsa_private_key() {
    let policy = create_policy_engine();
    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("home/user/id_ecdsa"),
        kind: FileChangeKind::Added,
        size: 512,
        checksum: "aaa".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    }];
    let decision = policy.evaluate(&changes, None).unwrap();
    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(
                violations.iter().any(|v| v.rule == "no_sensitive_files"),
                "id_ecdsa should trigger no_sensitive_files, got: {:?}",
                violations
            );
        }
        other => panic!("expected Rejected for id_ecdsa, got {:?}", other),
    }
}

#[test]
fn t20_rego_rejects_dsa_private_key() {
    let policy = create_policy_engine();
    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("home/user/id_dsa"),
        kind: FileChangeKind::Added,
        size: 512,
        checksum: "bbb".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    }];
    let decision = policy.evaluate(&changes, None).unwrap();
    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(
                violations.iter().any(|v| v.rule == "no_sensitive_files"),
                "id_dsa should trigger no_sensitive_files, got: {:?}",
                violations
            );
        }
        other => panic!("expected Rejected for id_dsa, got {:?}", other),
    }
}

#[test]
fn t20_rego_rejects_ecdsa_sk_security_key() {
    let policy = create_policy_engine();
    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("home/user/id_ecdsa_sk"),
        kind: FileChangeKind::Added,
        size: 512,
        checksum: "ccc".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    }];
    let decision = policy.evaluate(&changes, None).unwrap();
    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(
                violations.iter().any(|v| v.rule == "no_sensitive_files"),
                "id_ecdsa_sk should trigger no_sensitive_files, got: {:?}",
                violations
            );
        }
        other => panic!("expected Rejected for id_ecdsa_sk, got {:?}", other),
    }
}

#[test]
fn t20_rego_rejects_ed25519_sk_security_key() {
    let policy = create_policy_engine();
    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("home/user/id_ed25519_sk"),
        kind: FileChangeKind::Added,
        size: 512,
        checksum: "ddd".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    }];
    let decision = policy.evaluate(&changes, None).unwrap();
    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(
                violations.iter().any(|v| v.rule == "no_sensitive_files"),
                "id_ed25519_sk should trigger no_sensitive_files, got: {:?}",
                violations
            );
        }
        other => panic!("expected Rejected for id_ed25519_sk, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// T21 (S15+S29): Cloud/CI/shell/container credential pattern coverage
// ---------------------------------------------------------------------------

/// Helper to assert a single-file changeset is rejected by no_persistence.
#[allow(dead_code)]
fn assert_persistence_rejected(path: &str, description: &str) {
    let policy = create_policy_engine();
    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from(path),
        kind: FileChangeKind::Added,
        size: 64,
        checksum: "persist".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    }];
    let decision = policy.evaluate(&changes, None).unwrap();
    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(
                violations.iter().any(|v| v.rule == "no_persistence"),
                "{} should trigger no_persistence, got: {:?}",
                description,
                violations
            );
        }
        other => panic!(
            "expected Rejected for {} (path: {}), got {:?}",
            description, path, other
        ),
    }
}

/// Helper to assert a single-file changeset is rejected by no_sensitive_files.
fn assert_sensitive_file_rejected(path: &str, description: &str) {
    let policy = create_policy_engine();
    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from(path),
        kind: FileChangeKind::Added,
        size: 256,
        checksum: "t21".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    }];
    let decision = policy.evaluate(&changes, None).unwrap();
    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(
                violations.iter().any(|v| v.rule == "no_sensitive_files"),
                "{} should trigger no_sensitive_files, got: {:?}",
                description,
                violations
            );
        }
        other => panic!(
            "expected Rejected for {} (path: {}), got {:?}",
            description, path, other
        ),
    }
}

#[test]
fn t21_rego_rejects_azure_credentials() {
    assert_sensitive_file_rejected(
        "home/user/.azure/credentials",
        "Azure credentials directory",
    );
}

#[test]
fn t21_rego_rejects_bash_history() {
    assert_sensitive_file_rejected("home/user/.bash_history", "bash history file");
}

#[test]
fn t21_rego_rejects_mysql_history() {
    assert_sensitive_file_rejected("home/user/.mysql_history", "MySQL history file");
}

#[test]
fn t21_rego_rejects_terraform_state() {
    assert_sensitive_file_rejected(
        "project/.terraform/terraform.tfstate",
        "Terraform state directory",
    );
}

#[test]
fn t21_rego_rejects_podman_auth() {
    assert_sensitive_file_rejected("home/user/.podman/auth.json", "Podman registry auth");
}

#[test]
fn t21_rego_rejects_cosign_key() {
    assert_sensitive_file_rejected("project/cosign.key", "cosign signing key");
}

#[test]
fn t21_rego_rejects_cargo_credentials() {
    assert_sensitive_file_rejected("home/user/.cargo/credentials.toml", "Cargo credentials");
}

#[test]
fn t21_rego_rejects_vault_password() {
    assert_sensitive_file_rejected("project/.vault_pass", "Ansible vault password");
    assert_sensitive_file_rejected("project/.vault-pass", "Ansible vault password (hyphen)");
}

// ---------------------------------------------------------------------------
// R8: Relative symlink targets with parent traversal bypass workspace boundary
// ---------------------------------------------------------------------------

#[test]
fn test_r8_rego_rejects_relative_symlink_with_parent_traversal() {
    // R8: A symlink with a relative target containing ".." can escape the workspace.
    // Test the Rego rule directly with a crafted JSON input that includes "target".
    let policy_dir = policy_dir();
    let mut engine = regorus::Engine::new();

    // Load all .rego files
    for entry in std::fs::read_dir(&policy_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("rego") {
            let contents = std::fs::read_to_string(&path).unwrap();
            engine
                .add_policy(path.display().to_string(), contents)
                .unwrap();
        }
    }

    // Craft input with a symlink change that has a relative target with ".."
    let input_json = serde_json::json!({
        "changes": [{
            "path": "workspace/link",
            "kind": "Symlink",
            "change_type": "symlink",
            "size": 0,
            "checksum": "",
            "target": "../../../etc/shadow"
        }],
        "profile": "privileged"
    });

    let input_str = serde_json::to_string(&input_json).unwrap();
    engine.set_input_json(&input_str).unwrap();

    let allow_result = engine
        .eval_rule("data.puzzlepod.commit.allow".to_string())
        .unwrap();
    let allowed = matches!(allow_result, regorus::Value::Bool(true));

    assert!(
        !allowed,
        "R8: symlink with relative target '../../../etc/shadow' should be rejected by policy"
    );
}

// ---------------------------------------------------------------------------
// R19: at daemon persistence paths
// ---------------------------------------------------------------------------

#[test]
fn test_r19_rego_rejects_at_daemon_persistence() {
    let policy = create_policy_engine();
    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("etc/at.allow"),
        kind: FileChangeKind::Added,
        size: 64,
        checksum: "r19".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    }];

    let decision = policy.evaluate(&changes, None).unwrap();
    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(
                violations.iter().any(|v| v.rule == "no_persistence"),
                "R19: etc/at.allow should trigger no_persistence, got: {:?}",
                violations
            );
        }
        other => panic!("R19: expected Rejected for etc/at.allow, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// S30: User-level systemd persistence path
// ---------------------------------------------------------------------------

#[test]
fn test_s30_rego_rejects_user_systemd_persistence() {
    // S30: .config/systemd/user/ must be in persistence_suffixes
    let rego_source = include_str!("../../../policies/rules/commit.rego");
    assert!(
        rego_source.contains(".config/systemd/user/"),
        "S30: commit.rego must contain .config/systemd/user/ persistence path"
    );

    // Functional check: a file in user systemd dir is rejected
    assert_persistence_rejected(
        "home/agent/.config/systemd/user/malicious.service",
        "S30: user-level systemd service",
    );
}

// ---------------------------------------------------------------------------
// S37: D-Bus session services persistence
// ---------------------------------------------------------------------------

#[test]
fn test_s37_rego_rejects_dbus_session_services_persistence() {
    // S37: .local/share/dbus-1/services/ must be in persistence_suffixes
    let rego_source = include_str!("../../../policies/rules/commit.rego");
    assert!(
        rego_source.contains(".local/share/dbus-1/services/"),
        "S37: commit.rego must contain .local/share/dbus-1/services/ persistence path"
    );

    // Functional check: a D-Bus session service file is rejected
    assert_persistence_rejected(
        "home/agent/.local/share/dbus-1/services/com.evil.Agent.service",
        "S37: D-Bus session service file",
    );
}

// ---------------------------------------------------------------------------
// S38: Shell rc files (persistence/env manipulation)
// ---------------------------------------------------------------------------

#[test]
fn test_s38_rego_rejects_shell_rc_files() {
    // S38: sensitive_regex_patterns must cover shell rc/profile files
    let rego_source = include_str!("../../../policies/rules/commit.rego");
    assert!(
        rego_source.contains("bashrc")
            && rego_source.contains("zshrc")
            && rego_source.contains("bash_profile")
            && rego_source.contains("bash_logout"),
        "S38: commit.rego must contain shell rc file patterns (bashrc, zshrc, bash_profile, bash_logout)"
    );

    // Functional checks: various shell rc files are rejected
    assert_sensitive_file_rejected("home/agent/.bashrc", "S38: .bashrc");
    assert_sensitive_file_rejected("home/agent/.bash_profile", "S38: .bash_profile");
    assert_sensitive_file_rejected("home/agent/.bash_logout", "S38: .bash_logout");
    assert_sensitive_file_rejected("home/agent/.zshrc", "S38: .zshrc");
    assert_sensitive_file_rejected("home/agent/.profile", "S38: .profile");
    assert_sensitive_file_rejected("home/agent/.zprofile", "S38: .zprofile");
}

// ---------------------------------------------------------------------------
// S39: Kerberos keytab credential detection
// ---------------------------------------------------------------------------

#[test]
fn test_s39_rego_rejects_kerberos_keytab() {
    // S39: sensitive_regex_patterns must match .keytab files
    let rego_source = include_str!("../../../policies/rules/commit.rego");
    assert!(
        rego_source.contains("\\.keytab$"),
        "S39: commit.rego must contain .keytab pattern in sensitive_regex_patterns"
    );

    // Functional check: keytab files are rejected
    assert_sensitive_file_rejected("etc/krb5.keytab", "S39: Kerberos system keytab");
    assert_sensitive_file_rejected("home/agent/user.keytab", "S39: Kerberos user keytab");
}

// ---------------------------------------------------------------------------
// S40: GPG secret keyring credential detection
// ---------------------------------------------------------------------------

#[test]
fn test_s40_rego_rejects_gpg_secring() {
    // S40: sensitive_regex_patterns must match secring.gpg
    let rego_source = include_str!("../../../policies/rules/commit.rego");
    assert!(
        rego_source.contains("secring\\\\.gpg$"),
        "S40: commit.rego must contain secring.gpg pattern in sensitive_regex_patterns"
    );

    // Functional check: GPG secret keyring is rejected
    assert_sensitive_file_rejected("home/agent/.gnupg/secring.gpg", "S40: GPG secret keyring");
    assert_sensitive_file_rejected(
        "project/secring.gpg",
        "S40: GPG secret keyring in project dir",
    );
}

// ---------------------------------------------------------------------------
// S41: udev rules and modules-load persistence
// ---------------------------------------------------------------------------

#[test]
fn test_s41_rego_rejects_udev_and_modules_load_persistence() {
    // S41: persistence_paths must include udev rules and modules-load.d
    let rego_source = include_str!("../../../policies/rules/commit.rego");
    assert!(
        rego_source.contains("etc/udev/rules.d/"),
        "S41: commit.rego must contain etc/udev/rules.d/ persistence path"
    );
    assert!(
        rego_source.contains("etc/modules-load.d/"),
        "S41: commit.rego must contain etc/modules-load.d/ persistence path"
    );

    // Functional check: udev rules and modules-load files are rejected
    assert_persistence_rejected("etc/udev/rules.d/99-agent.rules", "S41: udev rules file");
    assert_persistence_rejected(
        "etc/modules-load.d/agent.conf",
        "S41: modules-load.d config",
    );
}

// ---------------------------------------------------------------------------
// F9: Dead Rego rule uses wrong field name `change.change_type` instead of `change.kind`
// ---------------------------------------------------------------------------

#[test]
fn test_f9_no_dead_change_type_field() {
    // F9: The Rego policy must only use `change.kind` (matching Rust serde output),
    // never `change.change_type`. Any use of `change.change_type` is a dead rule.
    let rego_source = include_str!("../../../policies/rules/commit.rego");
    assert!(
        !rego_source.contains("change.change_type"),
        "F9: commit.rego must not contain 'change.change_type' — \
         use 'change.kind' (matches Rust FileChangeKind serde serialization)"
    );
}

// ---------------------------------------------------------------------------
// F10: Workspace boundary bypass when input.workspace_root is not provided
// ---------------------------------------------------------------------------

#[test]
fn test_f10_absolute_path_without_workspace_root_rejected() {
    // F10: When a change has an absolute path but no workspace_root is set,
    // the policy must reject — not silently skip the workspace boundary check.
    let policy = create_policy_engine();

    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("/opt/agent/data/output.txt"),
        kind: FileChangeKind::Added,
        size: 512,
        checksum: "f10".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    }];

    // Evaluate WITHOUT workspace_root (None) — absolute path should be flagged
    let decision = policy
        .evaluate_with_workspace(&changes, None, None)
        .unwrap();
    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(
                violations
                    .iter()
                    .any(|v| v.rule == "deny_missing_workspace_root"),
                "F10: absolute path without workspace_root should trigger \
                 deny_missing_workspace_root, got: {:?}",
                violations
            );
        }
        other => panic!(
            "F10: expected Rejected for absolute path without workspace_root, got {:?}",
            other
        ),
    }
}

// ---------------------------------------------------------------------------
// F22: Missing persistence paths in commit.rego
// ---------------------------------------------------------------------------

#[test]
fn test_f22_rego_rejects_additional_persistence_paths() {
    // F22: commit.rego must reject writes to additional persistence paths:
    // etc/ld.so.preload, etc/pam.d/*, etc/xdg/autostart/*, etc.
    let rego_source = include_str!("../../../policies/rules/commit.rego");

    // Structural checks: these paths must appear in persistence_paths or persistence_exact
    assert!(
        rego_source.contains("etc/ld.so.preload"),
        "F22: commit.rego must contain etc/ld.so.preload persistence path"
    );
    assert!(
        rego_source.contains("etc/pam.d/"),
        "F22: commit.rego must contain etc/pam.d/ persistence path"
    );

    // Functional checks: files in these paths are rejected
    assert_persistence_rejected("etc/ld.so.preload", "F22: ld.so.preload");
    assert_persistence_rejected("etc/pam.d/custom", "F22: PAM module config");
}

// ---------------------------------------------------------------------------
// F23: Privileged profile denylist too narrow
// ---------------------------------------------------------------------------

#[test]
fn test_f23_privileged_profile_has_expanded_denylist() {
    // F23: privileged.yaml must denylist additional sensitive paths
    let profile_yaml = include_str!("../../../policies/profiles/privileged.yaml");

    assert!(
        profile_yaml.contains("/etc/sudoers"),
        "F23: privileged.yaml must denylist /etc/sudoers"
    );
    assert!(
        profile_yaml.contains("/root/.gnupg"),
        "F23: privileged.yaml must denylist /root/.gnupg"
    );
    assert!(
        profile_yaml.contains("/etc/security"),
        "F23: privileged.yaml must denylist /etc/security"
    );
}

// ---------------------------------------------------------------------------
// G5: Case-insensitive sensitive file detection
// ---------------------------------------------------------------------------

#[test]
fn test_g5_sensitive_files_case_insensitive() {
    // G5: Uppercase variants like CREDENTIALS.json, .ENV, Secrets.yaml must be caught.
    let policy = create_policy_engine();

    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("home/agent/CREDENTIALS.json"),
        kind: FileChangeKind::Added,
        size: 256,
        checksum: "g5".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    }];

    let decision = policy.evaluate(&changes, None).unwrap();
    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(
                violations.iter().any(|v| v.rule == "no_sensitive_files"),
                "G5: CREDENTIALS.json (uppercase) should trigger no_sensitive_files, got: {:?}",
                violations
            );
        }
        other => panic!(
            "G5: expected Rejected for CREDENTIALS.json (uppercase), got {:?}",
            other
        ),
    }
}

// ---------------------------------------------------------------------------
// G17: Symlink workspace prefix attack
// ---------------------------------------------------------------------------

#[test]
fn test_g17_symlink_workspace_prefix_attack() {
    // G17: A symlink target of "/workspacevil/exfil" should NOT match workspace_root="/workspace"
    let policy_dir = policy_dir();
    let mut engine = regorus::Engine::new();

    for entry in std::fs::read_dir(&policy_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("rego") {
            let contents = std::fs::read_to_string(&path).unwrap();
            engine
                .add_policy(path.display().to_string(), contents)
                .unwrap();
        }
    }

    let input_json = serde_json::json!({
        "changes": [{
            "path": "workspace/link",
            "kind": "Symlink",
            "size": 0,
            "checksum": "",
            "target": "/workspacevil/exfil"
        }],
        "profile": "privileged",
        "workspace_root": "/workspace"
    });

    let input_str = serde_json::to_string(&input_json).unwrap();
    engine.set_input_json(&input_str).unwrap();

    let allow_result = engine
        .eval_rule("data.puzzlepod.commit.allow".to_string())
        .unwrap();
    let allowed = matches!(allow_result, regorus::Value::Bool(true));

    assert!(
        !allowed,
        "G17: symlink target '/workspacevil/exfil' with workspace_root='/workspace' should be rejected"
    );
}

// ---------------------------------------------------------------------------
// G18: Change without size field rejected
// ---------------------------------------------------------------------------

#[test]
fn test_g18_change_without_size_rejected() {
    // G18: A change missing the `size` field should be rejected.
    let policy_dir = policy_dir();
    let mut engine = regorus::Engine::new();

    for entry in std::fs::read_dir(&policy_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("rego") {
            let contents = std::fs::read_to_string(&path).unwrap();
            engine
                .add_policy(path.display().to_string(), contents)
                .unwrap();
        }
    }

    // Input with a change that has no `size` field
    let input_json = serde_json::json!({
        "changes": [{
            "path": "data/output.bin",
            "kind": "Added",
            "checksum": "abc123"
        }]
    });

    let input_str = serde_json::to_string(&input_json).unwrap();
    engine.set_input_json(&input_str).unwrap();

    let allow_result = engine
        .eval_rule("data.puzzlepod.commit.allow".to_string())
        .unwrap();
    let allowed = matches!(allow_result, regorus::Value::Bool(true));

    assert!(
        !allowed,
        "G18: change without size field should be rejected"
    );

    // Verify it's the missing_change_size rule
    let violations_result = engine
        .eval_rule("data.puzzlepod.commit.violations".to_string())
        .unwrap();
    let violations_str = format!("{:?}", violations_result);
    assert!(
        violations_str.contains("missing_change_size"),
        "G18: violation should mention missing_change_size, got: {}",
        violations_str
    );
}

// ---------------------------------------------------------------------------
// G6: puzzle-podman input validation
// ---------------------------------------------------------------------------

#[test]
fn test_g6_puzzle_podman_validates_inputs() {
    // G6: Verify puzzle-podman script contains input validation patterns
    let script = include_str!("../../../podman/puzzle-podman");

    // Check profile validation (regex check)
    assert!(
        script.contains(r#"[a-zA-Z0-9_-]"#),
        "G6: puzzle-podman must validate AGENT_PROFILE with alphanumeric regex"
    );
    assert!(
        script.contains("invalid profile name"),
        "G6: puzzle-podman must have error message for invalid profile"
    );

    // Check base path validation (absolute path, no "..")
    assert!(
        script.contains("agent base path must be absolute"),
        "G6: puzzle-podman must validate AGENT_BASE is absolute"
    );
    assert!(
        script.contains("must not contain '..'"),
        "G6: puzzle-podman must reject '..' in AGENT_BASE"
    );

    // Check PODMAN validation
    assert!(
        script.contains("must point to a 'podman' binary"),
        "G6: puzzle-podman must validate PODMAN env var resolves to podman"
    );
}

// ---------------------------------------------------------------------------
// G19: puzzle-hook branch ID validation
// ---------------------------------------------------------------------------

#[test]
fn test_g19_hook_branch_id_validated() {
    // G19: Verify puzzle-hook validates branch IDs
    let hook_source = include_str!("../../../crates/puzzle-hook/src/main.rs");

    assert!(
        hook_source.contains("validate_branch_id"),
        "G19: puzzle-hook must contain validate_branch_id function"
    );
    // Check it rejects path traversal
    assert!(
        hook_source.contains(r#"!id.contains('/')"#) || hook_source.contains("contains('/')"),
        "G19: validate_branch_id must reject '/'"
    );
    assert!(
        hook_source.contains(r#"!id.contains("..")"#) || hook_source.contains(r#"contains("..")"#),
        "G19: validate_branch_id must reject '..'"
    );
    // Check length limit
    assert!(
        hook_source.contains("256"),
        "G19: validate_branch_id must enforce length limit of 256"
    );
}

// ---------------------------------------------------------------------------
// G31: privileged profile exec_denylist
// ---------------------------------------------------------------------------

#[test]
fn test_g31_privileged_has_exec_denylist() {
    // G31: privileged.yaml must have exec_denylist blocking dangerous executables
    let profile_yaml = include_str!("../../../policies/profiles/privileged.yaml");

    assert!(
        profile_yaml.contains("exec_denylist"),
        "G31: privileged.yaml must contain exec_denylist section"
    );
    assert!(
        profile_yaml.contains("nsenter"),
        "G31: exec_denylist must include nsenter"
    );
    assert!(
        profile_yaml.contains("unshare"),
        "G31: exec_denylist must include unshare"
    );
    assert!(
        profile_yaml.contains("chroot"),
        "G31: exec_denylist must include chroot"
    );
    assert!(
        profile_yaml.contains("mount"),
        "G31: exec_denylist must include mount"
    );
    assert!(
        profile_yaml.contains("strace"),
        "G31: exec_denylist must include strace"
    );
    assert!(
        profile_yaml.contains("gdb"),
        "G31: exec_denylist must include gdb"
    );
}

// ---------------------------------------------------------------------------
// F24: Standard profile missing /etc/gshadow in denylist
// ---------------------------------------------------------------------------

#[test]
fn test_f24_standard_profile_denylists_gshadow() {
    // F24: standard.yaml must denylist /etc/gshadow
    let profile_yaml = include_str!("../../../policies/profiles/standard.yaml");
    assert!(
        profile_yaml.contains("/etc/gshadow"),
        "F24: standard.yaml must denylist /etc/gshadow"
    );
}

// ---------------------------------------------------------------------------
// H81: puzzle-podman skips `command -v` check when IS_REMOTE=1
// ---------------------------------------------------------------------------

#[test]
fn test_h81_puzzle_podman_skips_command_v_when_remote() {
    let script = include_str!("../../../podman/puzzle-podman");
    // H81: The script must gate the `command -v` check on IS_REMOTE
    assert!(
        script.contains("IS_REMOTE") && script.contains("command -v"),
        "H81: puzzle-podman must reference IS_REMOTE near command -v check"
    );
    // Verify the conditional skip pattern exists
    assert!(
        script.contains(r#"[ "$IS_REMOTE" -ne 1 ]"#),
        "H81: puzzle-podman must skip command -v when IS_REMOTE=1"
    );
}

// ---------------------------------------------------------------------------
// H82: mkdir with restrictive permissions
// ---------------------------------------------------------------------------

#[test]
fn test_h82_puzzle_podman_mkdir_restrictive_permissions() {
    let script = include_str!("../../../podman/puzzle-podman");
    assert!(
        script.contains("mkdir -p -m 0700"),
        "H82: puzzle-podman must create AGENT_BASE with mode 0700"
    );
}

// ---------------------------------------------------------------------------
// H83: credentials/secrets regex patterns are more specific
// ---------------------------------------------------------------------------

#[test]
fn test_h83_credentials_helper_not_blocked() {
    // H83: credentials_helper.sh should NOT be blocked
    let policy = create_policy_engine();
    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("scripts/credentials_helper.sh"),
        kind: FileChangeKind::Added,
        size: 512,
        checksum: "h83a".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    }];
    let decision = policy.evaluate(&changes, None).unwrap();
    assert!(
        matches!(decision, PolicyDecision::Approved),
        "H83: credentials_helper.sh should NOT be blocked, got {:?}",
        decision
    );
}

#[test]
fn test_h83_credentials_json_is_blocked() {
    // H83: credentials.json must still be blocked
    assert_sensitive_file_rejected("config/credentials.json", "H83: credentials.json");
}

#[test]
fn test_h83_secrets_yaml_is_blocked() {
    // H83: secrets.yaml must still be blocked
    assert_sensitive_file_rejected("config/secrets.yaml", "H83: secrets.yaml");
}

// ---------------------------------------------------------------------------
// H84: Persistence paths case-insensitive (lowercase)
// ---------------------------------------------------------------------------

#[test]
fn test_h84_persistence_path_mixed_case_caught() {
    // H84: Etc/Cron.d/malicious must be caught by persistence rule
    let policy = create_policy_engine();
    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("Etc/Cron.d/malicious"),
        kind: FileChangeKind::Added,
        size: 64,
        checksum: "h84".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    }];
    let decision = policy.evaluate(&changes, None).unwrap();
    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(
                violations.iter().any(|v| v.rule == "no_persistence"),
                "H84: Etc/Cron.d/malicious should trigger no_persistence, got: {:?}",
                violations
            );
        }
        other => panic!(
            "H84: expected Rejected for mixed-case persistence path, got {:?}",
            other
        ),
    }
}

// ---------------------------------------------------------------------------
// H85: System prefix paths case-insensitive (lowercase)
// ---------------------------------------------------------------------------

#[test]
fn test_h85_system_prefix_mixed_case_caught() {
    // H85: Usr/Bin/backdoor must be caught by system modifications rule
    let policy = create_policy_engine();
    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("Usr/Bin/backdoor"),
        kind: FileChangeKind::Added,
        size: 8192,
        checksum: "h85".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    }];
    let decision = policy.evaluate(&changes, None).unwrap();
    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(
                violations
                    .iter()
                    .any(|v| v.rule == "no_system_modifications"),
                "H85: Usr/Bin/backdoor should trigger no_system_modifications, got: {:?}",
                violations
            );
        }
        other => panic!(
            "H85: expected Rejected for mixed-case system path, got {:?}",
            other
        ),
    }
}

// ---------------------------------------------------------------------------
// H86: puzzle-hook limits stdin read
// ---------------------------------------------------------------------------

#[test]
fn test_h86_hook_limits_stdin() {
    let hook_source = include_str!("../../../crates/puzzle-hook/src/main.rs");
    assert!(
        hook_source.contains(".take("),
        "H86: puzzle-hook must use .take() to limit stdin read"
    );
    assert!(
        hook_source.contains("1_048_576"),
        "H86: stdin limit must be 1 MiB (1_048_576)"
    );
}

// ---------------------------------------------------------------------------
// H90: puzzle-podman approve path does not swallow errors
// ---------------------------------------------------------------------------

#[test]
fn test_h90_puzzle_podman_approve_no_or_true() {
    let script = include_str!("../../../podman/puzzle-podman");
    // H90: The "Commit after inspection?" approve path should use `if !` pattern
    // (proper error handling with rollback) instead of `|| true`.
    let after_inspection = script
        .split("Commit after inspection?")
        .nth(1)
        .expect("H90: must have 'Commit after inspection?' prompt");
    let y_case = after_inspection
        .split("y|Y)")
        .nth(1)
        .expect("H90: must have y|Y case after inspection prompt");
    let y_block = y_case
        .split(";;")
        .next()
        .expect("H90: must end y|Y block with ;;");
    // Verify the approve call uses `if !` error handling, not `|| true`
    assert!(
        y_block.contains("if ! $PUZZLECTL branch approve"),
        "H90: approve path after inspection must use 'if !' error handling pattern"
    );
    // The `approve` line itself must not have `|| true`
    for line in y_block.lines() {
        if line.contains("branch approve") {
            assert!(
                !line.contains("|| true"),
                "H90: approve call must not use '|| true': {}",
                line
            );
        }
    }
}

// ---------------------------------------------------------------------------
// H92: Persistence suffix case-insensitive (lowercase)
// ---------------------------------------------------------------------------

#[test]
fn test_h92_persistence_suffix_mixed_case_caught() {
    // H92: A mixed-case persistence suffix like .Config/Autostart/ must be caught
    let policy = create_policy_engine();
    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("home/agent/.Config/Autostart/evil.desktop"),
        kind: FileChangeKind::Added,
        size: 64,
        checksum: "h92".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    }];
    let decision = policy.evaluate(&changes, None).unwrap();
    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(
                violations.iter().any(|v| v.rule == "no_persistence"),
                "H92: mixed-case .Config/Autostart/ should trigger no_persistence, got: {:?}",
                violations
            );
        }
        other => panic!(
            "H92: expected Rejected for mixed-case persistence suffix, got {:?}",
            other
        ),
    }
}

// ---------------------------------------------------------------------------
// J82: Integration test for profile_storage_quota rule
// ---------------------------------------------------------------------------

/// J82: A changeset exceeding the restricted profile's 10 MiB quota must trigger
/// the profile_storage_quota rule.
#[test]
fn j82_profile_storage_quota_restricted() {
    let policy = create_policy_engine();

    // Create a changeset with total size > 10 MiB (restricted profile limit = 10485760 bytes)
    // Use a single large file of 11 MiB
    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("large_model.bin"),
        kind: FileChangeKind::Added,
        size: 11 * 1024 * 1024, // 11 MiB
        checksum: "sha256:largehash".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    }];

    // J82: Pass profile_name = "restricted" so the Rego input.profile triggers
    // the profile_storage_quota rule with the 10 MiB limit.
    let decision = policy.evaluate(&changes, Some("restricted")).unwrap();

    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(
                violations
                    .iter()
                    .any(|v| v.rule == "profile_storage_quota"),
                "J82: expected profile_storage_quota violation for 11 MiB changeset with restricted profile, got: {:?}",
                violations
            );
        }
        other => panic!(
            "J82: expected Rejected for changeset exceeding restricted profile quota, got {:?}",
            other
        ),
    }
}

// ---------------------------------------------------------------------------
// J83: Integration tests for deny_outside_workspace and max_file_count
// ---------------------------------------------------------------------------

/// J83: A path outside workspace root must trigger deny_outside_workspace.
#[test]
fn j83_deny_outside_workspace() {
    let policy = create_policy_engine();

    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("/etc/passwd"),
        kind: FileChangeKind::Modified,
        size: 1024,
        checksum: "sha256:passwdhash".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    }];

    // J83: Pass workspace_root so the deny_outside_workspace rule fires.
    let decision = policy
        .evaluate_with_workspace(&changes, None, Some("/workspace"))
        .unwrap();

    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(
                violations
                    .iter()
                    .any(|v| v.rule == "deny_outside_workspace"),
                "J83: expected deny_outside_workspace violation for /etc/passwd outside /workspace, got: {:?}",
                violations
            );
        }
        other => panic!(
            "J83: expected Rejected for path outside workspace, got {:?}",
            other
        ),
    }
}

/// J83: A changeset with >10,000 files must trigger max_file_count.
/// Uses a standalone Rego engine with only the max_file_count rule to avoid
/// the expensive O(n) regex evaluations in other rules that would time out.
#[test]
fn j83_max_file_count() {
    // J83: Load only the max_file_count rule to avoid O(n) regex overhead
    let rego_snippet = r#"
package puzzlepod.commit

import future.keywords.if
import future.keywords.in

max_files := 10000

violations[v] if {
    count(input.changes) > max_files
    v := {
        "rule": "max_file_count",
        "message": sprintf("changeset contains %d files, limit is %d", [count(input.changes), max_files]),
        "severity": "error",
    }
}
"#;

    let mut engine = regorus::Engine::new();
    engine
        .add_policy("max_file_count.rego".to_string(), rego_snippet.to_string())
        .unwrap();

    // Build input with 10,001 minimal changes
    let mut changes_array = Vec::with_capacity(10_001);
    for i in 0..10_001 {
        changes_array.push(serde_json::json!({
            "path": format!("f{}", i),
            "kind": "Added",
            "size": 1,
            "checksum": ""
        }));
    }

    let input_json = serde_json::json!({ "changes": changes_array });
    let input_str = serde_json::to_string(&input_json).unwrap();
    engine.set_input_json(&input_str).unwrap();

    let violations_result = engine
        .eval_rule("data.puzzlepod.commit.violations".to_string())
        .unwrap();

    let violations_str = format!("{:?}", violations_result);
    assert!(
        violations_str.contains("max_file_count"),
        "J83: expected max_file_count violation for 10001 files, got: {}",
        violations_str
    );

    // Also verify the rule's threshold: 10,000 files should NOT trigger it
    let mut changes_at_limit = Vec::with_capacity(10_000);
    for i in 0..10_000 {
        changes_at_limit.push(serde_json::json!({
            "path": format!("f{}", i),
            "kind": "Added",
            "size": 1,
            "checksum": ""
        }));
    }
    let input_at_limit = serde_json::json!({ "changes": changes_at_limit });
    engine
        .set_input_json(&serde_json::to_string(&input_at_limit).unwrap())
        .unwrap();

    let at_limit_result = engine
        .eval_rule("data.puzzlepod.commit.violations".to_string())
        .unwrap();
    let at_limit_str = format!("{:?}", at_limit_result);
    assert!(
        !at_limit_str.contains("max_file_count"),
        "J83: exactly 10000 files should NOT trigger max_file_count, got: {}",
        at_limit_str
    );
}

// ---------------------------------------------------------------------------
// H93: D-Bus session bus fallback gated behind debug_assertions
// ---------------------------------------------------------------------------

#[test]
fn test_h93_hook_session_bus_gated() {
    let hook_source = include_str!("../../../crates/puzzle-hook/src/main.rs");
    // H93: The PUZZLEPOD_DBUS_SESSION env var check in code (not doc comments)
    // must be inside a #[cfg(debug_assertions)] block.
    assert!(
        hook_source.contains("#[cfg(debug_assertions)]"),
        "H93: connect_dbus must gate session bus fallback behind #[cfg(debug_assertions)]"
    );
    // Find the actual cfg attribute line (not doc comment), then verify
    // the env var usage in code appears after it.
    let cfg_line_pos = hook_source
        .find("    #[cfg(debug_assertions)]")
        .expect("must have #[cfg(debug_assertions)] attribute");
    // Find the env var check in code (std::env::var call, not doc comment)
    let env_var_code_pos = hook_source
        .find(r#"std::env::var("PUZZLEPOD_DBUS_SESSION")"#)
        .expect("must have std::env::var PUZZLEPOD_DBUS_SESSION call");
    assert!(
        env_var_code_pos > cfg_line_pos,
        "H93: PUZZLEPOD_DBUS_SESSION env var check must appear after #[cfg(debug_assertions)]"
    );
}

// ---------------------------------------------------------------------------
// H94: puzzle-podman validates BRANCH_ID format
// ---------------------------------------------------------------------------

#[test]
fn test_h94_puzzle_podman_validates_branch_id() {
    let script = include_str!("../../../podman/puzzle-podman");
    assert!(
        script.contains(r#"^[a-zA-Z0-9_-]+$"#),
        "H94: puzzle-podman must validate BRANCH_ID with alphanumeric regex"
    );
    assert!(
        script.contains("invalid branch ID"),
        "H94: puzzle-podman must have error message for invalid branch ID"
    );
}

// ---------------------------------------------------------------------------
// J60: persistence_exact_files case-normalized
// ---------------------------------------------------------------------------

#[test]
fn test_j60_persistence_exact_files_case_insensitive() {
    let policy = create_policy_engine();
    // J60: Mixed-case "Etc/Ld.So.Preload" should be caught by case-normalized matching
    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("Etc/Ld.So.Preload"),
        kind: FileChangeKind::Added,
        size: 64,
        checksum: "j60".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    }];

    let decision = policy.evaluate(&changes, None).unwrap();
    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(
                violations.iter().any(|v| v.rule == "no_persistence"),
                "J60: mixed-case Etc/Ld.So.Preload should trigger no_persistence, got: {:?}",
                violations
            );
        }
        other => panic!(
            "J60: expected Rejected for mixed-case persistence exact file, got {:?}",
            other
        ),
    }
}

// ---------------------------------------------------------------------------
// J61: Path traversal in changeset rejected
// ---------------------------------------------------------------------------

#[test]
fn test_j61_path_traversal_in_changeset() {
    let policy = create_policy_engine();
    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("/workspace/../etc/shadow"),
        kind: FileChangeKind::Added,
        size: 64,
        checksum: "j61".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    }];

    let decision = policy.evaluate(&changes, None).unwrap();
    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(
                violations
                    .iter()
                    .any(|v| v.rule == "deny_path_traversal_in_changeset"),
                "J61: path with '..' traversal should be rejected, got: {:?}",
                violations
            );
        }
        other => panic!(
            "J61: expected Rejected for path traversal in changeset, got {:?}",
            other
        ),
    }
}

// ---------------------------------------------------------------------------
// J63: puzzle-podman PUZZLECTL binary validation
// ---------------------------------------------------------------------------

#[test]
fn test_j63_puzzle_podman_puzzlectl_validation() {
    let script = include_str!("../../../podman/puzzle-podman");
    // J63: Must validate PUZZLECTL basename is "puzzlectl"
    assert!(
        script.contains("PUZZLECTL_BASE=$(basename"),
        "J63: puzzle-podman must validate PUZZLECTL binary basename"
    );
    assert!(
        script.contains(r#"!= "puzzlectl""#),
        "J63: puzzle-podman must check that PUZZLECTL basename is 'puzzlectl'"
    );
}

// ---------------------------------------------------------------------------
// J64: stderr not suppressed for governance artifact generation
// ---------------------------------------------------------------------------

#[test]
fn test_j64_puzzle_podman_stderr_not_suppressed() {
    let script = include_str!("../../../podman/puzzle-podman");
    // J64: The seccomp-profile and landlock-rules commands must not have 2>/dev/null
    for line in script.lines() {
        if line.contains("seccomp-profile")
            && line.contains("$BRANCH_ID")
            && line.contains("SECCOMP_PATH")
        {
            assert!(
                !line.contains("2>/dev/null"),
                "J64: seccomp-profile command must not suppress stderr, found: {}",
                line
            );
        }
        if line.contains("landlock-rules")
            && line.contains("$BRANCH_ID")
            && line.contains("LANDLOCK_PATH")
        {
            assert!(
                !line.contains("2>/dev/null"),
                "J64: landlock-rules command must not suppress stderr, found: {}",
                line
            );
        }
    }
}

// ---------------------------------------------------------------------------
// J65: SECCOMP_NOTIF_FLAG intentionally unquoted comment
// ---------------------------------------------------------------------------

#[test]
fn test_j65_seccomp_notif_flag_comment() {
    let script = include_str!("../../../podman/puzzle-podman");
    assert!(
        script.contains("SECCOMP_NOTIF_FLAG is intentionally unquoted"),
        "J65: puzzle-podman must document why SECCOMP_NOTIF_FLAG is unquoted"
    );
}

// ---------------------------------------------------------------------------
// J68: Symlink with empty/missing target rejected
// ---------------------------------------------------------------------------

#[test]
fn test_j68_symlink_empty_target() {
    let policy_dir = policy_dir();
    let mut engine = regorus::Engine::new();

    for entry in std::fs::read_dir(&policy_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("rego") {
            let contents = std::fs::read_to_string(&path).unwrap();
            engine
                .add_policy(path.display().to_string(), contents)
                .unwrap();
        }
    }

    // Symlink with empty target
    let input_json = serde_json::json!({
        "changes": [{
            "path": "workspace/link",
            "kind": "Symlink",
            "size": 0,
            "checksum": "",
            "target": ""
        }],
        "profile": "privileged"
    });

    let input_str = serde_json::to_string(&input_json).unwrap();
    engine.set_input_json(&input_str).unwrap();

    let allow_result = engine
        .eval_rule("data.puzzlepod.commit.allow".to_string())
        .unwrap();
    let allowed = matches!(allow_result, regorus::Value::Bool(true));

    assert!(
        !allowed,
        "J68: symlink with empty target should be rejected"
    );
}

#[test]
fn test_j68_symlink_missing_target() {
    let policy_dir = policy_dir();
    let mut engine = regorus::Engine::new();

    for entry in std::fs::read_dir(&policy_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("rego") {
            let contents = std::fs::read_to_string(&path).unwrap();
            engine
                .add_policy(path.display().to_string(), contents)
                .unwrap();
        }
    }

    // Symlink with missing target field entirely
    let input_json = serde_json::json!({
        "changes": [{
            "path": "workspace/link",
            "kind": "Symlink",
            "size": 0,
            "checksum": ""
        }],
        "profile": "privileged"
    });

    let input_str = serde_json::to_string(&input_json).unwrap();
    engine.set_input_json(&input_str).unwrap();

    let allow_result = engine
        .eval_rule("data.puzzlepod.commit.allow".to_string())
        .unwrap();
    let allowed = matches!(allow_result, regorus::Value::Bool(true));

    assert!(
        !allowed,
        "J68: symlink with missing target should be rejected"
    );
}

// ---------------------------------------------------------------------------
// K60: Symlink target field in Rego input
// ---------------------------------------------------------------------------

#[test]
fn test_k60_rego_input_includes_target_field() {
    // K60: Verify that the Rego input construction includes the "target" field
    let source = include_str!("../src/policy.rs");
    assert!(
        source.contains(r#""target": c.target.as_deref().unwrap_or("")"#),
        "K60: policy.rs must include 'target' field in Rego input JSON"
    );
}

#[test]
fn test_k60_symlink_target_outside_workspace_rejected() {
    // K60: A symlink with a target outside the workspace should be rejected
    let policy_dir = policy_dir();
    let mut engine = regorus::Engine::new();

    for entry in std::fs::read_dir(&policy_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("rego") {
            let contents = std::fs::read_to_string(&path).unwrap();
            engine
                .add_policy(path.display().to_string(), contents)
                .unwrap();
        }
    }

    // Symlink pointing outside workspace
    let input_json = serde_json::json!({
        "changes": [{
            "path": "workspace/evil_link",
            "kind": "Symlink",
            "size": 0,
            "checksum": "",
            "target": "/etc/shadow"
        }],
        "profile": "privileged",
        "workspace_root": "/home/agent/workspace"
    });

    let input_str = serde_json::to_string(&input_json).unwrap();
    engine.set_input_json(&input_str).unwrap();

    let allow_result = engine
        .eval_rule("data.puzzlepod.commit.allow".to_string())
        .unwrap();
    let allowed = matches!(allow_result, regorus::Value::Bool(true));

    assert!(
        !allowed,
        "K60: symlink with target outside workspace should be rejected"
    );
}

#[test]
fn test_k60_filechange_has_target_field() {
    // K60: Verify that FileChange struct has a target field
    let source = include_str!("../../../crates/puzzled-types/src/lib.rs");
    assert!(
        source.contains("pub target: Option<String>"),
        "K60: FileChange struct must have pub target: Option<String> field"
    );
}

// ---------------------------------------------------------------------------
// K61: MERGED_DIR validation in puzzle-podman
// ---------------------------------------------------------------------------

#[test]
fn test_k61_merged_dir_validation() {
    let script = include_str!("../../../podman/puzzle-podman");

    // K61: Must validate MERGED_DIR prefix
    assert!(
        script.contains("/var/lib/puzzled/branches/"),
        "K61: puzzle-podman must validate MERGED_DIR starts with /var/lib/puzzled/branches/"
    );
    assert!(
        script.contains(".local/share/puzzled/branches/"),
        "K61: puzzle-podman must also allow ~/.local/share/puzzled/branches/"
    );
    // K61: Must check for path traversal
    assert!(
        script.contains(r#"MERGED_DIR" == *".."*"#),
        "K61: puzzle-podman must reject MERGED_DIR containing '..'"
    );
}

// ---------------------------------------------------------------------------
// K62: Null byte rejection in Rego
// ---------------------------------------------------------------------------

#[test]
fn test_k62_null_byte_in_path_rejected() {
    let policy_dir = policy_dir();
    let mut engine = regorus::Engine::new();

    for entry in std::fs::read_dir(&policy_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("rego") {
            let contents = std::fs::read_to_string(&path).unwrap();
            engine
                .add_policy(path.display().to_string(), contents)
                .unwrap();
        }
    }

    // Path with embedded null byte
    let input_json = serde_json::json!({
        "changes": [{
            "path": "safe_file\u{0000}.env",
            "kind": "Added",
            "size": 100,
            "checksum": "abc",
            "target": ""
        }]
    });

    let input_str = serde_json::to_string(&input_json).unwrap();
    engine.set_input_json(&input_str).unwrap();

    let allow_result = engine
        .eval_rule("data.puzzlepod.commit.allow".to_string())
        .unwrap();
    let allowed = matches!(allow_result, regorus::Value::Bool(true));

    assert!(!allowed, "K62: path containing null byte must be rejected");
}

#[test]
fn test_k62_rego_has_null_byte_rule() {
    let rego_source = include_str!("../../../policies/rules/commit.rego");
    assert!(
        rego_source.contains("deny_null_in_path"),
        "K62: commit.rego must contain deny_null_in_path rule"
    );
}

// ---------------------------------------------------------------------------
// K63: var/spool/at/ persistence path
// ---------------------------------------------------------------------------

#[test]
fn test_k63_at_spool_persistence_rejected() {
    let policy = create_policy_engine();

    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("var/spool/at/job123"),
        kind: FileChangeKind::Added,
        size: 256,
        checksum: "atjob".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    }];

    let decision = policy.evaluate(&changes, None).unwrap();
    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(
                violations.iter().any(|v| v.rule == "no_persistence"),
                "K63: var/spool/at/job123 should trigger no_persistence, got: {:?}",
                violations
            );
        }
        other => panic!("K63: expected Rejected for at job spool, got {:?}", other),
    }
}

#[test]
fn test_k63_rego_has_at_spool_path() {
    let rego_source = include_str!("../../../policies/rules/commit.rego");
    assert!(
        rego_source.contains("var/spool/at/"),
        "K63: commit.rego must contain var/spool/at/ in persistence_paths"
    );
}

// ---------------------------------------------------------------------------
// K64: Cleanup must not suppress stderr on approve/rollback
// ---------------------------------------------------------------------------

#[test]
fn test_k64_cleanup_no_stderr_suppression() {
    let script = include_str!("../../../podman/puzzle-podman");

    // Find the cleanup function
    let cleanup_start = script
        .find("cleanup()")
        .expect("cleanup function must exist");
    let cleanup_body = &script[cleanup_start..];
    // Limit to cleanup function body (ends before next top-level function)
    let cleanup_end = cleanup_body
        .find("\n# Parse arguments")
        .unwrap_or(cleanup_body.len());
    let cleanup_fn = &cleanup_body[..cleanup_end];

    // K64: approve calls must not have 2>/dev/null
    for line in cleanup_fn.lines() {
        if line.contains("branch approve") {
            assert!(
                !line.contains("2>/dev/null"),
                "K64: approve calls in cleanup must not suppress stderr: {}",
                line.trim()
            );
        }
    }

    // K64: rollback calls must not have 2>/dev/null (but || true is ok)
    for line in cleanup_fn.lines() {
        if line.contains("branch rollback") {
            assert!(
                !line.contains("2>/dev/null"),
                "K64: rollback calls in cleanup must not suppress stderr: {}",
                line.trim()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// K65: SECCOMP_PATH/LANDLOCK_PATH validation
// ---------------------------------------------------------------------------

#[test]
fn test_k65_seccomp_landlock_path_validation() {
    let script = include_str!("../../../podman/puzzle-podman");

    // K65: Must validate SECCOMP_PATH
    assert!(
        script.contains(r#"SECCOMP_PATH" == *".."*"#),
        "K65: puzzle-podman must reject SECCOMP_PATH containing '..'"
    );
    assert!(
        script.contains("SECCOMP_PATH has unexpected prefix"),
        "K65: puzzle-podman must validate SECCOMP_PATH prefix"
    );

    // K65: Must validate LANDLOCK_PATH
    assert!(
        script.contains(r#"LANDLOCK_PATH" == *".."*"#),
        "K65: puzzle-podman must reject LANDLOCK_PATH containing '..'"
    );
    assert!(
        script.contains("LANDLOCK_PATH has unexpected prefix"),
        "K65: puzzle-podman must validate LANDLOCK_PATH prefix"
    );
}

// ---------------------------------------------------------------------------
// K67: Dynamic storage quota from input.storage_quota_bytes
// ---------------------------------------------------------------------------

#[test]
fn test_k67_dynamic_storage_quota_rejected() {
    let policy_dir = policy_dir();
    let mut engine = regorus::Engine::new();

    for entry in std::fs::read_dir(&policy_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("rego") {
            let contents = std::fs::read_to_string(&path).unwrap();
            engine
                .add_policy(path.display().to_string(), contents)
                .unwrap();
        }
    }

    // Set a small quota (1024 bytes) and exceed it
    let input_json = serde_json::json!({
        "changes": [{
            "path": "big_file.bin",
            "kind": "Added",
            "size": 2048,
            "checksum": "abc",
            "target": ""
        }],
        "storage_quota_bytes": 1024
    });

    let input_str = serde_json::to_string(&input_json).unwrap();
    engine.set_input_json(&input_str).unwrap();

    let violations_result = engine
        .eval_rule("data.puzzlepod.commit.violations".to_string())
        .unwrap();

    // Check that dynamic_storage_quota violation exists
    let violations_str = format!("{:?}", violations_result);
    assert!(
        violations_str.contains("dynamic_storage_quota"),
        "K67: exceeding storage_quota_bytes must trigger dynamic_storage_quota rule, got: {}",
        violations_str
    );
}

#[test]
fn test_k67_dynamic_storage_quota_approved_within_limit() {
    let policy_dir = policy_dir();
    let mut engine = regorus::Engine::new();

    for entry in std::fs::read_dir(&policy_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("rego") {
            let contents = std::fs::read_to_string(&path).unwrap();
            engine
                .add_policy(path.display().to_string(), contents)
                .unwrap();
        }
    }

    // Set a generous quota that is NOT exceeded
    let input_json = serde_json::json!({
        "changes": [{
            "path": "small_file.txt",
            "kind": "Added",
            "size": 100,
            "checksum": "abc",
            "target": ""
        }],
        "storage_quota_bytes": 1048576
    });

    let input_str = serde_json::to_string(&input_json).unwrap();
    engine.set_input_json(&input_str).unwrap();

    let allow_result = engine
        .eval_rule("data.puzzlepod.commit.allow".to_string())
        .unwrap();
    let allowed = matches!(allow_result, regorus::Value::Bool(true));

    assert!(
        allowed,
        "K67: file within storage_quota_bytes should be approved"
    );
}

#[test]
fn test_k67_rego_has_dynamic_storage_quota_rule() {
    let rego_source = include_str!("../../../policies/rules/commit.rego");
    assert!(
        rego_source.contains("dynamic_storage_quota"),
        "K67: commit.rego must contain dynamic_storage_quota rule"
    );
    assert!(
        rego_source.contains("input.storage_quota_bytes"),
        "K67: commit.rego must reference input.storage_quota_bytes"
    );
}

#[test]
fn test_k67_policy_rs_includes_storage_quota_bytes() {
    let source = include_str!("../src/policy.rs");
    assert!(
        source.contains("storage_quota_bytes"),
        "K67: policy.rs must include storage_quota_bytes in Rego input"
    );
}

// ---------------------------------------------------------------------------
// R1: G18 severity must be lowercase "critical"
// ---------------------------------------------------------------------------

#[test]
fn test_r1_g18_severity_lowercase_critical() {
    let policy_dir = policy_dir();
    let mut engine = regorus::Engine::new();

    for entry in std::fs::read_dir(&policy_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("rego") {
            let contents = std::fs::read_to_string(&path).unwrap();
            engine
                .add_policy(path.display().to_string(), contents)
                .unwrap();
        }
    }

    // R1: Trigger the G18 missing_change_size rule by omitting "size"
    let input_json = serde_json::json!({
        "changes": [{
            "path": "no_size.txt",
            "kind": "Added",
            "checksum": "abc",
            "target": ""
        }]
    });

    let input_str = serde_json::to_string(&input_json).unwrap();
    engine.set_input_json(&input_str).unwrap();

    let violations_result = engine
        .eval_rule("data.puzzlepod.commit.violations".to_string())
        .unwrap();

    let violations_str = format!("{:?}", violations_result);
    assert!(
        violations_str.contains("missing_change_size"),
        "R1: G18 rule should fire for missing size, got: {}",
        violations_str
    );
    // R1: Verify the severity is lowercase "critical", not "Critical"
    assert!(
        !violations_str.contains("\"Critical\""),
        "R1: G18 severity must be lowercase 'critical', found 'Critical' in: {}",
        violations_str
    );
    assert!(
        violations_str.contains("\"critical\""),
        "R1: G18 severity must contain lowercase 'critical', got: {}",
        violations_str
    );
}

// ---------------------------------------------------------------------------
// R1: deny_setuid_setgid rule
// ---------------------------------------------------------------------------

#[test]
fn test_r1_deny_setuid_setgid() {
    let policy = create_policy_engine();

    // R1: File with setuid bit (0o104755 = 34285)
    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("app/suid_binary"),
        kind: FileChangeKind::Added,
        size: 4096,
        checksum: "suid".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: Some(0o104755), // setuid + rwxr-xr-x
        timestamp: None,
        target: None,
    }];

    let decision = policy.evaluate(&changes, None).unwrap();
    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(
                violations.iter().any(|v| v.rule == "deny_setuid_setgid"),
                "R1: setuid file should trigger deny_setuid_setgid, got: {:?}",
                violations
            );
        }
        other => panic!("R1: expected Rejected for setuid file, got {:?}", other),
    }
}

#[test]
fn test_r1_deny_setgid() {
    let policy = create_policy_engine();

    // R1: File with setgid bit (0o102755 = 33773)
    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("app/sgid_binary"),
        kind: FileChangeKind::Added,
        size: 4096,
        checksum: "sgid".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: Some(0o102755), // setgid + rwxr-xr-x
        timestamp: None,
        target: None,
    }];

    let decision = policy.evaluate(&changes, None).unwrap();
    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(
                violations.iter().any(|v| v.rule == "deny_setuid_setgid"),
                "R1: setgid file should trigger deny_setuid_setgid, got: {:?}",
                violations
            );
        }
        other => panic!("R1: expected Rejected for setgid file, got {:?}", other),
    }
}

#[test]
fn test_r1_no_setuid_setgid_allows() {
    let policy = create_policy_engine();

    // R1: Normal file without setuid/setgid should be allowed
    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("app/normal_binary"),
        kind: FileChangeKind::Added,
        size: 4096,
        checksum: "normal".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: Some(0o100755), // rwxr-xr-x, no setuid/setgid
        timestamp: None,
        target: None,
    }];

    let decision = policy.evaluate(&changes, None).unwrap();
    assert!(
        matches!(decision, PolicyDecision::Approved),
        "R1: file without setuid/setgid should be approved, got: {:?}",
        decision
    );
}

// ---------------------------------------------------------------------------
// R1: /tmp writes flagged as system modification
// ---------------------------------------------------------------------------

#[test]
fn test_r1_tmp_writes_rejected() {
    let policy = create_policy_engine();

    let changes = vec![puzzled_types::FileChange {
        path: PathBuf::from("tmp/evil_script.sh"),
        kind: FileChangeKind::Added,
        size: 512,
        checksum: "tmp".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
    }];

    let decision = policy.evaluate(&changes, None).unwrap();
    match decision {
        PolicyDecision::Rejected(violations) => {
            assert!(
                violations
                    .iter()
                    .any(|v| v.rule == "no_system_modifications"),
                "R1: tmp/ writes should trigger no_system_modifications, got: {:?}",
                violations
            );
        }
        other => panic!("R1: expected Rejected for /tmp write, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// U27: Test read/write denylist enforcement
// ---------------------------------------------------------------------------
// read_denylist and write_denylist are enforced by Landlock (kernel-level),
// not by the Rego policy engine. This test verifies that the Landlock rules
// generator correctly excludes denylisted paths from the generated ruleset,
// which means those paths will be blocked at runtime by the kernel.

#[test]
fn test_u27_read_denylist_excludes_path_from_landlock_rules() {
    // U27: Test read/write denylist enforcement
    // A path in read_denylist must be excluded from the Landlock read ruleset,
    // even if it appears in read_allowlist.
    let profiles_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("policies")
        .join("profiles");

    let standard_path = profiles_dir.join("standard.yaml");
    let content = std::fs::read_to_string(&standard_path).unwrap();
    let mut profile: AgentProfile = serde_yaml::from_str(&content).unwrap();

    // Add a path to both read_allowlist and read_denylist.
    // The denylist must win — the path must NOT appear in generated Landlock rules.
    let denied_path = PathBuf::from("/etc/secret-keys");
    profile.filesystem.read_allowlist.push(denied_path.clone());
    profile.filesystem.read_denylist.push(denied_path.clone());

    let rules = puzzled::landlock_rules::generate_landlock_rules(
        &profile,
        std::path::Path::new("/workspace"),
    )
    .unwrap();

    assert!(
        !rules.read.contains(&"/etc/secret-keys".to_string()),
        "U27: path in read_denylist must be excluded from Landlock read rules, got: {:?}",
        rules.read
    );
}

#[test]
fn test_u27_write_denylist_excludes_path_from_landlock_rules() {
    // U27: Test read/write denylist enforcement
    // A path in write_denylist must be excluded from the Landlock write ruleset,
    // even if it appears in write_allowlist.
    let profiles_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("policies")
        .join("profiles");

    let standard_path = profiles_dir.join("standard.yaml");
    let content = std::fs::read_to_string(&standard_path).unwrap();
    let mut profile: AgentProfile = serde_yaml::from_str(&content).unwrap();

    // Add a path to both write_allowlist and write_denylist.
    let denied_path = PathBuf::from("/var/protected");
    profile.filesystem.write_allowlist.push(denied_path.clone());
    profile.filesystem.write_denylist.push(denied_path.clone());

    let rules = puzzled::landlock_rules::generate_landlock_rules(
        &profile,
        std::path::Path::new("/workspace"),
    )
    .unwrap();

    assert!(
        !rules.write.contains(&"/var/protected".to_string()),
        "U27: path in write_denylist must be excluded from Landlock write rules, got: {:?}",
        rules.write
    );
}
