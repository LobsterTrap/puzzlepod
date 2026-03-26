// SPDX-License-Identifier: Apache-2.0
//! Integration tests: Seccomp USER_NOTIF event loop (Linux-only, requires root).
//!
//! Tests that the seccomp notification handler correctly processes execve
//! notifications and applies profile-based policy decisions. All tests
//! are #[ignore] because they require root privileges and real seccomp
//! kernel infrastructure.

#![cfg(target_os = "linux")]

use puzzled_types::{
    AgentProfile, BehavioralConfig, BranchId, FailMode, FilesystemRules, NetworkConfig,
    NetworkMode, ResourceLimits,
};

use puzzled::seccomp_handler::SeccompNotifHandler;

/// Helper to create a test profile.
fn make_profile(exec_allowlist: Vec<String>) -> AgentProfile {
    AgentProfile {
        name: "seccomp-test".to_string(),
        description: "test profile for seccomp notification handler".to_string(),
        filesystem: FilesystemRules {
            read_allowlist: vec![],
            write_allowlist: vec![],
            denylist: vec![],
            read_denylist: vec![],
            write_denylist: vec![],
        },
        exec_allowlist,
        exec_denylist: vec![],
        resource_limits: ResourceLimits::default(),
        network: NetworkConfig {
            mode: NetworkMode::Blocked,
            allowed_domains: vec![],
            data_residency: None,
            dlp_rules_path: None,
        },
        behavioral: BehavioralConfig::default(),
        fail_mode: FailMode::FailClosed,
        capabilities: vec![],
        enforcement: Default::default(),
        seccomp_mode: Default::default(),
        allow_symlinks: false,
        allow_exec_overlay: false,
        credentials: None,
    }
}

// ---------------------------------------------------------------------------
// T4: Seccomp notification handler tests
// ---------------------------------------------------------------------------

/// Test that the handler can spawn and shut down cleanly.
#[tokio::test]
#[ignore] // Requires root + Linux with seccomp support
async fn test_handler_spawn_and_shutdown() {
    let handler = SeccompNotifHandler::spawn();
    // Give the handler time to start
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    handler.shutdown().await;
}

/// Test register/unregister cycle for seccomp notify fd.
#[tokio::test]
#[ignore] // Requires root + Linux with seccomp support
async fn test_handler_register_unregister() {
    let handler = SeccompNotifHandler::spawn();

    let profile = make_profile(vec!["/usr/bin/python3".to_string()]);
    let branch_id = BranchId::from("seccomp-reg-test".to_string());

    // Register with a fake fd (won't actually be polled in this test)
    handler
        .register(99, branch_id.clone(), profile, None)
        .expect("register should succeed");

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Unregister
    handler.unregister(branch_id);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    handler.shutdown().await;
}

/// Test async register for seccomp notify fd.
#[tokio::test]
#[ignore] // Requires root + Linux with seccomp support
async fn test_handler_register_async() {
    let handler = SeccompNotifHandler::spawn();

    let profile = make_profile(vec!["/usr/bin/ls".to_string(), "/bin/cat".to_string()]);
    let branch_id = BranchId::from("seccomp-async-reg".to_string());

    handler
        .register_async(99, branch_id.clone(), profile, None)
        .await
        .expect("async register should succeed");

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    handler.unregister(branch_id);
    handler.shutdown().await;
}

/// Test that multiple branches can be registered simultaneously.
#[tokio::test]
#[ignore] // Requires root + Linux with seccomp support
async fn test_handler_multiple_branches() {
    let handler = SeccompNotifHandler::spawn();

    let profile = make_profile(vec!["/usr/bin/python3".to_string()]);

    // Register multiple branches
    for i in 0..5 {
        let branch_id = BranchId::from(format!("seccomp-multi-{}", i));
        handler
            .register(100 + i, branch_id, profile.clone(), None)
            .expect("register should succeed");
    }

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Unregister all
    for i in 0..5 {
        let branch_id = BranchId::from(format!("seccomp-multi-{}", i));
        handler.unregister(branch_id);
    }

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    handler.shutdown().await;
}

/// Test that cloned handler can send commands.
#[tokio::test]
#[ignore] // Requires root + Linux with seccomp support
async fn test_handler_clone() {
    let handler = SeccompNotifHandler::spawn();
    let handler2 = handler.clone();

    let profile = make_profile(vec!["/usr/bin/python3".to_string()]);

    handler
        .register(
            200,
            BranchId::from("clone-a".to_string()),
            profile.clone(),
            None,
        )
        .expect("register via original should succeed");

    handler2
        .register(201, BranchId::from("clone-b".to_string()), profile, None)
        .expect("register via clone should succeed");

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    handler.shutdown().await;
}

/// Test unregister_by_fd (placeholder/no-op).
#[tokio::test]
#[ignore] // Requires root + Linux with seccomp support
async fn test_handler_unregister_by_fd() {
    let handler = SeccompNotifHandler::spawn();

    // unregister_by_fd is currently a no-op placeholder
    handler.unregister_by_fd(99);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    handler.shutdown().await;
}

/// Test that inject_fd_for_execve_with_path denies a path not in exec_allowlist.
/// This exercises the core DENY logic without requiring a real seccomp notif fd.
#[test]
fn test_unknown_exec_denied() {
    let profile = make_profile(vec!["/usr/bin/python3".to_string()]);

    let result =
        puzzled::seccomp_handler::inject_fd_for_execve_with_path(0, 0, 1, "/usr/bin/curl", &profile);

    assert!(
        result.is_err(),
        "should deny /usr/bin/curl when allowlist only contains python3"
    );
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("not in exec_allowlist"),
        "error should mention exec_allowlist, got: {err_msg}"
    );
}

/// F3: Test that inject_fd_for_execve_with_path denies when allowlist is empty.
#[test]
fn test_empty_allowlist_denied() {
    let profile = make_profile(vec![]); // empty allowlist

    let result =
        puzzled::seccomp_handler::inject_fd_for_execve_with_path(0, 0, 1, "/usr/bin/ls", &profile);

    assert!(
        result.is_err(),
        "should deny all execs with empty allowlist"
    );
}

/// F3: Test spawn, register a branch, and verify clean shutdown with active registrations.
#[tokio::test]
#[ignore] // Requires root + Linux with seccomp support
async fn test_handler_spawn_register_shutdown_roundtrip() {
    let handler = SeccompNotifHandler::spawn();

    let profile = make_profile(vec!["/usr/bin/python3".to_string()]);
    let branch_id = BranchId::from("roundtrip-test".to_string());

    // Register
    handler
        .register(99, branch_id.clone(), profile, None)
        .expect("register should succeed");

    // Allow the handler loop to process the registration
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Unregister
    handler.unregister(branch_id.clone());
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Re-register same branch (should not conflict)
    let profile2 = make_profile(vec!["/usr/bin/ls".to_string()]);
    handler
        .register(100, branch_id.clone(), profile2, None)
        .expect("re-register should succeed after unregister");

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Clean shutdown with active registration
    handler.shutdown().await;
}

/// Test OOM monitor registration (Linux-only).
#[tokio::test]
#[ignore] // Requires root + Linux with inotify
async fn test_handler_oom_monitor_registration() {
    let handler = SeccompNotifHandler::spawn();

    let branch_id = BranchId::from("oom-test".to_string());

    // Try to register OOM monitoring for a non-existent cgroup path.
    // The registration should be accepted (inotify watch may fail, but the
    // handler itself should not error).
    let result = handler.register_oom_monitor(
        branch_id,
        std::path::PathBuf::from("/sys/fs/cgroup/test/memory.events"),
    );

    // May succeed or fail depending on inotify availability; either is acceptable.
    let _ = result;

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    handler.shutdown().await;
}
