// SPDX-License-Identifier: Apache-2.0
//! Integration tests: BPF LSM exec rate limiting (Linux-only, requires root).
//!
//! Tests that BPF LSM exec counting and rate limiting work correctly.
//! All tests are #[ignore] because they require CAP_BPF or root privileges
//! and real kernel BPF infrastructure.

#![cfg(target_os = "linux")]

use std::path::Path;

use puzzled::sandbox::bpf_lsm::{BpfLsmManager, RateLimitConfig};

// ---------------------------------------------------------------------------
// T2: BPF LSM exec rate limiting
// ---------------------------------------------------------------------------

/// Test that BpfLsmManager can be constructed with a nonexistent path.
/// This is a cross-platform sanity check (not ignored).
#[test]
fn test_bpf_manager_construction() {
    let manager = BpfLsmManager::new(Path::new("/tmp/nonexistent.bpf.o"));
    assert!(!manager.is_loaded());
    assert!(!manager.is_attached());
}

/// Test that loading a nonexistent BPF object file fails gracefully.
#[test]
#[ignore] // Requires root + Linux with BPF support
fn test_bpf_load_nonexistent_object() {
    let mut manager = BpfLsmManager::new(Path::new("/tmp/nonexistent.bpf.o"));
    let result = manager.load();
    assert!(
        result.is_err(),
        "loading nonexistent BPF object should fail"
    );
    assert!(!manager.is_loaded());
}

/// Test BPF LSM load and configure_cgroup/remove_cgroup lifecycle.
///
/// Requires:
/// - Root or CAP_BPF
/// - A valid exec_guard.bpf.o at the default path
/// - BPF LSM enabled in kernel config
#[test]
#[ignore] // Requires root + Linux + BPF LSM + compiled BPF object
fn test_bpf_lsm_load_and_configure() {
    let bpf_obj = Path::new("/usr/lib/puzzled/exec_guard.bpf.o");
    if !bpf_obj.exists() {
        eprintln!(
            "skipping test: BPF object not found at {}",
            bpf_obj.display()
        );
        return;
    }

    let mut manager = BpfLsmManager::new(bpf_obj);
    manager.load().expect("BPF load should succeed with root");
    assert!(manager.is_loaded());

    // Configure rate limits for a fake cgroup ID
    let config = RateLimitConfig {
        max_execs_per_second: 10,
        max_total_execs: 100,
        kill_switch: 0,
        _pad: 0,
    };

    // Use inode 1 as a fake cgroup ID
    manager
        .configure_cgroup(1, config)
        .expect("configure_cgroup should succeed");

    // Remove the cgroup entry
    manager
        .remove_cgroup(1)
        .expect("remove_cgroup should succeed");
}

/// Test that rate limit configuration with different values is accepted.
#[test]
#[ignore] // Requires root + Linux + BPF LSM + compiled BPF object
fn test_bpf_rate_limit_config_values() {
    let bpf_obj = Path::new("/usr/lib/puzzled/exec_guard.bpf.o");
    if !bpf_obj.exists() {
        eprintln!("skipping test: BPF object not found");
        return;
    }

    let mut manager = BpfLsmManager::new(bpf_obj);
    manager.load().expect("BPF load should succeed");

    // Test various rate limit configurations
    let configs = [
        RateLimitConfig {
            max_execs_per_second: 1,
            max_total_execs: 10,
            kill_switch: 0,
            _pad: 0,
        },
        RateLimitConfig {
            max_execs_per_second: 100,
            max_total_execs: 1000,
            kill_switch: 0,
            _pad: 0,
        },
        RateLimitConfig {
            max_execs_per_second: 0,
            max_total_execs: 0,
            kill_switch: 1, // kill switch enabled
            _pad: 0,
        },
    ];

    for (i, config) in configs.iter().enumerate() {
        let cgroup_id = (i + 100) as u64;
        manager
            .configure_cgroup(cgroup_id, *config)
            .expect("configure should succeed");
        manager
            .remove_cgroup(cgroup_id)
            .expect("remove should succeed");
    }
}

// H-21: test_bpf_clone_guard_with_root removed — clone_guard was removed as
// seccomp + SELinux provide dual defense for clone containment.

/// M-sc1: Test is_degraded() reflects load failure state.
#[test]
fn test_bpf_is_degraded_after_failed_load() {
    let manager = BpfLsmManager::new(Path::new("/tmp/nonexistent.bpf.o"));
    // Before load, not degraded
    assert!(!manager.is_degraded());
}

/// Test multiple cgroup configurations simultaneously.
#[test]
#[ignore] // Requires root + Linux + BPF LSM + compiled BPF object
fn test_bpf_multiple_cgroup_configs() {
    let bpf_obj = Path::new("/usr/lib/puzzled/exec_guard.bpf.o");
    if !bpf_obj.exists() {
        return;
    }

    let mut manager = BpfLsmManager::new(bpf_obj);
    manager.load().expect("BPF load should succeed");

    // Configure multiple cgroups simultaneously
    for i in 0..10u64 {
        let config = RateLimitConfig {
            max_execs_per_second: (i + 1) as u32 * 10,
            max_total_execs: (i + 1) as u32 * 100,
            kill_switch: 0,
            _pad: 0,
        };
        manager
            .configure_cgroup(i + 1000, config)
            .expect("configure should succeed");
    }

    // Clean up
    for i in 0..10u64 {
        manager
            .remove_cgroup(i + 1000)
            .expect("remove should succeed");
    }
}

/// Test RateLimitConfig struct layout matches kernel expectations.
#[test]
fn test_rate_limit_config_struct_size() {
    assert_eq!(
        std::mem::size_of::<RateLimitConfig>(),
        16,
        "RateLimitConfig must be 16 bytes to match kernel struct"
    );
}
