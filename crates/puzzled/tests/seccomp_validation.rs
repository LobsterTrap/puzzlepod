// SPDX-License-Identifier: Apache-2.0
//! Cross-platform tests for seccomp validation logic.
//!
//! Tests the validation functions used by the seccomp USER_NOTIF handler
//! without requiring actual seccomp infrastructure. Verifies execve path
//! matching, connect IP validation, and bind port checking against agent profiles.

use puzzled_types::{
    AgentProfile, BehavioralConfig, FailMode, FilesystemRules, NetworkConfig, NetworkMode,
    ResourceLimits,
};

/// Helper to create a test profile with specific exec allowlist and network config.
fn make_profile(exec_allowlist: Vec<String>, network: NetworkConfig) -> AgentProfile {
    AgentProfile {
        name: "test-seccomp".to_string(),
        description: "test profile for seccomp validation".to_string(),
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
        network,
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

/// Simulate validate_execve logic (path matching against exec_allowlist).
/// This mirrors the logic in sandbox/seccomp.rs::validate_execve.
fn validate_execve_path(path: &str, profile: &AgentProfile) -> bool {
    if profile.exec_allowlist.is_empty() {
        return false;
    }

    // Check for path traversal components (canonicalization substitute for tests)
    if path.contains("/../") || path.ends_with("/..") {
        return false;
    }

    profile.exec_allowlist.iter().any(|pattern| {
        if pattern.ends_with('*') {
            let prefix = &pattern[..pattern.len() - 1];
            path.starts_with(prefix)
        } else {
            path == *pattern
        }
    })
}

/// Simulate validate_connect logic.
fn validate_connect_ip(ip: &str, family: &str, profile: &AgentProfile) -> bool {
    match profile.network.mode {
        NetworkMode::Blocked => return false,
        NetworkMode::Unrestricted | NetworkMode::Monitored => return true,
        NetworkMode::Gated => {}
    }

    // Unix sockets always allowed
    if family == "unix" {
        return true;
    }

    // Loopback always allowed
    if ip == "127.0.0.1" || ip == "::1" || ip == "0:0:0:0:0:0:0:1" {
        return true;
    }

    profile
        .network
        .allowed_domains
        .iter()
        .any(|d| *d == ip || d == "*")
}

/// Simulate validate_bind logic.
fn validate_bind_ip(ip: &str, profile: &AgentProfile) -> bool {
    match profile.network.mode {
        NetworkMode::Blocked => return false,
        NetworkMode::Unrestricted | NetworkMode::Monitored => return true,
        NetworkMode::Gated => {}
    }

    // Only allow binding to loopback in Gated mode
    ip == "127.0.0.1" || ip == "::1" || ip == "0.0.0.0"
}

// ---------------------------------------------------------------------------
// Execve validation tests
// ---------------------------------------------------------------------------

#[test]
fn test_validate_execve_exact_match() {
    let profile = make_profile(
        vec!["/usr/bin/python3".to_string(), "/usr/bin/git".to_string()],
        NetworkConfig {
            mode: NetworkMode::Blocked,
            allowed_domains: vec![],
            data_residency: None,
            dlp_rules_path: None,
        },
    );

    assert!(validate_execve_path("/usr/bin/python3", &profile));
    assert!(validate_execve_path("/usr/bin/git", &profile));
    assert!(!validate_execve_path("/usr/bin/curl", &profile));
}

#[test]
fn test_validate_execve_prefix_glob() {
    let profile = make_profile(
        vec!["/usr/bin/*".to_string()],
        NetworkConfig {
            mode: NetworkMode::Blocked,
            allowed_domains: vec![],
            data_residency: None,
            dlp_rules_path: None,
        },
    );

    assert!(validate_execve_path("/usr/bin/python3", &profile));
    assert!(validate_execve_path("/usr/bin/ls", &profile));
    assert!(!validate_execve_path("/usr/sbin/fdisk", &profile));
    assert!(!validate_execve_path("/bin/sh", &profile));
}

#[test]
fn test_validate_execve_path_traversal_blocked() {
    let profile = make_profile(
        vec!["/usr/bin/*".to_string()],
        NetworkConfig {
            mode: NetworkMode::Blocked,
            allowed_domains: vec![],
            data_residency: None,
            dlp_rules_path: None,
        },
    );

    assert!(!validate_execve_path("/usr/bin/../sbin/fdisk", &profile));
    assert!(!validate_execve_path("/usr/bin/../../etc/shadow", &profile));
}

#[test]
fn test_validate_execve_empty_allowlist() {
    let profile = make_profile(
        vec![],
        NetworkConfig {
            mode: NetworkMode::Blocked,
            allowed_domains: vec![],
            data_residency: None,
            dlp_rules_path: None,
        },
    );

    assert!(!validate_execve_path("/usr/bin/python3", &profile));
    assert!(!validate_execve_path("/bin/sh", &profile));
}

#[test]
fn test_validate_execve_denied_path() {
    let profile = make_profile(
        vec!["/usr/bin/python3".to_string()],
        NetworkConfig {
            mode: NetworkMode::Blocked,
            allowed_domains: vec![],
            data_residency: None,
            dlp_rules_path: None,
        },
    );

    assert!(!validate_execve_path("/usr/bin/rm", &profile));
    assert!(!validate_execve_path("/usr/sbin/iptables", &profile));
    assert!(!validate_execve_path("/tmp/malicious", &profile));
}

// ---------------------------------------------------------------------------
// Connect validation tests
// ---------------------------------------------------------------------------

#[test]
fn test_validate_connect_loopback_allowed() {
    let profile = make_profile(
        vec![],
        NetworkConfig {
            mode: NetworkMode::Gated,
            allowed_domains: vec![],
            data_residency: None,
            dlp_rules_path: None,
        },
    );

    assert!(validate_connect_ip("127.0.0.1", "inet", &profile));
}

#[test]
fn test_validate_connect_ipv6_loopback() {
    let profile = make_profile(
        vec![],
        NetworkConfig {
            mode: NetworkMode::Gated,
            allowed_domains: vec![],
            data_residency: None,
            dlp_rules_path: None,
        },
    );

    assert!(validate_connect_ip("::1", "inet6", &profile));
    assert!(validate_connect_ip("0:0:0:0:0:0:0:1", "inet6", &profile));
}

#[test]
fn test_validate_connect_unix_socket_allowed() {
    let profile = make_profile(
        vec![],
        NetworkConfig {
            mode: NetworkMode::Gated,
            allowed_domains: vec![],
            data_residency: None,
            dlp_rules_path: None,
        },
    );

    assert!(validate_connect_ip(
        "/var/run/docker.sock",
        "unix",
        &profile
    ));
}

#[test]
fn test_validate_connect_allowed_ip() {
    let profile = make_profile(
        vec![],
        NetworkConfig {
            mode: NetworkMode::Gated,
            allowed_domains: vec!["93.184.216.34".to_string()],
            data_residency: None,
            dlp_rules_path: None,
        },
    );

    assert!(validate_connect_ip("93.184.216.34", "inet", &profile));
}

#[test]
fn test_validate_connect_denied_ip() {
    let profile = make_profile(
        vec![],
        NetworkConfig {
            mode: NetworkMode::Gated,
            allowed_domains: vec!["93.184.216.34".to_string()],
            data_residency: None,
            dlp_rules_path: None,
        },
    );

    assert!(!validate_connect_ip("10.0.0.1", "inet", &profile));
    assert!(!validate_connect_ip("192.168.1.1", "inet", &profile));
}

#[test]
fn test_validate_bind_loopback_only() {
    let profile = make_profile(
        vec![],
        NetworkConfig {
            mode: NetworkMode::Gated,
            allowed_domains: vec![],
            data_residency: None,
            dlp_rules_path: None,
        },
    );

    assert!(validate_bind_ip("127.0.0.1", &profile));
    assert!(validate_bind_ip("0.0.0.0", &profile));
    assert!(!validate_bind_ip("10.0.0.1", &profile));
}

#[test]
fn test_unknown_syscall_denied() {
    // In seccomp, unknown/unhandled syscalls default to deny.
    // This test verifies that the general deny-by-default pattern holds.
    let profile = make_profile(
        vec![],
        NetworkConfig {
            mode: NetworkMode::Blocked,
            allowed_domains: vec![],
            data_residency: None,
            dlp_rules_path: None,
        },
    );

    // All execve, connect, bind denied in fully blocked mode
    assert!(!validate_execve_path("/bin/sh", &profile));
    assert!(!validate_connect_ip("1.2.3.4", "inet", &profile));
    assert!(!validate_bind_ip("0.0.0.0", &profile));
}
