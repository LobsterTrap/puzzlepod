// SPDX-License-Identifier: Apache-2.0
//! Integration test: Profile loading and validation.
//!
//! Tests parsing all bundled profiles and validates that invalid profiles
//! are properly rejected.

use std::fs;
use std::path::PathBuf;

use puzzled_types::{AgentProfile, FailMode, NetworkMode, SeccompMode};

fn profiles_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("policies")
        .join("profiles")
}

#[test]
fn test_load_restricted_profile() {
    let path = profiles_dir().join("restricted.yaml");
    let content = fs::read_to_string(&path).unwrap();
    let profile: AgentProfile = serde_yaml::from_str(&content).unwrap();

    assert_eq!(profile.name, "restricted");
    assert_eq!(profile.network.mode, NetworkMode::Blocked);
    assert!(profile.resource_limits.memory_bytes <= 512 * 1024 * 1024);
    assert!(profile.resource_limits.max_pids <= 32);
    assert!(!profile.exec_allowlist.is_empty());
    assert!(profile.filesystem.write_allowlist.is_empty());
}

#[test]
fn test_load_standard_profile() {
    let path = profiles_dir().join("standard.yaml");
    let content = fs::read_to_string(&path).unwrap();
    let profile: AgentProfile = serde_yaml::from_str(&content).unwrap();

    assert_eq!(profile.name, "standard");
    assert_eq!(profile.network.mode, NetworkMode::Gated);
    assert!(!profile.network.allowed_domains.is_empty());
    assert!(!profile.exec_allowlist.is_empty());
    assert!(profile.resource_limits.max_pids > 16);
}

#[test]
fn test_load_privileged_profile() {
    let path = profiles_dir().join("privileged.yaml");
    let content = fs::read_to_string(&path).unwrap();
    let profile: AgentProfile = serde_yaml::from_str(&content).unwrap();

    assert_eq!(profile.name, "privileged");
    // N19: Privileged profile uses Gated mode for proxy logging/credential injection
    assert_eq!(profile.network.mode, NetworkMode::Gated);
    assert!(profile.resource_limits.memory_bytes >= 512 * 1024 * 1024);
}

#[test]
fn test_all_profiles_have_required_fields() {
    let dir = profiles_dir();
    for entry in fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }

        let content = fs::read_to_string(&path).unwrap();
        let profile: AgentProfile = serde_yaml::from_str(&content)
            .unwrap_or_else(|e| panic!("failed to parse {}: {}", path.display(), e));

        // Every profile must have a name
        assert!(
            !profile.name.is_empty(),
            "profile {} has empty name",
            path.display()
        );

        // Resource limits must be non-zero
        assert!(
            profile.resource_limits.memory_bytes > 0,
            "profile {} has zero memory",
            path.display()
        );
        assert!(
            profile.resource_limits.max_pids > 0,
            "profile {} has zero max_pids",
            path.display()
        );

        // Exec allowlist should not be empty (agent needs to run something)
        assert!(
            !profile.exec_allowlist.is_empty(),
            "profile {} has empty exec_allowlist",
            path.display()
        );
    }
}

/// S14: All profiles must have explicit seccomp_mode — implicit defaults
/// could silently use a weaker posture than intended.
#[test]
fn test_all_profiles_have_explicit_seccomp_mode() {
    let dir = profiles_dir();
    for entry in fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }

        let content = fs::read_to_string(&path).unwrap();
        // Check that the YAML source explicitly declares seccomp_mode
        // (not just relying on serde default)
        assert!(
            content.contains("seccomp_mode"),
            "S14: profile {} must have explicit seccomp_mode field \
             (implicit Permissive default is a security clarity risk)",
            path.display()
        );
    }
}

#[test]
fn test_invalid_profile_yaml() {
    let content = "this: is: not: valid: yaml: [[[";
    let result = serde_yaml::from_str::<AgentProfile>(content);
    assert!(result.is_err());
}

#[test]
fn test_profile_missing_required_field() {
    // Profile without 'name' field
    let content = r#"
description: "incomplete profile"
filesystem:
  read_allowlist: []
  write_allowlist: []
  denylist: []
exec_allowlist: []
resource_limits:
  memory_bytes: 1024
  cpu_shares: 100
  io_weight: 100
  max_pids: 16
  storage_quota_mb: 256
  inode_quota: 1000
network:
  mode: Blocked
  allowed_domains: []
behavioral:
  max_deletions: 10
  max_reads_per_minute: 100
  credential_access_alert: true
"#;

    let result = serde_yaml::from_str::<AgentProfile>(content);
    // Missing 'name' field should cause deserialization error
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// T20: Cross-profile hierarchy validation
// ---------------------------------------------------------------------------

#[test]
fn t20_cross_profile_hierarchy_restricted_le_standard_le_privileged() {
    let restricted_path = profiles_dir().join("restricted.yaml");
    let standard_path = profiles_dir().join("standard.yaml");
    let privileged_path = profiles_dir().join("privileged.yaml");

    let restricted: AgentProfile =
        serde_yaml::from_str(&fs::read_to_string(&restricted_path).unwrap()).unwrap();
    let standard: AgentProfile =
        serde_yaml::from_str(&fs::read_to_string(&standard_path).unwrap()).unwrap();
    let privileged: AgentProfile =
        serde_yaml::from_str(&fs::read_to_string(&privileged_path).unwrap()).unwrap();

    // Memory: restricted <= standard <= privileged
    assert!(
        restricted.resource_limits.memory_bytes <= standard.resource_limits.memory_bytes,
        "restricted memory ({}) must be <= standard memory ({})",
        restricted.resource_limits.memory_bytes,
        standard.resource_limits.memory_bytes
    );
    assert!(
        standard.resource_limits.memory_bytes <= privileged.resource_limits.memory_bytes,
        "standard memory ({}) must be <= privileged memory ({})",
        standard.resource_limits.memory_bytes,
        privileged.resource_limits.memory_bytes
    );

    // max_pids: restricted <= standard <= privileged
    assert!(
        restricted.resource_limits.max_pids <= standard.resource_limits.max_pids,
        "restricted max_pids ({}) must be <= standard max_pids ({})",
        restricted.resource_limits.max_pids,
        standard.resource_limits.max_pids
    );
    assert!(
        standard.resource_limits.max_pids <= privileged.resource_limits.max_pids,
        "standard max_pids ({}) must be <= privileged max_pids ({})",
        standard.resource_limits.max_pids,
        privileged.resource_limits.max_pids
    );

    // cpu_shares: restricted <= standard <= privileged
    assert!(
        restricted.resource_limits.cpu_shares <= standard.resource_limits.cpu_shares,
        "restricted cpu_shares ({}) must be <= standard cpu_shares ({})",
        restricted.resource_limits.cpu_shares,
        standard.resource_limits.cpu_shares
    );
    assert!(
        standard.resource_limits.cpu_shares <= privileged.resource_limits.cpu_shares,
        "standard cpu_shares ({}) must be <= privileged cpu_shares ({})",
        standard.resource_limits.cpu_shares,
        privileged.resource_limits.cpu_shares
    );

    // io_weight: restricted <= standard <= privileged
    assert!(
        restricted.resource_limits.io_weight <= standard.resource_limits.io_weight,
        "restricted io_weight ({}) must be <= standard io_weight ({})",
        restricted.resource_limits.io_weight,
        standard.resource_limits.io_weight
    );
    assert!(
        standard.resource_limits.io_weight <= privileged.resource_limits.io_weight,
        "standard io_weight ({}) must be <= privileged io_weight ({})",
        standard.resource_limits.io_weight,
        privileged.resource_limits.io_weight
    );

    // storage_quota_mb: restricted <= standard <= privileged
    assert!(
        restricted.resource_limits.storage_quota_mb <= standard.resource_limits.storage_quota_mb,
        "restricted storage_quota_mb ({}) must be <= standard storage_quota_mb ({})",
        restricted.resource_limits.storage_quota_mb,
        standard.resource_limits.storage_quota_mb
    );
    assert!(
        standard.resource_limits.storage_quota_mb <= privileged.resource_limits.storage_quota_mb,
        "standard storage_quota_mb ({}) must be <= privileged storage_quota_mb ({})",
        standard.resource_limits.storage_quota_mb,
        privileged.resource_limits.storage_quota_mb
    );

    // inode_quota: restricted <= standard <= privileged
    assert!(
        restricted.resource_limits.inode_quota <= standard.resource_limits.inode_quota,
        "restricted inode_quota ({}) must be <= standard inode_quota ({})",
        restricted.resource_limits.inode_quota,
        standard.resource_limits.inode_quota
    );
    assert!(
        standard.resource_limits.inode_quota <= privileged.resource_limits.inode_quota,
        "standard inode_quota ({}) must be <= privileged inode_quota ({})",
        standard.resource_limits.inode_quota,
        privileged.resource_limits.inode_quota
    );

    // behavioral.max_deletions: restricted <= standard <= privileged
    assert!(
        restricted.behavioral.max_deletions <= standard.behavioral.max_deletions,
        "restricted max_deletions ({}) must be <= standard max_deletions ({})",
        restricted.behavioral.max_deletions,
        standard.behavioral.max_deletions
    );
    assert!(
        standard.behavioral.max_deletions <= privileged.behavioral.max_deletions,
        "standard max_deletions ({}) must be <= privileged max_deletions ({})",
        standard.behavioral.max_deletions,
        privileged.behavioral.max_deletions
    );

    // behavioral.max_reads_per_minute: restricted <= standard <= privileged
    assert!(
        restricted.behavioral.max_reads_per_minute <= standard.behavioral.max_reads_per_minute,
        "restricted max_reads_per_minute ({}) must be <= standard ({})",
        restricted.behavioral.max_reads_per_minute,
        standard.behavioral.max_reads_per_minute
    );
    assert!(
        standard.behavioral.max_reads_per_minute <= privileged.behavioral.max_reads_per_minute,
        "standard max_reads_per_minute ({}) must be <= privileged ({})",
        standard.behavioral.max_reads_per_minute,
        privileged.behavioral.max_reads_per_minute
    );
}

#[test]
fn test_profile_serialization_roundtrip() {
    let profile = AgentProfile {
        name: "test".to_string(),
        description: "test profile".to_string(),
        filesystem: puzzled_types::FilesystemRules {
            read_allowlist: vec![PathBuf::from("/usr/share")],
            write_allowlist: vec![],
            denylist: vec![PathBuf::from("/etc/shadow")],
            read_denylist: vec![],
            write_denylist: vec![],
        },
        exec_allowlist: vec!["python3".to_string()],
        exec_denylist: vec![],
        resource_limits: puzzled_types::ResourceLimits::default(),
        network: puzzled_types::NetworkConfig {
            mode: NetworkMode::Blocked,
            allowed_domains: vec![],
            data_residency: None,
            dlp_rules_path: None,
        },
        behavioral: puzzled_types::BehavioralConfig::default(),
        fail_mode: puzzled_types::FailMode::default(),
        capabilities: vec![],
        enforcement: Default::default(),
        seccomp_mode: Default::default(),
        allow_symlinks: false,
        allow_exec_overlay: false,
        credentials: None,
    };

    let yaml = serde_yaml::to_string(&profile).unwrap();
    let deserialized: AgentProfile = serde_yaml::from_str(&yaml).unwrap();

    assert_eq!(deserialized.name, profile.name);
    assert_eq!(deserialized.network.mode, profile.network.mode);
    assert_eq!(
        deserialized.resource_limits.memory_bytes,
        profile.resource_limits.memory_bytes
    );
}

// ---------------------------------------------------------------------------
// T12: Profile deserialization with all struct fields
// ---------------------------------------------------------------------------

/// Test that a profile with ALL fields (including optional serde(default) fields)
/// deserializes correctly — exec_denylist, read_denylist, write_denylist,
/// capabilities, fail_mode, and all ResourceLimits optional fields.
#[test]
fn test_profile_deserialization_all_fields() {
    let yaml = r#"
name: "full-featured"
description: "A profile exercising every field in AgentProfile"
filesystem:
  read_allowlist:
    - /usr/share
    - /usr/lib
    - /opt/agent
  write_allowlist:
    - /workspace
    - /tmp/agent
  denylist:
    - /etc/shadow
    - /etc/gshadow
  read_denylist:
    - /proc/kcore
    - /proc/kallsyms
    - /sys/firmware
  write_denylist:
    - /boot
    - /usr/bin
    - /sbin
exec_allowlist:
  - /usr/bin/python3
  - /usr/bin/node
  - /usr/bin/git
exec_denylist:
  - /usr/bin/curl
  - /usr/bin/wget
  - /usr/bin/nc
  - /usr/bin/ncat
resource_limits:
  memory_bytes: 1073741824
  cpu_shares: 200
  io_weight: 150
  max_pids: 128
  storage_quota_mb: 2048
  inode_quota: 50000
  max_threads: 256
  no_new_privileges: true
  max_files_read: 10000
  max_files_written: 5000
  max_single_file_size_mb: 100
  cpu_quota_us: 50000
network:
  mode: Gated
  allowed_domains:
    - api.github.com
    - pypi.org
    - registry.npmjs.org
behavioral:
  max_deletions: 100
  max_reads_per_minute: 5000
  credential_access_alert: true
fail_mode: FailOperational
capabilities:
  - CAP_NET_BIND_SERVICE
  - CAP_DAC_READ_SEARCH
"#;

    let profile: AgentProfile = serde_yaml::from_str(yaml).unwrap();

    // Core fields
    assert_eq!(profile.name, "full-featured");
    assert_eq!(
        profile.description,
        "A profile exercising every field in AgentProfile"
    );

    // Filesystem rules
    assert_eq!(profile.filesystem.read_allowlist.len(), 3);
    assert_eq!(profile.filesystem.write_allowlist.len(), 2);
    assert_eq!(profile.filesystem.denylist.len(), 2);
    assert_eq!(profile.filesystem.denylist[0], PathBuf::from("/etc/shadow"));

    // read_denylist and write_denylist (serde(default) fields)
    assert_eq!(profile.filesystem.read_denylist.len(), 3);
    assert_eq!(
        profile.filesystem.read_denylist[0],
        PathBuf::from("/proc/kcore")
    );
    assert_eq!(
        profile.filesystem.read_denylist[1],
        PathBuf::from("/proc/kallsyms")
    );
    assert_eq!(
        profile.filesystem.read_denylist[2],
        PathBuf::from("/sys/firmware")
    );

    assert_eq!(profile.filesystem.write_denylist.len(), 3);
    assert_eq!(profile.filesystem.write_denylist[0], PathBuf::from("/boot"));
    assert_eq!(
        profile.filesystem.write_denylist[1],
        PathBuf::from("/usr/bin")
    );

    // exec_allowlist
    assert_eq!(profile.exec_allowlist.len(), 3);
    assert!(profile
        .exec_allowlist
        .contains(&"/usr/bin/python3".to_string()));

    // exec_denylist (serde(default) field)
    assert_eq!(profile.exec_denylist.len(), 4);
    assert!(profile.exec_denylist.contains(&"/usr/bin/curl".to_string()));
    assert!(profile.exec_denylist.contains(&"/usr/bin/wget".to_string()));
    assert!(profile.exec_denylist.contains(&"/usr/bin/nc".to_string()));
    assert!(profile.exec_denylist.contains(&"/usr/bin/ncat".to_string()));

    // Resource limits (required fields)
    assert_eq!(profile.resource_limits.memory_bytes, 1_073_741_824);
    assert_eq!(profile.resource_limits.cpu_shares, 200);
    assert_eq!(profile.resource_limits.io_weight, 150);
    assert_eq!(profile.resource_limits.max_pids, 128);
    assert_eq!(profile.resource_limits.storage_quota_mb, 2048);
    assert_eq!(profile.resource_limits.inode_quota, 50_000);

    // Resource limits (optional serde(default) fields)
    assert_eq!(profile.resource_limits.max_threads, Some(256));
    assert_eq!(profile.resource_limits.no_new_privileges, Some(true));
    assert_eq!(profile.resource_limits.max_files_read, Some(10_000));
    assert_eq!(profile.resource_limits.max_files_written, Some(5_000));
    assert_eq!(profile.resource_limits.max_single_file_size_mb, Some(100));
    assert_eq!(profile.resource_limits.cpu_quota_us, Some(50_000));

    // Network
    assert_eq!(profile.network.mode, NetworkMode::Gated);
    assert_eq!(profile.network.allowed_domains.len(), 3);
    assert!(profile
        .network
        .allowed_domains
        .contains(&"api.github.com".to_string()));

    // Behavioral config
    assert_eq!(profile.behavioral.max_deletions, 100);
    assert_eq!(profile.behavioral.max_reads_per_minute, 5_000);
    assert!(profile.behavioral.credential_access_alert);

    // Fail mode (serde(default) field)
    assert_eq!(profile.fail_mode, puzzled_types::FailMode::FailOperational);

    // Capabilities (serde(default) field)
    assert_eq!(profile.capabilities.len(), 2);
    assert!(profile
        .capabilities
        .contains(&"CAP_NET_BIND_SERVICE".to_string()));
    assert!(profile
        .capabilities
        .contains(&"CAP_DAC_READ_SEARCH".to_string()));
}

/// Test that a profile WITHOUT optional fields uses correct defaults.
#[test]
fn test_profile_deserialization_optional_fields_default() {
    let yaml = r#"
name: "minimal-with-defaults"
description: "Profile that omits all serde(default) fields"
filesystem:
  read_allowlist:
    - /usr/share
  write_allowlist: []
  denylist: []
exec_allowlist:
  - /usr/bin/ls
resource_limits:
  memory_bytes: 268435456
  cpu_shares: 50
  io_weight: 50
  max_pids: 16
  storage_quota_mb: 256
  inode_quota: 1000
network:
  mode: Blocked
  allowed_domains: []
behavioral:
  max_deletions: 10
  max_reads_per_minute: 100
  credential_access_alert: false
"#;

    let profile: AgentProfile = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(profile.name, "minimal-with-defaults");

    // Optional filesystem fields should default to empty vecs
    assert!(
        profile.filesystem.read_denylist.is_empty(),
        "read_denylist should default to empty"
    );
    assert!(
        profile.filesystem.write_denylist.is_empty(),
        "write_denylist should default to empty"
    );

    // exec_denylist should default to empty
    assert!(
        profile.exec_denylist.is_empty(),
        "exec_denylist should default to empty"
    );

    // Optional resource limits should default to None
    assert_eq!(profile.resource_limits.max_threads, None);
    assert_eq!(profile.resource_limits.no_new_privileges, None);
    assert_eq!(profile.resource_limits.max_files_read, None);
    assert_eq!(profile.resource_limits.max_files_written, None);
    assert_eq!(profile.resource_limits.max_single_file_size_mb, None);
    assert_eq!(profile.resource_limits.cpu_quota_us, None);

    // fail_mode should default to FailClosed
    assert_eq!(
        profile.fail_mode,
        puzzled_types::FailMode::FailClosed,
        "fail_mode should default to FailClosed"
    );

    // capabilities should default to empty
    assert!(
        profile.capabilities.is_empty(),
        "capabilities should default to empty"
    );
}

/// Test all four fail modes deserialize correctly.
#[test]
fn test_profile_all_fail_modes() {
    let fail_modes = vec![
        ("FailClosed", puzzled_types::FailMode::FailClosed),
        ("FailSilent", puzzled_types::FailMode::FailSilent),
        ("FailOperational", puzzled_types::FailMode::FailOperational),
        ("FailSafeState", puzzled_types::FailMode::FailSafeState),
    ];

    for (yaml_value, expected) in fail_modes {
        let yaml = format!(
            r#"
name: "fail-mode-test"
description: "test"
filesystem:
  read_allowlist: []
  write_allowlist: []
  denylist: []
exec_allowlist:
  - /bin/true
resource_limits:
  memory_bytes: 268435456
  cpu_shares: 50
  io_weight: 50
  max_pids: 16
  storage_quota_mb: 256
  inode_quota: 1000
network:
  mode: Blocked
  allowed_domains: []
behavioral:
  max_deletions: 10
  max_reads_per_minute: 100
  credential_access_alert: false
fail_mode: {}
"#,
            yaml_value
        );

        let profile: AgentProfile = serde_yaml::from_str(&yaml)
            .unwrap_or_else(|e| panic!("failed to parse fail_mode={}: {}", yaml_value, e));
        assert_eq!(
            profile.fail_mode, expected,
            "fail_mode '{}' should deserialize to {:?}",
            yaml_value, expected
        );
    }
}

/// Test serialization roundtrip preserves all fields including optionals.
#[test]
fn test_profile_full_roundtrip_all_fields() {
    let profile = AgentProfile {
        name: "roundtrip-all".to_string(),
        description: "tests all fields survive serialization roundtrip".to_string(),
        filesystem: puzzled_types::FilesystemRules {
            read_allowlist: vec![PathBuf::from("/usr/share"), PathBuf::from("/opt")],
            write_allowlist: vec![PathBuf::from("/workspace")],
            denylist: vec![PathBuf::from("/etc/shadow")],
            read_denylist: vec![PathBuf::from("/proc/kcore")],
            write_denylist: vec![PathBuf::from("/boot")],
        },
        exec_allowlist: vec!["python3".to_string(), "node".to_string()],
        exec_denylist: vec!["curl".to_string(), "wget".to_string()],
        resource_limits: puzzled_types::ResourceLimits {
            memory_bytes: 2_147_483_648,
            cpu_shares: 300,
            io_weight: 200,
            max_pids: 256,
            storage_quota_mb: 4096,
            inode_quota: 100_000,
            max_threads: Some(512),
            no_new_privileges: Some(true),
            max_files_read: Some(50_000),
            max_files_written: Some(25_000),
            max_single_file_size_mb: Some(200),
            cpu_quota_us: Some(75_000),
            memory_high: None,
            io_max: None,
            max_exec_calls: None,
            max_open_fds: None,
            max_files_deleted: None,
            max_total_write_mb: None,
            lifetime_minutes: None,
        },
        network: puzzled_types::NetworkConfig {
            mode: NetworkMode::Gated,
            allowed_domains: vec!["example.com".to_string()],
            data_residency: None,
            dlp_rules_path: None,
        },
        behavioral: puzzled_types::BehavioralConfig {
            max_deletions: 200,
            max_reads_per_minute: 10_000,
            credential_access_alert: true,
            phantom_token_prefixes: Vec::new(),
        },
        fail_mode: puzzled_types::FailMode::FailSafeState,
        capabilities: vec![
            "CAP_NET_BIND_SERVICE".to_string(),
            "CAP_DAC_OVERRIDE".to_string(),
        ],
        enforcement: Default::default(),
        seccomp_mode: Default::default(),
        allow_symlinks: false,
        allow_exec_overlay: false,
        credentials: None,
    };

    let yaml = serde_yaml::to_string(&profile).unwrap();
    let deserialized: AgentProfile = serde_yaml::from_str(&yaml).unwrap();

    // Verify all fields survived the roundtrip
    assert_eq!(deserialized.name, profile.name);
    assert_eq!(deserialized.description, profile.description);
    assert_eq!(
        deserialized.filesystem.read_allowlist,
        profile.filesystem.read_allowlist
    );
    assert_eq!(
        deserialized.filesystem.write_allowlist,
        profile.filesystem.write_allowlist
    );
    assert_eq!(
        deserialized.filesystem.denylist,
        profile.filesystem.denylist
    );
    assert_eq!(
        deserialized.filesystem.read_denylist,
        profile.filesystem.read_denylist
    );
    assert_eq!(
        deserialized.filesystem.write_denylist,
        profile.filesystem.write_denylist
    );
    assert_eq!(deserialized.exec_allowlist, profile.exec_allowlist);
    assert_eq!(deserialized.exec_denylist, profile.exec_denylist);
    assert_eq!(
        deserialized.resource_limits.memory_bytes,
        profile.resource_limits.memory_bytes
    );
    assert_eq!(
        deserialized.resource_limits.cpu_shares,
        profile.resource_limits.cpu_shares
    );
    assert_eq!(
        deserialized.resource_limits.io_weight,
        profile.resource_limits.io_weight
    );
    assert_eq!(
        deserialized.resource_limits.max_pids,
        profile.resource_limits.max_pids
    );
    assert_eq!(
        deserialized.resource_limits.storage_quota_mb,
        profile.resource_limits.storage_quota_mb
    );
    assert_eq!(
        deserialized.resource_limits.inode_quota,
        profile.resource_limits.inode_quota
    );
    assert_eq!(
        deserialized.resource_limits.max_threads,
        profile.resource_limits.max_threads
    );
    assert_eq!(
        deserialized.resource_limits.no_new_privileges,
        profile.resource_limits.no_new_privileges
    );
    assert_eq!(
        deserialized.resource_limits.max_files_read,
        profile.resource_limits.max_files_read
    );
    assert_eq!(
        deserialized.resource_limits.max_files_written,
        profile.resource_limits.max_files_written
    );
    assert_eq!(
        deserialized.resource_limits.max_single_file_size_mb,
        profile.resource_limits.max_single_file_size_mb
    );
    assert_eq!(
        deserialized.resource_limits.cpu_quota_us,
        profile.resource_limits.cpu_quota_us
    );
    assert_eq!(deserialized.network.mode, profile.network.mode);
    assert_eq!(
        deserialized.network.allowed_domains,
        profile.network.allowed_domains
    );
    assert_eq!(
        deserialized.behavioral.max_deletions,
        profile.behavioral.max_deletions
    );
    assert_eq!(
        deserialized.behavioral.max_reads_per_minute,
        profile.behavioral.max_reads_per_minute
    );
    assert_eq!(
        deserialized.behavioral.credential_access_alert,
        profile.behavioral.credential_access_alert
    );
    assert_eq!(deserialized.fail_mode, profile.fail_mode);
    assert_eq!(deserialized.capabilities, profile.capabilities);
}

// ---------------------------------------------------------------------------
// H87: Privileged profile must have read_denylist entries
// ---------------------------------------------------------------------------

#[test]
fn test_h87_privileged_profile_read_denylist() {
    let path = profiles_dir().join("privileged.yaml");
    let content = fs::read_to_string(&path).unwrap();
    let profile: AgentProfile = serde_yaml::from_str(&content).unwrap();

    let read_denylist_strs: Vec<String> = profile
        .filesystem
        .read_denylist
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    assert!(
        read_denylist_strs.iter().any(|p| p == "/etc/sudoers.d"),
        "H87: privileged profile must denylist /etc/sudoers.d in read_denylist"
    );
    assert!(
        read_denylist_strs.iter().any(|p| p == "/etc/pam.d"),
        "H87: privileged profile must denylist /etc/pam.d in read_denylist"
    );
    assert!(
        read_denylist_strs.iter().any(|p| p == "/etc/ssh"),
        "H87: privileged profile must denylist /etc/ssh in read_denylist"
    );
}

// ---------------------------------------------------------------------------
// H88: web-scraper must not allow overly broad TLD wildcards
// ---------------------------------------------------------------------------

#[test]
fn test_h88_web_scraper_no_broad_wildcards() {
    let path = profiles_dir().join("web-scraper.yaml");
    let content = fs::read_to_string(&path).unwrap();
    let profile: AgentProfile = serde_yaml::from_str(&content).unwrap();

    let broad_wildcards = ["*.org", "*.gov", "*.edu"];
    for wildcard in &broad_wildcards {
        assert!(
            !profile
                .network
                .allowed_domains
                .contains(&wildcard.to_string()),
            "H88: web-scraper must not allow overly broad wildcard '{}'",
            wildcard
        );
    }
}

// ---------------------------------------------------------------------------
// H89: ResourceLimits validate() catches zero memory_bytes and storage_quota_mb
// ---------------------------------------------------------------------------

#[test]
fn test_h89_resource_limits_validate_zero_memory() {
    let limits = puzzled_types::ResourceLimits {
        memory_bytes: 0,
        ..Default::default()
    };
    let errors = limits.validate();
    assert!(
        errors.iter().any(|e| e.contains("memory_bytes")),
        "H89: validate() must catch memory_bytes: 0, got errors: {:?}",
        errors
    );
}

#[test]
fn test_h89_resource_limits_validate_zero_storage_quota() {
    let limits = puzzled_types::ResourceLimits {
        storage_quota_mb: 0,
        ..Default::default()
    };
    let errors = limits.validate();
    assert!(
        errors.iter().any(|e| e.contains("storage_quota_mb")),
        "H89: validate() must catch storage_quota_mb: 0, got errors: {:?}",
        errors
    );
}

// ---------------------------------------------------------------------------
// H91: security-scanner missing denylist entries
// ---------------------------------------------------------------------------

#[test]
fn test_h91_security_scanner_denylist() {
    let path = profiles_dir().join("security-scanner.yaml");
    let content = fs::read_to_string(&path).unwrap();
    let profile: AgentProfile = serde_yaml::from_str(&content).unwrap();

    let denylist_strs: Vec<String> = profile
        .filesystem
        .denylist
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    assert!(
        denylist_strs
            .iter()
            .any(|p| p.contains("ssh_host") && p.contains("_key")),
        "H91: security-scanner must denylist SSH host keys"
    );
    assert!(
        denylist_strs.iter().any(|p| p == "/etc/sudoers"),
        "H91: security-scanner must denylist /etc/sudoers"
    );
    assert!(
        denylist_strs.iter().any(|p| p == "/etc/sudoers.d"),
        "H91: security-scanner must denylist /etc/sudoers.d"
    );
    assert!(
        denylist_strs.iter().any(|p| p == "/etc/pam.d"),
        "H91: security-scanner must denylist /etc/pam.d"
    );
}

// ---------------------------------------------------------------------------
// H95: container-builder must have exec_denylist
// ---------------------------------------------------------------------------

#[test]
fn test_h95_container_builder_exec_denylist() {
    let path = profiles_dir().join("container-builder.yaml");
    let content = fs::read_to_string(&path).unwrap();
    let profile: AgentProfile = serde_yaml::from_str(&content).unwrap();

    let dangerous = ["nsenter", "unshare", "chroot", "mount", "strace", "gdb"];
    for binary in &dangerous {
        assert!(
            profile.exec_denylist.contains(&binary.to_string()),
            "H95: container-builder exec_denylist must include '{}'",
            binary
        );
    }
}

// ---------------------------------------------------------------------------
// H96: ci-runner must not include docker in exec_allowlist
// ---------------------------------------------------------------------------

#[test]
fn test_h96_ci_runner_no_docker() {
    let path = profiles_dir().join("ci-runner.yaml");
    let content = fs::read_to_string(&path).unwrap();
    let profile: AgentProfile = serde_yaml::from_str(&content).unwrap();

    assert!(
        !profile.exec_allowlist.iter().any(|e| e.contains("docker")),
        "H96: ci-runner exec_allowlist must not include docker"
    );
}

// ---------------------------------------------------------------------------
// H97: ResourceLimits::validate() doc comment exists
// ---------------------------------------------------------------------------

#[test]
fn test_h97_validate_doc_comment() {
    let source = include_str!("../../../crates/puzzled-types/src/lib.rs");
    assert!(
        source.contains("Callers MUST call `validate()` after deserialization"),
        "H97: ResourceLimits::validate() must document that callers MUST call it after deserialization"
    );
}

// ---------------------------------------------------------------------------
// J84: Safety-critical profile validation
// ---------------------------------------------------------------------------

/// J84: The safety-critical profile must use Strict seccomp, FailSafeState fail mode,
/// max_pids <= 4, and Blocked network mode.
#[test]
fn j84_safety_critical_profile() {
    let path = profiles_dir().join("safety-critical.yaml");
    let content = fs::read_to_string(&path)
        .expect("J84: safety-critical.yaml must exist in policies/profiles/");
    let profile: AgentProfile = serde_yaml::from_str(&content)
        .expect("J84: safety-critical.yaml must parse as a valid AgentProfile");

    assert_eq!(
        profile.seccomp_mode,
        SeccompMode::Strict,
        "J84: safety-critical profile must use Strict seccomp mode"
    );
    assert_eq!(
        profile.fail_mode,
        FailMode::FailSafeState,
        "J84: safety-critical profile must use FailSafeState fail mode"
    );
    assert!(
        profile.resource_limits.max_pids <= 4,
        "J84: safety-critical profile max_pids ({}) must be <= 4",
        profile.resource_limits.max_pids
    );
    assert_eq!(
        profile.network.mode,
        NetworkMode::Blocked,
        "J84: safety-critical profile must have Blocked network mode"
    );
}

// ---------------------------------------------------------------------------
// J85: exec_denylist coverage for profiles with network access
// ---------------------------------------------------------------------------

/// J85: All profiles with Gated or Monitored network mode must have exec_denylist
/// entries covering dangerous namespace-escape binaries.
#[test]
fn j85_exec_denylist_coverage_for_networked_profiles() {
    let dir = profiles_dir();
    let required_denylisted = ["nsenter", "unshare", "chroot", "mount"];

    for entry in fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }

        let content = fs::read_to_string(&path).unwrap();
        let profile: AgentProfile = serde_yaml::from_str(&content)
            .unwrap_or_else(|e| panic!("failed to parse {}: {}", path.display(), e));

        if profile.network.mode == NetworkMode::Gated
            || profile.network.mode == NetworkMode::Monitored
        {
            for binary in &required_denylisted {
                // J85: Check if the binary name appears in exec_denylist
                // (either as bare name or full path like /usr/bin/nsenter)
                let has_entry = profile
                    .exec_denylist
                    .iter()
                    .any(|e| e == *binary || e.ends_with(&format!("/{}", binary)));
                assert!(
                    has_entry,
                    "J85: profile '{}' has {:?} network mode but exec_denylist \
                     does not contain '{}'. Profiles with network access must \
                     deny namespace-escape binaries. exec_denylist: {:?}",
                    profile.name, profile.network.mode, binary, profile.exec_denylist
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// J62: Privileged exec_denylist extended entries
// ---------------------------------------------------------------------------

#[test]
fn test_j62_privileged_extended_exec_denylist() {
    let path = profiles_dir().join("privileged.yaml");
    let content = fs::read_to_string(&path).unwrap();
    let profile: AgentProfile = serde_yaml::from_str(&content).unwrap();

    let extended = [
        "umount",
        "pivot_root",
        "ltrace",
        "capsh",
        "setcap",
        "modprobe",
        "insmod",
        "kexec",
        "bpftool",
        "dd",
        "losetup",
        "dmsetup",
        "ip",
        "iptables",
        "nft",
        "nc",
        "ncat",
        "socat",
    ];
    for binary in &extended {
        assert!(
            profile.exec_denylist.contains(&binary.to_string()),
            "J62: privileged exec_denylist must include '{}', got: {:?}",
            binary,
            profile.exec_denylist
        );
    }
}

// ---------------------------------------------------------------------------
// J66: infrastructure-auditor missing denylist entries
// ---------------------------------------------------------------------------

#[test]
fn test_j66_infrastructure_auditor_denylist() {
    let path = profiles_dir().join("infrastructure-auditor.yaml");
    let content = fs::read_to_string(&path).unwrap();
    let profile: AgentProfile = serde_yaml::from_str(&content).unwrap();

    let denylist_strs: Vec<String> = profile
        .filesystem
        .denylist
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    let required = [
        "/etc/ssh/ssh_host_*_key",
        "/etc/sudoers",
        "/etc/sudoers.d",
        "/etc/pam.d",
        "/etc/security",
        "/etc/krb5.keytab",
    ];
    for entry in &required {
        assert!(
            denylist_strs.iter().any(|p| p == *entry),
            "J66: infrastructure-auditor denylist must include '{}', got: {:?}",
            entry,
            denylist_strs
        );
    }
}

// ---------------------------------------------------------------------------
// J67: security-scanner missing keytab/opasswd
// ---------------------------------------------------------------------------

#[test]
fn test_j67_security_scanner_denylist() {
    let path = profiles_dir().join("security-scanner.yaml");
    let content = fs::read_to_string(&path).unwrap();
    let profile: AgentProfile = serde_yaml::from_str(&content).unwrap();

    let denylist_strs: Vec<String> = profile
        .filesystem
        .denylist
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    let required = [
        "/etc/krb5.keytab",
        "/etc/security/opasswd",
        "/etc/openldap/ldap.conf",
    ];
    for entry in &required {
        assert!(
            denylist_strs.iter().any(|p| p == *entry),
            "J67: security-scanner denylist must include '{}', got: {:?}",
            entry,
            denylist_strs
        );
    }
}

// ---------------------------------------------------------------------------
// J69: Upper bounds on memory_bytes/storage_quota_mb
// ---------------------------------------------------------------------------

#[test]
fn test_j69_excessive_memory_bytes() {
    let limits = puzzled_types::ResourceLimits {
        memory_bytes: puzzled_types::ResourceLimits::MAX_MEMORY_BYTES + 1,
        ..Default::default()
    };
    let errors = limits.validate();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("J69") && e.contains("memory_bytes")),
        "J69: validate() must catch memory_bytes exceeding 64 TiB, got: {:?}",
        errors
    );
}

#[test]
fn test_j69_excessive_storage_quota_mb() {
    let limits = puzzled_types::ResourceLimits {
        storage_quota_mb: puzzled_types::ResourceLimits::MAX_STORAGE_QUOTA_MB + 1,
        ..Default::default()
    };
    let errors = limits.validate();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("J69") && e.contains("storage_quota_mb")),
        "J69: validate() must catch storage_quota_mb exceeding 1 PiB, got: {:?}",
        errors
    );
}

// ---------------------------------------------------------------------------
// K66: Privileged profile must have write_denylist
// ---------------------------------------------------------------------------

#[test]
fn test_k66_privileged_profile_write_denylist() {
    let path = profiles_dir().join("privileged.yaml");
    let content = fs::read_to_string(&path).unwrap();
    let profile: AgentProfile = serde_yaml::from_str(&content).unwrap();

    assert!(
        !profile.filesystem.write_denylist.is_empty(),
        "K66: privileged profile must have non-empty write_denylist"
    );

    let write_denylist_strs: Vec<String> = profile
        .filesystem
        .write_denylist
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    let required = [
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/security",
        "/etc/pam.d",
        "/etc/ssh",
    ];
    for entry in &required {
        assert!(
            write_denylist_strs.iter().any(|p| p == *entry),
            "K66: privileged write_denylist must include '{}', got: {:?}",
            entry,
            write_denylist_strs
        );
    }
}

// ---------------------------------------------------------------------------
// J70: All profiles must have exec_denylist
// ---------------------------------------------------------------------------

#[test]
fn test_j70_all_profiles_have_exec_denylist() {
    let dir = profiles_dir();
    let standard_denylist = ["nsenter", "unshare", "chroot", "mount", "strace", "gdb"];

    for entry in fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }

        let content = fs::read_to_string(&path).unwrap();
        let profile: AgentProfile = serde_yaml::from_str(&content)
            .unwrap_or_else(|e| panic!("failed to parse {}: {}", path.display(), e));

        assert!(
            !profile.exec_denylist.is_empty(),
            "J70: profile {} must have non-empty exec_denylist",
            path.display()
        );

        for binary in &standard_denylist {
            assert!(
                profile.exec_denylist.contains(&binary.to_string()),
                "J70: profile {} exec_denylist must include '{}', got: {:?}",
                path.display(),
                binary,
                profile.exec_denylist
            );
        }
    }
}
