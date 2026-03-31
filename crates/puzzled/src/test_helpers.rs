// SPDX-License-Identifier: Apache-2.0
//! Test helpers for puzzled unit tests.
//!
//! Provides factory functions for creating test fixtures (profiles, branches,
//! temp directories) used across multiple test modules.

use puzzled_types::{
    AgentProfile, BehavioralConfig, EnforcementRequirements, FailMode, FilesystemRules,
    NetworkConfig, NetworkMode, ResourceLimits, SeccompMode,
};
use std::path::PathBuf;

/// Create a minimal restricted profile for testing.
pub fn create_test_profile(name: &str) -> AgentProfile {
    AgentProfile {
        name: name.to_string(),
        description: format!("Test profile: {}", name),
        filesystem: FilesystemRules {
            read_allowlist: vec![PathBuf::from("/usr"), PathBuf::from("/tmp")],
            write_allowlist: vec![PathBuf::from("/tmp")],
            denylist: vec![PathBuf::from("/etc/shadow"), PathBuf::from("/root")],
            read_denylist: vec![],
            write_denylist: vec![],
        },
        exec_allowlist: vec![
            "/usr/bin/python3".to_string(),
            "/usr/bin/cat".to_string(),
            "/usr/local/bin/*".to_string(),
        ],
        exec_denylist: vec!["/usr/bin/rm".to_string()],
        resource_limits: ResourceLimits {
            memory_bytes: 512 * 1024 * 1024,
            cpu_shares: 100,
            max_pids: 64,
            storage_quota_mb: 1024,
            inode_quota: 10000,
            io_weight: 100,
            ..Default::default()
        },
        network: NetworkConfig {
            mode: NetworkMode::Gated,
            allowed_domains: vec!["example.com".to_string(), "*.github.com".to_string()],
            data_residency: None,
            dlp_rules_path: None,
        },
        behavioral: BehavioralConfig::default(),
        fail_mode: FailMode::FailClosed,
        capabilities: vec![],
        enforcement: EnforcementRequirements::default(),
        seccomp_mode: SeccompMode::default(),
        allow_symlinks: false,
        allow_exec_overlay: false,
        credentials: None,
        extends: None,
    }
}

/// Create a profile with no exec allowlist (blocks all execs).
pub fn create_restricted_profile() -> AgentProfile {
    AgentProfile {
        name: "test-restricted".to_string(),
        description: "Restricted test profile".to_string(),
        filesystem: FilesystemRules {
            read_allowlist: vec![],
            write_allowlist: vec![],
            denylist: vec![],
            read_denylist: vec![],
            write_denylist: vec![],
        },
        exec_allowlist: vec![],
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
        enforcement: EnforcementRequirements::default(),
        seccomp_mode: SeccompMode::default(),
        allow_symlinks: false,
        allow_exec_overlay: false,
        credentials: None,
        extends: None,
    }
}

/// Create a privileged profile for testing.
pub fn create_privileged_profile() -> AgentProfile {
    AgentProfile {
        name: "test-privileged".to_string(),
        description: "Privileged test profile".to_string(),
        filesystem: FilesystemRules {
            read_allowlist: vec![PathBuf::from("/")],
            write_allowlist: vec![PathBuf::from("/tmp"), PathBuf::from("/workspace")],
            denylist: vec![],
            read_denylist: vec![],
            write_denylist: vec![],
        },
        exec_allowlist: vec!["/usr/bin/*".to_string(), "/usr/local/bin/*".to_string()],
        exec_denylist: vec![],
        resource_limits: ResourceLimits {
            memory_bytes: 4096 * 1024 * 1024,
            cpu_shares: 400,
            max_pids: 256,
            storage_quota_mb: 10240,
            inode_quota: 100000,
            io_weight: 100,
            ..Default::default()
        },
        network: NetworkConfig {
            mode: NetworkMode::Monitored,
            allowed_domains: vec!["*".to_string()],
            data_residency: None,
            dlp_rules_path: None,
        },
        behavioral: BehavioralConfig::default(),
        fail_mode: FailMode::FailClosed,
        capabilities: vec![],
        enforcement: EnforcementRequirements::default(),
        seccomp_mode: SeccompMode::default(),
        allow_symlinks: true,
        allow_exec_overlay: true,
        credentials: None,
        extends: None,
    }
}

/// Create a BranchManager for testing, with temp subdirectories for profiles,
/// policies, WAL, and branches.
pub fn create_test_branch_manager(
    dir: &std::path::Path,
    max_branches: u32,
) -> crate::branch::BranchManager {
    let profiles_dir = dir.join("profiles");
    let policies_dir = dir.join("policies");
    let wal_dir = dir.join("wal");
    let branch_root = dir.join("branches");

    std::fs::create_dir_all(&profiles_dir).unwrap();
    std::fs::create_dir_all(&policies_dir).unwrap();
    std::fs::create_dir_all(&wal_dir).unwrap();
    std::fs::create_dir_all(&branch_root).unwrap();

    let config = crate::config::DaemonConfig {
        branch_root,
        profiles_dir: profiles_dir.clone(),
        policies_dir: policies_dir.clone(),
        max_branches,
        ..Default::default()
    };

    let profile_loader = crate::profile::ProfileLoader::new(profiles_dir);
    let policy_engine = crate::policy::PolicyEngine::new(policies_dir);
    let wal = crate::wal::WriteAheadLog::new(wal_dir);
    let audit = std::sync::Arc::new(crate::audit::AuditLogger::new());
    let conflict_detector = std::sync::Arc::new(std::sync::Mutex::new(
        crate::conflict::ConflictDetector::new(),
    ));
    let budget_manager =
        std::sync::Arc::new(std::sync::Mutex::new(crate::budget::BudgetManager::new()));

    crate::branch::BranchManager::new(
        config,
        profile_loader,
        policy_engine,
        wal,
        audit,
        None,
        conflict_detector,
        budget_manager,
        None,
        None,
    )
}

// M4: Removed dead code `create_temp_branch_dir()` — was never called from any test.

#[cfg(test)]
mod tests {
    /// M4: Verify dead code `create_temp_branch_dir` has been removed.
    #[test]
    fn test_m4_no_dead_code_create_temp_branch_dir() {
        let source = include_str!("test_helpers.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            !prod_source.contains("fn create_temp_branch_dir"),
            "M4: create_temp_branch_dir() is dead code and should be removed"
        );
    }
}
