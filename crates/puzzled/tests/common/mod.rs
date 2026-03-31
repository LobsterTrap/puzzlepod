// SPDX-License-Identifier: Apache-2.0
// Shared helpers for puzzled integration tests.
//
// This module is included by integration tests via `mod common;`
// It provides common setup functions to eliminate duplication across
// test files that need a configured BranchManager.
//
// Not every test file uses every function, so suppress dead_code warnings.
#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Return the project root directory (workspace root containing `crates/`, `policies/`, etc.).
pub fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Return the path to the `policies/profiles` directory.
pub fn profiles_dir() -> PathBuf {
    project_root().join("policies").join("profiles")
}

/// Return the path to the `policies/rules` directory.
pub fn policies_dir() -> PathBuf {
    project_root().join("policies").join("rules")
}

/// Build a BranchManager wired to the real policy engine and profiles.
///
/// This is the standard test manager used across most integration tests.
/// It creates the branch_root, loads profiles and policies from the project's
/// `policies/` directory, initializes WAL, and wires up all components
/// (AuditLogger, ConflictDetector, BudgetManager, SeccompNotifHandler).
///
/// # Arguments
/// * `dir` — A temp directory path. The branch_root will be `dir/branches`.
pub fn make_manager(dir: &std::path::Path) -> puzzled::branch::BranchManager {
    let branch_root = dir.join("branches");
    let profiles_dir = profiles_dir();
    let policies_dir = policies_dir();

    fs::create_dir_all(&branch_root).unwrap();

    let config = puzzled::config::DaemonConfig {
        branch_root: branch_root.clone(),
        profiles_dir: profiles_dir.clone(),
        policies_dir: policies_dir.clone(),
        max_branches: 64,
        bus_type: puzzled::config::BusType::Session,
        fs_type: puzzled::config::FsType::Ext4,
        log_level: puzzled::config::LogLevel::Debug,
        watchdog_timeout_secs: 30,
        ..Default::default()
    };

    let mut profile_loader = puzzled::profile::ProfileLoader::new(profiles_dir);
    profile_loader.load_all().unwrap();

    let policy_engine = puzzled::policy::PolicyEngine::new(policies_dir);
    policy_engine.reload().unwrap();

    let wal_dir = branch_root.join("wal");
    puzzled::wal::WriteAheadLog::init(&wal_dir).unwrap();
    let wal = puzzled::wal::WriteAheadLog::new(wal_dir);

    let audit = puzzled::audit::AuditLogger::new();
    let conflict_detector = Arc::new(Mutex::new(puzzled::conflict::ConflictDetector::new()));
    let budget_manager = Arc::new(Mutex::new(puzzled::budget::BudgetManager::new()));
    let seccomp_handler = puzzled::seccomp_handler::SeccompNotifHandler::spawn();

    puzzled::branch::BranchManager::new(
        config,
        profile_loader,
        policy_engine,
        wal,
        Arc::new(audit),
        None,
        conflict_detector,
        budget_manager,
        Some(seccomp_handler),
        None,
    )
}

/// Build a BranchManager with a custom policy directory.
///
/// Like [`make_manager`], but uses a caller-specified policy directory instead
/// of the project's default `policies/rules/`. Useful for tests that need
/// custom or empty policy sets while still using the standard profiles.
///
/// # Arguments
/// * `dir` — A temp directory path. The branch_root will be `dir/branches`.
/// * `policy_dir` — Path to the directory containing Rego policy files.
pub fn make_manager_with_policies(
    dir: &std::path::Path,
    policy_dir: &std::path::Path,
) -> puzzled::branch::BranchManager {
    let branch_root = dir.join("branches");
    let profiles_dir = profiles_dir();

    fs::create_dir_all(&branch_root).unwrap();

    let config = puzzled::config::DaemonConfig {
        branch_root: branch_root.clone(),
        profiles_dir: profiles_dir.clone(),
        policies_dir: policy_dir.to_path_buf(),
        max_branches: 64,
        bus_type: puzzled::config::BusType::Session,
        fs_type: puzzled::config::FsType::Ext4,
        log_level: puzzled::config::LogLevel::Debug,
        watchdog_timeout_secs: 30,
        ..Default::default()
    };

    let mut profile_loader = puzzled::profile::ProfileLoader::new(profiles_dir);
    profile_loader.load_all().unwrap();

    let policy_engine = puzzled::policy::PolicyEngine::new(policy_dir.to_path_buf());
    policy_engine.reload().unwrap();

    let wal_dir = branch_root.join("wal");
    puzzled::wal::WriteAheadLog::init(&wal_dir).unwrap();
    let wal = puzzled::wal::WriteAheadLog::new(wal_dir);

    let audit = puzzled::audit::AuditLogger::new();
    let conflict_detector = Arc::new(Mutex::new(puzzled::conflict::ConflictDetector::new()));
    let budget_manager = Arc::new(Mutex::new(puzzled::budget::BudgetManager::new()));

    let seccomp_handler = puzzled::seccomp_handler::SeccompNotifHandler::spawn();
    puzzled::branch::BranchManager::new(
        config,
        profile_loader,
        policy_engine,
        wal,
        Arc::new(audit),
        None,
        conflict_detector,
        budget_manager,
        Some(seccomp_handler),
        None,
    )
}
