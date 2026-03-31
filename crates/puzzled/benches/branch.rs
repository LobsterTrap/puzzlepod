// SPDX-License-Identifier: Apache-2.0
use criterion::{criterion_group, criterion_main, Criterion};

/// Helper to create a BranchManager with temporary directories.
fn create_branch_manager(dir: &tempfile::TempDir) -> puzzled::branch::BranchManager {
    let profiles_dir = dir.path().join("profiles");
    let policies_dir = dir.path().join("policies");
    let wal_dir = dir.path().join("wal");
    let branch_root = dir.path().join("branches");
    std::fs::create_dir_all(&profiles_dir).unwrap();
    std::fs::create_dir_all(&policies_dir).unwrap();
    std::fs::create_dir_all(&wal_dir).unwrap();
    std::fs::create_dir_all(&branch_root).unwrap();

    let config = puzzled::config::DaemonConfig {
        branch_root,
        profiles_dir: profiles_dir.clone(),
        policies_dir: policies_dir.clone(),
        max_branches: 64,
        ..Default::default()
    };
    let profile_loader = puzzled::profile::ProfileLoader::new(profiles_dir);
    let policy_engine = puzzled::policy::PolicyEngine::new(policies_dir);
    let wal = puzzled::wal::WriteAheadLog::new(wal_dir);
    let audit = puzzled::audit::AuditLogger::new();
    let conflict_detector = std::sync::Arc::new(std::sync::Mutex::new(
        puzzled::conflict::ConflictDetector::new(),
    ));
    let budget_manager =
        std::sync::Arc::new(std::sync::Mutex::new(puzzled::budget::BudgetManager::new()));

    puzzled::branch::BranchManager::new(
        config,
        profile_loader,
        policy_engine,
        wal,
        std::sync::Arc::new(audit),
        None,
        conflict_detector,
        budget_manager,
        None,
        None,
    )
}

fn bench_branch_lifecycle(c: &mut Criterion) {
    // Benchmark creating a BranchManager and doing list/inspect operations
    // Use the non-Linux test helper pattern
    c.bench_function("branch_manager_new", |b| {
        b.iter(|| {
            let dir = tempfile::tempdir().unwrap();
            criterion::black_box(create_branch_manager(&dir));
        });
    });

    c.bench_function("branch_list_empty", |b| {
        let dir = tempfile::tempdir().unwrap();
        let manager = create_branch_manager(&dir);

        b.iter(|| {
            criterion::black_box(manager.list());
        });
    });
}

// ---------------------------------------------------------------------------
// T22: Branch creation benchmark
// ---------------------------------------------------------------------------

fn bench_branch_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("branch_creation");

    // Benchmark the directory structure setup that branch creation requires.
    // On non-Linux platforms this benchmarks the filesystem setup portion
    // (OverlayFS mount and namespace creation require Linux).
    group.bench_function("branch_dirs_setup", |b| {
        b.iter(|| {
            let dir = tempfile::tempdir().unwrap();
            let branch_id = format!("bench-{}", uuid::Uuid::new_v4());
            let branch_dir = dir.path().join("branches").join(&branch_id);
            let upper_dir = branch_dir.join("upper");
            let work_dir = branch_dir.join("work");
            let merged_dir = branch_dir.join("merged");

            std::fs::create_dir_all(&upper_dir).unwrap();
            std::fs::create_dir_all(&work_dir).unwrap();
            std::fs::create_dir_all(&merged_dir).unwrap();

            criterion::black_box((&upper_dir, &work_dir, &merged_dir));
        });
    });

    // Benchmark BranchManager instantiation + directory setup together
    // (simulates the full creation overhead minus kernel namespace calls)
    group.bench_function("branch_manager_and_dirs", |b| {
        b.iter(|| {
            let dir = tempfile::tempdir().unwrap();
            let manager = create_branch_manager(&dir);

            // Create branch directory structure as the manager would
            let branch_id = format!("bench-{}", uuid::Uuid::new_v4());
            let branch_dir = dir.path().join("branches").join(&branch_id);
            std::fs::create_dir_all(branch_dir.join("upper")).unwrap();
            std::fs::create_dir_all(branch_dir.join("work")).unwrap();
            std::fs::create_dir_all(branch_dir.join("merged")).unwrap();

            criterion::black_box((&manager, &branch_dir));
        });
    });

    // Benchmark profile loading (part of branch creation)
    group.bench_function("profile_load_yaml", |b| {
        let profile_yaml = r#"
name: bench-profile
description: "Benchmark profile"
filesystem:
  read_allowlist: ["/usr/share"]
  write_allowlist: []
  denylist: ["/etc/shadow"]
exec_allowlist: ["/usr/bin/python3"]
resource_limits:
  memory_bytes: 536870912
  cpu_shares: 100
  io_weight: 100
  max_pids: 64
  storage_quota_mb: 1024
  inode_quota: 10000
network:
  mode: Blocked
  allowed_domains: []
behavioral:
  max_deletions: 50
  max_reads_per_minute: 1000
  credential_access_alert: true
"#;

        b.iter(|| {
            let profile: puzzled_types::AgentProfile =
                serde_yaml::from_str(criterion::black_box(profile_yaml)).unwrap();
            criterion::black_box(&profile);
        });
    });

    // Benchmark WAL entry creation (part of branch commit)
    group.bench_function("wal_create_and_write", |b| {
        b.iter(|| {
            let dir = tempfile::tempdir().unwrap();
            let wal_dir = dir.path().join("wal");
            std::fs::create_dir_all(&wal_dir).unwrap();

            let wal = puzzled::wal::WriteAheadLog::new(wal_dir);
            criterion::black_box(&wal);
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// T23: Concurrent branch creation benchmark
// ---------------------------------------------------------------------------

fn bench_concurrent_branches(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_branches");

    for branch_count in [4, 8, 16, 32, 64] {
        group.bench_function(format!("{}_branches_sequential", branch_count), |b| {
            b.iter(|| {
                let managers: Vec<_> = (0..branch_count)
                    .map(|_| {
                        let dir = tempfile::tempdir().unwrap();
                        let manager = create_branch_manager(&dir);
                        (dir, manager)
                    })
                    .collect();
                criterion::black_box(&managers);
            });
        });
    }

    // Benchmark concurrent branch directory setup using threads
    for branch_count in [4, 8, 16, 32, 64] {
        group.bench_function(format!("{}_branches_parallel", branch_count), |b| {
            b.iter(|| {
                let dir = tempfile::tempdir().unwrap();
                let base = dir.path().to_path_buf();
                std::thread::scope(|s| {
                    let handles: Vec<_> = (0..branch_count)
                        .map(|i| {
                            let base = base.clone();
                            s.spawn(move || {
                                let branch_dir = base.join(format!("branch_{}", i));
                                std::fs::create_dir_all(branch_dir.join("upper")).unwrap();
                                std::fs::create_dir_all(branch_dir.join("work")).unwrap();
                                std::fs::create_dir_all(branch_dir.join("merged")).unwrap();
                                criterion::black_box(&branch_dir);
                            })
                        })
                        .collect();
                    for h in handles {
                        h.join().unwrap();
                    }
                });
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// T24: Full commit cycle benchmark (diff + policy + WAL)
// ---------------------------------------------------------------------------

fn bench_full_commit_cycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_commit_cycle");

    for file_count in [10, 100, 1000] {
        group.bench_function(format!("commit_{}_files", file_count), |b| {
            b.iter_with_setup(
                || {
                    let dir = tempfile::tempdir().unwrap();
                    let wal_dir = dir.path().join("wal");
                    let upper_dir = dir.path().join("upper");
                    let base_path = dir.path().join("base");
                    std::fs::create_dir_all(&wal_dir).unwrap();
                    std::fs::create_dir_all(&upper_dir).unwrap();
                    std::fs::create_dir_all(&base_path).unwrap();

                    // Create files in upper
                    for i in 0..file_count {
                        let path = upper_dir.join(format!("file_{}.txt", i));
                        std::fs::write(&path, format!("content for file {}", i)).unwrap();
                    }

                    // Build changeset
                    let changes: Vec<puzzled_types::FileChange> = (0..file_count)
                        .map(|i| puzzled_types::FileChange {
                            path: std::path::PathBuf::from(format!("file_{}.txt", i)),
                            kind: puzzled_types::FileChangeKind::Added,
                            size: 20,
                            checksum: format!("cksum_{}", i),
                            old_size: None,
                            old_mode: None,
                            new_mode: None,
                            timestamp: None,
                            target: None,
                            entropy: None,
                            has_base64_blocks: None,
                        })
                        .collect();

                    puzzled::wal::WriteAheadLog::init(&wal_dir).unwrap();
                    let wal = puzzled::wal::WriteAheadLog::new(wal_dir);

                    (dir, wal, changes, upper_dir, base_path)
                },
                |(dir, wal, changes, upper_dir, base_path)| {
                    let branch_id =
                        puzzled_types::BranchId::from(format!("bench-{}", uuid::Uuid::new_v4()));
                    let executor = puzzled::commit::CommitExecutor::new(&wal);
                    executor
                        .execute(&branch_id, &changes, &base_path, &upper_dir)
                        .unwrap();
                    drop(dir);
                },
            );
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_branch_lifecycle,
    bench_branch_creation,
    bench_concurrent_branches,
    bench_full_commit_cycle,
);
criterion_main!(benches);
