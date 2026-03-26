// SPDX-License-Identifier: Apache-2.0
//! WAL performance benchmarks.
//!
//! Measures append, recovery, and backup/restore throughput to verify
//! WAL operations meet latency targets.

use std::path::PathBuf;

use puzzled_types::BranchId;
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_wal_append_1_operation(c: &mut Criterion) {
    c.bench_function("wal_append_1_operation", |b| {
        b.iter_with_setup(
            || {
                let dir = tempfile::tempdir().unwrap();
                let wal_dir = dir.path().join("wal");
                let wal = puzzled::wal::WriteAheadLog::new(wal_dir);
                (dir, wal, 0u32)
            },
            |(dir, wal, counter)| {
                let branch = BranchId::from(format!("bench-{}", counter));
                let ops = vec![puzzled::wal::WalOperation::CopyFile {
                    from: PathBuf::from("/src/file.txt"),
                    to: PathBuf::from("/dst/file.txt"),
                }];
                wal.begin_commit(&branch, ops).unwrap();
                wal.mark_operation_complete(&branch, 0).unwrap();
                wal.mark_commit_complete(&branch).unwrap();
                drop(dir);
            },
        );
    });
}

fn bench_wal_append_100_operations(c: &mut Criterion) {
    c.bench_function("wal_append_100_operations", |b| {
        b.iter_with_setup(
            || {
                let dir = tempfile::tempdir().unwrap();
                let wal_dir = dir.path().join("wal");
                let wal = puzzled::wal::WriteAheadLog::new(wal_dir);
                (dir, wal)
            },
            |(dir, wal)| {
                let branch = BranchId::from("bench-100".to_string());
                let ops: Vec<_> = (0..100)
                    .map(|i| puzzled::wal::WalOperation::CopyFile {
                        from: PathBuf::from(format!("/src/{}.txt", i)),
                        to: PathBuf::from(format!("/dst/{}.txt", i)),
                    })
                    .collect();
                wal.begin_commit(&branch, ops).unwrap();
                for i in 0..100 {
                    wal.mark_operation_complete(&branch, i).unwrap();
                }
                wal.mark_commit_complete(&branch).unwrap();
                drop(dir);
            },
        );
    });
}

fn bench_wal_recovery_10_entries(c: &mut Criterion) {
    c.bench_function("wal_recovery_10_entries", |b| {
        b.iter_with_setup(
            || {
                let dir = tempfile::tempdir().unwrap();
                let wal_dir = dir.path().join("wal");

                // Pre-populate 10 incomplete WAL entries
                {
                    let wal = puzzled::wal::WriteAheadLog::new(wal_dir.clone());
                    for i in 0..10 {
                        let branch = BranchId::from(format!("recovery-{}", i));
                        let ops = vec![puzzled::wal::WalOperation::CopyFile {
                            from: PathBuf::from(format!("/src/{}.txt", i)),
                            to: PathBuf::from(format!("/dst/{}.txt", i)),
                        }];
                        wal.begin_commit(&branch, ops).unwrap();
                        wal.mark_operation_complete(&branch, 0).unwrap();
                        // Deliberately don't mark complete
                    }
                }

                (dir, wal_dir)
            },
            |(dir, wal_dir)| {
                let wal = puzzled::wal::WriteAheadLog::new(wal_dir);
                let incomplete = wal.recover().unwrap();
                assert_eq!(incomplete.len(), 10);
                drop(dir);
            },
        );
    });
}

fn bench_wal_backup_and_restore(c: &mut Criterion) {
    c.bench_function("wal_backup_and_restore", |b| {
        b.iter_with_setup(
            || {
                let dir = tempfile::tempdir().unwrap();
                let wal_dir = dir.path().join("wal");
                let target = dir.path().join("target.txt");
                std::fs::write(&target, "original content for backup benchmark").unwrap();

                let wal = puzzled::wal::WriteAheadLog::new(wal_dir);
                (dir, wal, target)
            },
            |(dir, wal, target)| {
                let branch = BranchId::from("backup-bench".to_string());
                let ops = vec![puzzled::wal::WalOperation::CopyFile {
                    from: PathBuf::from("/src/file.txt"),
                    to: target.clone(),
                }];
                wal.begin_commit(&branch, ops.clone()).unwrap();
                wal.backup_file(&branch, &target).unwrap();

                // Simulate modification
                std::fs::write(&target, "modified content").unwrap();

                // Restore
                let completed: std::collections::HashSet<usize> = [0].into_iter().collect();
                let _ = wal.reverse_operations(&branch, &ops, &completed);
                drop(dir);
            },
        );
    });
}

criterion_group!(
    benches,
    bench_wal_append_1_operation,
    bench_wal_append_100_operations,
    bench_wal_recovery_10_entries,
    bench_wal_backup_and_restore,
);
criterion_main!(benches);
