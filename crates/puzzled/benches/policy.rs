// SPDX-License-Identifier: Apache-2.0
use criterion::{criterion_group, criterion_main, Criterion};
use puzzled_types::{FileChange, FileChangeKind};
use std::path::PathBuf;

fn bench_policy_evaluation(c: &mut Criterion) {
    let policy_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("policies")
        .join("rules");

    let mut group = c.benchmark_group("policy_evaluation");

    for size in [1, 10, 100] {
        group.bench_function(format!("evaluate_{}_files", size), |b| {
            let engine = puzzled::policy::PolicyEngine::new(policy_dir.clone());
            engine.reload().unwrap();

            let changes: Vec<FileChange> = (0..size)
                .map(|i| FileChange {
                    path: PathBuf::from(format!("src/file_{}.rs", i)),
                    kind: FileChangeKind::Modified,
                    size: 1024,
                    checksum: format!("checksum_{}", i),
                    old_size: None,
                    old_mode: None,
                    new_mode: None,
                    timestamp: None,
                    target: None,
                    entropy: None,
                    has_base64_blocks: None,
                })
                .collect();

            b.iter(|| {
                engine
                    .evaluate(criterion::black_box(&changes), None)
                    .unwrap();
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_policy_evaluation);
criterion_main!(benches);
