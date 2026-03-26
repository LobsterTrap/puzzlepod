// SPDX-License-Identifier: Apache-2.0
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_diff_engine(c: &mut Criterion) {
    let mut group = c.benchmark_group("diff_engine");

    for file_count in [10, 100, 1000, 10000] {
        group.bench_function(format!("diff_{}_files", file_count), |b| {
            let dir = tempfile::tempdir().unwrap();
            let upper = dir.path().join("upper");
            let lower = dir.path().join("lower");
            std::fs::create_dir_all(&upper).unwrap();
            std::fs::create_dir_all(&lower).unwrap();

            // Create files in upper (new files = Added)
            for i in 0..file_count {
                let path = upper.join(format!("file_{}.txt", i));
                std::fs::write(&path, format!("content {}", i)).unwrap();
            }

            let engine = puzzled::diff::DiffEngine::new();

            b.iter(|| {
                engine
                    .generate(
                        criterion::black_box(&upper),
                        criterion::black_box(&lower),
                        None,
                    )
                    .unwrap();
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Diff with nested subdirectories (more realistic workload)
// ---------------------------------------------------------------------------

fn bench_diff_nested(c: &mut Criterion) {
    let mut group = c.benchmark_group("diff_nested");

    // 1K files spread across 100 subdirectories
    group.bench_function("diff_1k_nested_100dirs", |b| {
        let dir = tempfile::tempdir().unwrap();
        let upper = dir.path().join("upper");
        let lower = dir.path().join("lower");
        std::fs::create_dir_all(&upper).unwrap();
        std::fs::create_dir_all(&lower).unwrap();

        for d in 0..100 {
            let subdir = upper.join(format!("dir_{}", d));
            std::fs::create_dir_all(&subdir).unwrap();
            for f in 0..10 {
                let path = subdir.join(format!("file_{}.txt", f));
                std::fs::write(&path, format!("content dir={} file={}", d, f)).unwrap();
            }
        }

        let engine = puzzled::diff::DiffEngine::new();

        b.iter(|| {
            engine
                .generate(
                    criterion::black_box(&upper),
                    criterion::black_box(&lower),
                    None,
                )
                .unwrap();
        });
    });

    // Modified files (lower has originals, upper has modified versions)
    group.bench_function("diff_500_modified", |b| {
        let dir = tempfile::tempdir().unwrap();
        let upper = dir.path().join("upper");
        let lower = dir.path().join("lower");
        std::fs::create_dir_all(&upper).unwrap();
        std::fs::create_dir_all(&lower).unwrap();

        for i in 0..500 {
            let name = format!("file_{}.txt", i);
            std::fs::write(lower.join(&name), format!("original content {}", i)).unwrap();
            std::fs::write(upper.join(&name), format!("modified content {}", i)).unwrap();
        }

        let engine = puzzled::diff::DiffEngine::new();

        b.iter(|| {
            engine
                .generate(
                    criterion::black_box(&upper),
                    criterion::black_box(&lower),
                    None,
                )
                .unwrap();
        });
    });

    group.finish();
}

criterion_group!(benches, bench_diff_engine, bench_diff_nested);
criterion_main!(benches);
