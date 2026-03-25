---
name: PuzzlePod Testing Patterns
description: "Auto-activates when editing test files or files in tests/ directories. Provides testing conventions, test registration requirements, and benchmark patterns."
---

# PuzzlePod Testing Patterns

## Test Organization

| Location | Type | Requirements |
|----------|------|-------------|
| In-module `#[cfg(test)]` | Unit tests | None |
| `crates/<crate>/tests/<name>.rs` | Integration tests | May need root + Linux |
| `tests/security/test_<name>.sh` | Security shell tests | Root + Linux |
| `crates/puzzled/tests/live_dbus_integration.rs` | Live D-Bus tests | Running puzzled instance |
| `crates/puzzled/benches/{branch,diff,policy,wal}.rs` | Benchmarks | criterion crate |

## CRITICAL: Registering New Test Files

When adding a NEW integration test file to `crates/puzzled/tests/`:

1. **Update `.github/workflows/ci.yml`**: Add the test name to the explicit `--test` list in Suite 3/5 (Unit Tests job)
2. **Update `scripts/run_all_tests.sh`**: Add the test to the appropriate suite
3. The `live_dbus_integration` test is EXCLUDED from general `cargo test` runs to prevent hangs

Failing to register new test files means they will not run in CI.

## Conventions

- Root-required tests: `#[ignore] // Requires root on Linux`
- Async tests: `#[tokio::test]`
- Integration tests needing serial execution: run with `-- --test-threads=1`
- Use `tempfile` crate for test fixtures and temporary directories
- Use synthetic data only -- never real credentials, PII, or production data
- Test names should describe scenario + expected result

## Test Commands

```bash
make test              # Unit tests (no root required)
make test-integration  # Integration tests (root + Linux)
make test-dbus         # Live D-Bus tests (requires running puzzled)
make test-security     # Security shell tests (root + Linux)
make test-all          # All 5 suites (~920 tests)
make ci                # fmt + clippy + test + deny
```

## Benchmarks (criterion)

```bash
cargo bench -p puzzled                              # Run all benchmarks
cargo bench -p puzzled -- --save-baseline <name>     # Save baseline
critcmp <baseline1> <baseline2>                      # Compare baselines
```

Existing benchmarks: `branch.rs`, `diff.rs`, `policy.rs`, `wal.rs`

Regression thresholds:
- Warning: > 5% degradation
- Failure: > 10% degradation
