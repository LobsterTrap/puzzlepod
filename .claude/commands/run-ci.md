Run the full CI check suite locally and report results.

Execute `make ci` which runs:
1. `cargo fmt --all -- --check` (formatting)
2. `cargo clippy --workspace --all-targets -- -D warnings` (linting)
3. `cargo test --workspace` (unit tests)
4. `cargo-deny check` (dependency audit)

Report results in a structured format:
- Suite name: PASS/FAIL
- If any failures: show the relevant error output
- Summary: X/4 suites passed
