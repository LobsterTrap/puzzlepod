Run criterion benchmarks comparing current branch against main.

1. Save current branch name
2. Run benchmarks on current branch: `cargo bench -p puzzled -- --save-baseline current`
3. Checkout main: `git stash && git checkout main`
4. Run benchmarks on main: `cargo bench -p puzzled -- --save-baseline main`
5. Return to original branch: `git checkout <branch> && git stash pop`
6. Compare: `critcmp main current`
7. Report results:
   - Per-benchmark: name, main baseline, current, delta %, verdict
   - Flag any regression > 5% as WARNING, > 10% as FAILURE
   - Overall verdict: PASS / REGRESSED / IMPROVED

Benchmarks located in: `crates/puzzled/benches/{branch,diff,policy,wal}.rs`
