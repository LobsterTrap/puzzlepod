// SPDX-License-Identifier: Apache-2.0
//! puzzle-sim-worker — runs inside a sandboxed branch, executing scenario actions.
//!
//! Usage: puzzle-sim-worker --scenario /path/to/scenario.yaml --root /merged
//!
//! This binary is spawned by `activate_branch()` inside the full sandbox
//! (namespaces, seccomp, Landlock, cgroup). It loads the scenario YAML,
//! executes each action against the overlay-merged root, and exits.
//! The exit code signals the outcome to the outer SimEngine.
//!
//! Requires the `sim` feature (enabled by default). Without it, the binary
//! prints an error and exits. For edge deployments that don't need the
//! simulator, compile with `--no-default-features --features tui` to exclude
//! both the simulator and this binary's implementation.

#[cfg(feature = "sim")]
fn main() -> anyhow::Result<()> {
    use puzzlectl::sim::scenario::Scenario;
    use anyhow::Context;
    use std::path::PathBuf;

    let args: Vec<String> = std::env::args().collect();

    let scenario_path = parse_arg(&args, "--scenario").context("missing --scenario <path>")?;
    let root = parse_arg(&args, "--root")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"));

    let scenario = Scenario::from_file(scenario_path.as_ref())
        .with_context(|| format!("loading scenario {}", scenario_path))?;

    eprintln!(
        "[puzzle-sim-worker] scenario={}, actions={}, root={}",
        scenario.name,
        scenario.actions.len(),
        root.display()
    );

    for (i, action) in scenario.actions.iter().enumerate() {
        eprintln!(
            "[puzzle-sim-worker] [{}/{}] {} {}",
            i + 1,
            scenario.actions.len(),
            action.action_type,
            action.display_target()
        );
        action
            .execute(&root)
            .with_context(|| format!("action {} failed", i))?;
    }

    eprintln!("[puzzle-sim-worker] all actions completed");
    Ok(())
}

#[cfg(not(feature = "sim"))]
fn main() {
    eprintln!("puzzle-sim-worker: not available (compile with --features sim)");
    std::process::exit(1);
}

#[cfg(feature = "sim")]
fn parse_arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}
