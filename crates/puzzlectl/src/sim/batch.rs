// SPDX-License-Identifier: Apache-2.0
use std::path::Path;

use anyhow::{Context, Result};

use crate::client::PuzzledClient;

use super::engine::{SimEngine, SimMode};
use super::report::{outcome_matches, BatchReport, ScenarioResult};
use super::scenario::{discover_scenarios, Scenario};

async fn run_scenario(
    client: &PuzzledClient,
    scenario: &Scenario,
    profile_override: Option<&str>,
    storage_base: &str,
    verbose: bool,
    mode: SimMode,
    pace: bool,
) -> Result<ScenarioResult> {
    let mut engine = SimEngine::new(storage_base).with_mode(mode);
    let mut scenario = scenario.clone();
    if let Some(p) = profile_override {
        scenario.profile = p.to_string();
    }

    let profile = scenario.profile.clone();
    let name = scenario.name.clone();
    let expected = scenario.expected_outcome;
    engine.load(scenario);

    if verbose {
        let mode_label = if mode == SimMode::Sandbox {
            " (sandbox)"
        } else {
            " (direct)"
        };
        println!(
            "\n[orchestrator] Creating branch with profile '{}'{}...",
            profile, mode_label
        );
    }

    let bid = engine
        .start(client)
        .await
        .context("failed to start branch")?;

    if verbose {
        println!("[orchestrator] Branch {} started", &bid[..8.min(bid.len())]);
    }

    // --pace: let TUI poll and see the branch in Active state
    if pace {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }

    let action_count;
    if mode == SimMode::Sandbox {
        if verbose {
            println!("[agent] Worker executing actions inside sandbox...");
        }
        let final_state = engine
            .wait_for_worker(client)
            .await
            .context("waiting for worker")?;
        if verbose {
            println!("[orchestrator] Worker finished (state: {})", final_state);
        }
        action_count = engine.total_actions();
    } else {
        if verbose {
            println!("[agent] Executing actions...");
        }
        let steps = engine
            .run(&[], &[])
            .await
            .context("failed to run actions")?;
        if verbose {
            for s in &steps {
                let mark = if s.skipped { "SKIPPED" } else { "ok" };
                println!(
                    "  [{}/{}] {}: {} -- {}",
                    s.index + 1,
                    s.total,
                    s.action_type,
                    s.target,
                    mark
                );
            }
        }
        action_count = steps.iter().filter(|s| !s.skipped).count();
    }

    // --pace: let TUI poll and see the branch with executed actions
    if pace {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }

    if verbose {
        println!("[orchestrator] Submitting for policy review...");
    }

    let approve_result = engine.approve(client).await.context("approve failed")?;

    if verbose {
        match &approve_result.deny_reason {
            Some(reason) => println!("[puzzled] DENIED: {}", reason),
            None => println!("[puzzled] APPROVED: {} files changed", action_count),
        }
    }

    let pass = outcome_matches(approve_result.outcome, expected);

    Ok(ScenarioResult {
        scenario: name,
        profile,
        outcome: approve_result.outcome.to_string(),
        expected: expected.to_string(),
        pass,
        deny_reason: approve_result.deny_reason,
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn run_one_with_mode(
    client: &PuzzledClient,
    scenarios_dir: &Path,
    name: &str,
    profile_override: Option<&str>,
    storage_base: &str,
    json_output: bool,
    mode: SimMode,
    pace: bool,
) -> i32 {
    let all = match discover_scenarios(scenarios_dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error discovering scenarios: {}", e);
            return 2;
        }
    };

    let found = all.iter().find(|(slug, _)| slug == name);
    let (_, scenario) = match found {
        Some(s) => s,
        None => {
            eprintln!(
                "Scenario '{}' not found. Available: {}",
                name,
                all.iter()
                    .map(|(s, _)| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            return 1;
        }
    };

    match run_scenario(
        client,
        scenario,
        profile_override,
        storage_base,
        !json_output,
        mode,
        pace,
    )
    .await
    {
        Ok(result) => {
            let report = BatchReport::new(vec![result]);
            if json_output {
                report.print_json();
            } else {
                report.print_table();
            }
            if report.summary.failed > 0 {
                1
            } else {
                0
            }
        }
        Err(e) => {
            eprintln!("Error running scenario '{}': {:#}", name, e);
            2
        }
    }
}

pub async fn run_all_with_mode(
    client: &PuzzledClient,
    scenarios_dir: &Path,
    profile_override: Option<&str>,
    storage_base: &str,
    json_output: bool,
    mode: SimMode,
    pace: bool,
) -> i32 {
    let all = match discover_scenarios(scenarios_dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error discovering scenarios: {}", e);
            return 2;
        }
    };

    if all.is_empty() {
        eprintln!("No scenarios found in {}", scenarios_dir.display());
        return 1;
    }

    if !json_output {
        println!(
            "Running {} scenario{}...\n",
            all.len(),
            if all.len() == 1 { "" } else { "s" }
        );
    }

    let mut results = Vec::new();
    for (slug, scenario) in &all {
        if !json_output {
            println!("=== {} ===", slug);
        }
        match run_scenario(
            client,
            scenario,
            profile_override,
            storage_base,
            !json_output,
            mode,
            pace,
        )
        .await
        {
            Ok(result) => results.push(result),
            Err(e) => {
                eprintln!("Error running '{}': {:#}", slug, e);
                results.push(ScenarioResult {
                    scenario: scenario.name.clone(),
                    profile: scenario.profile.clone(),
                    outcome: "error".to_string(),
                    expected: scenario.expected_outcome.to_string(),
                    pass: false,
                    deny_reason: Some(e.to_string()),
                });
            }
        }
    }

    let report = BatchReport::new(results);
    if json_output {
        report.print_json();
    } else {
        report.print_table();
    }
    if report.summary.failed > 0 {
        1
    } else {
        0
    }
}
