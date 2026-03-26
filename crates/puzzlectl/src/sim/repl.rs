// SPDX-License-Identifier: Apache-2.0
use std::path::Path;

use anyhow::{Context, Result};
use rustyline::error::ReadlineError;
use rustyline::Editor;

use crate::client::PuzzledClient;

use super::completer::SimCompleter;
use super::engine::{SimEngine, SimMode};
use super::scenario::discover_scenarios;

const PROMPT: &str = "agent> ";

fn print_help() {
    println!(
        "\
Commands:
  help                    Show this help
  list scenarios          List available scenarios
  list profiles           List available profiles
  load <name>             Load a scenario by name
  set profile <name>      Override the scenario's profile
  set mode <direct|sandbox>  Set execution mode
  start                   Create a branch and prepare the agent
  step                    Execute the next agent action (direct mode)
  run                     Execute all remaining actions (direct mode)
  run --skip <N>          Execute all, skip action at index N (1-based)
  run --skip-tagged <tag> Execute all, skip actions with given tag
  execute                 Start, run all actions, approve (sandbox mode)
  inspect                 Show current branch changeset
  approve                 Submit for policy review
  reject                  Rollback the branch
  status                  Show daemon status
  history                 Show actions executed in this session
  quit / exit             Clean up and exit"
    );
}

fn print_scenario_summary(name: &str, engine: &SimEngine) {
    if let Some(s) = engine.scenario() {
        println!("Loaded scenario: {}", s.name);
        if let Some(d) = &s.description {
            println!("  Description: {}", d);
        }
        println!("  Profile:  {}", engine.active_profile().unwrap_or("?"));
        println!("  Task:     \"{}\"", s.task);
        println!("  Actions:  {} steps", s.actions.len());
        println!(
            "  Expected: {} {}",
            s.expected_outcome,
            s.expected_reason
                .as_deref()
                .map(|r| format!("({})", r))
                .unwrap_or_default()
        );
        let _ = name;
    }
}

pub async fn run_repl(
    client: &PuzzledClient,
    scenarios_dir: &Path,
    profile_dir: &Path,
    storage_base: &str,
    preload: Option<&str>,
) -> i32 {
    let scenarios = match discover_scenarios(scenarios_dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error discovering scenarios: {}", e);
            return 2;
        }
    };

    let scenario_names: Vec<String> = scenarios.iter().map(|(n, _)| n.clone()).collect();
    let profile_names = discover_profile_names(profile_dir);

    let completer = SimCompleter::new(scenario_names, profile_names);
    let mut rl = match Editor::new() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Failed to create editor: {}", e);
            return 2;
        }
    };
    rl.set_helper(Some(completer));

    let mut engine = SimEngine::new(storage_base);

    println!("puzzlectl sim v0.1.0");
    println!("Type 'help' for commands, 'quit' to exit.");

    if let Some(name) = preload {
        if let Some((_, scenario)) = scenarios.iter().find(|(n, _)| n == name) {
            engine.load(scenario.clone());
            println!();
            print_scenario_summary(name, &engine);
        } else {
            eprintln!("Warning: scenario '{}' not found", name);
        }
    }

    loop {
        let readline = rl.readline(PROMPT);
        match readline {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(line);
                if let Err(e) =
                    handle_command(line, &mut engine, client, &scenarios, profile_dir).await
                {
                    eprintln!("Error: {}", e);
                }
                if line == "quit" || line == "exit" {
                    break;
                }
            }
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => {
                cleanup(&mut engine, client).await;
                break;
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                break;
            }
        }
    }
    0
}

async fn cleanup(engine: &mut SimEngine, client: &PuzzledClient) {
    if engine.is_started() {
        eprintln!("[orchestrator] Cleaning up active branch...");
        let _ = engine.reject(client).await;
    }
}

async fn handle_command(
    line: &str,
    engine: &mut SimEngine,
    client: &PuzzledClient,
    scenarios: &[(String, super::scenario::Scenario)],
    profile_dir: &Path,
) -> Result<()> {
    match line {
        "help" => {
            print_help();
        }

        "list scenarios" => {
            if scenarios.is_empty() {
                println!("No scenarios found.");
            } else {
                println!("{:<28} {:<14} EXPECTED", "NAME", "PROFILE");
                println!("{}", "-".repeat(56));
                for (slug, s) in scenarios {
                    println!("{:<28} {:<14} {}", slug, s.profile, s.expected_outcome);
                }
            }
        }

        "list profiles" => {
            let names = discover_profile_names(profile_dir);
            if names.is_empty() {
                println!("No profiles found in {}", profile_dir.display());
            } else {
                for name in &names {
                    println!("  {}", name);
                }
            }
        }

        cmd if cmd.starts_with("load ") => {
            let name = cmd.strip_prefix("load ").unwrap().trim();
            if let Some((slug, scenario)) = scenarios.iter().find(|(n, _)| n == name) {
                if engine.is_started() {
                    eprintln!("[orchestrator] Rejecting current branch first...");
                    let _ = engine.reject(client).await;
                }
                engine.load(scenario.clone());
                print_scenario_summary(slug, engine);
            } else {
                eprintln!(
                    "Scenario '{}' not found. Use 'list scenarios' to see available.",
                    name
                );
            }
        }

        cmd if cmd.starts_with("set profile ") => {
            let profile = cmd.strip_prefix("set profile ").unwrap().trim();
            if engine.scenario().is_none() {
                eprintln!("No scenario loaded. Use 'load <name>' first.");
            } else {
                let old = engine.active_profile().unwrap_or("?").to_string();
                engine.set_profile(profile.to_string());
                println!("Profile overridden: {} (was: {})", profile, old);
            }
        }

        cmd if cmd.starts_with("set mode ") => {
            let mode_str = cmd.strip_prefix("set mode ").unwrap().trim();
            match mode_str {
                "direct" => {
                    // V50: Preserve loaded scenario when switching modes
                    let current_scenario = engine.scenario().cloned();
                    *engine =
                        SimEngine::new(&engine_storage_base(engine)).with_mode(SimMode::Direct);
                    if let Some(scenario) = current_scenario {
                        engine.load(scenario);
                    }
                    println!("Mode set to: direct (actions execute without sandbox)");
                }
                "sandbox" => {
                    // V50: Preserve loaded scenario when switching modes
                    let current_scenario = engine.scenario().cloned();
                    *engine =
                        SimEngine::new(&engine_storage_base(engine)).with_mode(SimMode::Sandbox);
                    if let Some(scenario) = current_scenario {
                        engine.load(scenario);
                    }
                    println!("Mode set to: sandbox (actions run inside full sandbox via puzzle-sim-worker)");
                }
                _ => {
                    eprintln!("Unknown mode '{}'. Use 'direct' or 'sandbox'.", mode_str);
                }
            }
        }

        "start" => {
            if engine.scenario().is_none() {
                eprintln!("No scenario loaded. Use 'load <name>' first.");
                return Ok(());
            }
            if engine.is_started() {
                eprintln!("[orchestrator] Rejecting previous branch...");
                let _ = engine.reject(client).await;
                engine.reset();
            }
            let profile = engine.active_profile().unwrap_or("?").to_string();
            println!(
                "[orchestrator] Creating branch with profile '{}'...",
                profile
            );
            let bid = engine.start(client).await?;
            println!("[orchestrator] Branch {} active", &bid[..8.min(bid.len())]);

            // N5: Propagate error instead of unwrap
            let s = engine.scenario().context("N5: scenario not loaded")?;
            println!("[agent] Task: \"{}\"", s.task);
            println!(
                "[agent] Planned {} actions. Type 'step' to execute next, 'run' to execute all.",
                s.actions.len()
            );
        }

        "step" => {
            if !engine.is_started() {
                eprintln!("No active branch. Use 'start' first.");
                return Ok(());
            }
            if !engine.has_remaining_actions() {
                println!("All actions executed. Use 'inspect', 'approve', or 'reject'.");
                return Ok(());
            }
            let result = engine.step().await?;
            let desc = result.description.as_deref().unwrap_or("");
            if result.skipped {
                println!(
                    "  [{}/{}] {}: {} -- SKIPPED",
                    result.index + 1,
                    result.total,
                    result.action_type,
                    result.target,
                );
            } else {
                println!(
                    "  [{}/{}] {}: {}",
                    result.index + 1,
                    result.total,
                    result.action_type,
                    result.target,
                );
            }
            if !desc.is_empty() {
                println!("        {}", desc);
            }

            if let Some(scenario) = engine.scenario() {
                if let Some(action) = scenario.actions.get(result.index) {
                    if action
                        .tags
                        .iter()
                        .any(|t| t == "sensitive" || t == "trigger")
                    {
                        println!("        WARNING: This action is tagged as sensitive");
                    }
                }
            }
        }

        cmd if cmd.starts_with("run") => {
            if !engine.is_started() {
                eprintln!("No active branch. Use 'start' first.");
                return Ok(());
            }

            let (skip_indices, skip_tags) = parse_run_flags(cmd);

            let results = engine.run(&skip_indices, &skip_tags).await?;
            for r in &results {
                let mark = if r.skipped { " -- SKIPPED" } else { "" };
                println!(
                    "  [{}/{}] {}: {}{}",
                    r.index + 1,
                    r.total,
                    r.action_type,
                    r.target,
                    mark,
                );
            }
            if results.is_empty() {
                println!("No remaining actions.");
            }
        }

        "execute" => {
            if engine.scenario().is_none() {
                eprintln!("No scenario loaded. Use 'load <name>' first.");
                return Ok(());
            }
            if engine.is_started() {
                eprintln!("[orchestrator] Rejecting previous branch...");
                let _ = engine.reject(client).await;
                engine.reset();
            }

            let saved_mode = engine.mode();
            if saved_mode == SimMode::Direct {
                eprintln!("Note: 'execute' uses sandbox mode. Switching temporarily.");
                // V51: Preserve loaded scenario when switching to sandbox mode for execute
                let current_scenario = engine.scenario().cloned();
                *engine = SimEngine::new(&engine_storage_base(engine)).with_mode(SimMode::Sandbox);
                if let Some(scenario) = current_scenario {
                    engine.load(scenario);
                }
            }

            let profile = engine.active_profile().unwrap_or("?").to_string();
            println!(
                "[orchestrator] Creating branch with profile '{}' (sandbox)...",
                profile
            );
            let bid = engine.start(client).await?;
            println!(
                "[orchestrator] Branch {} started, worker running...",
                &bid[..8.min(bid.len())]
            );

            let state = engine.wait_for_worker(client).await?;
            println!("[orchestrator] Worker finished (state: {})", state);

            println!("[orchestrator] Submitting for policy review...");
            let result = engine.approve(client).await?;
            match result.deny_reason {
                Some(reason) => {
                    println!("[puzzled] DENIED: {}", reason);
                    println!("Branch rolled back.");
                }
                None => {
                    println!("[puzzled] APPROVED: changes committed");
                }
            }
        }

        "inspect" => {
            if !engine.is_started() {
                eprintln!("No active branch.");
                return Ok(());
            }
            let result = engine.inspect(client).await?;
            println!("  Changes:");
            println!(
                "    added: {}, modified: {}, deleted: {}",
                result.added, result.modified, result.deleted
            );
            println!(
                "    total: {} files, {} bytes",
                result.total_files, result.total_bytes
            );
            if !result.files.is_empty() {
                println!();
                for (path, change_type) in &result.files {
                    let marker = match change_type.as_str() {
                        "Added" | "ADDED" => "+",
                        "Deleted" | "DELETED" => "-",
                        "Modified" | "MODIFIED" => "~",
                        _ => "?",
                    };
                    println!("    {} {} ({})", marker, path, change_type);
                }
            }
        }

        "approve" => {
            if !engine.is_started() {
                eprintln!("No active branch.");
                return Ok(());
            }
            println!("[orchestrator] Submitting for policy review...");
            let result = engine.approve(client).await?;
            match result.deny_reason {
                Some(reason) => {
                    println!("[puzzled] DENIED: {}", reason);
                    println!("Branch rolled back.");
                }
                None => {
                    println!("[puzzled] APPROVED: changes committed");
                }
            }
        }

        "reject" => {
            if !engine.is_started() {
                eprintln!("No active branch.");
                return Ok(());
            }
            engine.reject(client).await?;
            println!("[orchestrator] Branch rejected (rolled back).");
        }

        "status" => {
            let branches = client.list_branches().await?;
            println!("{}", branches);
        }

        "history" => {
            let history = engine.history();
            if history.is_empty() {
                println!("No actions executed yet.");
            } else {
                for entry in history {
                    let mark = if entry.skipped { " [SKIPPED]" } else { "" };
                    println!(
                        "  [{}] {}: {}{}",
                        entry.index + 1,
                        entry.action_type,
                        entry.target,
                        mark,
                    );
                }
            }
        }

        "quit" | "exit" => {
            cleanup(engine, client).await;
            println!("Goodbye.");
        }

        _ => {
            eprintln!(
                "Unknown command: '{}'. Type 'help' for available commands.",
                line
            );
        }
    }
    Ok(())
}

fn parse_run_flags(cmd: &str) -> (Vec<usize>, Vec<String>) {
    let mut skip_indices = Vec::new();
    let mut skip_tags = Vec::new();

    let parts: Vec<&str> = cmd.split_whitespace().collect();
    let mut i = 1;
    while i < parts.len() {
        match parts[i] {
            "--skip" if i + 1 < parts.len() => {
                if let Ok(n) = parts[i + 1].parse::<usize>() {
                    if n > 0 {
                        skip_indices.push(n - 1);
                    }
                }
                i += 2;
            }
            "--skip-tagged" if i + 1 < parts.len() => {
                skip_tags.push(parts[i + 1].to_string());
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }
    (skip_indices, skip_tags)
}

fn engine_storage_base(engine: &SimEngine) -> String {
    engine.storage_base().to_string()
}

fn discover_profile_names(dir: &Path) -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
                if let Some(stem) = path.file_stem() {
                    names.push(stem.to_string_lossy().to_string());
                }
            }
        }
    }
    names.sort();
    names
}
