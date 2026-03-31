// SPDX-License-Identifier: Apache-2.0
use anyhow::{Context, Result};

use crate::cli::OutputFormat;
use crate::client;
use crate::commands::branch::print_diff_text;

/// Parse a string field from a JSON response.
pub fn parse_json_field(json: &str, field: &str) -> Result<String> {
    let v: serde_json::Value = serde_json::from_str(json).context("parsing JSON response")?;
    v.get(field)
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| anyhow::anyhow!("missing '{}' in response: {}", field, json))
}

/// Poll InspectBranch until state leaves active/creating/frozen/committing.
async fn poll_branch_until_done(
    client: &client::PuzzledClient,
    branch_id: &str,
    poll_ms: u64,
) -> Result<String> {
    let interval = std::time::Duration::from_millis(poll_ms.clamp(100, 10_000));
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(86400);
    loop {
        if tokio::time::Instant::now() > deadline {
            anyhow::bail!("branch {branch_id} did not exit within 24h");
        }
        tokio::time::sleep(interval).await;
        let info = client.inspect_branch(branch_id).await?;
        let state = parse_json_field(&info, "state").unwrap_or_else(|_| "unknown".into());
        match state.as_str() {
            "active" | "creating" | "ready" | "frozen" | "committing" => continue,
            _ => return Ok(state),
        }
    }
}

enum Decision {
    Approve,
    Reject,
    ShowDiff,
}

fn prompt_approve_reject() -> Result<Decision> {
    use std::io::Write;
    eprint!("[run] approve changes? [y/N/d(iff)]: ");
    std::io::stderr().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    match input.trim().to_lowercase().as_str() {
        "y" | "yes" => Ok(Decision::Approve),
        "d" | "diff" => Ok(Decision::ShowDiff),
        _ => Ok(Decision::Reject),
    }
}

fn output_run_result(format: OutputFormat, branch_id: &str, status: &str, changes: usize) {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::json!({
                    "branch_id": branch_id, "status": status, "changes": changes
                })
            );
        }
        OutputFormat::Text => eprintln!("[run] {status} ({changes} file(s))"),
    }
}

/// Returns true if the policy rejected the commit.
fn output_run_result_with_governance(
    format: OutputFormat,
    branch_id: &str,
    commit_json: &str,
    changes: usize,
) -> bool {
    let mut rejected = false;
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::from_str::<serde_json::Value>(commit_json)
                        .unwrap_or(serde_json::Value::String(commit_json.to_string()))
                )
                .unwrap_or_else(|_| commit_json.to_string())
            );
            // Check for rejection in JSON output mode too
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(commit_json) {
                if let Some(result) = v.get("policy_result") {
                    if result.get("Rejected").is_some() {
                        rejected = true;
                    }
                }
            }
        }
        OutputFormat::Text => {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(commit_json) {
                if let Some(result) = v.get("policy_result") {
                    if result.get("Approved").is_some() {
                        eprintln!("[run] committed ({changes} file(s), policy: approved)");
                    } else if let Some(violations) = result.get("Rejected") {
                        rejected = true;
                        eprintln!(
                            "[run] rolled back by policy ({} violation(s)):",
                            violations.as_array().map(|a| a.len()).unwrap_or(0)
                        );
                        if let Some(arr) = violations.as_array() {
                            for vi in arr {
                                let msg = vi
                                    .get("message")
                                    .and_then(|m| m.as_str())
                                    .unwrap_or("unknown");
                                let sev = vi
                                    .get("severity")
                                    .and_then(|s| s.as_str())
                                    .unwrap_or("error");
                                eprintln!("  [{sev}] {msg}");
                            }
                        }
                    } else {
                        eprintln!("[run] committed ({changes} file(s), branch: {branch_id})");
                    }
                } else {
                    eprintln!("[run] committed ({changes} file(s), branch: {branch_id})");
                }
            } else {
                eprintln!("[run] {commit_json}");
            }
        }
    }
    rejected
}

#[allow(clippy::too_many_arguments)]
pub async fn cmd_run(
    client: &client::PuzzledClient,
    profile: &str,
    base: &str,
    cmd_args: &[String],
    auto_commit: bool,
    auto_rollback: bool,
    show_diff: bool,
    poll_ms: u64,
    output: OutputFormat,
) -> Result<()> {
    use std::io::IsTerminal;

    if cmd_args.is_empty() {
        anyhow::bail!("no command specified");
    }

    let abs_base = std::fs::canonicalize(base)
        .with_context(|| format!("resolving base path '{}'", base))?
        .to_string_lossy()
        .to_string();

    let command_json = serde_json::to_string(&cmd_args)?;

    // Step 1: Create branch
    if matches!(output, OutputFormat::Text) {
        eprintln!("[run] creating branch (profile={profile})...");
    }
    let create_json = client
        .create_branch(profile, &abs_base, &command_json)
        .await?;
    let branch_id = parse_json_field(&create_json, "id")?;

    // Step 2: Activate branch
    if matches!(output, OutputFormat::Text) {
        eprintln!("[run] branch {branch_id} created, activating...");
    }
    client.activate_branch(&branch_id, &command_json).await?;
    if matches!(output, OutputFormat::Text) {
        eprintln!("[run] agent running, waiting for exit...");
    }

    // Step 3: Poll until terminal state
    let final_state = poll_branch_until_done(client, &branch_id, poll_ms).await?;
    if matches!(output, OutputFormat::Text) {
        eprintln!("[run] agent exited (state: {final_state})");
    }

    // Check for terminal error states before attempting diff/commit
    match final_state.as_str() {
        "exited" | "governance_review" => {} // proceed to diff/commit
        "failed" | "terminated" | "degraded" => {
            let reason = format!("branch ended in state: {final_state}");
            let _ = client.rollback_branch(&branch_id, &reason).await;
            output_run_result(output, &branch_id, &final_state, 0);
            anyhow::bail!("branch {branch_id} ended in terminal state: {final_state}");
        }
        _ => {
            if matches!(output, OutputFormat::Text) {
                eprintln!("[run] warning: unexpected state '{final_state}', attempting diff");
            }
        }
    }

    // Step 4: Get diff
    let diff_json = client.diff_branch(&branch_id).await?;
    let change_count = serde_json::from_str::<Vec<serde_json::Value>>(&diff_json)
        .map(|v| v.len())
        .unwrap_or(0);

    // Step 5: Handle empty changeset
    if change_count == 0 {
        if matches!(output, OutputFormat::Text) {
            eprintln!("[run] no changes detected");
        }
        let _ = client.rollback_branch(&branch_id, "no changes").await;
        output_run_result(output, &branch_id, "no_changes", 0);
        return Ok(());
    }

    // Step 6: Show diff if requested
    if show_diff && matches!(output, OutputFormat::Text) {
        eprintln!("[run] {} file(s) changed:", change_count);
        print_diff_text(&diff_json);
        eprintln!();
    }

    // Step 7: Decision
    let mut policy_rejected = false;
    if auto_rollback {
        client.rollback_branch(&branch_id, "auto-rollback").await?;
        output_run_result(output, &branch_id, "rolled_back", change_count);
    } else if auto_commit {
        let result = client.commit_branch(&branch_id).await?;
        policy_rejected =
            output_run_result_with_governance(output, &branch_id, &result, change_count);
    } else {
        // Interactive prompt
        if !std::io::stdin().is_terminal() {
            eprintln!("[run] non-interactive stdin, rolling back (use --auto-commit to override)");
            client
                .rollback_branch(&branch_id, "non-interactive")
                .await?;
            output_run_result(output, &branch_id, "rolled_back", change_count);
        } else {
            match prompt_approve_reject()? {
                Decision::Approve => {
                    let result = client.commit_branch(&branch_id).await?;
                    policy_rejected = output_run_result_with_governance(
                        output,
                        &branch_id,
                        &result,
                        change_count,
                    );
                }
                Decision::Reject => {
                    client.rollback_branch(&branch_id, "user rejected").await?;
                    output_run_result(output, &branch_id, "rolled_back", change_count);
                }
                Decision::ShowDiff => {
                    print_diff_text(&diff_json);
                    eprint!("[run] approve? [y/N]: ");
                    std::io::Write::flush(&mut std::io::stderr())?;
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line)?;
                    if line.trim().eq_ignore_ascii_case("y") {
                        let result = client.commit_branch(&branch_id).await?;
                        policy_rejected = output_run_result_with_governance(
                            output,
                            &branch_id,
                            &result,
                            change_count,
                        );
                    } else {
                        client.rollback_branch(&branch_id, "user rejected").await?;
                        output_run_result(output, &branch_id, "rolled_back", change_count);
                    }
                }
            }
        }
    }
    if policy_rejected {
        anyhow::bail!("governance policy rejected the changes");
    }
    Ok(())
}
