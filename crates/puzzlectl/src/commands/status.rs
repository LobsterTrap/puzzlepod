// SPDX-License-Identifier: Apache-2.0
use crate::cli::OutputFormat;
use crate::client;
use crate::commands::branch::print_branches_text;
use crate::output::{output_json_or_text, validate_branch_id};
use anyhow::Result;

pub async fn handle(
    id: Option<String>,
    client: &client::PuzzledClient,
    output: OutputFormat,
) -> Result<()> {
    if let Some(branch_id) = id {
        validate_branch_id(&branch_id)?;
        let info = client.agent_info(&branch_id).await?;
        output_json_or_text(output, &info, |s| {
            println!("Branch status for {}:", branch_id);
            println!("{s}");
        });
    } else {
        let branches = client.list_branches().await?;
        match output {
            OutputFormat::Json => {
                let parsed: serde_json::Value = serde_json::from_str(&branches)
                    .unwrap_or(serde_json::Value::String(branches.clone()));
                let count = parsed.as_array().map(|a| a.len()).unwrap_or(0);
                let status = serde_json::json!({
                    "daemon": "connected",
                    "branch_count": count,
                    "branches": parsed,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&status).unwrap_or(branches)
                );
            }
            OutputFormat::Text => {
                println!("Daemon: connected");
                let parsed: Result<Vec<serde_json::Value>, _> = serde_json::from_str(&branches);
                match parsed {
                    Ok(list) => {
                        println!("Active branches: {}", list.len());
                        if !list.is_empty() {
                            println!();
                            print_branches_text(&branches);
                        }
                    }
                    Err(_) => println!("{branches}"),
                }
            }
        }
    }
    Ok(())
}
