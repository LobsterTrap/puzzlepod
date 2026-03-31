// SPDX-License-Identifier: Apache-2.0
use crate::cli::OutputFormat;
use crate::client;
use crate::commands::branch::print_branches_text;
use crate::output::{output_action, output_json_or_text, validate_branch_id};
use anyhow::Result;

pub async fn handle(
    action: crate::cli::AgentAction,
    client: &client::PuzzledClient,
    output: OutputFormat,
) -> Result<()> {
    match action {
        crate::cli::AgentAction::List => {
            let agents = client.list_agents().await?;
            output_json_or_text(output, &agents, print_branches_text);
        }
        crate::cli::AgentAction::Info { id } => {
            // M-ctl2: Validate branch ID before D-Bus call
            validate_branch_id(&id)?;
            let info = client.agent_info(&id).await?;
            output_json_or_text(output, &info, |s| println!("{s}"));
        }
        crate::cli::AgentAction::Kill { id } => {
            // M-ctl2: Validate branch ID before D-Bus call
            validate_branch_id(&id)?;
            client.kill_agent(&id).await?;
            output_action(
                output,
                "killed",
                &id,
                "",
                &format!("Agent {id} killed and branch rolled back"),
            );
        }
    }
    Ok(())
}
