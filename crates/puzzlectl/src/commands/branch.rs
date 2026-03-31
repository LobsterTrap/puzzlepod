// SPDX-License-Identifier: Apache-2.0
use crate::cli::OutputFormat;
use crate::client;
use crate::output::{
    filter_branches_by_state, output_action, output_json_or_text, validate_branch_id,
};
use anyhow::Result;
use puzzled_types::FileChange;

pub async fn handle(
    action: crate::cli::BranchAction,
    client: &client::PuzzledClient,
    output: OutputFormat,
) -> Result<()> {
    match action {
        crate::cli::BranchAction::List { state } => {
            let branches = client.list_branches().await?;
            // L-ctl1: Filter branches by state
            let filtered = filter_branches_by_state(&branches, &state);
            output_json_or_text(output, &filtered, print_branches_text);
        }
        crate::cli::BranchAction::Inspect { id } => {
            // M-ctl2: Validate branch ID before D-Bus call
            validate_branch_id(&id)?;
            let info = client.inspect_branch(&id).await?;
            output_json_or_text(output, &info, |s| println!("{s}"));
        }
        crate::cli::BranchAction::Approve { id } => {
            // M-ctl2: Validate branch ID before D-Bus call
            validate_branch_id(&id)?;
            let result = client.approve_branch(&id).await?;
            output_json_or_text(output, &result, |s| println!("{s}"));
        }
        crate::cli::BranchAction::Reject { id, reason } => {
            // M-ctl2: Validate branch ID before D-Bus call
            validate_branch_id(&id)?;
            // M27: Log and pass the rejection reason to D-Bus
            let reason_str = reason.as_deref().unwrap_or("");
            if !reason_str.is_empty() {
                eprintln!("Rejecting branch {id}: {reason_str}");
            }
            client.reject_branch(&id, reason_str).await?;
            output_action(
                output,
                "rejected",
                &id,
                reason_str,
                &format!("Branch {id} rejected and rolled back"),
            );
        }
        crate::cli::BranchAction::Rollback { id, reason } => {
            // M-ctl2: Validate branch ID before D-Bus call
            validate_branch_id(&id)?;
            let reason_str = reason.as_deref().unwrap_or("");
            client.rollback_branch(&id, reason_str).await?;
            let text_msg = if reason_str.is_empty() {
                format!("Branch {id} rolled back")
            } else {
                format!("Branch {id} rolled back: {reason_str}")
            };
            output_action(output, "rolled_back", &id, reason_str, &text_msg);
        }
        crate::cli::BranchAction::Diff { id } => {
            // M-ctl2: Validate branch ID before D-Bus call
            validate_branch_id(&id)?;
            let diff_json = client.diff_branch(&id).await?;
            match output {
                OutputFormat::Json => println!("{diff_json}"),
                OutputFormat::Text => print_diff_text(&diff_json),
            }
        }
        crate::cli::BranchAction::Create {
            profile,
            base,
            command,
        } => {
            let result = client.create_branch(&profile, &base, &command).await?;
            output_json_or_text(output, &result, |s| println!("{s}"));
        }
        crate::cli::BranchAction::Activate { id, command } => {
            validate_branch_id(&id)?;
            let result = client.activate_branch(&id, &command).await?;
            output_json_or_text(output, &result, |s| println!("{s}"));
        }
        crate::cli::BranchAction::Ensure {
            id_or_profile,
            profile,
            base,
        } => {
            let profile_name = profile.as_deref().unwrap_or(&id_or_profile);
            let result = client.ensure_branch(profile_name, &base).await?;
            output_json_or_text(output, &result, |s| println!("{s}"));
        }
        crate::cli::BranchAction::SeccompProfile {
            id,
            format,
            no_notif,
        } => {
            validate_branch_id(&id)?;
            let path = client.generate_seccomp_profile(&id).await?;
            // Strip USER_NOTIF rules and listenerPath if --no-notif
            if no_notif {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(mut profile) = serde_json::from_str::<serde_json::Value>(&content) {
                        // Remove listenerPath and listenerMetadata
                        if let Some(obj) = profile.as_object_mut() {
                            obj.remove("listenerPath");
                            obj.remove("listener_path");
                            obj.remove("listenerMetadata");
                            obj.remove("listener_metadata");
                        }
                        // Remove SCMP_ACT_NOTIFY rules
                        if let Some(syscalls) =
                            profile.get_mut("syscalls").and_then(|s| s.as_array_mut())
                        {
                            syscalls.retain(|rule| {
                                rule.get("action").and_then(|a| a.as_str())
                                    != Some("SCMP_ACT_NOTIFY")
                            });
                        }
                        let stripped = serde_json::to_string_pretty(&profile).unwrap_or(content);
                        std::fs::write(&path, &stripped).ok();
                    }
                }
            }
            match format.as_str() {
                "path" => println!("{path}"),
                _ => {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        println!("{content}");
                    } else {
                        println!("{path}");
                    }
                }
            }
        }
        crate::cli::BranchAction::LandlockRules { id, format } => {
            validate_branch_id(&id)?;
            let path = client.generate_landlock_rules(&id).await?;
            match format.as_str() {
                "path" => println!("{path}"),
                _ => {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        println!("{content}");
                    } else {
                        println!("{path}");
                    }
                }
            }
        }
    }
    Ok(())
}

/// Pretty-print a diff changeset in text mode.
pub fn print_diff_text(json: &str) {
    match serde_json::from_str::<Vec<FileChange>>(json) {
        Ok(changes) => {
            if changes.is_empty() {
                println!("No changes.");
                return;
            }
            for change in &changes {
                let prefix = match change.kind {
                    puzzled_types::FileChangeKind::Added => "+",
                    puzzled_types::FileChangeKind::Modified => "~",
                    puzzled_types::FileChangeKind::Deleted => "-",
                    puzzled_types::FileChangeKind::MetadataChanged => "M",
                    puzzled_types::FileChangeKind::Renamed => "R",
                    puzzled_types::FileChangeKind::Symlink => "S",
                    // Q6: New special file type variants
                    puzzled_types::FileChangeKind::Hardlink => "H",
                    puzzled_types::FileChangeKind::BlockDevice => "B",
                    puzzled_types::FileChangeKind::CharDevice => "C",
                    puzzled_types::FileChangeKind::Fifo => "F",
                };
                println!(
                    "{} {} ({} bytes)",
                    prefix,
                    change.path.display(),
                    change.size
                );
            }
            println!("\n{} file(s) changed", changes.len());
        }
        Err(e) => {
            eprintln!("Error parsing diff: {}", e);
            println!("{json}");
        }
    }
}

/// Pretty-print branches/agents list in text mode.
pub fn print_branches_text(json: &str) {
    match serde_json::from_str::<Vec<serde_json::Value>>(json) {
        Ok(branches) => {
            if branches.is_empty() {
                println!("No branches.");
                return;
            }
            println!(
                "{:<38} {:<15} {:<10} {:>6} {:<20}",
                "ID", "PROFILE", "STATE", "UID", "CREATED"
            );
            println!("{}", "-".repeat(89));
            for b in &branches {
                println!(
                    "{:<38} {:<15} {:<10} {:>6} {:<20}",
                    b.get("id").and_then(|v| v.as_str()).unwrap_or("-"),
                    b.get("profile").and_then(|v| v.as_str()).unwrap_or("-"),
                    b.get("state").and_then(|v| v.as_str()).unwrap_or("-"),
                    b.get("uid").and_then(|v| v.as_u64()).unwrap_or(0),
                    b.get("created_at").and_then(|v| v.as_str()).unwrap_or("-"),
                );
            }
        }
        Err(_) => {
            println!("{json}");
        }
    }
}
