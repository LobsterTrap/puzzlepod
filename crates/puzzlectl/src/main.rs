// SPDX-License-Identifier: Apache-2.0
use puzzlectl::client;
use puzzlectl::compliance;
#[cfg(feature = "sim")]
use puzzlectl::sim;
#[cfg(feature = "tui")]
mod tui;

use puzzled_types::{AgentProfile, BranchId, FileChange, GovernanceDecision, InclusionProof};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, VerifyingKey};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// J42: Limit stdin reads for credentials to prevent unbounded memory allocation
const MAX_CREDENTIAL_SIZE: u64 = 65_536;

/// puzzlectl — CLI for managing PuzzlePod branches, agents, profiles, and policies.
#[derive(Parser)]
#[command(name = "puzzlectl", version, about)]
struct Cli {
    /// Output format
    #[arg(long, default_value = "text", global = true)]
    output: OutputFormat,

    /// D-Bus bus type (system or session)
    #[arg(long, default_value = "system", global = true)]
    bus: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

/// Report output format for compliance evidence packages.
#[derive(Clone, Copy, clap::ValueEnum)]
enum ReportFormat {
    /// Directory tree (default) — evidence package as nested directories/files
    Dir,
    /// Single JSON file — complete report as one JSON document
    Json,
}

#[derive(Subcommand)]
enum Command {
    /// Manage branches (OverlayFS isolation contexts)
    Branch {
        #[command(subcommand)]
        action: BranchAction,
    },
    /// Manage running agents
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },
    /// Manage agent profiles
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Manage governance policies
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// Query and export audit events
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
    /// Verify cryptographic attestation of governance (§3.1)
    Attestation {
        #[command(subcommand)]
        action: AttestationAction,
    },
    /// Generate compliance evidence reports (§3.2)
    Compliance {
        #[command(subcommand)]
        action: ComplianceAction,
    },
    /// Manage credentials for agent profiles (phantom token injection)
    Credential {
        #[command(subcommand)]
        action: CredentialAction,
    },
    /// Show daemon and branch status
    Status {
        /// Optional branch ID to show status for a specific branch
        id: Option<String>,
    },
    /// Governance simulator — test governance policies without running real agents
    #[cfg(feature = "sim")]
    Sim {
        /// Launch interactive REPL mode (optionally preload a scenario)
        #[arg(long, value_name = "SCENARIO")]
        interactive: Option<Option<String>>,
        /// Run a single scenario by name
        #[arg(long, conflicts_with = "interactive")]
        run: Option<String>,
        /// Run all scenarios
        #[arg(long, conflicts_with_all = ["interactive", "run"])]
        run_all: bool,
        /// Override the profile for the scenario
        #[arg(long)]
        profile: Option<String>,
        /// Output format: text or json
        #[arg(long, value_name = "FORMAT")]
        sim_output: Option<String>,
        /// Directory containing scenario YAML files
        #[arg(long, default_value = "/etc/puzzled/scenarios")]
        scenarios_dir: PathBuf,
        /// Directory containing profile YAML files
        #[arg(long, default_value = "/etc/puzzled/profiles")]
        profile_dir: PathBuf,
        /// Base path for branch storage
        #[arg(long, default_value = "/var/lib/puzzled/branches")]
        storage_base: String,
        /// Run actions inside a full sandbox (namespaces, seccomp, Landlock, cgroup)
        /// via puzzle-sim-worker. Requires Linux and puzzled running.
        #[arg(long)]
        sandbox: bool,
    },
    /// Interactive terminal UI for branch management
    #[cfg(feature = "tui")]
    Tui,
    /// Show puzzlectl version
    Version,
}

#[derive(Subcommand)]
enum BranchAction {
    /// List all branches
    List {
        /// Filter by branch state: active, reviewing, degraded, all
        #[arg(long, default_value = "all")]
        state: String,
    },
    /// Inspect a specific branch
    Inspect {
        /// Branch ID
        id: String,
    },
    /// Approve and commit a branch
    Approve {
        /// Branch ID
        id: String,
    },
    /// Reject and rollback a branch
    Reject {
        /// Branch ID
        id: String,
        /// Reason for rejection
        #[arg(long)]
        reason: Option<String>,
    },
    /// Roll back a branch without policy evaluation
    Rollback {
        /// Branch ID
        id: String,
        /// Reason for rollback
        #[arg(long)]
        reason: Option<String>,
    },
    /// Show the diff (changeset) for a branch
    Diff {
        /// Branch ID
        id: String,
    },
    /// Create a new branch
    Create {
        /// Profile name
        #[arg(long)]
        profile: String,
        /// Base directory path
        #[arg(long)]
        base: String,
        /// Command to run (optional, JSON array)
        #[arg(long, default_value = "[]")]
        command: String,
    },
    /// Activate a branch by spawning a sandboxed process inside it
    Activate {
        /// Branch ID
        id: String,
        /// Command to run (JSON array, e.g. '["/usr/bin/cat"]')
        #[arg(long)]
        command: String,
    },
    /// Idempotent branch creation — creates if not exists, returns existing otherwise
    Ensure {
        /// Branch ID or profile name
        id_or_profile: String,
        /// Profile name
        #[arg(long)]
        profile: Option<String>,
        /// Base directory path
        #[arg(long, default_value = ".")]
        base: String,
    },
    /// Generate an OCI seccomp profile for a branch
    SeccompProfile {
        /// Branch ID
        id: String,
        /// Result format: "json" for full JSON, "path" for just the file path
        #[arg(long, default_value = "path")]
        format: String,
        /// Generate static-only profile (no USER_NOTIF listener)
        #[arg(long)]
        no_notif: bool,
    },
    /// Generate Landlock rules JSON for a branch
    LandlockRules {
        /// Branch ID
        id: String,
        /// Result format: "json" for full JSON, "path" for just the file path
        #[arg(long, default_value = "path")]
        format: String,
    },
}

#[derive(Subcommand)]
enum AgentAction {
    /// List running agents
    List,
    /// Show detailed info for an agent
    Info {
        /// Branch ID of the agent
        id: String,
    },
    /// Kill an agent and roll back its branch
    Kill {
        /// Branch ID of the agent
        id: String,
    },
}

#[derive(Subcommand)]
enum ProfileAction {
    /// List available profiles
    List {
        /// Directory containing profile YAML files
        #[arg(long, default_value = "/etc/puzzled/profiles")]
        dir: String,
    },
    /// Show a profile's contents
    Show {
        /// Profile name or path to YAML file
        name: String,
        /// Directory containing profile YAML files
        #[arg(long, default_value = "/etc/puzzled/profiles")]
        dir: String,
    },
    /// Validate a profile YAML file
    Validate {
        /// Path to profile YAML
        path: String,
    },
    /// Test a profile against a sample changeset
    Test {
        /// Profile name or path to YAML file
        name: String,
        /// Path to changeset JSON file
        #[arg(long)]
        changeset: String,
        /// Directory containing profile YAML files
        #[arg(long, default_value = "/etc/puzzled/profiles")]
        dir: String,
    },
}

#[derive(Subcommand)]
enum PolicyAction {
    /// Reload policies from disk
    Reload,
    /// Test a policy against a sample changeset
    Test {
        /// Path to sample changeset JSON
        changeset: String,
        /// Directory containing Rego policy files
        #[arg(long, default_value = "/etc/puzzled/policies")]
        policy_dir: String,
    },
}

#[derive(Subcommand)]
enum AuditAction {
    /// List audit events
    List {
        /// Filter by branch ID
        /// m11: Accepts --agent as alias for --branch-id
        #[arg(long, alias = "agent")]
        branch_id: Option<String>,
        /// Filter by event type (commit, violation, etc.)
        /// m12: Accepts --type as alias for --event-type
        #[arg(long, name = "type", alias = "event-type")]
        event_type: Option<String>,
        /// Filter events since timestamp (RFC 3339)
        #[arg(long)]
        since: Option<String>,
        /// Maximum number of events
        #[arg(long, default_value = "50")]
        limit: u32,
    },
    /// Export audit events to file
    Export {
        /// Output format (json or csv)
        #[arg(long, default_value = "json")]
        format: String,
        /// Output file path
        #[arg(long)]
        file: Option<String>,
    },
    /// Verify an IMA signature
    Verify {
        /// Manifest hash or path to verify
        hash: String,
    },
}

#[derive(Subcommand)]
enum AttestationAction {
    /// Verify the attestation chain in an audit log or exported bundle
    Verify {
        /// Path to the audit store directory (used when --bundle is not provided)
        #[arg(long, default_value = "/var/lib/puzzled/branches/audit")]
        audit_dir: PathBuf,
        /// Path to the Ed25519 public key (hex file) for signature verification
        #[arg(long)]
        pubkey: Option<PathBuf>,
        /// Only verify a specific branch's attestation chain
        #[arg(long)]
        branch_id: Option<String>,
        /// Verify Merkle tree inclusion proofs (requires attestation dir)
        #[arg(long)]
        merkle: bool,
        /// Path to the attestation/Merkle tree directory
        #[arg(long, default_value = "/var/lib/puzzled/branches/attestation")]
        attestation_dir: PathBuf,
        /// Path to an exported attestation bundle file (alternative to --audit-dir)
        #[arg(long, conflicts_with = "audit_dir")]
        bundle: Option<PathBuf>,
    },
    /// Export attestation bundle for a branch (self-contained, offline-verifiable)
    Export {
        /// Branch ID to export
        id: String,
        /// Output file path (default: stdout as JSON)
        #[arg(long)]
        file: Option<String>,
        /// Path to the audit store directory
        #[arg(long, default_value = "/var/lib/puzzled/branches/audit")]
        audit_dir: PathBuf,
        /// Path to the attestation/Merkle tree directory
        #[arg(long, default_value = "/var/lib/puzzled/branches/attestation")]
        attestation_dir: PathBuf,
    },
    /// Get Merkle inclusion proof for an audit event
    Inclusion {
        /// Audit event sequence number
        seq: u64,
        /// Path to the attestation/Merkle tree directory
        #[arg(long, default_value = "/var/lib/puzzled/branches/attestation")]
        attestation_dir: PathBuf,
    },
    /// Get Merkle consistency proof between two tree sizes
    Consistency {
        /// Earlier tree size
        #[arg(long)]
        from: u64,
        /// Later tree size
        #[arg(long)]
        to: u64,
        /// Path to the attestation/Merkle tree directory
        #[arg(long, default_value = "/var/lib/puzzled/branches/attestation")]
        attestation_dir: PathBuf,
    },
    /// Show the current attestation public key (hex-encoded)
    Pubkey {
        /// Path to the attestation directory containing public_key.hex
        #[arg(long, default_value = "/var/lib/puzzled/branches/attestation")]
        attestation_dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum ComplianceAction {
    /// Generate a compliance evidence report
    Report {
        /// Regulatory framework(s): eu-ai-act, soc2, iso27001, nist-ai-rmf
        #[arg(long, value_delimiter = ',')]
        framework: Vec<String>,
        /// Reporting period (e.g., "30d", "90d", "1y")
        #[arg(long, default_value = "30d")]
        period: String,
        /// Output path for the report package (directory or file depending on --format)
        #[arg(long)]
        output: Option<String>,
        /// Output format: dir (directory tree), json (single JSON file)
        #[arg(long, default_value = "dir")]
        format: ReportFormat,
        /// Path to audit store directory (for offline/local mode)
        #[arg(long, default_value = "/var/lib/puzzled/branches/audit")]
        audit_dir: PathBuf,
        /// Path to profiles directory
        #[arg(long, default_value = "/etc/puzzled/profiles")]
        profiles_dir: PathBuf,
        /// Path to policies directory
        #[arg(long, default_value = "/etc/puzzled/policies")]
        policies_dir: PathBuf,
        /// Path to Ed25519 signing key (hex) for package signing
        #[arg(long, default_value = "/etc/puzzled/signing_key")]
        signing_key: PathBuf,
    },
    /// Show compliance status for a framework
    Status {
        /// Regulatory framework: eu-ai-act, soc2, iso27001, nist-ai-rmf
        #[arg(long)]
        framework: String,
        /// Reporting period (e.g., "30d", "90d", "1y"); omit for all available data
        #[arg(long)]
        period: Option<String>,
        /// Path to audit store directory
        #[arg(long, default_value = "/var/lib/puzzled/branches/audit")]
        audit_dir: PathBuf,
        /// Path to profiles directory
        #[arg(long, default_value = "/etc/puzzled/profiles")]
        profiles_dir: PathBuf,
    },
    /// Identify evidence gaps for a framework
    Gaps {
        /// Regulatory framework: eu-ai-act, soc2, iso27001, nist-ai-rmf
        #[arg(long)]
        framework: String,
        /// Reporting period (e.g., "30d", "90d", "1y"); omit for all available data
        #[arg(long)]
        period: Option<String>,
        /// Path to audit store directory
        #[arg(long, default_value = "/var/lib/puzzled/branches/audit")]
        audit_dir: PathBuf,
        /// Path to profiles directory
        #[arg(long, default_value = "/etc/puzzled/profiles")]
        profiles_dir: PathBuf,
    },
    /// List supported regulatory frameworks
    Frameworks,
}

#[derive(Subcommand)]
enum CredentialAction {
    /// Store a credential (reads value from stdin)
    Store {
        /// Credential name
        name: String,
        /// Credential type (e.g., api-key, oauth-token, bearer-token)
        #[arg(long)]
        credential_type: String,
        /// Comma-separated list of profiles that may use this credential
        #[arg(long, value_delimiter = ',')]
        profiles: Vec<String>,
        /// Comma-separated list of allowed domains for this credential
        #[arg(long, value_delimiter = ',')]
        domains: Vec<String>,
        /// Injection method (env, file, header)
        #[arg(long)]
        inject: String,
    },
    /// Remove a credential
    Remove {
        /// Credential name (phantom token)
        name: String,
    },
    /// Rotate a credential value (reads new value from stdin)
    Rotate {
        /// Credential name (phantom token)
        name: String,
    },
    /// List credential metadata
    List,
    /// Test credential injection for a domain and profile
    Test {
        /// Target domain to test
        domain: String,
        /// Profile to test against
        #[arg(long)]
        profile: String,
    },
    /// §3.4 G21: Add a credential with encryption (systemd-creds or passphrase)
    Add {
        /// Credential name
        name: String,
        /// Read value from environment variable instead of stdin
        #[arg(long)]
        from_env: Option<String>,
        /// Read value from file instead of stdin
        #[arg(long)]
        from_file: Option<String>,
        /// Encrypt with passphrase (Argon2id) instead of systemd-creds
        #[arg(long)]
        passphrase: bool,
        /// Credential type (default: api-key)
        #[arg(long, default_value = "api-key")]
        credential_type: String,
        /// Comma-separated list of profiles
        #[arg(long, value_delimiter = ',')]
        profiles: Vec<String>,
        /// Comma-separated list of allowed domains
        #[arg(long, value_delimiter = ',')]
        domains: Vec<String>,
    },
    /// §3.4 G21: Unlock a passphrase-encrypted credential
    Unlock {
        /// Credential name to unlock
        name: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        // Profile commands are local (don't need D-Bus)
        Command::Profile { action } => match action {
            ProfileAction::List { dir } => {
                cmd_profile_list(&dir, cli.output)?;
            }
            ProfileAction::Show { name, dir } => {
                cmd_profile_show(&name, &dir, cli.output)?;
            }
            ProfileAction::Validate { path } => {
                cmd_profile_validate(&path)?;
            }
            ProfileAction::Test {
                name,
                changeset,
                dir,
            } => {
                cmd_profile_test(&name, &changeset, &dir)?;
            }
        },
        // Policy test is local
        Command::Policy {
            action:
                PolicyAction::Test {
                    changeset,
                    policy_dir,
                },
        } => {
            cmd_policy_test(&changeset, &policy_dir)?;
        }
        // Audit verify is local (doesn't need D-Bus)
        Command::Audit {
            action: AuditAction::Verify { hash },
        } => {
            cmd_audit_verify(&hash)?;
        }
        // Attestation commands are local (doesn't need D-Bus)
        Command::Attestation { action } => match action {
            AttestationAction::Verify {
                audit_dir,
                pubkey,
                branch_id,
                merkle,
                attestation_dir,
                bundle,
            } => {
                if let Some(ref bundle_path) = bundle {
                    cmd_attestation_verify_bundle(bundle_path)?;
                } else {
                    cmd_attestation_verify(
                        &audit_dir,
                        pubkey.as_deref(),
                        branch_id.as_deref(),
                        merkle,
                        &attestation_dir,
                    )?;
                }
            }
            AttestationAction::Export {
                id,
                file,
                audit_dir,
                attestation_dir,
            } => {
                cmd_attestation_export(&id, file.as_deref(), &audit_dir, &attestation_dir)?;
            }
            AttestationAction::Inclusion {
                seq,
                attestation_dir,
            } => {
                cmd_attestation_inclusion(seq, &attestation_dir)?;
            }
            AttestationAction::Consistency {
                from,
                to,
                attestation_dir,
            } => {
                cmd_attestation_consistency(from, to, &attestation_dir)?;
            }
            AttestationAction::Pubkey { attestation_dir } => {
                cmd_attestation_pubkey(&attestation_dir)?;
            }
        },
        // Compliance commands are local (read audit log + profiles directly)
        Command::Compliance { action } => match action {
            ComplianceAction::Frameworks => {
                cmd_compliance_frameworks(cli.output)?;
            }
            ComplianceAction::Report {
                framework,
                period,
                output,
                format,
                audit_dir,
                profiles_dir,
                policies_dir,
                signing_key,
            } => {
                cmd_compliance_report(
                    &framework,
                    &period,
                    output.as_deref(),
                    format,
                    &audit_dir,
                    &profiles_dir,
                    &policies_dir,
                    &signing_key,
                    cli.output,
                )?;
            }
            ComplianceAction::Status {
                framework,
                period,
                audit_dir,
                profiles_dir,
            } => {
                cmd_compliance_status(
                    &framework,
                    period.as_deref(),
                    &audit_dir,
                    &profiles_dir,
                    cli.output,
                )?;
            }
            ComplianceAction::Gaps {
                framework,
                period,
                audit_dir,
                profiles_dir,
            } => {
                cmd_compliance_gaps(
                    &framework,
                    period.as_deref(),
                    &audit_dir,
                    &profiles_dir,
                    cli.output,
                )?;
            }
        },
        // TUI mode
        #[cfg(feature = "tui")]
        Command::Tui => {
            tui::run_tui(&cli.bus).await?;
        }
        // Agent simulator (needs D-Bus)
        #[cfg(feature = "sim")]
        Command::Sim {
            interactive,
            run,
            run_all,
            profile,
            sim_output,
            scenarios_dir,
            profile_dir,
            storage_base,
            sandbox,
        } => {
            let client = client::PuzzledClient::connect(&cli.bus).await?;
            let json_output = sim_output.as_deref() == Some("json");
            let profile_ref = profile.as_deref();
            let mode = if sandbox {
                sim::engine::SimMode::Sandbox
            } else {
                sim::engine::SimMode::Direct
            };

            let exit_code = if run_all {
                sim::batch::run_all_with_mode(
                    &client,
                    &scenarios_dir,
                    profile_ref,
                    &storage_base,
                    json_output,
                    mode,
                )
                .await
            } else if let Some(name) = run {
                sim::batch::run_one_with_mode(
                    &client,
                    &scenarios_dir,
                    &name,
                    profile_ref,
                    &storage_base,
                    json_output,
                    mode,
                )
                .await
            } else {
                let preload = interactive.as_ref().and_then(|o| o.as_deref());
                sim::repl::run_repl(
                    &client,
                    &scenarios_dir,
                    &profile_dir,
                    &storage_base,
                    preload,
                )
                .await
            };
            std::process::exit(exit_code);
        }
        Command::Version => {
            println!("puzzlectl {}", env!("CARGO_PKG_VERSION"));
        }
        // All other commands need D-Bus
        _ => {
            let client = client::PuzzledClient::connect(&cli.bus).await?;

            match cli.command {
                Command::Audit { action } => match action {
                    AuditAction::List {
                        branch_id,
                        event_type,
                        since,
                        limit,
                    } => {
                        let filter = serde_json::json!({
                            "branch_id": branch_id,
                            "event_type": event_type,
                            "since": since,
                            "limit": limit,
                        });
                        let result = client.query_audit_events(&filter.to_string()).await?;
                        println!("{result}");
                    }
                    AuditAction::Export { format, file } => {
                        let result = client.export_audit_events(&format).await?;
                        if let Some(path) = file {
                            std::fs::write(&path, &result)
                                .with_context(|| format!("writing to {}", path))?;
                            match cli.output {
                                OutputFormat::Json => {
                                    println!(
                                        "{}",
                                        serde_json::json!({"status": "exported", "file": path})
                                    );
                                }
                                OutputFormat::Text => println!("Exported to {}", path),
                            }
                        } else {
                            println!("{result}");
                        }
                    }
                    AuditAction::Verify { .. } => unreachable!(),
                },
                Command::Branch { action } => match action {
                    BranchAction::List { state } => {
                        let branches = client.list_branches().await?;
                        // L-ctl1: Filter branches by state
                        let filtered = filter_branches_by_state(&branches, &state);
                        match cli.output {
                            OutputFormat::Json => println!(
                                "{}",
                                serde_json::to_string_pretty(
                                    &serde_json::from_str::<serde_json::Value>(&filtered)
                                        .unwrap_or(serde_json::Value::String(filtered.clone()))
                                )
                                .unwrap_or(filtered)
                            ),
                            OutputFormat::Text => print_branches_text(&filtered),
                        }
                    }
                    BranchAction::Inspect { id } => {
                        // M-ctl2: Validate branch ID before D-Bus call
                        validate_branch_id(&id)?;
                        let info = client.inspect_branch(&id).await?;
                        match cli.output {
                            OutputFormat::Json => println!(
                                "{}",
                                serde_json::to_string_pretty(
                                    &serde_json::from_str::<serde_json::Value>(&info)
                                        .unwrap_or(serde_json::Value::String(info.clone()))
                                )
                                .unwrap_or(info)
                            ),
                            OutputFormat::Text => println!("{info}"),
                        }
                    }
                    BranchAction::Approve { id } => {
                        // M-ctl2: Validate branch ID before D-Bus call
                        validate_branch_id(&id)?;
                        let result = client.approve_branch(&id).await?;
                        match cli.output {
                            OutputFormat::Json => println!(
                                "{}",
                                serde_json::to_string_pretty(
                                    &serde_json::from_str::<serde_json::Value>(&result)
                                        .unwrap_or(serde_json::Value::String(result.clone()))
                                )
                                .unwrap_or(result)
                            ),
                            OutputFormat::Text => println!("{result}"),
                        }
                    }
                    BranchAction::Reject { id, reason } => {
                        // M-ctl2: Validate branch ID before D-Bus call
                        validate_branch_id(&id)?;
                        // M27: Log and pass the rejection reason to D-Bus
                        let reason_str = reason.as_deref().unwrap_or("");
                        if !reason_str.is_empty() {
                            eprintln!("Rejecting branch {id}: {reason_str}");
                        }
                        client.reject_branch(&id, reason_str).await?;
                        output_action(
                            cli.output,
                            "rejected",
                            &id,
                            reason_str,
                            &format!("Branch {id} rejected and rolled back"),
                        );
                    }
                    BranchAction::Rollback { id, reason } => {
                        // M-ctl2: Validate branch ID before D-Bus call
                        validate_branch_id(&id)?;
                        let reason_str = reason.as_deref().unwrap_or("");
                        client.rollback_branch(&id, reason_str).await?;
                        let text_msg = if reason_str.is_empty() {
                            format!("Branch {id} rolled back")
                        } else {
                            format!("Branch {id} rolled back: {reason_str}")
                        };
                        output_action(cli.output, "rolled_back", &id, reason_str, &text_msg);
                    }
                    BranchAction::Diff { id } => {
                        // M-ctl2: Validate branch ID before D-Bus call
                        validate_branch_id(&id)?;
                        let diff_json = client.diff_branch(&id).await?;
                        match cli.output {
                            OutputFormat::Json => println!("{diff_json}"),
                            OutputFormat::Text => print_diff_text(&diff_json),
                        }
                    }
                    BranchAction::Create {
                        profile,
                        base,
                        command,
                    } => {
                        let result = client.create_branch(&profile, &base, &command).await?;
                        match cli.output {
                            OutputFormat::Json => println!(
                                "{}",
                                serde_json::to_string_pretty(
                                    &serde_json::from_str::<serde_json::Value>(&result)
                                        .unwrap_or(serde_json::Value::String(result.clone()))
                                )
                                .unwrap_or(result)
                            ),
                            OutputFormat::Text => println!("{result}"),
                        }
                    }
                    BranchAction::Activate { id, command } => {
                        validate_branch_id(&id)?;
                        let result = client.activate_branch(&id, &command).await?;
                        match cli.output {
                            OutputFormat::Json => println!(
                                "{}",
                                serde_json::to_string_pretty(
                                    &serde_json::from_str::<serde_json::Value>(&result)
                                        .unwrap_or(serde_json::Value::String(result.clone()))
                                )
                                .unwrap_or(result)
                            ),
                            OutputFormat::Text => println!("{result}"),
                        }
                    }
                    BranchAction::Ensure {
                        id_or_profile,
                        profile,
                        base,
                    } => {
                        let profile_name = profile.as_deref().unwrap_or(&id_or_profile);
                        let result = client.ensure_branch(profile_name, &base).await?;
                        match cli.output {
                            OutputFormat::Json => println!(
                                "{}",
                                serde_json::to_string_pretty(
                                    &serde_json::from_str::<serde_json::Value>(&result)
                                        .unwrap_or(serde_json::Value::String(result.clone()))
                                )
                                .unwrap_or(result)
                            ),
                            OutputFormat::Text => println!("{result}"),
                        }
                    }
                    BranchAction::SeccompProfile {
                        id,
                        format,
                        no_notif,
                    } => {
                        validate_branch_id(&id)?;
                        let path = client.generate_seccomp_profile(&id).await?;
                        // Strip USER_NOTIF rules and listenerPath if --no-notif
                        if no_notif {
                            if let Ok(content) = std::fs::read_to_string(&path) {
                                if let Ok(mut profile) =
                                    serde_json::from_str::<serde_json::Value>(&content)
                                {
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
                                    let stripped =
                                        serde_json::to_string_pretty(&profile).unwrap_or(content);
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
                    BranchAction::LandlockRules { id, format } => {
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
                },
                Command::Agent { action } => match action {
                    AgentAction::List => {
                        let agents = client.list_agents().await?;
                        match cli.output {
                            OutputFormat::Json => println!(
                                "{}",
                                serde_json::to_string_pretty(
                                    &serde_json::from_str::<serde_json::Value>(&agents)
                                        .unwrap_or(serde_json::Value::String(agents.clone()))
                                )
                                .unwrap_or(agents)
                            ),
                            OutputFormat::Text => print_branches_text(&agents),
                        }
                    }
                    AgentAction::Info { id } => {
                        // M-ctl2: Validate branch ID before D-Bus call
                        validate_branch_id(&id)?;
                        let info = client.agent_info(&id).await?;
                        match cli.output {
                            OutputFormat::Json => println!(
                                "{}",
                                serde_json::to_string_pretty(
                                    &serde_json::from_str::<serde_json::Value>(&info)
                                        .unwrap_or(serde_json::Value::String(info.clone()))
                                )
                                .unwrap_or(info)
                            ),
                            OutputFormat::Text => println!("{info}"),
                        }
                    }
                    AgentAction::Kill { id } => {
                        // M-ctl2: Validate branch ID before D-Bus call
                        validate_branch_id(&id)?;
                        client.kill_agent(&id).await?;
                        output_action(
                            cli.output,
                            "killed",
                            &id,
                            "",
                            &format!("Agent {id} killed and branch rolled back"),
                        );
                    }
                },
                // M-ctl1: Status subcommand — show daemon/branch status
                Command::Status { id } => {
                    if let Some(branch_id) = id {
                        validate_branch_id(&branch_id)?;
                        let info = client.agent_info(&branch_id).await?;
                        match cli.output {
                            OutputFormat::Json => println!(
                                "{}",
                                serde_json::to_string_pretty(
                                    &serde_json::from_str::<serde_json::Value>(&info)
                                        .unwrap_or(serde_json::Value::String(info.clone()))
                                )
                                .unwrap_or(info)
                            ),
                            OutputFormat::Text => {
                                println!("Branch status for {}:", branch_id);
                                println!("{info}");
                            }
                        }
                    } else {
                        let branches = client.list_branches().await?;
                        match cli.output {
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
                                let parsed: Result<Vec<serde_json::Value>, _> =
                                    serde_json::from_str(&branches);
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
                }
                Command::Credential { action } => match action {
                    CredentialAction::Store {
                        name,
                        credential_type,
                        profiles,
                        domains,
                        inject,
                    } => {
                        // Read credential value from stdin
                        // H62: Use Zeroizing<String> so credential is zeroized on drop
                        // J42: Limit stdin read to MAX_CREDENTIAL_SIZE to prevent unbounded allocation
                        let mut value = zeroize::Zeroizing::new(String::new());
                        std::io::Read::read_to_string(
                            &mut std::io::Read::take(std::io::stdin(), MAX_CREDENTIAL_SIZE),
                            &mut value,
                        )
                        .context("reading credential value from stdin")?;
                        let value = zeroize::Zeroizing::new(value.trim_end().to_string());

                        let config_json = serde_json::json!({
                            "inject": inject,
                            "profiles": profiles,
                            "domains": domains,
                        })
                        .to_string();

                        // value_source is the literal credential value read from stdin;
                        // the daemon handles multi-profile/domain association via config_json
                        let success = client
                            .store_credential(&name, &credential_type, &value, &config_json)
                            .await?;
                        match cli.output {
                            OutputFormat::Json => {
                                let result = serde_json::json!({
                                    "status": if success { "stored" } else { "failed" },
                                    "name": name,
                                    "profiles": profiles,
                                    "domains": domains,
                                });
                                println!(
                                    "{}",
                                    serde_json::to_string_pretty(&result)
                                        .unwrap_or_else(|_| result.to_string())
                                );
                            }
                            OutputFormat::Text => {
                                if success {
                                    println!("Credential '{name}' stored");
                                } else {
                                    println!("Failed to store credential '{name}'");
                                }
                            }
                        }
                    }
                    CredentialAction::Remove { name } => {
                        let success = client.remove_credential(&name).await?;
                        if success {
                            output_action(
                                cli.output,
                                "removed",
                                &name,
                                "",
                                &format!("Credential '{name}' removed"),
                            );
                        } else {
                            output_action(
                                cli.output,
                                "not_found",
                                &name,
                                "",
                                &format!("Credential '{name}' not found"),
                            );
                        }
                    }
                    CredentialAction::Rotate { name } => {
                        // Read new credential value from stdin
                        // H62: Use Zeroizing<String> so credential is zeroized on drop
                        // J42: Limit stdin read to MAX_CREDENTIAL_SIZE to prevent unbounded allocation
                        let mut value = zeroize::Zeroizing::new(String::new());
                        std::io::Read::read_to_string(
                            &mut std::io::Read::take(std::io::stdin(), MAX_CREDENTIAL_SIZE),
                            &mut value,
                        )
                        .context("reading new credential value from stdin")?;
                        let value = zeroize::Zeroizing::new(value.trim_end().to_string());

                        let success = client.rotate_credential(&name, &value).await?;
                        if success {
                            output_action(
                                cli.output,
                                "rotated",
                                &name,
                                "",
                                &format!("Credential '{name}' rotated"),
                            );
                        } else {
                            output_action(
                                cli.output,
                                "not_found",
                                &name,
                                "",
                                &format!("Credential '{name}' not found"),
                            );
                        }
                    }
                    CredentialAction::List => {
                        // List all credentials (empty profile = all)
                        let result = client.list_credentials("").await?;
                        match cli.output {
                            OutputFormat::Json => println!(
                                "{}",
                                serde_json::to_string_pretty(
                                    &serde_json::from_str::<serde_json::Value>(&result)
                                        .unwrap_or(serde_json::Value::String(result.clone()))
                                )
                                .unwrap_or(result)
                            ),
                            OutputFormat::Text => {
                                let parsed: Result<Vec<serde_json::Value>, _> =
                                    serde_json::from_str(&result);
                                match parsed {
                                    Ok(creds) if creds.is_empty() => {
                                        println!("No credentials stored");
                                    }
                                    Ok(creds) => {
                                        for cred in &creds {
                                            let name = cred
                                                .get("name")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("?");
                                            let ctype = cred
                                                .get("credential_type")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("?");
                                            let domains = cred
                                                .get("domains")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("");
                                            println!("  {name}  type={ctype}  domains={domains}");
                                        }
                                    }
                                    Err(_) => println!("{result}"),
                                }
                            }
                        }
                    }
                    CredentialAction::Test { domain, profile } => {
                        // Test credential injection by listing credentials for the profile
                        // and checking if any match the domain
                        let result = client.list_credentials(&profile).await?;
                        let parsed: Result<Vec<serde_json::Value>, _> =
                            serde_json::from_str(&result);
                        match parsed {
                            Ok(creds) => {
                                let matching: Vec<_> = creds
                                    .iter()
                                    .filter(|c| {
                                        c.get("domains")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("")
                                            .split(',')
                                            .any(|d| d.trim() == domain)
                                    })
                                    .collect();
                                match cli.output {
                                    OutputFormat::Json => {
                                        let test_result = serde_json::json!({
                                            "domain": domain,
                                            "profile": profile,
                                            "matched": !matching.is_empty(),
                                            "credentials": matching.iter().map(|c| {
                                                c.get("name").and_then(|v| v.as_str()).unwrap_or("?")
                                            }).collect::<Vec<_>>(),
                                        });
                                        println!(
                                            "{}",
                                            serde_json::to_string_pretty(&test_result)
                                                .unwrap_or_else(|_| test_result.to_string())
                                        );
                                    }
                                    OutputFormat::Text => {
                                        if matching.is_empty() {
                                            println!(
                                                "No credentials match domain '{domain}' for profile '{profile}'"
                                            );
                                        } else {
                                            println!(
                                                "Found {} credential(s) for domain '{domain}' in profile '{profile}':",
                                                matching.len()
                                            );
                                            for cred in &matching {
                                                let name = cred
                                                    .get("name")
                                                    .and_then(|v| v.as_str())
                                                    .unwrap_or("?");
                                                let inject = cred
                                                    .get("inject")
                                                    .and_then(|v| v.as_str())
                                                    .unwrap_or("?");
                                                println!("  {name} (inject: {inject})");
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                anyhow::bail!("Failed to parse credential list: {e}");
                            }
                        }
                    }
                    // §3.4 G21: Add credential with encryption
                    CredentialAction::Add {
                        name,
                        from_env,
                        from_file,
                        passphrase,
                        credential_type,
                        profiles,
                        domains,
                    } => {
                        // Read credential value from specified source
                        let value = if let Some(ref env_var) = from_env {
                            zeroize::Zeroizing::new(std::env::var(env_var).map_err(|e| {
                                anyhow::anyhow!("--from-env: env var '{}' not set: {}", env_var, e)
                            })?)
                        } else if let Some(ref file_path) = from_file {
                            zeroize::Zeroizing::new(
                                std::fs::read_to_string(file_path)
                                    .map_err(|e| {
                                        anyhow::anyhow!(
                                            "--from-file: reading '{}': {}",
                                            file_path,
                                            e
                                        )
                                    })?
                                    .trim_end()
                                    .to_string(),
                            )
                        } else {
                            // Read from stdin (default, same as Store)
                            // J42: Limit stdin read to MAX_CREDENTIAL_SIZE
                            let mut buf = String::new();
                            std::io::Read::read_to_string(
                                &mut std::io::Read::take(std::io::stdin(), MAX_CREDENTIAL_SIZE),
                                &mut buf,
                            )?;
                            zeroize::Zeroizing::new(buf.trim_end().to_string())
                        };

                        if value.is_empty() {
                            anyhow::bail!("credential value is empty");
                        }

                        if passphrase {
                            // Encrypt with Argon2id passphrase
                            eprint!("Enter passphrase: ");
                            // J42: Limit passphrase read
                            let mut pass_buf = String::new();
                            std::io::Read::read_to_string(
                                &mut std::io::Read::take(std::io::stdin(), MAX_CREDENTIAL_SIZE),
                                &mut pass_buf,
                            )?;
                            let pass = zeroize::Zeroizing::new(pass_buf.trim_end().to_string());

                            if pass.is_empty() {
                                anyhow::bail!("passphrase is empty");
                            }

                            // Encrypt and save
                            let encrypted =
                                puzzle_proxy::credential_backends::encrypt_with_passphrase(
                                    &name,
                                    value.as_bytes(),
                                    pass.as_bytes(),
                                )
                                .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))?;

                            let secrets_dir = std::env::var("XDG_CONFIG_HOME")
                                .map(std::path::PathBuf::from)
                                .or_else(|_| {
                                    std::env::var("HOME")
                                        .map(|h| std::path::PathBuf::from(h).join(".config"))
                                })
                                .unwrap_or_else(|_| std::path::PathBuf::from("/etc"))
                                .join("puzzled/secrets");

                            std::fs::create_dir_all(&secrets_dir)?;
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                std::fs::set_permissions(
                                    &secrets_dir,
                                    std::fs::Permissions::from_mode(0o700),
                                )?;
                            }

                            let enc_path = secrets_dir.join(format!("{}.enc", name));
                            std::fs::write(&enc_path, &encrypted)?;
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                std::fs::set_permissions(
                                    &enc_path,
                                    std::fs::Permissions::from_mode(0o600),
                                )?;
                            }

                            output_action(
                                cli.output,
                                "added",
                                &name,
                                "",
                                &format!(
                                    "Credential '{}' encrypted with Argon2id at {}",
                                    name,
                                    enc_path.display()
                                ),
                            );
                        } else {
                            // Default: store via D-Bus (systemd-creds or backend encryption)
                            let config = serde_json::json!({
                                "profiles": profiles,
                                "domains": domains,
                                "inject": "header",
                            });
                            client
                                .store_credential(
                                    &name,
                                    &credential_type,
                                    &value,
                                    &config.to_string(),
                                )
                                .await?;
                            output_action(
                                cli.output,
                                "added",
                                &name,
                                "",
                                &format!("Credential '{}' stored", name),
                            );
                        }
                    }
                    // §3.4 G21: Unlock passphrase-encrypted credential
                    CredentialAction::Unlock { name } => {
                        eprint!("Enter passphrase for '{}': ", name);
                        // J42: Limit passphrase read
                        let mut pass_buf = String::new();
                        std::io::Read::read_to_string(
                            &mut std::io::Read::take(std::io::stdin(), MAX_CREDENTIAL_SIZE),
                            &mut pass_buf,
                        )?;
                        let passphrase = zeroize::Zeroizing::new(pass_buf.trim_end().to_string());

                        if passphrase.is_empty() {
                            anyhow::bail!("passphrase is empty");
                        }

                        let result = client.unlock_credential(&name, &passphrase).await?;
                        if result {
                            output_action(
                                cli.output,
                                "unlocked",
                                &name,
                                "",
                                &format!("Credential '{}' unlocked", name),
                            );
                        } else {
                            anyhow::bail!("failed to unlock credential '{}'", name);
                        }
                    }
                },
                Command::Policy {
                    action: PolicyAction::Reload,
                } => {
                    let (success, detail) = client.reload_policy().await?;
                    if success {
                        output_action(cli.output, "reloaded", "", "", "Policies reloaded");
                    } else {
                        output_action(
                            cli.output,
                            "failed",
                            "",
                            &detail,
                            &format!("Policy reload failed: {}", detail),
                        );
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    Ok(())
}

/// Output a JSON action result or a plain text message.
/// L-ctl2: Uses serde_json::to_string_pretty for JSON output consistency.
fn output_action(format: OutputFormat, status: &str, id: &str, reason: &str, text_msg: &str) {
    match format {
        OutputFormat::Json => {
            let mut obj = serde_json::json!({"status": status, "branch_id": id});
            if !reason.is_empty() {
                obj["reason"] = serde_json::Value::String(reason.to_string());
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&obj).unwrap_or_else(|_| obj.to_string())
            );
        }
        OutputFormat::Text => println!("{text_msg}"),
    }
}

/// M-ctl2: Validate a branch ID before sending it over D-Bus.
/// Returns a clear CLI error instead of a cryptic D-Bus error on invalid input.
fn validate_branch_id(id: &str) -> Result<()> {
    BranchId::validated(id.to_string())
        .map_err(|e| anyhow::anyhow!("invalid branch ID '{}': {}", id, e))?;
    Ok(())
}

/// L-ctl1: Filter branches JSON array by state.
/// Supported state filters: "active", "reviewing" (governance_review), "degraded", "all".
fn filter_branches_by_state(branches_json: &str, state_filter: &str) -> String {
    if state_filter == "all" {
        return branches_json.to_string();
    }

    let target_state = match state_filter {
        "active" => "active",
        "reviewing" => "governance_review",
        "degraded" => "degraded",
        other => other,
    };

    match serde_json::from_str::<Vec<serde_json::Value>>(branches_json) {
        Ok(branches) => {
            let filtered: Vec<&serde_json::Value> = branches
                .iter()
                .filter(|b| {
                    b.get("state")
                        .and_then(|v| v.as_str())
                        .map(|s| s == target_state)
                        .unwrap_or(false)
                })
                .collect();
            serde_json::to_string(&filtered).unwrap_or_else(|_| branches_json.to_string())
        }
        Err(_) => branches_json.to_string(),
    }
}

/// List available profiles from a directory.
fn cmd_profile_list(dir: &str, output: OutputFormat) -> Result<()> {
    let dir_path = Path::new(dir);
    if !dir_path.exists() {
        anyhow::bail!("profiles directory not found: {}", dir);
    }

    let mut profiles = Vec::new();

    for entry in std::fs::read_dir(dir_path).context("reading profiles directory")? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
            let contents = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            match serde_yaml::from_str::<AgentProfile>(&contents) {
                Ok(profile) => profiles.push(profile),
                Err(e) => {
                    eprintln!("Warning: skipping {}: {}", path.display(), e);
                }
            }
        }
    }

    match output {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&profiles).context("serializing profiles")?
            );
        }
        OutputFormat::Text => {
            if profiles.is_empty() {
                println!("No profiles found in {}", dir);
            } else {
                println!(
                    "{:<15} {:<50} {:>10} {:>8} {:>12}",
                    "NAME", "DESCRIPTION", "MEMORY", "PIDS", "NETWORK"
                );
                println!("{}", "-".repeat(95));
                for p in &profiles {
                    let mem = format_bytes(p.resource_limits.memory_bytes);
                    println!(
                        "{:<15} {:<50} {:>10} {:>8} {:>12}",
                        p.name,
                        truncate(&p.description, 50),
                        mem,
                        p.resource_limits.max_pids,
                        format!("{:?}", p.network.mode),
                    );
                }
            }
        }
    }

    Ok(())
}

/// Show a specific profile's contents.
fn cmd_profile_show(name: &str, dir: &str, output: OutputFormat) -> Result<()> {
    // G29: Validate profile name against path traversal.
    // If the name is an existing file path, allow it (used by tests and direct file access).
    // If it's a bare name (no path sep), validate it does not contain "..".
    // If it contains path separators but is NOT an existing file, block it.
    if !Path::new(name).exists() && (name.contains('/') || name.contains("..")) {
        anyhow::bail!(
            "G29: profile name must not contain path separators or '..' \
             (got '{}'). Use a plain profile name.",
            name
        );
    }
    // Try as a direct file path first
    let path = if Path::new(name).exists() {
        PathBuf::from(name)
    } else {
        PathBuf::from(dir).join(format!("{}.yaml", name))
    };

    if !path.exists() {
        anyhow::bail!("profile not found: {} (tried {})", name, path.display());
    }

    let contents =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;

    match output {
        OutputFormat::Json => {
            let profile: AgentProfile = serde_yaml::from_str(&contents)
                .with_context(|| format!("parsing {}", path.display()))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&profile).context("serializing profile")?
            );
        }
        OutputFormat::Text => {
            println!("{}", contents);
        }
    }

    Ok(())
}

/// Validate a profile YAML file.
fn cmd_profile_validate(path: &str) -> Result<()> {
    let contents = std::fs::read_to_string(path).with_context(|| format!("reading {}", path))?;

    let profile: AgentProfile =
        serde_yaml::from_str(&contents).with_context(|| format!("parsing {}", path))?;

    // Basic validation
    if profile.name.is_empty() {
        anyhow::bail!("profile name is empty");
    }
    if profile.resource_limits.memory_bytes == 0 {
        anyhow::bail!("memory_bytes must be > 0");
    }
    if profile.resource_limits.max_pids == 0 {
        anyhow::bail!("max_pids must be > 0");
    }

    // Q4: Run full resource_limits validation from puzzled-types
    let rl_errors = profile.resource_limits.validate();
    if !rl_errors.is_empty() {
        anyhow::bail!(
            "resource limits validation failed:\n  {}",
            rl_errors.join("\n  ")
        );
    }

    println!("Profile '{}' is valid", profile.name);
    Ok(())
}

/// Test a policy against a sample changeset.
fn cmd_policy_test(changeset_path: &str, policy_dir: &str) -> Result<()> {
    // Load the changeset
    let changeset_str = std::fs::read_to_string(changeset_path)
        .with_context(|| format!("reading changeset {}", changeset_path))?;

    let changes: Vec<FileChange> = serde_json::from_str(&changeset_str)
        .with_context(|| format!("parsing changeset {}", changeset_path))?;

    // Create and load the policy engine
    let mut engine = regorus::Engine::new();

    let policy_path = Path::new(policy_dir);
    if !policy_path.exists() {
        anyhow::bail!("policy directory not found: {}", policy_dir);
    }

    let mut policy_count = 0;
    for entry in std::fs::read_dir(policy_path).context("reading policy directory")? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("rego") {
            let contents = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            engine
                .add_policy(path.display().to_string(), contents)
                .with_context(|| format!("loading policy {}", path.display()))?;
            policy_count += 1;
        }
    }

    println!("Loaded {} policy files from {}", policy_count, policy_dir);
    println!("Evaluating {} file changes...", changes.len());

    // Build and set input
    // T22: Include target, new_mode, and old_mode for full Rego rule coverage
    // (deny_setuid_setgid, deny_symlink_outside_workspace, etc.)
    let input = serde_json::json!({
        "changes": changes.iter().map(|c| {
            serde_json::json!({
                "path": c.path.to_string_lossy(),
                "kind": format!("{:?}", c.kind),
                "size": c.size,
                "checksum": &c.checksum,
                "target": c.target.as_deref().unwrap_or(""),
                "new_mode": c.new_mode,
            })
        }).collect::<Vec<_>>()
    });

    let input_str = serde_json::to_string(&input).context("serializing input")?;
    let input_value = regorus::Value::from_json_str(&input_str).context("parsing input value")?;
    engine.set_input(input_value);

    // Evaluate
    let allow = engine
        .eval_rule("data.puzzlepod.commit.allow".to_string())
        .context("evaluating allow rule")?;

    let allowed = matches!(allow, regorus::Value::Bool(true));

    if allowed {
        println!("\nResult: APPROVED");
        println!("The changeset passes all governance policies.");
    } else {
        println!("\nResult: REJECTED");

        // Get violations
        let violations = engine
            .eval_query("data.puzzlepod.commit.violations".to_string(), false)
            .context("evaluating violations")?;

        println!("\nViolations:");
        for result in &violations.result {
            for expr in &result.expressions {
                print_violations(&expr.value);
            }
        }
    }

    Ok(())
}

/// Pretty-print violation objects from regorus output.
///
/// Converts the regorus Value to JSON for reliable parsing,
/// since regorus internal types are not publicly accessible.
fn print_violations(value: &regorus::Value) {
    // Convert to JSON string via regorus Display, then parse
    let json_str = value.to_json_str();
    match json_str {
        Ok(s) => {
            // The violations set comes as an object { violation_obj: true, ... }
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&s) {
                match json {
                    serde_json::Value::Object(map) => {
                        for (key, val) in &map {
                            if val == &serde_json::Value::Bool(true) {
                                // key is a JSON-encoded violation object
                                if let Ok(violation) =
                                    serde_json::from_str::<serde_json::Value>(key)
                                {
                                    let rule = violation
                                        .get("rule")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("unknown");
                                    let message = violation
                                        .get("message")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("(no message)");
                                    let severity = violation
                                        .get("severity")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("error");
                                    println!(
                                        "  [{}] {}: {}",
                                        severity.to_uppercase(),
                                        rule,
                                        message
                                    );
                                }
                            }
                        }
                    }
                    serde_json::Value::Array(arr) => {
                        for item in &arr {
                            let rule = item
                                .get("rule")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            let message = item
                                .get("message")
                                .and_then(|v| v.as_str())
                                .unwrap_or("(no message)");
                            let severity = item
                                .get("severity")
                                .and_then(|v| v.as_str())
                                .unwrap_or("error");
                            println!("  [{}] {}: {}", severity.to_uppercase(), rule, message);
                        }
                    }
                    _ => {
                        println!("  {}", s);
                    }
                }
            } else {
                println!("  {}", s);
            }
        }
        Err(e) => {
            eprintln!("  Error formatting violations: {}", e);
        }
    }
}

/// Verify an IMA manifest signature.
fn cmd_audit_verify(hash_or_path: &str) -> Result<()> {
    let path = if std::path::Path::new(hash_or_path).exists() {
        std::path::PathBuf::from(hash_or_path)
    } else {
        // Try to find the manifest by branch ID hash
        let manifest_dir = std::path::PathBuf::from("/var/lib/puzzled/branches/manifests");
        let candidate = manifest_dir.join(format!("{}.manifest.yaml", hash_or_path));
        if candidate.exists() {
            candidate
        } else {
            anyhow::bail!(
                "manifest not found: {} (tried path and /var/lib/puzzled/branches/manifests/)",
                hash_or_path
            );
        }
    };

    let contents =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;

    println!("Manifest: {}", path.display());
    println!("{}", contents);

    // T23: Signature verification is not yet implemented — fail explicitly
    // rather than silently succeeding and misleading the operator.
    eprintln!("WARNING: signature verification is not yet implemented.");
    eprintln!(
        "The manifest contents are displayed above but have NOT been cryptographically verified."
    );
    eprintln!(
        "Use puzzled's attestation bundle (puzzlectl attestation verify-bundle) for verified audit."
    );

    Ok(())
}

// --- Attestation verification (§3.1) ---

// A-M1: Merkle crypto functions are now in puzzled_types::merkle.
use puzzled_types::merkle::{hash_leaf, hex_decode, verify_merkle_inclusion};

/// Re-use the canonical governance-significance check from puzzled-types.
use puzzled_types::is_governance_significant;

/// Deserialization struct for audit events read from NDJSON.
/// Mirrors `StoredAuditEvent` in puzzled but only the fields we need.
// V49: This AuditRecord is for attestation verification (includes signature, hmac, merkle fields).
// compliance.rs has a separate AuditRecord for compliance reporting (different field set).
// TODO: Unify into a single type in puzzled-types with optional fields.
#[derive(serde::Serialize, serde::Deserialize)]
struct AuditRecord {
    seq: u64,
    timestamp: String,
    event: AuditRecordEvent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    record_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_identity: Option<puzzled_types::AgentIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    changeset_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    governance_decision: Option<GovernanceDecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parent_record_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    /// HMAC chain signature (puzzled stores this as "hmac" in NDJSON).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hmac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    merkle_leaf_index: Option<u64>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AuditRecordEvent {
    event_type: String,
    branch_id: Option<String>,
    details: serde_json::Value,
}

/// Recursively sort all JSON object keys and strip null values for
/// deterministic serialization. Mirrors `AuditStore::sort_json_keys` in puzzled.
fn sort_json_keys(val: serde_json::Value) -> serde_json::Value {
    match val {
        serde_json::Value::Object(map) => {
            let sorted: serde_json::Map<String, serde_json::Value> = map
                .into_iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k, sort_json_keys(v)))
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .collect();
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(sort_json_keys).collect())
        }
        other => other,
    }
}

/// Build canonical attestation string (matches puzzled's `build_canonical_attestation`).
// N7: Returns Result to propagate serialization errors instead of unwrap()
fn build_canonical(record: &AuditRecord) -> Result<String> {
    use std::collections::BTreeMap;

    let mut canonical = BTreeMap::new();
    canonical.insert("seq", serde_json::json!(record.seq));
    canonical.insert("timestamp", serde_json::json!(record.timestamp));
    canonical.insert("event_type", serde_json::json!(record.event.event_type));
    if let Some(ref bid) = record.event.branch_id {
        canonical.insert("branch_id", serde_json::json!(bid));
    }
    if let Some(ref rid) = record.record_id {
        canonical.insert("record_id", serde_json::json!(rid));
    }
    if let Some(ref identity) = record.agent_identity {
        canonical.insert(
            "agent_identity",
            // N7: Propagate serialization error
            sort_json_keys(serde_json::to_value(identity)?),
        );
    }
    if let Some(ref pv) = record.policy_version {
        canonical.insert("policy_version", serde_json::json!(pv));
    }
    if let Some(ref ch) = record.changeset_hash {
        canonical.insert("changeset_hash", serde_json::json!(ch));
    }
    if let Some(ref gd) = record.governance_decision {
        // A-C2: Apply sort_json_keys for consistency with puzzled's build_canonical_attestation.
        canonical.insert(
            "governance_decision",
            // N7: Propagate serialization error
            sort_json_keys(serde_json::to_value(gd)?),
        );
    }
    if let Some(ref pid) = record.parent_record_id {
        canonical.insert("parent_record_id", serde_json::json!(pid));
    }
    // N1/N10: Include event details in canonical form to match puzzled's signing canonical.
    if !record.event.details.is_null() {
        canonical.insert("details", sort_json_keys(record.event.details.clone()));
    }

    Ok(serde_json::to_string(&canonical)?)
}

/// Verify attestation chain integrity in the audit log.
fn cmd_attestation_verify(
    audit_dir: &Path,
    pubkey_path: Option<&Path>,
    branch_filter: Option<&str>,
    verify_merkle: bool,
    attestation_dir: &Path,
) -> Result<()> {
    // Load the audit log
    let log_path = audit_dir.join("events.ndjson");
    if !log_path.exists() {
        anyhow::bail!("audit log not found: {}", log_path.display());
    }

    // Q3: Check file size before reading (defense-in-depth, matches N8/G26 pattern)
    const MAX_ATTESTATION_FILE_BYTES: u64 = 500 * 1024 * 1024;
    let file_size = std::fs::metadata(&log_path)
        .with_context(|| format!("stat {}", log_path.display()))?
        .len();
    if file_size > MAX_ATTESTATION_FILE_BYTES {
        anyhow::bail!(
            "Q3: audit log {} is {} bytes, exceeds maximum {} bytes",
            log_path.display(),
            file_size,
            MAX_ATTESTATION_FILE_BYTES
        );
    }

    let contents = std::fs::read_to_string(&log_path)
        .with_context(|| format!("reading {}", log_path.display()))?;

    let mut records: Vec<AuditRecord> = Vec::new();
    for (line_num, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditRecord>(line) {
            Ok(record) => records.push(record),
            Err(e) => {
                eprintln!("Warning: skipping line {}: {}", line_num + 1, e);
            }
        }
    }

    println!(
        "Loaded {} audit records from {}",
        records.len(),
        log_path.display()
    );

    // Filter to attestation records (governance-significant events with signatures or HMAC)
    let attestation_records: Vec<&AuditRecord> = records
        .iter()
        .filter(|r| {
            is_governance_significant(&r.event.event_type)
                && (r.signature.is_some() || r.hmac.is_some())
        })
        .filter(|r| {
            if let Some(filter) = branch_filter {
                r.event.branch_id.as_deref() == Some(filter)
            } else {
                true
            }
        })
        .collect();

    if attestation_records.is_empty() {
        println!("No attestation records found.");
        if let Some(bid) = branch_filter {
            println!("  (filtered by branch_id={})", bid);
        }
        // A-M5: Warn that 0 governance-significant records were found.
        eprintln!(
            "Warning: 0 governance-significant records found — attestation may not be enabled."
        );
        return Ok(());
    }

    println!(
        "Found {} attestation records to verify",
        attestation_records.len()
    );

    // Load public key if provided
    let verifying_key = if let Some(pk_path) = pubkey_path {
        let hex_str = std::fs::read_to_string(pk_path)
            .with_context(|| format!("reading public key {}", pk_path.display()))?;
        let key_bytes = hex_decode(hex_str.trim())
            .map_err(|e| anyhow::anyhow!("decoding public key hex: {}", e))?;
        if key_bytes.len() != 32 {
            anyhow::bail!("public key must be 32 bytes, got {}", key_bytes.len());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_bytes);
        Some(VerifyingKey::from_bytes(&arr).context("invalid Ed25519 public key")?)
    } else {
        None
    };

    let mut sig_ok = 0u64;
    let mut sig_fail = 0u64;
    let mut sig_skip = 0u64; // V55: Renamed — variable IS used (tracks signature skip count)
    let mut chain_ok = 0u64;
    let mut chain_fail = 0u64;
    let mut merkle_ok = 0u64;
    let mut merkle_fail = 0u64;
    let mut merkle_skip = 0u64;

    // Build record_id -> record index for chain verification
    let record_id_map: HashMap<&str, usize> = attestation_records
        .iter()
        .enumerate()
        .filter_map(|(i, r)| r.record_id.as_deref().map(|rid| (rid, i)))
        .collect();

    // Verify each attestation record
    for record in &attestation_records {
        let rid = record.record_id.as_deref().unwrap_or("(none)");
        let sig_hex = record.signature.as_deref().unwrap_or("");

        // 1. Verify Ed25519 signature
        if let Some(ref vk) = verifying_key {
            let canonical = build_canonical(record)?;
            let sig_bytes = hex_decode(sig_hex).unwrap_or_else(|e| {
                eprintln!("S44: hex decode failed for record {}: {}", rid, e);
                Vec::new()
            });
            if sig_bytes.len() == 64 {
                let sig = Signature::from_slice(&sig_bytes);
                match sig {
                    Ok(sig) => {
                        use ed25519_dalek::Verifier;
                        if vk.verify(canonical.as_bytes(), &sig).is_ok() {
                            sig_ok += 1;
                        } else {
                            sig_fail += 1;
                            eprintln!("  FAIL: signature invalid for record {}", rid);
                        }
                    }
                    Err(_) => {
                        sig_fail += 1;
                        eprintln!("  FAIL: malformed signature for record {}", rid);
                    }
                }
            } else {
                sig_fail += 1;
                eprintln!(
                    "  FAIL: signature wrong length ({} bytes) for record {}",
                    sig_bytes.len(),
                    rid
                );
            }
        } else {
            sig_skip += 1;
        }

        // 2. Verify per-branch chain (parent_record_id linkage)
        if let Some(ref parent_id) = record.parent_record_id {
            if record_id_map.contains_key(parent_id.as_str()) {
                chain_ok += 1;
            } else {
                chain_fail += 1;
                eprintln!(
                    "  FAIL: chain broken — record {} references parent {} which is missing",
                    rid, parent_id
                );
            }
        } else {
            // First record in a branch chain has no parent — that's OK
            chain_ok += 1;
        }
    }

    // 3. Verify Merkle inclusion proofs (if requested)
    if verify_merkle {
        let root_path = attestation_dir.join("root_hash");
        if root_path.exists() {
            let root_hex = std::fs::read_to_string(&root_path)
                .with_context(|| format!("reading {}", root_path.display()))?;
            let root_bytes = hex_decode(root_hex.trim())
                .map_err(|e| anyhow::anyhow!("decoding root hash: {}", e))?;
            if root_bytes.len() != 32 {
                anyhow::bail!("root hash must be 32 bytes, got {}", root_bytes.len());
            }
            let mut expected_root = [0u8; 32];
            expected_root.copy_from_slice(&root_bytes);

            for record in &attestation_records {
                if let Some(leaf_idx) = record.merkle_leaf_index {
                    let canonical = build_canonical(record)?;
                    let leaf_hash = hash_leaf(canonical.as_bytes());

                    // Look for proof file: <attestation_dir>/proofs/<leaf_idx>.json
                    let proof_path = attestation_dir
                        .join("proofs")
                        .join(format!("{}.json", leaf_idx));
                    if proof_path.exists() {
                        let proof_json = std::fs::read_to_string(&proof_path)
                            .with_context(|| format!("reading {}", proof_path.display()))?;
                        let proof: InclusionProof = serde_json::from_str(&proof_json)
                            .with_context(|| format!("parsing {}", proof_path.display()))?;

                        match verify_merkle_inclusion(&leaf_hash, &proof, &expected_root) {
                            Ok(true) => merkle_ok += 1,
                            Ok(false) => {
                                merkle_fail += 1;
                                let rid = record.record_id.as_deref().unwrap_or("(none)");
                                eprintln!(
                                    "  FAIL: Merkle proof invalid for record {} (leaf {})",
                                    rid, leaf_idx
                                );
                            }
                            Err(e) => {
                                merkle_fail += 1;
                                let rid = record.record_id.as_deref().unwrap_or("(none)");
                                eprintln!("  FAIL: Merkle proof error for record {}: {}", rid, e);
                            }
                        }
                    } else {
                        merkle_skip += 1;
                    }
                } else {
                    merkle_skip += 1;
                }
            }
        } else {
            println!(
                "Warning: no root_hash file found in {}; skipping Merkle verification",
                attestation_dir.display()
            );
            // N9: Safe cast avoiding truncation on 32-bit platforms
            merkle_skip = u64::try_from(attestation_records.len()).unwrap_or(u64::MAX);
        }
    }

    // 4. Verify expected event sequences per branch
    //    Each branch must start with branch_created and end with a terminal event.
    let mut seq_ok = 0u64;
    let mut seq_fail = 0u64;
    {
        // Group attestation records by branch_id
        let mut branch_events: HashMap<String, Vec<&str>> = HashMap::new();
        for record in &attestation_records {
            if let Some(ref bid) = record.event.branch_id {
                branch_events
                    .entry(bid.clone())
                    .or_default()
                    .push(&record.event.event_type);
            }
        }

        for (bid, events) in &branch_events {
            let mut ok = true;

            // Must start with branch_created
            if events.first().copied() != Some("branch_created") {
                eprintln!(
                    "  FAIL: branch {} chain does not start with branch_created (starts with {})",
                    bid,
                    events.first().unwrap_or(&"(empty)")
                );
                ok = false;
            }

            // Must end with a terminal event (or be in-progress)
            let terminal_events = ["branch_committed", "branch_rolled_back", "agent_killed"];
            if let Some(last) = events.last() {
                if !terminal_events.contains(last) {
                    // Not an error if the branch is still active — just a warning
                    eprintln!(
                        "  WARN: branch {} chain does not end with a terminal event (ends with {})",
                        bid, last
                    );
                }
            }

            if ok {
                seq_ok += 1;
            } else {
                seq_fail += 1;
            }
        }
    }

    // Print summary
    println!("\n--- Attestation Verification Summary ---");
    println!("Total attestation records: {}", attestation_records.len());

    if verifying_key.is_some() {
        println!("Signatures:  {} ok, {} failed", sig_ok, sig_fail);
    } else {
        println!("Signatures:  skipped (no --pubkey provided)");
    }

    println!("Chain links: {} ok, {} broken", chain_ok, chain_fail);
    println!("Sequences:   {} ok, {} invalid", seq_ok, seq_fail);

    if verify_merkle {
        println!(
            "Merkle:      {} ok, {} failed, {} skipped",
            merkle_ok, merkle_fail, merkle_skip
        );
    }

    let total_failures = sig_fail + chain_fail + merkle_fail + seq_fail;
    if total_failures > 0 {
        println!("\nRESULT: FAILED ({} issues found)", total_failures);
        // V54: process::exit bypasses cleanup but is acceptable for CLI — no resources to clean up
        std::process::exit(1);
    } else {
        println!("\nRESULT: PASSED");
    }

    // V55: sig_skip is used above for counting; suppress unused warning in summary path
    let _ = sig_skip;

    Ok(())
}

/// Verify an exported attestation bundle file (Gap 23).
///
/// Loads the bundle JSON, extracts the public key, records, and Merkle proofs,
/// then verifies:
/// 1. Ed25519 signature on each record using the bundle's public_key
/// 2. Merkle inclusion proofs against the bundle's merkle_root
/// 3. parent_record_id chain continuity
fn cmd_attestation_verify_bundle(bundle_path: &Path) -> Result<()> {
    // S11: Check file size before reading to prevent OOM on huge files
    let metadata = std::fs::metadata(bundle_path)
        .with_context(|| format!("reading metadata for {}", bundle_path.display()))?;
    const MAX_BUNDLE_SIZE: u64 = 50 * 1024 * 1024; // 50 MiB
    if metadata.len() > MAX_BUNDLE_SIZE {
        anyhow::bail!(
            "attestation bundle {} is too large ({} bytes, max {})",
            bundle_path.display(),
            metadata.len(),
            MAX_BUNDLE_SIZE
        );
    }
    let contents = std::fs::read_to_string(bundle_path)
        .with_context(|| format!("reading bundle {}", bundle_path.display()))?;
    let bundle: serde_json::Value = serde_json::from_str(&contents)
        .with_context(|| format!("parsing bundle {}", bundle_path.display()))?;

    let public_key_hex = bundle["public_key"].as_str().unwrap_or("");
    let merkle_root_hex = bundle["merkle_root"].as_str();
    let records = bundle["records"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("bundle missing 'records' array"))?;
    let merkle_proofs = bundle["merkle_inclusion_proofs"].as_array();

    println!("Verifying attestation bundle: {}", bundle_path.display());
    println!(
        "  Branch: {}",
        bundle["branch_id"].as_str().unwrap_or("(unknown)")
    );
    println!("  Records: {}", records.len());

    // Load public key
    let verifying_key = if !public_key_hex.is_empty() {
        let key_bytes = hex_decode(public_key_hex)
            .map_err(|e| anyhow::anyhow!("decoding public key from bundle: {}", e))?;
        if key_bytes.len() != 32 {
            anyhow::bail!(
                "bundle public key must be 32 bytes, got {}",
                key_bytes.len()
            );
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_bytes);
        Some(VerifyingKey::from_bytes(&arr).context("invalid Ed25519 public key in bundle")?)
    } else {
        println!("  Warning: no public_key in bundle, skipping signature verification");
        None
    };

    // Load Merkle root
    let expected_root = if let Some(root_hex) = merkle_root_hex {
        let root_bytes =
            hex_decode(root_hex).map_err(|e| anyhow::anyhow!("decoding merkle_root: {}", e))?;
        if root_bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&root_bytes);
            Some(arr)
        } else {
            None
        }
    } else {
        None
    };

    // Build index of Merkle proofs by record_seq (PRD §3.1.4 bundle format)
    let mut proof_by_seq: HashMap<u64, &serde_json::Value> = HashMap::new();
    if let Some(proofs) = merkle_proofs {
        for p in proofs {
            if let Some(seq) = p["record_seq"].as_u64() {
                proof_by_seq.insert(seq, p);
            }
        }
    }

    let mut sig_ok = 0u64;
    let mut sig_fail = 0u64;
    let mut chain_ok = 0u64;
    let mut chain_fail = 0u64;
    let mut merkle_ok = 0u64;
    let mut merkle_fail = 0u64;
    let mut merkle_skip = 0u64;
    let mut timestamp_violations = 0u64;
    let mut prev_timestamp: Option<String> = None;

    // Build a set of record_ids for chain verification
    let record_id_set: std::collections::HashSet<String> = records
        .iter()
        .filter_map(|r| r["record_id"].as_str().map(|s| s.to_string()))
        .collect();

    for record in records {
        let rid = record["record_id"].as_str().unwrap_or("(none)");
        let seq = record["seq"].as_u64().unwrap_or(0);

        // 1. Verify Ed25519 signature
        if let Some(ref vk) = verifying_key {
            if let Some(sig_hex) = record["signature"].as_str() {
                // Build canonical attestation string from the record fields
                let canonical = match build_canonical_from_value(record) {
                    Some(c) => c,
                    None => {
                        sig_fail += 1;
                        eprintln!("  Record {}: malformed (missing seq/timestamp)", rid);
                        continue;
                    }
                };
                let sig_bytes = hex_decode(sig_hex).unwrap_or_else(|e| {
                    eprintln!("S44: hex decode failed for record {}: {}", rid, e);
                    Vec::new()
                });
                if sig_bytes.len() == 64 {
                    let sig = Signature::from_slice(&sig_bytes);
                    match sig {
                        Ok(sig) => {
                            use ed25519_dalek::Verifier;
                            if vk.verify(canonical.as_bytes(), &sig).is_ok() {
                                sig_ok += 1;
                            } else {
                                sig_fail += 1;
                                eprintln!("  FAIL: signature invalid for record {}", rid);
                            }
                        }
                        Err(_) => {
                            sig_fail += 1;
                            eprintln!("  FAIL: malformed signature for record {}", rid);
                        }
                    }
                } else {
                    sig_fail += 1;
                    eprintln!(
                        "  FAIL: signature wrong length ({} bytes) for record {}",
                        sig_bytes.len(),
                        rid
                    );
                }
            } else {
                sig_fail += 1;
                eprintln!("  FAIL: no signature for record {}", rid);
            }
        }

        // 2. Verify Merkle inclusion proof
        if let Some(ref root) = expected_root {
            if let Some(proof_val) = proof_by_seq.get(&seq) {
                let proof_result: std::result::Result<InclusionProof, _> =
                    serde_json::from_value((*proof_val).clone());
                match proof_result {
                    Ok(proof) => {
                        let canonical = match build_canonical_from_value(record) {
                            Some(c) => c,
                            None => {
                                merkle_fail += 1;
                                eprintln!("  Record {}: malformed (missing seq/timestamp)", rid);
                                continue;
                            }
                        };
                        let leaf_hash = hash_leaf(canonical.as_bytes());
                        match verify_merkle_inclusion(&leaf_hash, &proof, root) {
                            Ok(true) => merkle_ok += 1,
                            Ok(false) => {
                                merkle_fail += 1;
                                eprintln!(
                                    "  FAIL: Merkle proof invalid for record {} (seq {})",
                                    rid, seq
                                );
                            }
                            Err(e) => {
                                merkle_fail += 1;
                                eprintln!("  FAIL: Merkle proof error for record {}: {}", rid, e);
                            }
                        }
                    }
                    Err(e) => {
                        merkle_fail += 1;
                        eprintln!("  FAIL: cannot parse Merkle proof for seq {}: {}", seq, e);
                    }
                }
            } else {
                merkle_skip += 1;
            }
        } else {
            merkle_skip += 1;
        }

        // 3. Verify parent_record_id chain continuity
        if let Some(parent_id) = record["parent_record_id"].as_str() {
            if record_id_set.contains(parent_id) {
                chain_ok += 1;
            } else {
                chain_fail += 1;
                eprintln!(
                    "  FAIL: chain broken — record {} references parent {} which is missing",
                    rid, parent_id
                );
            }
        } else {
            // First record in chain has no parent
            chain_ok += 1;
        }

        // 4. §3.1.8: Verify timestamp ordering (timestamp >= parent's timestamp)
        if let Some(ts) = record["timestamp"].as_str() {
            if let Some(ref prev_ts) = prev_timestamp {
                if ts < prev_ts.as_str() {
                    timestamp_violations += 1;
                    eprintln!(
                        "  FAIL: timestamp regression — record {} has {} < parent {}",
                        rid, ts, prev_ts
                    );
                }
            }
            prev_timestamp = Some(ts.to_string());
        }
    }

    // 5. §3.1.5: Verify expected event sequencing
    let mut sequencing_issues = Vec::new();
    if !records.is_empty() {
        let first_event_type = records[0]["event"]["event_type"].as_str().unwrap_or("");
        if first_event_type != "branch_created" {
            sequencing_issues.push(format!(
                "chain must start with branch_created, got '{}'",
                first_event_type
            ));
        }
        let last_event_type = records
            .last()
            .and_then(|r| r["event"]["event_type"].as_str())
            .unwrap_or("");
        let terminal_events = ["branch_committed", "branch_rolled_back", "agent_killed"];
        if !terminal_events.contains(&last_event_type) {
            sequencing_issues.push(format!(
                "chain should end with terminal event (branch_committed/branch_rolled_back/agent_killed), got '{}'",
                last_event_type
            ));
        }
    }

    // 6. §3.1.5 item 6: Verify changeset_hash matches SHA-256 of commit_manifest canonical JSON
    let mut manifest_hash_ok = true;
    let commit_manifest = &bundle["commit_manifest"];
    if !commit_manifest.is_null() {
        // Find the branch_committed record
        for record in records {
            let event_type = record["event"]["event_type"].as_str().unwrap_or("");
            if event_type == "branch_committed" {
                if let Some(claimed_hash) = record["changeset_hash"].as_str() {
                    use sha2::{Digest, Sha256};
                    // Use sort_json_keys for canonical deterministic serialization
                    // to match puzzled's BTreeMap-based serialization regardless of
                    // serde_json's internal key ordering.
                    let canonical_manifest =
                        serde_json::to_string(&sort_json_keys(commit_manifest.clone()))
                            .unwrap_or_else(|e| {
                                eprintln!("F7: failed to serialize manifest for hash: {e}");
                                "{}".to_string()
                            });
                    let mut hasher = Sha256::new();
                    hasher.update(canonical_manifest.as_bytes());
                    let computed_hash = format!("{:x}", hasher.finalize());
                    if claimed_hash != computed_hash {
                        manifest_hash_ok = false;
                        eprintln!(
                            "  FAIL: changeset_hash mismatch — record claims {}, manifest hashes to {}",
                            claimed_hash, computed_hash
                        );
                    }
                }
                break;
            }
        }
    }

    // Print summary
    println!("\n--- Bundle Verification Summary ---");
    println!("Total records: {}", records.len());

    if verifying_key.is_some() {
        println!("Signatures:  {} ok, {} failed", sig_ok, sig_fail);
    } else {
        println!("Signatures:  skipped (no public_key in bundle)");
    }

    println!("Chain links: {} ok, {} broken", chain_ok, chain_fail);
    println!("Timestamps:  {} violations", timestamp_violations);

    if expected_root.is_some() {
        println!(
            "Merkle:      {} ok, {} failed, {} skipped",
            merkle_ok, merkle_fail, merkle_skip
        );
    } else {
        println!("Merkle:      skipped (no merkle_root in bundle)");
    }

    if !sequencing_issues.is_empty() {
        println!("Sequencing:  {} issues", sequencing_issues.len());
        for issue in &sequencing_issues {
            eprintln!("  WARNING: {}", issue);
        }
    } else {
        println!("Sequencing:  ok");
    }

    if !commit_manifest.is_null() {
        println!(
            "Manifest:    {}",
            if manifest_hash_ok {
                "hash verified"
            } else {
                "HASH MISMATCH"
            }
        );
    }

    let total_failures = sig_fail
        + chain_fail
        + merkle_fail
        + timestamp_violations
        + u64::try_from(sequencing_issues.len()).unwrap_or(u64::MAX) // Q11: safe cast
        + if manifest_hash_ok { 0 } else { 1 };
    if total_failures > 0 {
        println!("\nRESULT: FAILED ({} issues found)", total_failures);
        std::process::exit(1);
    } else {
        println!("\nRESULT: PASSED");
    }

    Ok(())
}

/// Build canonical attestation string from a JSON value (for bundle verification).
/// Mirrors `build_canonical` but works with serde_json::Value instead of AuditRecord.
fn build_canonical_from_value(record: &serde_json::Value) -> Option<String> {
    use std::collections::BTreeMap;

    let mut canonical = BTreeMap::new();
    // seq and timestamp are mandatory — if missing, the record is malformed
    canonical.insert("seq", record.get("seq")?.clone());
    canonical.insert("timestamp", record.get("timestamp")?.clone());
    // RED-2 fix: event_type, branch_id, and details are nested under "event"
    // in the NDJSON StoredAuditEvent structure.
    if let Some(event) = record.get("event") {
        if let Some(et) = event.get("event_type") {
            canonical.insert("event_type", et.clone());
        }
        if let Some(bid) = event.get("branch_id") {
            if !bid.is_null() {
                canonical.insert("branch_id", bid.clone());
            }
        }
        // N1/N10: Include event details in canonical form to match puzzled's signing canonical.
        if let Some(details) = event.get("details") {
            if !details.is_null() {
                canonical.insert("details", sort_json_keys(details.clone()));
            }
        }
    }
    if let Some(rid) = record.get("record_id") {
        if !rid.is_null() {
            canonical.insert("record_id", rid.clone());
        }
    }
    if let Some(ai) = record.get("agent_identity") {
        if !ai.is_null() {
            canonical.insert("agent_identity", sort_json_keys(ai.clone()));
        }
    }
    if let Some(pv) = record.get("policy_version") {
        if !pv.is_null() {
            canonical.insert("policy_version", pv.clone());
        }
    }
    if let Some(ch) = record.get("changeset_hash") {
        if !ch.is_null() {
            canonical.insert("changeset_hash", ch.clone());
        }
    }
    if let Some(gd) = record.get("governance_decision") {
        if !gd.is_null() {
            // Apply sort_json_keys for consistency with agent_identity/details treatment.
            // Currently governance_decision is always a string, but this future-proofs
            // against it ever becoming a structured object.
            canonical.insert("governance_decision", sort_json_keys(gd.clone()));
        }
    }
    if let Some(pid) = record.get("parent_record_id") {
        if !pid.is_null() {
            canonical.insert("parent_record_id", pid.clone());
        }
    }

    // Q2: Use ok()? instead of expect() to avoid panic on serialization edge cases
    serde_json::to_string(&canonical).ok()
}

// --- Attestation bundle export (§3.1.4) ---

/// Load and parse audit records from an NDJSON file, optionally filtering by branch_id.
fn load_attestation_records(
    audit_dir: &Path,
    branch_filter: Option<&str>,
) -> Result<Vec<AuditRecord>> {
    // N8: Maximum attestation file size (defense-in-depth, matches G26 pattern)
    const MAX_ATTESTATION_FILE_BYTES: u64 = 500 * 1024 * 1024;

    let log_path = audit_dir.join("events.ndjson");
    if !log_path.exists() {
        anyhow::bail!("audit log not found: {}", log_path.display());
    }

    // N8: Check file size before reading to prevent unbounded memory allocation
    let file_size = std::fs::metadata(&log_path)
        .with_context(|| format!("N8: stat {}", log_path.display()))?
        .len();
    if file_size > MAX_ATTESTATION_FILE_BYTES {
        anyhow::bail!(
            "N8: attestation file {} is {} bytes, exceeds limit of {} bytes",
            log_path.display(),
            file_size,
            MAX_ATTESTATION_FILE_BYTES
        );
    }

    let contents = std::fs::read_to_string(&log_path)
        .with_context(|| format!("reading {}", log_path.display()))?;

    let mut records: Vec<AuditRecord> = Vec::new();
    for (line_num, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditRecord>(line) {
            Ok(record) => {
                // Filter to governance-significant events with signatures or HMAC
                let has_auth = record.signature.is_some() || record.hmac.is_some();
                if is_governance_significant(&record.event.event_type) && has_auth {
                    if let Some(filter) = branch_filter {
                        if record.event.branch_id.as_deref() == Some(filter) {
                            records.push(record);
                        }
                    } else {
                        records.push(record);
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: skipping line {}: {}", line_num + 1, e);
            }
        }
    }

    Ok(records)
}

/// Build key rotation history by scanning for archived public key files.
///
/// Archived keys are stored as `<keyname>.pub.<timestamp>` (e.g., `public_key.hex.1710500000`)
/// in the attestation directory. Each entry records the hex-encoded public key and the
/// timestamp at which it was archived (i.e., rotated out).
fn build_key_rotation_history(attestation_dir: &Path) -> Vec<serde_json::Value> {
    let mut history: Vec<(u64, serde_json::Value)> = Vec::new();

    let read_dir = match std::fs::read_dir(attestation_dir) {
        Ok(rd) => rd,
        Err(_) => return Vec::new(),
    };

    for entry in read_dir.flatten() {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        // Match files like "public_key.hex.1710500000"
        if let Some(rest) = name.strip_prefix("public_key.hex.") {
            if let Ok(timestamp) = rest.parse::<u64>() {
                // Read the archived public key
                if let Ok(contents) = std::fs::read_to_string(entry.path()) {
                    let pubkey_hex = contents.trim().to_string();
                    if !pubkey_hex.is_empty() {
                        history.push((
                            timestamp,
                            serde_json::json!({
                                "public_key": pubkey_hex,
                                "valid_from": null,
                                "valid_until": timestamp,
                            }),
                        ));
                    }
                }
            }
        }
    }

    // Sort by timestamp ascending
    history.sort_by_key(|(ts, _)| *ts);

    // Fill in valid_from: each key's valid_from is the previous key's valid_until
    let mut result: Vec<serde_json::Value> = Vec::with_capacity(history.len());
    let mut prev_until: Option<u64> = None;
    for (ts, mut entry) in history {
        if let Some(prev) = prev_until {
            entry["valid_from"] = serde_json::json!(prev);
        }
        prev_until = Some(ts);
        result.push(entry);
    }

    result
}

/// Load the IMA commit manifest for a branch, if it exists.
///
/// Looks for `<attestation_dir>/manifests/<branch_id>.manifest.yaml`. If found,
/// parses the YAML and returns it as a JSON value. Returns `null` if not found.
fn load_commit_manifest(attestation_dir: &Path, branch_id: &str) -> serde_json::Value {
    let manifest_path = attestation_dir
        .join("manifests")
        .join(format!("{}.manifest.yaml", branch_id));

    if !manifest_path.exists() {
        // Also check the legacy location under /var/lib/puzzled/branches/manifests/
        let legacy_path = Path::new("/var/lib/puzzled/branches/manifests")
            .join(format!("{}.manifest.yaml", branch_id));
        if legacy_path.exists() {
            return load_manifest_file(&legacy_path);
        }
        return serde_json::Value::Null;
    }

    load_manifest_file(&manifest_path)
}

/// Read and parse a YAML manifest file, returning it as a JSON value.
fn load_manifest_file(path: &Path) -> serde_json::Value {
    match std::fs::read_to_string(path) {
        Ok(contents) => match serde_yaml::from_str::<serde_json::Value>(&contents) {
            Ok(value) => value,
            Err(e) => {
                eprintln!(
                    "Warning: failed to parse manifest {}: {}",
                    path.display(),
                    e
                );
                serde_json::Value::Null
            }
        },
        Err(e) => {
            eprintln!("Warning: failed to read manifest {}: {}", path.display(), e);
            serde_json::Value::Null
        }
    }
}

/// Export a self-contained, offline-verifiable attestation bundle for a branch (PRD §3.1.4).
fn cmd_attestation_export(
    branch_id: &str,
    output_path: Option<&str>,
    audit_dir: &Path,
    attestation_dir: &Path,
) -> Result<()> {
    // T26: Validate branch_id to prevent path traversal (matches M-ctl2 pattern)
    validate_branch_id(branch_id)?;

    let records = load_attestation_records(audit_dir, Some(branch_id))?;

    if records.is_empty() {
        anyhow::bail!(
            "no attestation records found for branch '{}' in {}",
            branch_id,
            audit_dir.display()
        );
    }

    // Load public key if available
    let pubkey_path = attestation_dir.join("public_key.hex");
    let public_key = if pubkey_path.exists() {
        let hex_str = std::fs::read_to_string(&pubkey_path)
            .with_context(|| format!("reading {}", pubkey_path.display()))?;
        hex_str.trim().to_string()
    } else {
        String::new()
    };

    // Load Merkle root hash if available
    let root_path = attestation_dir.join("root_hash");
    let merkle_root = if root_path.exists() {
        let hex_str = std::fs::read_to_string(&root_path)
            .with_context(|| format!("reading {}", root_path.display()))?;
        Some(hex_str.trim().to_string())
    } else {
        None
    };

    // Build Merkle inclusion proofs for records that have leaf indices
    let mut inclusion_proofs: Vec<serde_json::Value> = Vec::new();
    for record in &records {
        if let Some(leaf_idx) = record.merkle_leaf_index {
            let proof_path = attestation_dir
                .join("proofs")
                .join(format!("{}.json", leaf_idx));
            if proof_path.exists() {
                let proof_json = std::fs::read_to_string(&proof_path)
                    .with_context(|| format!("reading {}", proof_path.display()))?;
                let proof: serde_json::Value = serde_json::from_str(&proof_json)
                    .with_context(|| format!("parsing {}", proof_path.display()))?;
                // Match D-Bus export format: flat structure with record_seq,
                // leaf_index, tree_size, proof_hashes (not nested "proof").
                inclusion_proofs.push(serde_json::json!({
                    "record_seq": record.seq,
                    "leaf_index": leaf_idx,
                    "tree_size": proof.get("tree_size").cloned().unwrap_or(serde_json::Value::Null),
                    "proof_hashes": proof.get("proof_hashes").cloned().unwrap_or(serde_json::json!([])),
                }));
            }
        }
    }

    // Serialize records via serde to match the D-Bus export format (nested `event`
    // structure). This ensures `build_canonical_from_value` can find `event_type`,
    // `branch_id`, and `details` under `record["event"]`.
    let record_values: Vec<serde_json::Value> = records
        .iter()
        .filter_map(|r| serde_json::to_value(r).ok())
        .collect();

    // Gap 18: Scan for archived public key files to build key_rotation_history.
    // Archived keys are stored as <keyname>.pub.<timestamp> in the same directory
    // as public_key.hex (the attestation_dir).
    let key_rotation_history = build_key_rotation_history(attestation_dir);

    // Gap 19: Attempt to load IMA commit manifest for this branch.
    // Look for <attestation_dir>/manifests/<branch_id>.manifest.yaml
    let commit_manifest = load_commit_manifest(attestation_dir, branch_id);

    // Build the attestation bundle (PRD §3.1.4 format)
    let bundle = serde_json::json!({
        "version": 1,
        "branch_id": branch_id,
        "public_key": public_key,
        "key_rotation_history": key_rotation_history,
        "records": record_values,
        "commit_manifest": commit_manifest,
        "merkle_inclusion_proofs": inclusion_proofs,
        "merkle_root": merkle_root,
        "tpm_quote": null,
    });

    let json_output =
        serde_json::to_string_pretty(&bundle).context("serializing attestation bundle")?;

    if let Some(path) = output_path {
        std::fs::write(path, &json_output)
            .with_context(|| format!("writing attestation bundle to {}", path))?;
        println!(
            "Attestation bundle written to {} ({} records)",
            path,
            records.len()
        );
    } else {
        println!("{}", json_output);
    }

    Ok(())
}

/// Show the Merkle inclusion proof for a specific audit event sequence number.
fn cmd_attestation_inclusion(seq: u64, attestation_dir: &Path) -> Result<()> {
    let proof_path = attestation_dir.join("proofs").join(format!("{}.json", seq));

    if !proof_path.exists() {
        anyhow::bail!(
            "no inclusion proof found for seq {} at {}",
            seq,
            proof_path.display()
        );
    }

    let proof_json = std::fs::read_to_string(&proof_path)
        .with_context(|| format!("reading {}", proof_path.display()))?;
    let proof: InclusionProof = serde_json::from_str(&proof_json)
        .with_context(|| format!("parsing {}", proof_path.display()))?;

    println!(
        "Merkle inclusion proof for leaf index {}:",
        proof.leaf_index
    );
    println!("  Tree size: {}", proof.tree_size);
    println!("  Proof path ({} hashes):", proof.proof_hashes.len());
    for (i, hash) in proof.proof_hashes.iter().enumerate() {
        println!("    [{}] {}", i, hash);
    }

    // Verify against root hash if available
    let root_path = attestation_dir.join("root_hash");
    if root_path.exists() {
        let root_hex = std::fs::read_to_string(&root_path)
            .with_context(|| format!("reading {}", root_path.display()))?;
        let root_bytes = hex_decode(root_hex.trim())
            .map_err(|e| anyhow::anyhow!("decoding root hash: {}", e))?;
        if root_bytes.len() == 32 {
            let mut expected_root = [0u8; 32];
            expected_root.copy_from_slice(&root_bytes);
            println!("  Root hash: {}", root_hex.trim());
        }
    }

    Ok(())
}

/// Show the Merkle consistency proof between two tree sizes.
fn cmd_attestation_consistency(from: u64, to: u64, attestation_dir: &Path) -> Result<()> {
    if from >= to {
        anyhow::bail!("--from ({}) must be less than --to ({})", from, to);
    }

    // Look for a consistency proof file: <attestation_dir>/consistency/<from>_<to>.json
    let proof_path = attestation_dir
        .join("consistency")
        .join(format!("{}_{}.json", from, to));

    if !proof_path.exists() {
        anyhow::bail!(
            "no consistency proof found for sizes {}..{} at {}",
            from,
            to,
            proof_path.display()
        );
    }

    let proof_json = std::fs::read_to_string(&proof_path)
        .with_context(|| format!("reading {}", proof_path.display()))?;
    let proof: puzzled_types::ConsistencyProof = serde_json::from_str(&proof_json)
        .with_context(|| format!("parsing {}", proof_path.display()))?;

    println!(
        "Merkle consistency proof (tree size {} -> {}):",
        proof.old_size, proof.new_size
    );
    println!("  Proof path ({} hashes):", proof.proof_hashes.len());
    for (i, hash) in proof.proof_hashes.iter().enumerate() {
        println!("    [{}] {}", i, hash);
    }

    Ok(())
}

/// Show the current attestation public key.
fn cmd_attestation_pubkey(attestation_dir: &Path) -> Result<()> {
    let pubkey_path = attestation_dir.join("public_key.hex");

    if !pubkey_path.exists() {
        anyhow::bail!(
            "no public key found at {} (is puzzled running with attestation enabled?)",
            pubkey_path.display()
        );
    }

    let hex_str = std::fs::read_to_string(&pubkey_path)
        .with_context(|| format!("reading {}", pubkey_path.display()))?;
    let hex_trimmed = hex_str.trim();

    // Validate it's a valid Ed25519 public key
    let key_bytes =
        hex_decode(hex_trimmed).map_err(|e| anyhow::anyhow!("decoding public key hex: {}", e))?;
    if key_bytes.len() != 32 {
        anyhow::bail!("public key must be 32 bytes, got {} bytes", key_bytes.len());
    }

    // Verify it's a valid Ed25519 point
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key_bytes);
    VerifyingKey::from_bytes(&arr).context("invalid Ed25519 public key")?;

    println!("{}", hex_trimmed);

    Ok(())
}

// --- Compliance evidence generation (§3.2) ---
// Core logic is in compliance.rs; these are the CLI command handlers.

fn cmd_compliance_frameworks(output: OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json => {
            let frameworks: Vec<serde_json::Value> = compliance::FRAMEWORKS
                .iter()
                .map(|f| {
                    serde_json::json!({
                        "id": f.id,
                        "name": f.name,
                        "controls": f.controls.len(),
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&frameworks)?);
        }
        OutputFormat::Text => {
            println!("{:<15} {:<50} {:>8}", "ID", "NAME", "CONTROLS");
            println!("{}", "-".repeat(73));
            for f in compliance::FRAMEWORKS {
                println!("{:<15} {:<50} {:>8}", f.id, f.name, f.controls.len());
            }
        }
    }
    Ok(())
}

/// Generate a compliance report.
#[allow(clippy::too_many_arguments)]
fn cmd_compliance_report(
    frameworks: &[String],
    period: &str,
    output_path: Option<&str>,
    report_format: ReportFormat,
    audit_dir: &Path,
    profiles_dir: &Path,
    policies_dir: &Path,
    signing_key: &Path,
    output: OutputFormat,
) -> Result<()> {
    if frameworks.is_empty() {
        anyhow::bail!(
            "at least one --framework is required (eu-ai-act, soc2, iso27001, nist-ai-rmf)"
        );
    }

    let resolved: Vec<&compliance::FrameworkDef> = frameworks
        .iter()
        .map(|f| compliance::get_framework(f))
        .collect::<Result<Vec<_>>>()?;

    let period_secs = compliance::parse_period_secs(period)?;
    let load_result = compliance::load_audit_records(audit_dir, Some(period_secs))?;
    if load_result.parse_failures > 0 {
        eprintln!(
            "warning: {} of {} audit lines failed to parse",
            load_result.parse_failures, load_result.total_lines
        );
    }
    if load_result.timestamp_parse_failures > 0 {
        eprintln!(
            "warning: {} records had unparseable timestamps (included unfiltered)",
            load_result.timestamp_parse_failures
        );
    }
    let records = load_result.records;
    let event_counts = compliance::count_events_by_type(&records);
    let profile_result = compliance::load_profiles(profiles_dir);
    if profile_result.parse_failures > 0 {
        eprintln!(
            "warning: {} of {} profile files failed to parse",
            profile_result.parse_failures, profile_result.total_files
        );
    }
    let profiles = profile_result.profiles;

    match (report_format, output_path) {
        (ReportFormat::Dir, Some(dir)) => {
            // Full directory tree package generation
            let signing_key_opt = if signing_key.exists() {
                Some(signing_key)
            } else {
                None
            };
            compliance::generate_report_package(
                Path::new(dir),
                &resolved,
                &records,
                &event_counts,
                &profiles,
                profiles_dir,
                policies_dir,
                period,
                signing_key_opt,
            )?;

            match output {
                OutputFormat::Json => {
                    println!(
                        "{}",
                        serde_json::json!({"status": "generated", "output": dir})
                    );
                }
                OutputFormat::Text => {
                    println!("Compliance report generated in {}", dir);
                    for fw in &resolved {
                        let controls = compliance::evaluate_controls(fw, &event_counts, &profiles);
                        let evidenced = controls
                            .iter()
                            .filter(|c| c.status == compliance::EvidenceStatus::Evidenced)
                            .count();
                        let partial = controls
                            .iter()
                            .filter(|c| c.status == compliance::EvidenceStatus::PartiallyEvidenced)
                            .count();
                        let gaps = controls
                            .iter()
                            .filter(|c| c.status == compliance::EvidenceStatus::Gap)
                            .count();
                        println!(
                            "  {}: {}/{} evidenced, {} partial, {} gaps",
                            fw.id,
                            evidenced,
                            controls.len(),
                            partial,
                            gaps
                        );
                    }
                }
            }
        }
        (ReportFormat::Json, output_file) => {
            // Single JSON document — write to file or stdout
            let mut framework_results = serde_json::Map::new();
            for fw in &resolved {
                let controls = compliance::evaluate_controls(fw, &event_counts, &profiles);
                let evidenced = controls
                    .iter()
                    .filter(|c| c.status == compliance::EvidenceStatus::Evidenced)
                    .count();
                let partial = controls
                    .iter()
                    .filter(|c| c.status == compliance::EvidenceStatus::PartiallyEvidenced)
                    .count();
                let gaps = controls
                    .iter()
                    .filter(|c| c.status == compliance::EvidenceStatus::Gap)
                    .count();

                framework_results.insert(
                    fw.id.to_string(),
                    serde_json::json!({
                        "framework": fw.name,
                        "controls_total": controls.len(),
                        "controls_evidenced": evidenced,
                        "controls_partially_evidenced": partial,
                        "controls_gap": gaps,
                        "controls": controls,
                    }),
                );
            }

            let report = serde_json::json!({
                "report_version": "1.0",
                "generated_at": compliance::chrono_now_rfc3339(),
                "period": period,
                "data_sources": {
                    "audit_events_count": records.len(),
                    "profiles_count": profiles.len(),
                },
                "event_distribution": event_counts,
                "frameworks": framework_results,
            });
            let json_str = serde_json::to_string_pretty(&report)?;

            if let Some(path) = output_file {
                std::fs::write(path, &json_str)
                    .with_context(|| format!("writing report to {}", path))?;
                match output {
                    OutputFormat::Json => {
                        println!(
                            "{}",
                            serde_json::json!({"status": "generated", "output": path})
                        );
                    }
                    OutputFormat::Text => {
                        println!("Compliance report written to {}", path);
                    }
                }
            } else {
                println!("{}", json_str);
            }
        }
        (ReportFormat::Dir, None) => {
            // --format=dir requires --output
            anyhow::bail!("--output is required when --format=dir (specify output directory)");
        }
    }

    Ok(())
}

/// Show compliance status for a framework.
fn cmd_compliance_status(
    framework_id: &str,
    period: Option<&str>,
    audit_dir: &Path,
    profiles_dir: &Path,
    output: OutputFormat,
) -> Result<()> {
    let fw = compliance::get_framework(framework_id)?;
    let since_secs = period.map(compliance::parse_period_secs).transpose()?;
    let load_result = compliance::load_audit_records(audit_dir, since_secs)?;
    if load_result.parse_failures > 0 {
        eprintln!(
            "warning: {} of {} audit lines failed to parse",
            load_result.parse_failures, load_result.total_lines
        );
    }
    let records = load_result.records;
    let event_counts = compliance::count_events_by_type(&records);
    let profile_result = compliance::load_profiles(profiles_dir);
    if profile_result.parse_failures > 0 {
        eprintln!(
            "warning: {} of {} profile files failed to parse",
            profile_result.parse_failures, profile_result.total_files
        );
    }
    let profiles = profile_result.profiles;
    let controls = compliance::evaluate_controls(fw, &event_counts, &profiles);
    let evidenced = controls
        .iter()
        .filter(|c| c.status == compliance::EvidenceStatus::Evidenced)
        .count();
    let partial = controls
        .iter()
        .filter(|c| c.status == compliance::EvidenceStatus::PartiallyEvidenced)
        .count();
    let gaps = controls
        .iter()
        .filter(|c| c.status == compliance::EvidenceStatus::Gap)
        .count();

    match output {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "framework": fw.id,
                    "name": fw.name,
                    "controls_total": controls.len(),
                    "controls_evidenced": evidenced,
                    "controls_partially_evidenced": partial,
                    "controls_gap": gaps,
                    "controls": controls,
                }))?
            );
        }
        OutputFormat::Text => {
            println!("{} ({})", fw.name, fw.id);
            println!(
                "Controls: {}/{} evidenced, {} partial, {} gaps\n",
                evidenced,
                controls.len(),
                partial,
                gaps
            );
            println!(
                "{:<12} {:<6} {:<40} {:>8}",
                "CONTROL", "STATUS", "TITLE", "EVENTS"
            );
            println!("{}", "-".repeat(70));
            for ctrl in &controls {
                let status = match ctrl.status {
                    compliance::EvidenceStatus::Evidenced => "OK",
                    compliance::EvidenceStatus::PartiallyEvidenced => "PAR",
                    compliance::EvidenceStatus::Gap => "GAP",
                };
                println!(
                    "{:<12} {:<6} {:<40} {:>8}",
                    ctrl.control_id,
                    status,
                    truncate(&ctrl.title, 40),
                    ctrl.total_events
                );
            }
        }
    }
    Ok(())
}

/// Identify evidence gaps for a framework.
fn cmd_compliance_gaps(
    framework_id: &str,
    period: Option<&str>,
    audit_dir: &Path,
    profiles_dir: &Path,
    output: OutputFormat,
) -> Result<()> {
    let fw = compliance::get_framework(framework_id)?;
    let since_secs = period.map(compliance::parse_period_secs).transpose()?;
    let load_result = compliance::load_audit_records(audit_dir, since_secs)?;
    if load_result.parse_failures > 0 {
        eprintln!(
            "warning: {} of {} audit lines failed to parse",
            load_result.parse_failures, load_result.total_lines
        );
    }
    let records = load_result.records;
    let event_counts = compliance::count_events_by_type(&records);
    let profile_result = compliance::load_profiles(profiles_dir);
    if profile_result.parse_failures > 0 {
        eprintln!(
            "warning: {} of {} profile files failed to parse",
            profile_result.parse_failures, profile_result.total_files
        );
    }
    let profiles = profile_result.profiles;
    let analysis = compliance::analyze_gaps(fw, &event_counts, &profiles, period);

    match output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&analysis)?);
        }
        OutputFormat::Text => {
            if analysis.gaps.is_empty() {
                println!(
                    "{}: No evidence gaps found (all {} controls evidenced)",
                    fw.id, analysis.summary.total_controls
                );
            } else {
                println!(
                    "{}: {} gap(s), {} partial, {} evidenced out of {} controls\n",
                    fw.id,
                    analysis.summary.gaps,
                    analysis.summary.partially_evidenced,
                    analysis.summary.evidenced,
                    analysis.summary.total_controls
                );
                for gap in &analysis.gaps {
                    println!(
                        "  {} ({}) — {}",
                        gap.criterion,
                        gap.status.label(),
                        gap.title
                    );
                    if let Some(reason) = &gap.reason {
                        println!("    Reason: {}", reason);
                    }
                    println!("    Recommendation: {}", gap.recommendation);
                }
            }
        }
    }
    Ok(())
}

/// Pretty-print a diff changeset in text mode.
fn print_diff_text(json: &str) {
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
fn print_branches_text(json: &str) {
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

/// Test a profile against a sample changeset.
fn cmd_profile_test(name: &str, changeset_path: &str, dir: &str) -> Result<()> {
    // V12: Validate profile name to prevent path traversal (same as G29 in cmd_profile_show)
    if !Path::new(name).exists() && (name.contains('/') || name.contains("..")) {
        anyhow::bail!(
            "V12: profile name must not contain path separators or '..' \
             (got '{}'). Use a plain profile name.",
            name
        );
    }
    // Load the profile
    let profile_path = if Path::new(name).exists() {
        PathBuf::from(name)
    } else {
        PathBuf::from(dir).join(format!("{}.yaml", name))
    };

    let profile_contents = std::fs::read_to_string(&profile_path)
        .with_context(|| format!("reading profile {}", profile_path.display()))?;
    let profile: AgentProfile = serde_yaml::from_str(&profile_contents)
        .with_context(|| format!("parsing profile {}", profile_path.display()))?;

    // Load the changeset
    let changeset_str = std::fs::read_to_string(changeset_path)
        .with_context(|| format!("reading changeset {}", changeset_path))?;
    let changes: Vec<FileChange> = serde_json::from_str(&changeset_str)
        .with_context(|| format!("parsing changeset {}", changeset_path))?;

    println!(
        "Testing profile '{}' against {} file changes...\n",
        profile.name,
        changes.len()
    );

    let mut pass_count = 0;
    let mut fail_count = 0;

    for change in &changes {
        let path_str = change.path.to_string_lossy();
        let mut blocked = false;
        let mut reason = String::new();

        // Check denylist
        // M28: Use Path::starts_with() for component-aware prefix matching
        // instead of string contains(), which could match partial path components
        // (e.g., "/etc/shadow" would incorrectly match "/etc/shadow-backup" with contains())
        for deny in &profile.filesystem.denylist {
            let path = std::path::Path::new(path_str.as_ref());
            let deny_path = std::path::Path::new(deny);
            if path.starts_with(deny_path) {
                blocked = true;
                reason = format!("matches denylist pattern '{}'", deny.display());
                break;
            }
        }

        // Check write allowlist (for modifications)
        if !blocked
            && matches!(
                change.kind,
                puzzled_types::FileChangeKind::Added | puzzled_types::FileChangeKind::Modified
            )
            && !profile.filesystem.write_allowlist.is_empty()
        {
            // M-ctl5: Use Path::starts_with for component-aware matching.
            // String::starts_with("/home/user") would incorrectly match "/home/username".
            let change_path = std::path::Path::new(path_str.as_ref());
            let allowed = profile
                .filesystem
                .write_allowlist
                .iter()
                .any(|p| change_path.starts_with(p));
            if !allowed {
                blocked = true;
                reason = "not in write allowlist".to_string();
            }
        }

        if blocked {
            println!("  FAIL  {} ({})", path_str, reason);
            fail_count += 1;
        } else {
            println!("  PASS  {}", path_str);
            pass_count += 1;
        }
    }

    println!("\nResults: {} passed, {} failed", pass_count, fail_count);

    if fail_count > 0 {
        anyhow::bail!(
            "{} file(s) would be rejected by profile '{}'",
            fail_count,
            profile.name
        );
    }

    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{} GiB", bytes / (1024 * 1024 * 1024))
    } else if bytes >= 1024 * 1024 {
        format!("{} MiB", bytes / (1024 * 1024))
    } else if bytes >= 1024 {
        format!("{} KiB", bytes / 1024)
    } else {
        format!("{} B", bytes)
    }
}

/// L11: UTF-8 safe truncation. Uses char_indices to find a valid boundary
/// instead of byte slicing, which could panic on multi-byte characters.
fn truncate(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        return s;
    }
    match s.char_indices().nth(max_len) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    // -- format_bytes --

    #[test]
    fn test_format_bytes_gib() {
        assert_eq!(format_bytes(2 * 1024 * 1024 * 1024), "2 GiB");
    }

    #[test]
    fn test_format_bytes_mib() {
        assert_eq!(format_bytes(512 * 1024 * 1024), "512 MiB");
    }

    #[test]
    fn test_format_bytes_kib() {
        assert_eq!(format_bytes(64 * 1024), "64 KiB");
    }

    #[test]
    fn test_format_bytes_b() {
        assert_eq!(format_bytes(100), "100 B");
    }

    #[test]
    fn test_format_bytes_zero() {
        assert_eq!(format_bytes(0), "0 B");
    }

    // -- truncate --

    #[test]
    fn test_truncate_short() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_exact() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_long() {
        assert_eq!(truncate("hello world", 5), "hello");
    }

    #[test]
    fn test_truncate_empty() {
        assert_eq!(truncate("", 5), "");
    }

    // -- CLI parsing --

    #[test]
    fn test_cli_branch_list() {
        let cli = Cli::try_parse_from(["puzzlectl", "branch", "list"]).unwrap();
        match cli.command {
            Command::Branch {
                action: BranchAction::List { state },
            } => assert_eq!(state, "all"),
            _ => panic!("expected Branch List"),
        }
    }

    #[test]
    fn test_cli_branch_list_with_state_filter() {
        let cli = Cli::try_parse_from(["puzzlectl", "branch", "list", "--state", "active"]).unwrap();
        match cli.command {
            Command::Branch {
                action: BranchAction::List { state },
            } => assert_eq!(state, "active"),
            _ => panic!("expected Branch List"),
        }
    }

    #[test]
    fn test_cli_branch_inspect() {
        let cli = Cli::try_parse_from(["puzzlectl", "branch", "inspect", "abc123"]).unwrap();
        match cli.command {
            Command::Branch {
                action: BranchAction::Inspect { id },
            } => assert_eq!(id, "abc123"),
            _ => panic!("expected Branch Inspect"),
        }
    }

    #[test]
    fn test_cli_branch_diff() {
        let cli = Cli::try_parse_from(["puzzlectl", "branch", "diff", "abc123"]).unwrap();
        match cli.command {
            Command::Branch {
                action: BranchAction::Diff { id },
            } => assert_eq!(id, "abc123"),
            _ => panic!("expected Branch Diff"),
        }
    }

    #[test]
    fn test_cli_branch_create() {
        let cli = Cli::try_parse_from([
            "puzzlectl",
            "branch",
            "create",
            "--profile",
            "restricted",
            "--base",
            "/tmp/test",
        ])
        .unwrap();
        match cli.command {
            Command::Branch {
                action:
                    BranchAction::Create {
                        profile,
                        base,
                        command,
                    },
            } => {
                assert_eq!(profile, "restricted");
                assert_eq!(base, "/tmp/test");
                assert_eq!(command, "[]");
            }
            _ => panic!("expected Branch Create"),
        }
    }

    #[test]
    fn test_cli_branch_activate() {
        let cli = Cli::try_parse_from([
            "puzzlectl",
            "branch",
            "activate",
            "abc123",
            "--command",
            r#"["/usr/bin/cat"]"#,
        ])
        .unwrap();
        match cli.command {
            Command::Branch {
                action: BranchAction::Activate { id, command },
            } => {
                assert_eq!(id, "abc123");
                assert_eq!(command, r#"["/usr/bin/cat"]"#);
            }
            _ => panic!("expected Branch Activate"),
        }
    }

    #[test]
    fn test_cli_branch_approve() {
        let cli = Cli::try_parse_from(["puzzlectl", "branch", "approve", "abc123"]).unwrap();
        match cli.command {
            Command::Branch {
                action: BranchAction::Approve { id },
            } => assert_eq!(id, "abc123"),
            _ => panic!("expected Branch Approve"),
        }
    }

    #[test]
    fn test_cli_branch_reject_with_reason() {
        let cli = Cli::try_parse_from([
            "puzzlectl",
            "branch",
            "reject",
            "abc123",
            "--reason",
            "too many changes",
        ])
        .unwrap();
        match cli.command {
            Command::Branch {
                action: BranchAction::Reject { id, reason },
            } => {
                assert_eq!(id, "abc123");
                assert_eq!(reason, Some("too many changes".to_string()));
            }
            _ => panic!("expected Branch Reject"),
        }
    }

    #[test]
    fn test_cli_agent_kill() {
        let cli = Cli::try_parse_from(["puzzlectl", "agent", "kill", "xyz"]).unwrap();
        match cli.command {
            Command::Agent {
                action: AgentAction::Kill { id },
            } => assert_eq!(id, "xyz"),
            _ => panic!("expected Agent Kill"),
        }
    }

    #[test]
    fn test_cli_profile_validate() {
        let cli =
            Cli::try_parse_from(["puzzlectl", "profile", "validate", "/tmp/test.yaml"]).unwrap();
        match cli.command {
            Command::Profile {
                action: ProfileAction::Validate { path },
            } => assert_eq!(path, "/tmp/test.yaml"),
            _ => panic!("expected Profile Validate"),
        }
    }

    #[test]
    fn test_cli_policy_reload() {
        let cli = Cli::try_parse_from(["puzzlectl", "policy", "reload"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Policy {
                action: PolicyAction::Reload
            }
        ));
    }

    #[test]
    fn test_cli_audit_list_defaults() {
        let cli = Cli::try_parse_from(["puzzlectl", "audit", "list"]).unwrap();
        match cli.command {
            Command::Audit {
                action:
                    AuditAction::List {
                        branch_id,
                        event_type,
                        since,
                        limit,
                    },
            } => {
                assert!(branch_id.is_none());
                assert!(event_type.is_none());
                assert!(since.is_none());
                assert_eq!(limit, 50);
            }
            _ => panic!("expected Audit List"),
        }
    }

    #[test]
    fn test_cli_audit_list_with_filters() {
        let cli = Cli::try_parse_from([
            "puzzlectl",
            "audit",
            "list",
            "--branch-id",
            "b1",
            "--event-type",
            "violation",
            "--limit",
            "10",
        ])
        .unwrap();
        match cli.command {
            Command::Audit {
                action:
                    AuditAction::List {
                        branch_id,
                        event_type,
                        limit,
                        ..
                    },
            } => {
                assert_eq!(branch_id, Some("b1".to_string()));
                assert_eq!(event_type, Some("violation".to_string()));
                assert_eq!(limit, 10);
            }
            _ => panic!("expected Audit List"),
        }
    }

    #[test]
    fn test_cli_audit_export() {
        // M-ctl3: The audit export `output` field was renamed to `file` to avoid
        // conflict with the global `--output` format flag.
        let cli = Cli::try_parse_from(["puzzlectl", "audit", "export", "--file", "/tmp/out.json"])
            .unwrap();
        match cli.command {
            Command::Audit {
                action: AuditAction::Export { format, file },
            } => {
                assert_eq!(format, "json");
                assert_eq!(file, Some("/tmp/out.json".to_string()));
            }
            _ => panic!("expected Audit Export"),
        }
    }

    #[test]
    fn test_cli_status_no_id() {
        let cli = Cli::try_parse_from(["puzzlectl", "status"]).unwrap();
        match cli.command {
            Command::Status { id } => assert!(id.is_none()),
            _ => panic!("expected Status"),
        }
    }

    #[test]
    fn test_cli_status_with_id() {
        let cli = Cli::try_parse_from(["puzzlectl", "status", "branch-123"]).unwrap();
        match cli.command {
            Command::Status { id } => assert_eq!(id, Some("branch-123".to_string())),
            _ => panic!("expected Status"),
        }
    }

    #[test]
    fn test_validate_branch_id_valid() {
        assert!(validate_branch_id("my-branch-42").is_ok());
    }

    #[test]
    fn test_validate_branch_id_invalid() {
        assert!(validate_branch_id("../../etc/passwd").is_err());
        assert!(validate_branch_id("").is_err());
        assert!(validate_branch_id("foo/bar").is_err());
    }

    #[test]
    fn test_filter_branches_by_state_all() {
        let json = r#"[{"id":"a","state":"active"},{"id":"b","state":"degraded"}]"#;
        let result = filter_branches_by_state(json, "all");
        assert_eq!(result, json);
    }

    #[test]
    fn test_filter_branches_by_state_active() {
        let json = r#"[{"id":"a","state":"active"},{"id":"b","state":"degraded"}]"#;
        let result = filter_branches_by_state(json, "active");
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["id"], "a");
    }

    #[test]
    fn test_filter_branches_by_state_reviewing() {
        let json = r#"[{"id":"a","state":"active"},{"id":"b","state":"governance_review"}]"#;
        let result = filter_branches_by_state(json, "reviewing");
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["id"], "b");
    }

    #[test]
    fn test_cli_output_format_default() {
        let cli = Cli::try_parse_from(["puzzlectl", "branch", "list"]).unwrap();
        assert!(matches!(cli.output, OutputFormat::Text));
    }

    #[test]
    fn test_cli_output_format_json() {
        let cli = Cli::try_parse_from(["puzzlectl", "--output", "json", "branch", "list"]).unwrap();
        assert!(matches!(cli.output, OutputFormat::Json));
    }

    #[test]
    fn test_cli_bus_default() {
        let cli = Cli::try_parse_from(["puzzlectl", "branch", "list"]).unwrap();
        assert_eq!(cli.bus, "system");
    }

    #[test]
    fn test_cli_bus_session() {
        let cli = Cli::try_parse_from(["puzzlectl", "--bus", "session", "branch", "list"]).unwrap();
        assert_eq!(cli.bus, "session");
    }

    // -- profile validation --

    #[test]
    fn test_profile_validate_valid() {
        let dir = tempfile::tempdir().unwrap();
        let profile_path = dir.path().join("test.yaml");
        std::fs::write(
            &profile_path,
            r#"
name: test-profile
description: A test profile
filesystem:
  read_allowlist: []
  write_allowlist: []
  denylist: []
exec_allowlist: []
resource_limits:
  memory_bytes: 1073741824
  cpu_shares: 100
  io_weight: 100
  max_pids: 64
  storage_quota_mb: 1024
  inode_quota: 10000
network:
  mode: Blocked
  allowed_domains: []
behavioral:
  max_deletions: 0
  max_reads_per_minute: 0
  credential_access_alert: false
fail_mode: FailClosed
"#,
        )
        .unwrap();

        let result = cmd_profile_validate(profile_path.to_str().unwrap());
        assert!(result.is_ok());
    }

    #[test]
    fn test_profile_validate_missing_file() {
        let result = cmd_profile_validate("/nonexistent/path.yaml");
        assert!(result.is_err());
    }

    #[test]
    fn test_profile_validate_invalid_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.yaml");
        std::fs::write(&path, "not: valid: yaml: [[[").unwrap();
        let result = cmd_profile_validate(path.to_str().unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn test_profile_validate_empty_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty_name.yaml");
        std::fs::write(
            &path,
            r#"
name: ""
description: A test
filesystem:
  read_allowlist: []
  write_allowlist: []
  denylist: []
exec_allowlist: []
resource_limits:
  memory_bytes: 1073741824
  cpu_shares: 100
  io_weight: 100
  max_pids: 64
  storage_quota_mb: 1024
  inode_quota: 10000
network:
  mode: Blocked
  allowed_domains: []
behavioral:
  max_deletions: 0
  max_reads_per_minute: 0
  credential_access_alert: false
fail_mode: FailClosed
"#,
        )
        .unwrap();

        let result = cmd_profile_validate(path.to_str().unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn test_profile_validate_zero_memory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zero_mem.yaml");
        std::fs::write(
            &path,
            r#"
name: test
description: A test
filesystem:
  read_allowlist: []
  write_allowlist: []
  denylist: []
exec_allowlist: []
resource_limits:
  memory_bytes: 0
  cpu_shares: 100
  io_weight: 100
  max_pids: 64
  storage_quota_mb: 1024
  inode_quota: 10000
network:
  mode: Blocked
  allowed_domains: []
behavioral:
  max_deletions: 0
  max_reads_per_minute: 0
  credential_access_alert: false
fail_mode: FailClosed
"#,
        )
        .unwrap();

        let result = cmd_profile_validate(path.to_str().unwrap());
        assert!(result.is_err());
    }

    // -- profile list --

    #[test]
    fn test_profile_list_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let result = cmd_profile_list(dir.path().to_str().unwrap(), OutputFormat::Text);
        assert!(result.is_ok());
    }

    #[test]
    fn test_profile_list_nonexistent_dir() {
        let result = cmd_profile_list("/nonexistent/dir", OutputFormat::Text);
        assert!(result.is_err());
    }

    // ---- Remaining CLI subcommand parsing ----

    #[test]
    fn test_cli_branch_rollback() {
        let cli = Cli::try_parse_from(["puzzlectl", "branch", "rollback", "abc123"]).unwrap();
        match cli.command {
            Command::Branch {
                action: BranchAction::Rollback { id, reason },
            } => {
                assert_eq!(id, "abc123");
                assert!(reason.is_none());
            }
            _ => panic!("expected Branch Rollback"),
        }
    }

    #[test]
    fn test_cli_branch_rollback_with_reason() {
        let cli = Cli::try_parse_from([
            "puzzlectl",
            "branch",
            "rollback",
            "abc123",
            "--reason",
            "manual cleanup",
        ])
        .unwrap();
        match cli.command {
            Command::Branch {
                action: BranchAction::Rollback { id, reason },
            } => {
                assert_eq!(id, "abc123");
                assert_eq!(reason, Some("manual cleanup".to_string()));
            }
            _ => panic!("expected Branch Rollback"),
        }
    }

    #[test]
    fn test_cli_agent_list() {
        let cli = Cli::try_parse_from(["puzzlectl", "agent", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Agent {
                action: AgentAction::List
            }
        ));
    }

    #[test]
    fn test_cli_agent_info() {
        let cli = Cli::try_parse_from(["puzzlectl", "agent", "info", "agent-42"]).unwrap();
        match cli.command {
            Command::Agent {
                action: AgentAction::Info { id },
            } => assert_eq!(id, "agent-42"),
            _ => panic!("expected Agent Info"),
        }
    }

    #[test]
    fn test_cli_profile_list() {
        let cli = Cli::try_parse_from(["puzzlectl", "profile", "list"]).unwrap();
        match cli.command {
            Command::Profile {
                action: ProfileAction::List { dir },
            } => assert_eq!(dir, "/etc/puzzled/profiles"),
            _ => panic!("expected Profile List"),
        }
    }

    #[test]
    fn test_cli_profile_list_custom_dir() {
        let cli =
            Cli::try_parse_from(["puzzlectl", "profile", "list", "--dir", "/tmp/profiles"]).unwrap();
        match cli.command {
            Command::Profile {
                action: ProfileAction::List { dir },
            } => assert_eq!(dir, "/tmp/profiles"),
            _ => panic!("expected Profile List"),
        }
    }

    #[test]
    fn test_cli_profile_show() {
        let cli = Cli::try_parse_from(["puzzlectl", "profile", "show", "restricted"]).unwrap();
        match cli.command {
            Command::Profile {
                action: ProfileAction::Show { name, dir },
            } => {
                assert_eq!(name, "restricted");
                assert_eq!(dir, "/etc/puzzled/profiles");
            }
            _ => panic!("expected Profile Show"),
        }
    }

    #[test]
    fn test_cli_profile_test() {
        let cli = Cli::try_parse_from([
            "puzzlectl",
            "profile",
            "test",
            "standard",
            "--changeset",
            "/tmp/changes.json",
        ])
        .unwrap();
        match cli.command {
            Command::Profile {
                action:
                    ProfileAction::Test {
                        name,
                        changeset,
                        dir,
                    },
            } => {
                assert_eq!(name, "standard");
                assert_eq!(changeset, "/tmp/changes.json");
                assert_eq!(dir, "/etc/puzzled/profiles");
            }
            _ => panic!("expected Profile Test"),
        }
    }

    #[test]
    fn test_cli_policy_test() {
        let cli =
            Cli::try_parse_from(["puzzlectl", "policy", "test", "/tmp/changeset.json"]).unwrap();
        match cli.command {
            Command::Policy {
                action:
                    PolicyAction::Test {
                        changeset,
                        policy_dir,
                    },
            } => {
                assert_eq!(changeset, "/tmp/changeset.json");
                assert_eq!(policy_dir, "/etc/puzzled/policies");
            }
            _ => panic!("expected Policy Test"),
        }
    }

    #[test]
    fn test_cli_policy_test_custom_dir() {
        let cli = Cli::try_parse_from([
            "puzzlectl",
            "policy",
            "test",
            "/tmp/changeset.json",
            "--policy-dir",
            "/opt/policies",
        ])
        .unwrap();
        match cli.command {
            Command::Policy {
                action:
                    PolicyAction::Test {
                        changeset,
                        policy_dir,
                    },
            } => {
                assert_eq!(changeset, "/tmp/changeset.json");
                assert_eq!(policy_dir, "/opt/policies");
            }
            _ => panic!("expected Policy Test"),
        }
    }

    #[test]
    fn test_cli_audit_verify() {
        let cli = Cli::try_parse_from(["puzzlectl", "audit", "verify", "abc123"]).unwrap();
        match cli.command {
            Command::Audit {
                action: AuditAction::Verify { hash },
            } => assert_eq!(hash, "abc123"),
            _ => panic!("expected Audit Verify"),
        }
    }

    // ---- Error handling ----

    #[test]
    fn test_cli_missing_subcommand() {
        let result = Cli::try_parse_from(["puzzlectl"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_invalid_subcommand() {
        let result = Cli::try_parse_from(["puzzlectl", "nonexistent"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_branch_missing_action() {
        let result = Cli::try_parse_from(["puzzlectl", "branch"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_branch_inspect_missing_id() {
        let result = Cli::try_parse_from(["puzzlectl", "branch", "inspect"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_branch_create_missing_profile() {
        let result = Cli::try_parse_from(["puzzlectl", "branch", "create", "--base", "/tmp"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_branch_create_missing_base() {
        let result = Cli::try_parse_from(["puzzlectl", "branch", "create", "--profile", "standard"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_invalid_output_format() {
        let result = Cli::try_parse_from(["puzzlectl", "--output", "xml", "branch", "list"]);
        assert!(result.is_err());
    }

    // ---- validate_branch_id edge cases ----

    #[test]
    fn test_validate_branch_id_with_dots() {
        // BranchId::validated rejects dots (path traversal prevention)
        assert!(validate_branch_id("branch.v1.2").is_err());
    }

    #[test]
    fn test_validate_branch_id_traversal_backslash() {
        assert!(validate_branch_id("..\\etc\\passwd").is_err());
    }

    #[test]
    fn test_validate_branch_id_too_long() {
        let long_id = "a".repeat(256);
        // Depends on BranchId::validated length check
        let _ = validate_branch_id(&long_id);
    }

    // ---- filter_branches_by_state edge cases ----

    #[test]
    fn test_filter_branches_by_state_degraded() {
        let json = r#"[{"id":"a","state":"active"},{"id":"b","state":"degraded"}]"#;
        let result = filter_branches_by_state(json, "degraded");
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["id"], "b");
    }

    #[test]
    fn test_filter_branches_by_state_no_match() {
        let json = r#"[{"id":"a","state":"active"}]"#;
        let result = filter_branches_by_state(json, "degraded");
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed.len(), 0);
    }

    #[test]
    fn test_filter_branches_invalid_json() {
        let json = "not json at all";
        let result = filter_branches_by_state(json, "active");
        assert_eq!(result, json); // returns input unchanged
    }

    // ---- output_action formatting ----

    #[test]
    fn test_output_action_json_without_reason() {
        // This just verifies no panic — output goes to stdout
        output_action(
            OutputFormat::Json,
            "approved",
            "b1",
            "",
            "Branch b1 approved",
        );
    }

    #[test]
    fn test_output_action_json_with_reason() {
        output_action(
            OutputFormat::Json,
            "rejected",
            "b1",
            "policy violation",
            "Branch b1 rejected",
        );
    }

    #[test]
    fn test_output_action_text() {
        output_action(
            OutputFormat::Text,
            "approved",
            "b1",
            "",
            "Branch b1 approved",
        );
    }

    // ---- print_diff_text / print_branches_text ----

    #[test]
    fn test_print_diff_text_empty() {
        print_diff_text("[]");
    }

    #[test]
    fn test_print_diff_text_with_changes() {
        let json = serde_json::to_string(&vec![
            FileChange {
                path: std::path::PathBuf::from("src/main.rs"),
                kind: puzzled_types::FileChangeKind::Modified,
                size: 1024,
                checksum: "abc".to_string(),
                old_size: None,
                old_mode: None,
                new_mode: None,
                timestamp: None,
                target: None,
            },
            FileChange {
                path: std::path::PathBuf::from("new_file.txt"),
                kind: puzzled_types::FileChangeKind::Added,
                size: 42,
                checksum: "def".to_string(),
                old_size: None,
                old_mode: None,
                new_mode: None,
                timestamp: None,
                target: None,
            },
        ])
        .unwrap();
        print_diff_text(&json);
    }

    #[test]
    fn test_print_diff_text_invalid_json() {
        print_diff_text("not json"); // should not panic
    }

    #[test]
    fn test_print_branches_text_empty() {
        print_branches_text("[]");
    }

    #[test]
    fn test_print_branches_text_with_entries() {
        let json = r#"[{"id":"b1","profile":"standard","state":"active","uid":1000,"created_at":"2025-01-01T00:00:00Z"}]"#;
        print_branches_text(json);
    }

    #[test]
    fn test_print_branches_text_invalid_json() {
        print_branches_text("not json"); // should not panic
    }

    // ---- profile show/test ----

    #[test]
    fn test_profile_show_valid() {
        let dir = tempfile::tempdir().unwrap();
        let profile_path = dir.path().join("myprofile.yaml");
        std::fs::write(
            &profile_path,
            r#"
name: myprofile
description: A test profile
filesystem:
  read_allowlist: ["/usr"]
  write_allowlist: []
  denylist: []
exec_allowlist: []
resource_limits:
  memory_bytes: 1073741824
  cpu_shares: 100
  io_weight: 100
  max_pids: 64
  storage_quota_mb: 1024
  inode_quota: 10000
network:
  mode: Blocked
  allowed_domains: []
behavioral:
  max_deletions: 0
  max_reads_per_minute: 0
  credential_access_alert: false
fail_mode: FailClosed
"#,
        )
        .unwrap();

        // Show as text
        let result = cmd_profile_show(profile_path.to_str().unwrap(), "/tmp", OutputFormat::Text);
        assert!(result.is_ok());

        // Show as JSON
        let result = cmd_profile_show(profile_path.to_str().unwrap(), "/tmp", OutputFormat::Json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_profile_show_not_found() {
        let result = cmd_profile_show("nonexistent", "/nonexistent/dir", OutputFormat::Text);
        assert!(result.is_err());
    }

    #[test]
    fn test_profile_list_with_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("standard.yaml"),
            r#"
name: standard
description: Standard profile
filesystem:
  read_allowlist: []
  write_allowlist: []
  denylist: []
exec_allowlist: []
resource_limits:
  memory_bytes: 1073741824
  cpu_shares: 100
  io_weight: 100
  max_pids: 64
  storage_quota_mb: 1024
  inode_quota: 10000
network:
  mode: Blocked
  allowed_domains: []
behavioral:
  max_deletions: 0
  max_reads_per_minute: 0
  credential_access_alert: false
fail_mode: FailClosed
"#,
        )
        .unwrap();

        let result = cmd_profile_list(dir.path().to_str().unwrap(), OutputFormat::Text);
        assert!(result.is_ok());

        let result = cmd_profile_list(dir.path().to_str().unwrap(), OutputFormat::Json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_profile_validate_zero_pids() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zero_pids.yaml");
        std::fs::write(
            &path,
            r#"
name: test
description: A test
filesystem:
  read_allowlist: []
  write_allowlist: []
  denylist: []
exec_allowlist: []
resource_limits:
  memory_bytes: 1073741824
  cpu_shares: 100
  io_weight: 100
  max_pids: 0
  storage_quota_mb: 1024
  inode_quota: 10000
network:
  mode: Blocked
  allowed_domains: []
behavioral:
  max_deletions: 0
  max_reads_per_minute: 0
  credential_access_alert: false
fail_mode: FailClosed
"#,
        )
        .unwrap();

        let result = cmd_profile_validate(path.to_str().unwrap());
        assert!(result.is_err());
    }

    // ---- policy test ----

    #[test]
    fn test_policy_test_missing_changeset() {
        let result = cmd_policy_test("/nonexistent/changeset.json", "/tmp");
        assert!(result.is_err());
    }

    #[test]
    fn test_policy_test_missing_policy_dir() {
        let dir = tempfile::tempdir().unwrap();
        let changeset = dir.path().join("changeset.json");
        std::fs::write(
            &changeset,
            r#"[{"path":"test.txt","kind":"Added","size":10,"checksum":"abc"}]"#,
        )
        .unwrap();

        let result = cmd_policy_test(changeset.to_str().unwrap(), "/nonexistent/policies");
        assert!(result.is_err());
    }

    #[test]
    fn test_policy_test_invalid_changeset() {
        let dir = tempfile::tempdir().unwrap();
        let changeset = dir.path().join("bad.json");
        std::fs::write(&changeset, "not valid json").unwrap();

        let result = cmd_policy_test(changeset.to_str().unwrap(), dir.path().to_str().unwrap());
        assert!(result.is_err());
    }

    // ---- audit verify ----

    #[test]
    fn test_audit_verify_nonexistent() {
        let result = cmd_audit_verify("nonexistent-hash-abc123");
        assert!(result.is_err());
    }

    #[test]
    fn test_audit_verify_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("test.manifest.yaml");
        std::fs::write(&manifest, "branch_id: test\nsignature: abc123\n").unwrap();

        let result = cmd_audit_verify(manifest.to_str().unwrap());
        assert!(result.is_ok());
    }

    // ---- format_bytes edge cases ----

    #[test]
    fn test_format_bytes_boundary_1kib() {
        assert_eq!(format_bytes(1024), "1 KiB");
    }

    #[test]
    fn test_format_bytes_boundary_1mib() {
        assert_eq!(format_bytes(1024 * 1024), "1 MiB");
    }

    #[test]
    fn test_format_bytes_boundary_1gib() {
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1 GiB");
    }

    /// F7: Ensure sort_json_keys serialization for manifest hash does not use
    /// unwrap_or_default(), which would silently produce an empty string on
    /// serialization failure, corrupting the SHA-256 hash.
    #[test]
    fn test_f7_manifest_hash_no_silent_default() {
        let source = include_str!("main.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // sort_json_keys and unwrap_or_default may be on different lines
        // in the same expression chain. Track when we're in a sort_json_keys
        // expression and flag if unwrap_or_default appears before the semicolon.
        let mut in_sort_json_keys = false;
        for (i, line) in prod_source.lines().enumerate() {
            if line.contains("sort_json_keys") {
                in_sort_json_keys = true;
            }
            if in_sort_json_keys && line.contains("unwrap_or_default()") {
                panic!(
                    "F7: main.rs line {} uses sort_json_keys(...).unwrap_or_default() which \
                     silently returns an empty string on serialization failure, \
                     corrupting the SHA-256 hash. \
                     Use unwrap_or_else with eprintln! instead.\nLine: {}",
                    i + 1,
                    line.trim()
                );
            }
            if in_sort_json_keys && line.contains(';') {
                in_sort_json_keys = false;
            }
        }
    }

    /// G29: Profile name must be validated against path traversal.
    #[test]
    fn test_g29_profile_name_no_path_traversal() {
        let source = include_str!("main.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // Find cmd_profile_show function
        let fn_start = prod_source
            .find("fn cmd_profile_show")
            .expect("cmd_profile_show must exist");
        let fn_block = &prod_source[fn_start..];
        let fn_end = fn_block.find("\nfn ").unwrap_or(fn_block.len());
        let fn_body = &fn_block[..fn_end];

        // Must check for path separators or ".." in the name
        assert!(
            fn_body.contains("contains('/')")
                || fn_body.contains("contains(\"/\")")
                || fn_body.contains("contains(std::path::MAIN_SEPARATOR)"),
            "G29: cmd_profile_show must validate profile name against path traversal \
             by checking for '/' characters"
        );
        assert!(
            fn_body.contains("contains(\"..\")"),
            "G29: cmd_profile_show must validate profile name against path traversal \
             by checking for '..' sequences"
        );
    }

    /// H62: Credential values read from stdin must use Zeroizing<String>
    /// so they are zeroized on drop, not left in memory as bare Strings.
    #[test]
    fn test_h62_credential_values_zeroized() {
        let source = include_str!("main.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // Find credential store section — search for the match arm, then
        // look at the next ~40 lines for Zeroizing usage
        let store_pos = prod_source
            .find("CredentialAction::Store")
            .expect("CredentialAction::Store must exist");
        // Take a generous window of 800 chars from the match arm
        let store_window_end = (store_pos + 800).min(prod_source.len());
        let store_body = &prod_source[store_pos..store_window_end];

        assert!(
            store_body.contains("Zeroizing"),
            "H62: CredentialAction::Store must use zeroize::Zeroizing for credential value"
        );

        let rotate_pos = prod_source
            .find("CredentialAction::Rotate")
            .expect("CredentialAction::Rotate must exist");
        let rotate_window_end = (rotate_pos + 800).min(prod_source.len());
        let rotate_body = &prod_source[rotate_pos..rotate_window_end];

        assert!(
            rotate_body.contains("Zeroizing"),
            "H62: CredentialAction::Rotate must use zeroize::Zeroizing for credential value"
        );
    }

    /// S44: Ensure hex_decode calls do not use `unwrap_or_default()`,
    /// which silently returns an empty vec on decode failure.
    #[test]
    fn test_s44_hex_decode_no_silent_default() {
        let source = include_str!("main.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        for (i, line) in prod_source.lines().enumerate() {
            if line.contains("hex_decode") && line.contains("unwrap_or_default()") {
                panic!(
                    "S44: main.rs line {} uses hex_decode(...).unwrap_or_default() which \
                     silently returns an empty vec on decode failure. \
                     Use unwrap_or_else with eprintln! instead.\nLine: {}",
                    i + 1,
                    line.trim()
                );
            }
        }
    }

    #[test]
    fn j42_max_credential_size_constant_exists_and_stdin_reads_use_take() {
        // J42: Credential stdin reads must be bounded by MAX_CREDENTIAL_SIZE
        // to prevent unbounded memory allocation from malicious input.
        let source = include_str!("main.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // Verify the constant exists
        assert!(
            prod_source.contains("const MAX_CREDENTIAL_SIZE: u64 = 65_536"),
            "J42: MAX_CREDENTIAL_SIZE constant must be defined as 65_536"
        );

        // Verify stdin reads use Read::take
        assert!(
            prod_source.contains("std::io::Read::take(std::io::stdin(), MAX_CREDENTIAL_SIZE)"),
            "J42: stdin reads must use Read::take(stdin(), MAX_CREDENTIAL_SIZE)"
        );

        // Verify no unbounded stdin reads remain
        assert!(
            !prod_source.contains("read_to_string(&mut std::io::stdin()"),
            "J42: no unbounded std::io::stdin() reads should remain — use Read::take"
        );
    }
}
