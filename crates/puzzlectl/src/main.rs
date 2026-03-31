// SPDX-License-Identifier: Apache-2.0
use puzzlectl::cli::{
    self, AttestationAction, AuditAction, Command, ComplianceAction, PolicyAction, ProfileAction,
};
use puzzlectl::client;
use puzzlectl::commands::{
    agent, attestation, audit, branch, compliance_cmd, credential, policy, profile, run, status,
};
#[cfg(feature = "sim")]
use puzzlectl::sim;
#[cfg(feature = "tui")]
mod tui;

use anyhow::{Context, Result};
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = cli::Cli::parse();

    match cli.command {
        // Profile commands are local (don't need D-Bus)
        Command::Profile { action } => match action {
            ProfileAction::List { dir } => {
                profile::cmd_profile_list(&dir, cli.output)?;
            }
            ProfileAction::Show { name, dir } => {
                profile::cmd_profile_show(&name, &dir, cli.output)?;
            }
            ProfileAction::Validate { path } => {
                profile::cmd_profile_validate(&path)?;
            }
            ProfileAction::Test {
                name,
                changeset,
                dir,
            } => {
                profile::cmd_profile_test(&name, &changeset, &dir)?;
            }
            ProfileAction::Init {
                output_file,
                non_interactive,
                name,
                extends,
                network_mode,
            } => {
                profile::cmd_profile_init(
                    output_file.as_deref(),
                    non_interactive,
                    name.as_deref(),
                    extends.as_deref(),
                    network_mode.as_deref(),
                )?;
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
            policy::cmd_policy_test(&changeset, &policy_dir)?;
        }
        // Policy add-rule is local (generates Rego, no D-Bus)
        Command::Policy {
            action:
                PolicyAction::AddRule {
                    deny_path,
                    max_file_size,
                    deny_extension,
                    max_files,
                    severity,
                    message,
                    policy_file,
                    dry_run,
                },
        } => {
            policy::cmd_policy_add_rule(
                deny_path.as_deref(),
                max_file_size,
                deny_extension.as_deref(),
                max_files,
                &severity,
                message.as_deref(),
                &policy_file,
                dry_run,
            )?;
        }
        // Audit verify is local (doesn't need D-Bus)
        Command::Audit {
            action: AuditAction::Verify { hash },
        } => {
            audit::cmd_audit_verify(&hash)?;
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
                    attestation::cmd_attestation_verify_bundle(bundle_path)?;
                } else {
                    attestation::cmd_attestation_verify(
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
                attestation::cmd_attestation_export(
                    &id,
                    file.as_deref(),
                    &audit_dir,
                    &attestation_dir,
                )?;
            }
            AttestationAction::Inclusion {
                seq,
                attestation_dir,
            } => {
                attestation::cmd_attestation_inclusion(seq, &attestation_dir)?;
            }
            AttestationAction::Consistency {
                from,
                to,
                attestation_dir,
            } => {
                attestation::cmd_attestation_consistency(from, to, &attestation_dir)?;
            }
            AttestationAction::Pubkey { attestation_dir } => {
                attestation::cmd_attestation_pubkey(&attestation_dir)?;
            }
        },
        // Compliance commands are local (read audit log + profiles directly)
        Command::Compliance { action } => match action {
            ComplianceAction::Frameworks => {
                compliance_cmd::cmd_compliance_frameworks(cli.output)?;
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
                compliance_cmd::cmd_compliance_report(
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
                compliance_cmd::cmd_compliance_status(
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
                compliance_cmd::cmd_compliance_gaps(
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
            pace,
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
                    pace,
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
                    pace,
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
            if exit_code != 0 {
                return Err(anyhow::anyhow!("simulation exited with code {}", exit_code));
            }
        }
        Command::Version => {
            println!("puzzlectl {}", env!("CARGO_PKG_VERSION"));
        }
        // All other commands need D-Bus
        _ => {
            let client = client::PuzzledClient::connect(&cli.bus)
                .await
                .context(format!(
                    "could not connect to puzzled daemon on {} bus.\n\
                     Hint: Is puzzled running? Try:\n  \
                     systemctl status puzzled          (system mode)\n  \
                     scripts/dev-setup-user.sh start   (rootless/session mode)",
                    cli.bus
                ))?;

            match cli.command {
                Command::Audit { action } => {
                    audit::handle_dbus(action, &client, cli.output).await?;
                }
                Command::Branch { action } => {
                    branch::handle(action, &client, cli.output).await?;
                }
                Command::Agent { action } => {
                    agent::handle(action, &client, cli.output).await?;
                }
                // M-ctl1: Status subcommand — show daemon/branch status
                Command::Status { id } => {
                    status::handle(id, &client, cli.output).await?;
                }
                Command::Credential { action } => {
                    credential::handle(action, &client, cli.output).await?;
                }
                Command::Policy {
                    action: PolicyAction::Reload,
                } => {
                    policy::handle_reload(&client, cli.output).await?;
                }
                Command::Run {
                    profile,
                    base,
                    auto_commit,
                    auto_rollback,
                    no_diff,
                    poll_ms,
                    command: cmd_args,
                } => {
                    run::cmd_run(
                        &client,
                        &profile,
                        &base,
                        &cmd_args,
                        auto_commit,
                        auto_rollback,
                        !no_diff,
                        poll_ms,
                        cli.output,
                    )
                    .await?;
                }
                _ => unreachable!(),
            }
        }
    }

    Ok(())
}
#[cfg(test)]
mod tests {
    use clap::Parser;
    use puzzlectl::cli::*;
    use puzzlectl::commands::{audit, branch, policy, profile, run};
    use puzzlectl::output::*;
    use puzzled_types::FileChange;

    // Re-export helpers for test use
    use policy::sanitize_rule_name;
    use run::parse_json_field;

    // -- format_bytes --

    #[test]
    fn test_format_bytes_gib() {
        assert_eq!(format_bytes(2 * 1024 * 1024 * 1024), "2.0 GiB");
    }

    #[test]
    fn test_format_bytes_mib() {
        assert_eq!(format_bytes(512 * 1024 * 1024), "512.0 MiB");
    }

    #[test]
    fn test_format_bytes_kib() {
        assert_eq!(format_bytes(64 * 1024), "64.0 KiB");
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
        let cli =
            Cli::try_parse_from(["puzzlectl", "branch", "list", "--state", "active"]).unwrap();
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
    fn test_cli_profile_init_parse() {
        let cli = Cli::try_parse_from([
            "puzzlectl",
            "profile",
            "init",
            "--non-interactive",
            "--name",
            "test-agent",
        ])
        .unwrap();
        match cli.command {
            Command::Profile {
                action:
                    ProfileAction::Init {
                        name,
                        non_interactive,
                        ..
                    },
            } => {
                assert_eq!(name, Some("test-agent".to_string()));
                assert!(non_interactive);
            }
            _ => panic!("expected Profile Init"),
        }
    }

    #[test]
    fn test_cli_policy_add_rule_parse() {
        let cli = Cli::try_parse_from([
            "puzzlectl",
            "policy",
            "add-rule",
            "--deny-path",
            "*.prod.yml",
            "--severity",
            "critical",
            "--dry-run",
        ])
        .unwrap();
        match cli.command {
            Command::Policy {
                action:
                    PolicyAction::AddRule {
                        deny_path,
                        severity,
                        dry_run,
                        ..
                    },
            } => {
                assert_eq!(deny_path, Some("*.prod.yml".to_string()));
                assert_eq!(severity, "critical");
                assert!(dry_run);
            }
            _ => panic!("expected Policy AddRule"),
        }
    }

    #[test]
    fn test_sanitize_rule_name() {
        assert_eq!(sanitize_rule_name("*.prod.yml"), "__prod_yml");
        assert_eq!(sanitize_rule_name("hello-world"), "hello_world");
        assert_eq!(sanitize_rule_name("abc123"), "abc123");
    }

    #[test]
    fn test_cli_run_parse_basic() {
        let cli = Cli::try_parse_from([
            "puzzlectl",
            "run",
            "--profile",
            "restricted",
            "--",
            "python3",
            "agent.py",
        ])
        .unwrap();
        match cli.command {
            Command::Run {
                profile,
                command,
                auto_commit,
                auto_rollback,
                ..
            } => {
                assert_eq!(profile, "restricted");
                assert_eq!(command, vec!["python3", "agent.py"]);
                assert!(!auto_commit);
                assert!(!auto_rollback);
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_cli_run_auto_commit() {
        let cli = Cli::try_parse_from(["puzzlectl", "run", "--auto-commit", "--", "echo", "hello"])
            .unwrap();
        match cli.command {
            Command::Run { auto_commit, .. } => assert!(auto_commit),
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_cli_run_auto_commit_auto_rollback_conflict() {
        let result = Cli::try_parse_from([
            "puzzlectl",
            "run",
            "--auto-commit",
            "--auto-rollback",
            "--",
            "echo",
        ]);
        assert!(
            result.is_err(),
            "auto-commit and auto-rollback should conflict"
        );
    }

    #[test]
    fn test_parse_json_field() {
        let json = r#"{"id":"abc-123","state":"active"}"#;
        assert_eq!(parse_json_field(json, "id").unwrap(), "abc-123");
        assert_eq!(parse_json_field(json, "state").unwrap(), "active");
        assert!(parse_json_field(json, "missing").is_err());
    }

    #[test]
    fn test_cli_run_default_profile() {
        let cli = Cli::try_parse_from(["puzzlectl", "run", "--", "ls"]).unwrap();
        match cli.command {
            Command::Run { profile, .. } => assert_eq!(profile, "standard"),
            _ => panic!("expected Run"),
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

        let result = profile::cmd_profile_validate(profile_path.to_str().unwrap());
        assert!(result.is_ok());
    }

    #[test]
    fn test_profile_validate_missing_file() {
        let result = profile::cmd_profile_validate("/nonexistent/path.yaml");
        assert!(result.is_err());
    }

    #[test]
    fn test_profile_validate_invalid_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.yaml");
        std::fs::write(&path, "not: valid: yaml: [[[").unwrap();
        let result = profile::cmd_profile_validate(path.to_str().unwrap());
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

        let result = profile::cmd_profile_validate(path.to_str().unwrap());
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

        let result = profile::cmd_profile_validate(path.to_str().unwrap());
        assert!(result.is_err());
    }

    // -- profile list --

    #[test]
    fn test_profile_list_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let result = profile::cmd_profile_list(dir.path().to_str().unwrap(), OutputFormat::Text);
        assert!(result.is_ok());
    }

    #[test]
    fn test_profile_list_nonexistent_dir() {
        let result = profile::cmd_profile_list("/nonexistent/dir", OutputFormat::Text);
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
        let cli = Cli::try_parse_from(["puzzlectl", "profile", "list", "--dir", "/tmp/profiles"])
            .unwrap();
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
        let result =
            Cli::try_parse_from(["puzzlectl", "branch", "create", "--profile", "standard"]);
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
        branch::print_diff_text("[]");
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
                entropy: None,
                has_base64_blocks: None,
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
                entropy: None,
                has_base64_blocks: None,
            },
        ])
        .unwrap();
        branch::print_diff_text(&json);
    }

    #[test]
    fn test_print_diff_text_invalid_json() {
        branch::print_diff_text("not json"); // should not panic
    }

    #[test]
    fn test_print_branches_text_empty() {
        branch::print_branches_text("[]");
    }

    #[test]
    fn test_print_branches_text_with_entries() {
        let json = r#"[{"id":"b1","profile":"standard","state":"active","uid":1000,"created_at":"2025-01-01T00:00:00Z"}]"#;
        branch::print_branches_text(json);
    }

    #[test]
    fn test_print_branches_text_invalid_json() {
        branch::print_branches_text("not json"); // should not panic
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
        let result =
            profile::cmd_profile_show(profile_path.to_str().unwrap(), "/tmp", OutputFormat::Text);
        assert!(result.is_ok());

        // Show as JSON
        let result =
            profile::cmd_profile_show(profile_path.to_str().unwrap(), "/tmp", OutputFormat::Json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_profile_show_not_found() {
        let result =
            profile::cmd_profile_show("nonexistent", "/nonexistent/dir", OutputFormat::Text);
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

        let result = profile::cmd_profile_list(dir.path().to_str().unwrap(), OutputFormat::Text);
        assert!(result.is_ok());

        let result = profile::cmd_profile_list(dir.path().to_str().unwrap(), OutputFormat::Json);
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

        let result = profile::cmd_profile_validate(path.to_str().unwrap());
        assert!(result.is_err());
    }

    // ---- policy test ----

    #[test]
    fn test_policy_test_missing_changeset() {
        let result = policy::cmd_policy_test("/nonexistent/changeset.json", "/tmp");
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

        let result = policy::cmd_policy_test(changeset.to_str().unwrap(), "/nonexistent/policies");
        assert!(result.is_err());
    }

    #[test]
    fn test_policy_test_invalid_changeset() {
        let dir = tempfile::tempdir().unwrap();
        let changeset = dir.path().join("bad.json");
        std::fs::write(&changeset, "not valid json").unwrap();

        let result =
            policy::cmd_policy_test(changeset.to_str().unwrap(), dir.path().to_str().unwrap());
        assert!(result.is_err());
    }

    // ---- audit verify ----

    #[test]
    fn test_audit_verify_nonexistent() {
        let result = audit::cmd_audit_verify("nonexistent-hash-abc123");
        assert!(result.is_err());
    }

    #[test]
    fn test_audit_verify_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("test.manifest.yaml");
        std::fs::write(&manifest, "branch_id: test\nsignature: abc123\n").unwrap();

        let result = audit::cmd_audit_verify(manifest.to_str().unwrap());
        assert!(result.is_ok());
    }

    // ---- format_bytes edge cases ----

    #[test]
    fn test_format_bytes_boundary_1kib() {
        assert_eq!(format_bytes(1024), "1.0 KiB");
    }

    #[test]
    fn test_format_bytes_boundary_1mib() {
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
    }

    #[test]
    fn test_format_bytes_boundary_1gib() {
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GiB");
    }

    /// F7: Ensure sort_json_keys serialization for manifest hash does not use
    /// unwrap_or_default(), which would silently produce an empty string on
    /// serialization failure, corrupting the SHA-256 hash.
    #[test]
    fn test_f7_manifest_hash_no_silent_default() {
        let source = include_str!("commands/attestation.rs");

        // sort_json_keys and unwrap_or_default may be on different lines
        // in the same expression chain. Track when we're in a sort_json_keys
        // expression and flag if unwrap_or_default appears before the semicolon.
        let mut in_sort_json_keys = false;
        for (i, line) in source.lines().enumerate() {
            if line.contains("sort_json_keys") {
                in_sort_json_keys = true;
            }
            if in_sort_json_keys && line.contains("unwrap_or_default()") {
                panic!(
                    "F7: attestation.rs line {} uses sort_json_keys(...).unwrap_or_default() which \
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
        let source = include_str!("commands/profile.rs");

        // Find cmd_profile_show function
        let fn_start = source
            .find("fn cmd_profile_show")
            .expect("cmd_profile_show must exist");
        let fn_block = &source[fn_start..];
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
        let source = include_str!("output.rs");

        // The read_credential_stdin helper must return Zeroizing<String>
        assert!(
            source.contains("fn read_credential_stdin"),
            "H62: read_credential_stdin helper must exist"
        );
        let helper_pos = source.find("fn read_credential_stdin").unwrap();
        let helper_end = (helper_pos + 500).min(source.len());
        let helper_body = &source[helper_pos..helper_end];
        assert!(
            helper_body.contains("Zeroizing"),
            "H62: read_credential_stdin must use zeroize::Zeroizing"
        );

        let cred_source = include_str!("commands/credential.rs");

        // Store and Rotate must call the helper (which handles Zeroizing)
        let store_pos = cred_source
            .find("CredentialAction::Store")
            .expect("CredentialAction::Store must exist");
        let store_window_end = (store_pos + 800).min(cred_source.len());
        let store_body = &cred_source[store_pos..store_window_end];
        assert!(
            store_body.contains("read_credential_stdin"),
            "H62: CredentialAction::Store must use read_credential_stdin"
        );

        let rotate_pos = cred_source
            .find("CredentialAction::Rotate")
            .expect("CredentialAction::Rotate must exist");
        let rotate_window_end = (rotate_pos + 800).min(cred_source.len());
        let rotate_body = &cred_source[rotate_pos..rotate_window_end];
        assert!(
            rotate_body.contains("read_credential_stdin"),
            "H62: CredentialAction::Rotate must use read_credential_stdin"
        );
    }

    /// S44: Ensure hex_decode calls do not use `unwrap_or_default()`,
    /// which silently returns an empty vec on decode failure.
    #[test]
    fn test_s44_hex_decode_no_silent_default() {
        let source = include_str!("commands/attestation.rs");
        for (i, line) in source.lines().enumerate() {
            if line.contains("hex_decode") && line.contains("unwrap_or_default()") {
                panic!(
                    "S44: attestation.rs line {} uses hex_decode(...).unwrap_or_default() which \
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
        let source = include_str!("output.rs");

        // Verify the constant exists
        assert!(
            source.contains("const MAX_CREDENTIAL_SIZE: u64 = 65_536"),
            "J42: MAX_CREDENTIAL_SIZE constant must be defined as 65_536"
        );

        // Verify stdin reads use Read::take
        assert!(
            source.contains("std::io::Read::take(std::io::stdin(), MAX_CREDENTIAL_SIZE)"),
            "J42: stdin reads must use Read::take(stdin(), MAX_CREDENTIAL_SIZE)"
        );

        // Verify no unbounded stdin reads remain
        assert!(
            !source.contains("read_to_string(&mut std::io::stdin()"),
            "J42: no unbounded std::io::stdin() reads should remain — use Read::take"
        );
    }
}
