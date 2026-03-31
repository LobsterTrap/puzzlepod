// SPDX-License-Identifier: Apache-2.0
use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// puzzlectl — CLI for managing PuzzlePod branches, agents, profiles, and policies.
#[derive(Parser)]
#[command(
    name = "puzzlectl",
    version,
    about,
    after_help = "Quick start:\n  puzzlectl run --profile=standard -- python3 agent.py\n  puzzlectl status\n  puzzlectl branch list"
)]
pub struct Cli {
    /// Output format
    #[arg(long, default_value = "text", global = true)]
    pub output: OutputFormat,

    /// D-Bus bus type (system or session)
    #[arg(long, default_value = "system", global = true)]
    pub bus: String,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

/// Report output format for compliance evidence packages.
#[derive(Clone, Copy, clap::ValueEnum)]
pub enum ReportFormat {
    /// Directory tree (default) — evidence package as nested directories/files
    Dir,
    /// Single JSON file — complete report as one JSON document
    Json,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run a command with full governance: create branch, activate, wait, review, commit/rollback
    #[command(display_order = 1)]
    Run {
        /// Agent profile name
        #[arg(long, default_value = "standard")]
        profile: String,
        /// Base directory for OverlayFS lower layer
        #[arg(long, default_value = ".")]
        base: String,
        /// Auto-commit on clean exit (no interactive prompt)
        #[arg(long)]
        auto_commit: bool,
        /// Auto-rollback on exit (discard all changes)
        #[arg(long, conflicts_with = "auto_commit")]
        auto_rollback: bool,
        /// Hide diff output before prompting
        #[arg(long)]
        no_diff: bool,
        /// Poll interval in ms for checking branch state
        #[arg(long, default_value = "500", hide = true)]
        poll_ms: u64,
        /// Command and arguments to run inside the sandbox
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Manage branches (OverlayFS isolation contexts)
    #[command(display_order = 2)]
    Branch {
        #[command(subcommand)]
        action: BranchAction,
    },
    /// Manage running agents
    #[command(display_order = 4)]
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },
    /// Manage agent profiles
    #[command(display_order = 5)]
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Manage governance policies
    #[command(display_order = 6)]
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// Query and export audit events
    #[command(display_order = 10)]
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
    /// Verify cryptographic attestation of governance (§3.1)
    #[command(display_order = 11)]
    Attestation {
        #[command(subcommand)]
        action: AttestationAction,
    },
    /// Generate compliance evidence reports (§3.2)
    #[command(display_order = 12)]
    Compliance {
        #[command(subcommand)]
        action: ComplianceAction,
    },
    /// Manage credentials for agent profiles (phantom token injection)
    #[command(display_order = 13)]
    Credential {
        #[command(subcommand)]
        action: CredentialAction,
    },
    /// Show daemon and branch status
    #[command(display_order = 3)]
    Status {
        /// Optional branch ID to show status for a specific branch
        id: Option<String>,
    },
    /// Governance simulator — test governance policies without running real agents
    #[command(display_order = 20)]
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
        /// Add delays between steps so TUI can poll and display branch state changes
        #[arg(long)]
        pace: bool,
    },
    /// Interactive terminal UI for branch management
    #[command(display_order = 21)]
    #[cfg(feature = "tui")]
    Tui,
    /// Show puzzlectl version
    #[command(display_order = 99)]
    Version,
}

#[derive(Subcommand)]
pub enum BranchAction {
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
pub enum AgentAction {
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
pub enum ProfileAction {
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
    /// Interactively generate a new profile YAML file
    Init {
        /// Output file path (default: stdout)
        #[arg(long = "out", short = 'o')]
        output_file: Option<String>,
        /// Non-interactive mode with defaults
        #[arg(long)]
        non_interactive: bool,
        /// Profile name
        #[arg(long)]
        name: Option<String>,
        /// Base profile to extend
        #[arg(long)]
        extends: Option<String>,
        /// Network mode: Blocked, Gated, Monitored, Unrestricted
        #[arg(long)]
        network_mode: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum PolicyAction {
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
    /// Add a governance rule from a template (no Rego required)
    AddRule {
        /// Deny files matching a glob pattern (e.g., "*.prod.yml")
        #[arg(long)]
        deny_path: Option<String>,
        /// Max allowed file size in bytes
        #[arg(long)]
        max_file_size: Option<u64>,
        /// Deny files with these extensions (comma-separated, e.g., ".exe,.dll")
        #[arg(long)]
        deny_extension: Option<String>,
        /// Max number of files in a changeset
        #[arg(long)]
        max_files: Option<u32>,
        /// Severity: warning, error, critical
        #[arg(long, default_value = "error")]
        severity: String,
        /// Violation message
        #[arg(long)]
        message: Option<String>,
        /// Rego file to append to
        #[arg(long, default_value = "policies/rules/custom_rules.rego")]
        policy_file: String,
        /// Print generated Rego without writing
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
pub enum AuditAction {
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
pub enum AttestationAction {
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
pub enum ComplianceAction {
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
pub enum CredentialAction {
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
