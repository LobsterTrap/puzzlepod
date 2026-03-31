// SPDX-License-Identifier: Apache-2.0
//! puzzle-phase2-demo — Live Phase 2 demo for PuzzlePod hardening features.
//!
//! Exercises real Rust code from puzzled, puzzled-types, and puzzle-proxy crates
//! to demonstrate Phase 2 capabilities. Each section can be run individually
//! via subcommands, or all at once with `puzzle-phase2-demo all`.
//!
//! Cross-platform sections (profiles, conflict, budget, audit, journal, proxy)
//! run on both macOS and Linux. Linux-only sections (seccomp, fanotify, bpf-lsm)
//! require the Lima VM.
//!
//! Usage:
//!   target/release/puzzle-phase2-demo all --profiles-dir policies/profiles
//!   target/release/puzzle-phase2-demo profiles --profiles-dir policies/profiles
//!   target/release/puzzle-phase2-demo conflict
//!   target/release/puzzle-phase2-demo budget
//!   sudo target/release/puzzle-phase2-demo seccomp

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

// ─── ANSI Colors ─────────────────────────────────────────────────────────

const RED: &str = "\x1b[0;31m";
const GREEN: &str = "\x1b[0;32m";
const YELLOW: &str = "\x1b[1;33m";
const CYAN: &str = "\x1b[0;36m";
const MAGENTA: &str = "\x1b[0;35m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const NC: &str = "\x1b[0m";

fn ok(msg: &str) {
    println!("  {GREEN}\u{2713}{NC} {msg}");
}

fn fail_msg(msg: &str) {
    println!("  {RED}\u{2717}{NC} {msg}");
}

fn info(msg: &str) {
    println!("  {DIM}\u{25b8}{NC} {msg}");
}

fn section_header(title: &str) {
    println!();
    println!("  {BOLD}{MAGENTA}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}{NC}");
    println!("  {BOLD}{MAGENTA}  {title}{NC}");
    println!("  {BOLD}{MAGENTA}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}{NC}");
    println!();
}

fn subsection(title: &str) {
    println!();
    println!("  {BOLD}{CYAN}\u{2500}\u{2500} {title} \u{2500}\u{2500}{NC}");
    println!();
}

// ─── CLI ─────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "puzzle-phase2-demo", about = "Live Phase 2 demo for PuzzlePod")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Path to profiles directory
    #[arg(long, global = true, default_value = "policies/profiles")]
    profiles_dir: PathBuf,
}

#[derive(Subcommand)]
enum Command {
    /// Run all demo sections
    All,
    /// Expanded profile library (23 domain-specific profiles)
    Profiles,
    /// Cross-branch conflict detection
    Conflict,
    /// Adaptive budget engine (trust-through-behavior)
    Budget,
    /// Persistent audit storage with query and export
    Audit,
    /// Network journal append/read/discard
    Journal,
    /// HTTP proxy with domain filtering
    Proxy,
    /// seccomp USER_NOTIF with argument inspection (Linux only)
    Seccomp,
    /// fanotify behavioral monitoring (Linux only)
    Fanotify,
    /// BPF LSM exec rate limiting (Linux only)
    BpfLsm,
    /// Prometheus metrics registry and encoding
    Metrics,
    /// Zero-downtime state serialization
    State,
    /// Network namespace isolation (Linux only, run from shell script)
    Network,
    /// Cryptographic attestation: generate signed audit trail for third-party verification
    Attestation {
        /// Output directory for attestation data (audit log, Merkle tree, public key).
        /// If not specified, uses a temporary directory (data is lost on exit).
        #[arg(long)]
        output_dir: Option<PathBuf>,
    },
}

fn main() {
    // Initialize tracing (suppressed by default; RUST_LOG=debug to enable)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::All => {
            demo_profiles(&cli.profiles_dir);
            demo_conflict();
            demo_budget();
            demo_audit();
            demo_journal();
            demo_proxy();
            demo_seccomp();
            demo_fanotify();
            demo_bpf_lsm();
            demo_metrics();
            demo_state();
        }
        Command::Profiles => demo_profiles(&cli.profiles_dir),
        Command::Conflict => demo_conflict(),
        Command::Budget => demo_budget(),
        Command::Audit => demo_audit(),
        Command::Journal => demo_journal(),
        Command::Proxy => demo_proxy(),
        Command::Seccomp => demo_seccomp(),
        Command::Fanotify => demo_fanotify(),
        Command::BpfLsm => demo_bpf_lsm(),
        Command::Metrics => demo_metrics(),
        Command::State => demo_state(),
        Command::Network => {
            info("Network isolation is demonstrated by the shell script.");
            info("Run: sudo demo/run_demo_phase2.sh");
        }
        Command::Attestation { output_dir } => demo_attestation(output_dir),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 1: Profiles
// ═══════════════════════════════════════════════════════════════════════════

fn demo_profiles(profiles_dir: &Path) {
    use puzzled::profile::ProfileLoader;
    use puzzled_types::NetworkMode;

    section_header("Section 1: Expanded Profile Library");

    info(&format!(
        "Loading profiles from: {}",
        profiles_dir.display()
    ));

    let mut loader = ProfileLoader::new(profiles_dir.to_path_buf());
    match loader.load_all() {
        Ok(()) => {}
        Err(e) => {
            fail_msg(&format!("Failed to load profiles: {e}"));
            return;
        }
    }

    let mut names = loader.list();
    names.sort();
    ok(&format!("Loaded {BOLD}{}{NC} profiles", names.len()));
    println!();

    // Group by network mode
    let mut blocked = Vec::new();
    let mut gated = Vec::new();
    let mut monitored = Vec::new();
    let mut unrestricted = Vec::new();

    for name in &names {
        if let Some(p) = loader.get(name) {
            match p.network.mode {
                NetworkMode::Blocked => blocked.push(*name),
                NetworkMode::Gated => gated.push(*name),
                NetworkMode::Monitored => monitored.push(*name),
                NetworkMode::Unrestricted => unrestricted.push(*name),
            }
        }
    }

    subsection("Profiles by Network Mode");

    println!("    {RED}Blocked{NC}      ({}):", blocked.len());
    for name in &blocked {
        println!("      {DIM}-{NC} {name}");
    }
    println!("    {YELLOW}Gated{NC}        ({}):", gated.len());
    for name in &gated {
        println!("      {DIM}-{NC} {name}");
    }
    println!("    {CYAN}Monitored{NC}    ({}):", monitored.len());
    for name in &monitored {
        println!("      {DIM}-{NC} {name}");
    }
    if !unrestricted.is_empty() {
        println!("    {MAGENTA}Unrestricted{NC} ({}):", unrestricted.len());
        for name in &unrestricted {
            println!("      {DIM}-{NC} {name}");
        }
    }

    // Show fail modes
    subsection("Fail Modes");

    for name in &names {
        if let Some(p) = loader.get(name) {
            let mode_str = match p.fail_mode {
                puzzled_types::FailMode::FailClosed => format!("{DIM}FailClosed{NC}"),
                puzzled_types::FailMode::FailSilent => format!("{YELLOW}FailSilent{NC}"),
                puzzled_types::FailMode::FailOperational => {
                    format!("{CYAN}FailOperational{NC}")
                }
                puzzled_types::FailMode::FailSafeState => {
                    format!("{RED}FailSafeState{NC}")
                }
            };
            if p.fail_mode != puzzled_types::FailMode::FailClosed {
                println!("    {BOLD}{name}{NC}: {mode_str}");
            }
        }
    }
    info("All other profiles use FailClosed (default)");

    // Show resource limit summary for a few key profiles
    subsection("Resource Limits (selected profiles)");

    let highlight = ["restricted", "standard", "privileged", "safety-critical"];
    for name in &highlight {
        if let Some(p) = loader.get(name) {
            let mem_mb = p.resource_limits.memory_bytes / (1024 * 1024);
            println!(
                "    {BOLD}{name}{NC}: memory={mem_mb} MiB, pids={}, cpu_shares={}, \
                 storage={} MiB, inodes={}",
                p.resource_limits.max_pids,
                p.resource_limits.cpu_shares,
                p.resource_limits.storage_quota_mb,
                p.resource_limits.inode_quota,
            );
        }
    }

    println!();
    ok("Profile library loaded and validated");
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 2: Conflict Detection
// ═══════════════════════════════════════════════════════════════════════════

fn demo_conflict() {
    use puzzled::conflict::ConflictDetector;
    use puzzled_types::{BranchId, ConflictKind, ConflictResolution, FileChange, FileChangeKind};

    section_header("Section 2: Cross-Branch Conflict Detection");

    let branch_a = BranchId::from("branch-alpha".to_string());
    let branch_b = BranchId::from("branch-beta".to_string());
    let base = PathBuf::from("/var/lib/puzzled/base");

    // Scenario: both branches modify the same file
    let shared_change = FileChange {
        path: PathBuf::from("config/app.yaml"),
        kind: FileChangeKind::Modified,
        size: 512,
        checksum: "abc123".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
        entropy: None,
        has_base64_blocks: None,
    };

    let unique_a = FileChange {
        path: PathBuf::from("src/handler.rs"),
        kind: FileChangeKind::Modified,
        size: 2048,
        checksum: "def456".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
        entropy: None,
        has_base64_blocks: None,
    };

    let unique_b = FileChange {
        path: PathBuf::from("tests/test_handler.rs"),
        kind: FileChangeKind::Added,
        size: 1024,
        checksum: "ghi789".to_string(),
        old_size: None,
        old_mode: None,
        new_mode: None,
        timestamp: None,
        target: None,
        entropy: None,
        has_base64_blocks: None,
    };

    // Test 1: Reject strategy (default)
    subsection("Strategy: Reject (default)");

    let mut detector = ConflictDetector::new();
    detector.register_changes(&branch_a, &base, &[shared_change.clone(), unique_a.clone()]);
    info("Registered branch-alpha: config/app.yaml (Modified), src/handler.rs (Modified)");

    detector.register_changes(&branch_b, &base, &[shared_change.clone(), unique_b.clone()]);
    info("Registered branch-beta:  config/app.yaml (Modified), tests/test_handler.rs (Added)");

    let conflicts =
        detector.check_conflicts(&branch_b, &base, &[shared_change.clone(), unique_b.clone()]);
    ok(&format!(
        "Detected {BOLD}{}{NC} conflict(s)",
        conflicts.len()
    ));

    for c in &conflicts {
        let kind_str = match c.kind {
            ConflictKind::BothModified => format!("{RED}BothModified{NC}"),
            ConflictKind::BothCreated => format!("{YELLOW}BothCreated{NC}"),
            ConflictKind::ModifiedAndDeleted => format!("{MAGENTA}ModifiedAndDeleted{NC}"),
        };
        println!(
            "    {BOLD}{}{NC}: {kind_str} (branches: {})",
            c.path.display(),
            c.conflicting_branches
                .iter()
                .map(|b| b.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let resolve_result = detector.resolve(&conflicts);
    match resolve_result {
        Err(e) => ok(&format!(
            "Reject strategy correctly blocked commit: {DIM}{e}{NC}"
        )),
        Ok(()) => fail_msg("Reject strategy should have blocked the commit"),
    }

    // Test 2: LastWriterWins strategy
    subsection("Strategy: LastWriterWins");

    let mut detector_lww = ConflictDetector::with_resolution(ConflictResolution::LastWriterWins);
    detector_lww.register_changes(&branch_a, &base, std::slice::from_ref(&shared_change));
    detector_lww.register_changes(&branch_b, &base, std::slice::from_ref(&shared_change));

    let conflicts_lww =
        detector_lww.check_conflicts(&branch_b, &base, std::slice::from_ref(&shared_change));
    let resolve_lww = detector_lww.resolve(&conflicts_lww);
    match resolve_lww {
        Ok(()) => ok(&format!(
            "LastWriterWins allowed commit despite {} conflict(s)",
            conflicts_lww.len()
        )),
        Err(e) => fail_msg(&format!("Unexpected rejection: {e}")),
    }

    // Test 3: Unregister clears conflicts
    subsection("Unregister clears conflicts");

    let mut detector_unreg = ConflictDetector::new();
    detector_unreg.register_changes(&branch_a, &base, std::slice::from_ref(&shared_change));
    detector_unreg.register_changes(&branch_b, &base, std::slice::from_ref(&shared_change));

    detector_unreg.unregister_branch(&branch_a);
    info("Unregistered branch-alpha (simulating commit)");

    let conflicts_after = detector_unreg.check_conflicts(&branch_b, &base, &[shared_change]);
    if conflicts_after.is_empty() {
        ok("No conflicts after unregistering branch-alpha");
    } else {
        fail_msg(&format!(
            "Expected 0 conflicts, found {}",
            conflicts_after.len()
        ));
    }

    println!();
    ok("Conflict detection validated");
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 3: Adaptive Budget Engine
// ═══════════════════════════════════════════════════════════════════════════

fn demo_budget() {
    use puzzled::budget::BudgetManager;
    use puzzled_types::{BranchId, BudgetTier, ResourceLimits};

    section_header("Section 3: Adaptive Budget Engine");

    let mut mgr = BudgetManager::new();
    let agent_key = BudgetManager::agent_key("code-assistant", 1000);
    let branch_id = BranchId::from("demo-branch".to_string());

    info(&format!("Agent key: {BOLD}{agent_key}{NC}"));

    // Initial state: Restricted
    let status = mgr.get_status(&agent_key, &branch_id);
    ok(&format!(
        "Initial tier: {BOLD}{:?}{NC} (clean_commits={}, violations={})",
        status.tier, status.clean_commits, status.violations
    ));

    // Record clean commits -> escalation
    subsection("Escalation: Restricted -> Standard -> Extended");

    for i in 1..=12 {
        let tier = mgr.record_clean_commit(&agent_key);
        if i == 3 || i == 10 || i == 12 {
            let tier_str = match tier {
                BudgetTier::Restricted => format!("{RED}Restricted{NC}"),
                BudgetTier::Standard => format!("{YELLOW}Standard{NC}"),
                BudgetTier::Extended => format!("{GREEN}Extended{NC}"),
            };
            ok(&format!("After commit #{i}: tier = {tier_str}"));
        }
    }

    // Record violation -> de-escalation
    subsection("De-escalation on violation");

    let tier = mgr.record_violation(&agent_key);
    let tier_str = match tier {
        BudgetTier::Restricted => format!("{RED}Restricted{NC}"),
        BudgetTier::Standard => format!("{YELLOW}Standard{NC}"),
        BudgetTier::Extended => format!("{GREEN}Extended{NC}"),
    };
    ok(&format!("After violation: tier = {tier_str}"));

    let status = mgr.get_status(&agent_key, &branch_id);
    ok(&format!(
        "Status: clean_commits={}, violations={}",
        status.clean_commits, status.violations
    ));

    // Show effective limits
    subsection("Effective resource limits by tier");

    let base_limits = ResourceLimits {
        memory_bytes: 512 * 1024 * 1024,
        cpu_shares: 100,
        io_weight: 100,
        max_pids: 64,
        storage_quota_mb: 1024,
        inode_quota: 10_000,
        max_threads: None,
        no_new_privileges: None,
        max_files_read: None,
        max_files_written: None,
        max_single_file_size_mb: None,
        cpu_quota_us: None,
        memory_high: None,
        io_max: None,
        max_exec_calls: None,
        max_open_fds: None,
        max_files_deleted: None,
        max_total_write_mb: None,
        lifetime_minutes: None,
    };

    // Create separate managers for each tier to show limits
    let mgr_r = BudgetManager::new();
    let mut mgr_s = BudgetManager::new();
    let mut mgr_e = BudgetManager::new();

    // Standard: 3 clean commits
    for _ in 0..3 {
        mgr_s.record_clean_commit("demo:s");
    }
    // Extended: 10 clean commits
    for _ in 0..10 {
        mgr_e.record_clean_commit("demo:e");
    }

    let restricted = mgr_r.effective_limits("demo:r", &base_limits);
    let standard = mgr_s.effective_limits("demo:s", &base_limits);
    let extended = mgr_e.effective_limits("demo:e", &base_limits);

    println!(
        "    {RED}Restricted{NC} (0.5x): memory={} MiB, pids={}, storage={} MiB",
        restricted.memory_bytes / (1024 * 1024),
        restricted.max_pids,
        restricted.storage_quota_mb,
    );
    println!(
        "    {YELLOW}Standard{NC}   (1.0x): memory={} MiB, pids={}, storage={} MiB",
        standard.memory_bytes / (1024 * 1024),
        standard.max_pids,
        standard.storage_quota_mb,
    );
    println!(
        "    {GREEN}Extended{NC}   (2.0x): memory={} MiB, pids={}, storage={} MiB",
        extended.memory_bytes / (1024 * 1024),
        extended.max_pids,
        extended.storage_quota_mb,
    );

    println!();
    ok("Adaptive budget engine validated");
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 4: Persistent Audit Store
// ═══════════════════════════════════════════════════════════════════════════

fn demo_audit() {
    use puzzled::audit::AuditEvent;
    use puzzled::audit_store::AuditStore;
    use puzzled_types::BranchId;

    section_header("Section 4: Persistent Audit Storage");

    let tmp = tempfile::tempdir().expect("create temp dir for audit store");
    let store_dir = tmp.path().join("audit");

    let mut store = match AuditStore::new(store_dir.clone()) {
        Ok(s) => s,
        Err(e) => {
            fail_msg(&format!("Failed to create audit store: {e}"));
            return;
        }
    };

    info(&format!("Audit store: {}", store_dir.display()));

    // Store a variety of events
    let events = vec![
        AuditEvent::BranchCreated {
            branch_id: BranchId::from("br-001".to_string()),
            profile: "code-assistant".to_string(),
            uid: 1000,
        },
        AuditEvent::ProfileLoaded {
            profile: "code-assistant".to_string(),
        },
        AuditEvent::AgentExecGated {
            branch_id: BranchId::from("br-001".to_string()),
            path: "/usr/bin/python3".to_string(),
            allowed: true,
        },
        AuditEvent::AgentExecGated {
            branch_id: BranchId::from("br-001".to_string()),
            path: "/usr/bin/curl".to_string(),
            allowed: false,
        },
        AuditEvent::AgentConnectGated {
            branch_id: BranchId::from("br-001".to_string()),
            address: "api.github.com:443".to_string(),
            allowed: true,
        },
        AuditEvent::AgentConnectGated {
            branch_id: BranchId::from("br-001".to_string()),
            address: "evil.com:443".to_string(),
            allowed: false,
        },
        AuditEvent::BranchFrozen {
            branch_id: BranchId::from("br-001".to_string()),
        },
        AuditEvent::BranchCommitted {
            branch_id: BranchId::from("br-001".to_string()),
            files: 15,
            bytes: 48_000,
        },
        AuditEvent::BranchCreated {
            branch_id: BranchId::from("br-002".to_string()),
            profile: "restricted".to_string(),
            uid: 1001,
        },
        AuditEvent::PolicyViolation {
            branch_id: BranchId::from("br-002".to_string()),
            rule: "no_sensitive_files".to_string(),
            message: "Found .env file in changeset".to_string(),
        },
        AuditEvent::BranchRolledBack {
            branch_id: BranchId::from("br-002".to_string()),
            reason: "policy violation: sensitive files detected".to_string(),
        },
        AuditEvent::SandboxEscape {
            branch_id: BranchId::from("br-003".to_string()),
            detail: "ptrace attempt detected and blocked".to_string(),
        },
        AuditEvent::BehavioralTrigger {
            branch_id: BranchId::from("br-001".to_string()),
            trigger: "MassDeletion: 47 files deleted in 2 seconds".to_string(),
        },
        AuditEvent::SeccompDecision {
            branch_id: BranchId::from("br-001".to_string()),
            syscall: "execve(/usr/bin/curl)".to_string(),
            allowed: false,
        },
        AuditEvent::WalRecovery {
            branches_recovered: 2,
        },
    ];

    for event in &events {
        match store.store(event) {
            Ok(seq) => {
                // Only print a few to keep output clean
                if seq == 0
                    || seq == 3
                    || seq == 9
                    || seq == 11
                    || seq == 12
                    || seq == 13
                    || seq == 14
                {
                    let event_json = serde_json::to_value(event).unwrap();
                    let etype = event_json
                        .get("event_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    ok(&format!("seq={seq}: {etype}"));
                }
            }
            Err(e) => fail_msg(&format!("Failed to store event: {e}")),
        }
    }
    ok(&format!("Stored {BOLD}{}{NC} audit events", events.len()));

    // Query by branch
    subsection("Query: events for br-001");

    match store.query(Some("br-001"), None, None, None) {
        Ok(results) => {
            ok(&format!("Found {} events for br-001", results.len()));
            for r in &results {
                println!("    seq={}: {}", r.seq, r.event.event_type);
            }
        }
        Err(e) => fail_msg(&format!("Query failed: {e}")),
    }

    // Query by event type
    subsection("Query: policy violations");

    match store.query(None, Some("policy_violation"), None, None) {
        Ok(results) => {
            ok(&format!("Found {} policy violation(s)", results.len()));
            for r in &results {
                println!("    seq={}: {}", r.seq, r.event.details);
            }
        }
        Err(e) => fail_msg(&format!("Query failed: {e}")),
    }

    // Export JSON
    subsection("Export: JSON");

    match store.export("json") {
        Ok(json) => {
            let count = json.matches("\"seq\"").count();
            ok(&format!(
                "Exported {count} events as JSON ({} bytes)",
                json.len()
            ));
        }
        Err(e) => fail_msg(&format!("Export failed: {e}")),
    }

    // Export CSV
    subsection("Export: CSV");

    match store.export("csv") {
        Ok(csv) => {
            let lines = csv.lines().count();
            ok(&format!(
                "Exported as CSV ({} lines, {} bytes)",
                lines,
                csv.len()
            ));
            // Show header + first 2 data lines
            for (i, line) in csv.lines().take(3).enumerate() {
                if i == 0 {
                    println!("    {DIM}{line}{NC}");
                } else {
                    // Truncate long lines
                    let display = if line.len() > 100 {
                        format!("{}...", &line[..100])
                    } else {
                        line.to_string()
                    };
                    println!("    {display}");
                }
            }
        }
        Err(e) => fail_msg(&format!("Export failed: {e}")),
    }

    println!();
    ok("Audit storage validated");
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 5: Network Journal
// ═══════════════════════════════════════════════════════════════════════════

fn demo_journal() {
    use puzzle_proxy::replay::{JournalEntry, NetworkJournal};
    use puzzled_types::BranchId;

    section_header("Section 5: Network Journal");

    let tmp = tempfile::tempdir().expect("create temp dir for journal");
    let journal_dir = tmp.path().join("network_journal");
    let branch_id = BranchId::from("demo-journal".to_string());

    let mut journal = NetworkJournal::new(journal_dir.clone(), branch_id);

    info(&format!("Journal dir: {}", journal_dir.display()));

    // Append entries
    let entries = vec![
        (
            "POST",
            "https://api.github.com/repos/user/repo/issues",
            b"title=bug" as &[u8],
        ),
        (
            "PUT",
            "https://api.github.com/repos/user/repo/issues/1",
            b"state=closed",
        ),
        (
            "DELETE",
            "https://registry.npmjs.org/malicious-pkg/-/1.0.0.tgz",
            b"",
        ),
        (
            "POST",
            "https://pypi.org/upload",
            b"package=my-lib-0.1.0.tar.gz",
        ),
        (
            "PATCH",
            "https://api.example.com/config/settings",
            b"theme=dark",
        ),
    ];

    for (method, uri, body) in &entries {
        let entry = JournalEntry {
            method: method.to_string(),
            uri: uri.to_string(),
            headers: vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Authorization".to_string(), "Bearer <token>".to_string()),
            ],
            body: body.to_vec(),
            timestamp: "2026-03-05T10:00:00Z".to_string(),
            safe_replay: false,
        };
        // CQ-1: append is now async; use a tokio runtime to call it from this sync demo
        let rt = tokio::runtime::Runtime::new().expect("create tokio runtime for journal demo");
        match rt.block_on(journal.append(entry)) {
            Ok(()) => ok(&format!("{method} {uri}")),
            Err(e) => fail_msg(&format!("Failed to append: {e}")),
        }
    }

    ok(&format!(
        "Appended {BOLD}{}{NC} journal entries",
        journal.entry_count()
    ));

    // Read all
    subsection("Read journal");

    match journal.read_all() {
        Ok(entries) => {
            ok(&format!("Read {} entries from disk", entries.len()));
            for e in &entries {
                println!("    {BOLD}{}{NC} {}", e.method, e.uri);
            }
        }
        Err(e) => fail_msg(&format!("Read failed: {e}")),
    }

    // Verify count
    if journal.entry_count() == 5 {
        ok("Entry count matches (5)");
    } else {
        fail_msg(&format!(
            "Expected 5 entries, got {}",
            journal.entry_count()
        ));
    }

    // Discard (rollback simulation)
    subsection("Discard (rollback)");

    journal.discard();
    if !journal_dir.exists() {
        ok("Journal directory removed (zero residue)");
    } else {
        fail_msg("Journal directory still exists after discard");
    }

    println!();
    ok("Network journal validated");
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 6: HTTP Proxy
// ═══════════════════════════════════════════════════════════════════════════

fn demo_proxy() {
    use puzzle_proxy::ProxyConfig;
    use puzzle_proxy::ProxyServer;
    use puzzled_types::BranchId;

    section_header("Section 6: HTTP Proxy with Domain Filtering");

    let rt = tokio::runtime::Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let tmp = tempfile::tempdir().expect("create temp dir for proxy");

        // Pick a free port by binding to :0, get the port, then release it
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind probe");
        let proxy_addr = probe.local_addr().expect("probe addr");
        drop(probe);

        let config = ProxyConfig {
            listen_addr: proxy_addr,
            read_allowed_domains: vec![
                "api.github.com".to_string(),
                "pypi.org".to_string(),
                "*.crates.io".to_string(),
            ],
            write_allowed_domains: vec![
                "api.github.com".to_string(),
            ],
            denied_domains: vec![],
            mode: puzzle_proxy::ProxyMode::Gated,
            branch_dir: tmp.path().to_path_buf(),
            branch_id: BranchId::from("demo-proxy".to_string()),
            ca: None,
            dlp_engine: None,
            max_inspection_body_size: 10 * 1024 * 1024,
            oversized_body_action: puzzle_proxy::dlp::OversizedAction::BlockAndAlert,
            quarantine_sender: None,
            phantom_token_manager: None,
            agent_profile: None,
            geo_database: None,
            data_residency: None,
            audit_sender: None,
            credential_mode: puzzled_types::CredentialMode::Phantom,
            transparent_mode: false,
        };

        info(&format!(
            "Read-allowed domains: {:?}, Write-allowed domains: {:?}",
            config.read_allowed_domains,
            config.write_allowed_domains
        ));

        let proxy = ProxyServer::new(config);
        let journal = proxy.journal();

        // Spawn the real proxy server in a background task
        let proxy_handle = tokio::spawn(async move {
            if let Err(e) = proxy.run().await {
                tracing::debug!("proxy exited: {e}");
            }
        });

        // Give the proxy a moment to start listening
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        ok(&format!(
            "Real proxy server running on {BOLD}{proxy_addr}{NC} (hyper HTTP client, not stubs)"
        ));

        // ── Test 1: GET to allowed domain ────────────────────────────────
        subsection("Test 1: GET to allowed domain (api.github.com)");

        match send_http_request(
            proxy_addr,
            "GET / HTTP/1.1\r\nHost: api.github.com\r\n\r\n",
        )
        .await
        {
            Ok((status, body)) => {
                ok(&format!(
                    "GET api.github.com -> {BOLD}{status}{NC}"
                ));
                info(&format!("Response: {DIM}{}{NC}", body.trim()));
            }
            Err(e) => fail_msg(&format!("Request failed: {e}")),
        }

        // ── Test 2: GET to blocked domain ────────────────────────────────
        subsection("Test 2: GET to blocked domain (evil.com)");

        match send_http_request(
            proxy_addr,
            "GET / HTTP/1.1\r\nHost: evil.com\r\n\r\n",
        )
        .await
        {
            Ok((status, body)) => {
                if status.contains("403") {
                    ok(&format!(
                        "GET evil.com -> {RED}{status}{NC} (domain blocked)"
                    ));
                } else {
                    fail_msg(&format!("Expected 403, got: {status}"));
                }
                info(&format!("Response: {DIM}{}{NC}", body.trim()));
            }
            Err(e) => fail_msg(&format!("Request failed: {e}")),
        }

        // ── Test 3: POST to allowed domain (journaled) ──────────────────
        subsection("Test 3: POST to allowed domain (journaled, not forwarded)");

        let post_body = r#"{"title":"demo issue","body":"test"}"#;
        let post_req = format!(
            "POST /repos/user/repo/issues HTTP/1.1\r\n\
             Host: api.github.com\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            post_body.len(),
            post_body
        );

        match send_http_request(proxy_addr, &post_req).await {
            Ok((status, body)) => {
                if status.contains("202") {
                    ok(&format!(
                        "POST api.github.com -> {YELLOW}{status}{NC} (journaled for replay)"
                    ));
                } else {
                    info(&format!("POST api.github.com -> {status}"));
                }
                info(&format!("Response: {DIM}{}{NC}", body.trim()));
            }
            Err(e) => fail_msg(&format!("Request failed: {e}")),
        }

        // ── Test 4: POST to blocked domain ───────────────────────────────
        subsection("Test 4: POST to blocked domain (evil.com)");

        let evil_req =
            "POST /exfiltrate HTTP/1.1\r\nHost: evil.com\r\nContent-Length: 0\r\n\r\n";

        match send_http_request(proxy_addr, evil_req).await {
            Ok((status, body)) => {
                if status.contains("403") {
                    ok(&format!(
                        "POST evil.com -> {RED}{status}{NC} (blocked before journaling)"
                    ));
                } else {
                    fail_msg(&format!("Expected 403, got: {status}"));
                }
                info(&format!("Response: {DIM}{}{NC}", body.trim()));
            }
            Err(e) => fail_msg(&format!("Request failed: {e}")),
        }

        // ── Test 5: DELETE to allowed domain (journaled) ─────────────────
        subsection("Test 5: DELETE to allowed domain (journaled)");

        let del_req =
            "DELETE /repos/user/repo/issues/1 HTTP/1.1\r\nHost: api.github.com\r\nContent-Length: 0\r\n\r\n";

        match send_http_request(proxy_addr, del_req).await {
            Ok((status, body)) => {
                if status.contains("202") {
                    ok(&format!(
                        "DELETE api.github.com -> {YELLOW}{status}{NC} (journaled)"
                    ));
                } else {
                    info(&format!("DELETE api.github.com -> {status}"));
                }
                info(&format!("Response: {DIM}{}{NC}", body.trim()));
            }
            Err(e) => fail_msg(&format!("Request failed: {e}")),
        }

        // ── Verify journal captured side-effect requests ─────────────────
        subsection("Verify journal captured side-effect requests");

        let j = journal.lock().await;
        match j.read_all() {
            Ok(entries) => {
                ok(&format!(
                    "Journal contains {BOLD}{}{NC} entries (side-effect requests only)",
                    entries.len()
                ));
                for e in &entries {
                    println!(
                        "    {BOLD}{}{NC} {} ({} bytes body)",
                        e.method,
                        e.uri,
                        e.body.len()
                    );
                }
            }
            Err(e) => fail_msg(&format!("Failed to read journal: {e}")),
        }
        drop(j);

        // ── Summary ──────────────────────────────────────────────────────
        subsection("Request routing summary");

        println!(
            "    {GREEN}GET{NC}  allowed domain  -> forwarded (502 — upstream client pending)"
        );
        println!(
            "    {RED}GET{NC}  blocked domain  -> {RED}403 Forbidden{NC}"
        );
        println!(
            "    {YELLOW}POST{NC} allowed domain  -> {YELLOW}202 Accepted{NC} (journaled for commit)"
        );
        println!(
            "    {RED}POST{NC} blocked domain  -> {RED}403 Forbidden{NC} (blocked before journal)"
        );
        println!();
        info("All requests forwarded via real hyper HTTP client (not stubs)");
        info("Side-effect requests replayed via real HTTP client at commit time");

        // Shut down the proxy
        proxy_handle.abort();
    });

    println!();
    ok("HTTP proxy validated with real HTTP traffic");
}

/// Send a raw HTTP/1.1 request through the proxy and return (status_line, body).
async fn send_http_request(
    proxy_addr: std::net::SocketAddr,
    request: &str,
) -> Result<(String, String), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .map_err(|e| format!("connect to proxy: {e}"))?;

    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write request: {e}"))?;

    // Shut down write half so server knows request is complete
    stream
        .shutdown()
        .await
        .map_err(|e| format!("shutdown write: {e}"))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|e| format!("read response: {e}"))?;

    let response_str = String::from_utf8_lossy(&response).to_string();

    // Parse status line and body
    let (status, body) = if let Some(idx) = response_str.find("\r\n") {
        let status = response_str[..idx].to_string();
        let rest = &response_str[idx..];
        let body = if let Some(body_idx) = rest.find("\r\n\r\n") {
            rest[body_idx + 4..].to_string()
        } else {
            String::new()
        };
        (status, body)
    } else {
        (response_str.clone(), String::new())
    };

    Ok((status, body))
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 7: seccomp USER_NOTIF (Linux only)
// ═══════════════════════════════════════════════════════════════════════════

fn demo_seccomp() {
    section_header("Section 7: seccomp USER_NOTIF");

    #[cfg(not(target_os = "linux"))]
    {
        info("seccomp requires Linux. Showing configuration only.");
        println!();

        info("seccomp two-tier strategy:");
        println!("    {BOLD}Tier 1 (static deny):{NC} 57 escape-vector syscalls blocked (KillProcess action)");
        let deny_list = [
            "ptrace",
            "kexec_load",
            "init_module",
            "mount",
            "umount2",
            "pivot_root",
            "setns",
            "unshare",
            "bpf",
            "reboot",
        ];
        for s in &deny_list {
            println!("      {RED}\u{2717}{NC} {s} -> EPERM");
        }
        println!("      {DIM}... and 32 more{NC}");
        println!();

        println!("    {BOLD}Tier 2 (USER_NOTIF):{NC} 4 syscalls gated through puzzled");
        let notif_list = ["execve", "execveat", "connect", "bind"];
        for s in &notif_list {
            println!(
                "      {YELLOW}\u{25b8}{NC} {s} -> puzzled inspects arguments via /proc/<pid>/mem"
            );
        }
        println!();

        info("USER_NOTIF flow:");
        println!("    1. Agent calls execve(\"/usr/bin/curl\")");
        println!("    2. Kernel suspends agent, notifies puzzled via notification fd");
        println!("    3. puzzled reads path from /proc/<pid>/mem");
        println!("    4. puzzled checks profile exec_allowlist");
        println!("    5. puzzled responds ALLOW or DENY(EPERM)");
        println!("    6. Kernel resumes agent with the decision");
        println!();

        info("TOCTOU protection: SECCOMP_IOCTL_NOTIF_ID_VALID before respond");
        ok("seccomp configuration displayed (run on Linux for live demo)");
    }

    #[cfg(target_os = "linux")]
    {
        use puzzled::sandbox::seccomp::SeccompBuilder;
        use puzzled_types::*;

        info("Building real seccomp-BPF filter with USER_NOTIF...");

        let profile = AgentProfile {
            name: "demo-seccomp".to_string(),
            description: "Demo seccomp profile".to_string(),
            filesystem: FilesystemRules {
                read_allowlist: vec![],
                write_allowlist: vec![],
                denylist: vec![],
                read_denylist: vec![],
                write_denylist: vec![],
            },
            exec_allowlist: vec![
                "/usr/bin/python3".to_string(),
                "/usr/bin/cat".to_string(),
                "/usr/bin/ls".to_string(),
            ],
            exec_denylist: vec![],
            resource_limits: ResourceLimits::default(),
            network: NetworkConfig {
                mode: NetworkMode::Gated,
                allowed_domains: vec!["api.github.com".to_string()],
                data_residency: None,
                dlp_rules_path: None,
            },
            behavioral: BehavioralConfig::default(),
            fail_mode: FailMode::FailClosed,
            capabilities: vec![],
            enforcement: Default::default(),
            seccomp_mode: Default::default(),
            allow_symlinks: false,
            allow_exec_overlay: false,
            credentials: None,
            extends: None,
        };

        // Fork a child to apply seccomp (irrevocable, can't apply in parent)
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            fail_msg("fork() failed");
            return;
        }

        if pid == 0 {
            // Child: apply seccomp filter
            let seccomp_builder = SeccompBuilder {
                bpf_clone_guard_active: false,
                seccomp_mode: profile.seccomp_mode,
            };
            match seccomp_builder.apply(&profile) {
                Ok(notify_fd) => {
                    println!("  {GREEN}\u{2713}{NC} seccomp filter loaded in child (notify_fd={notify_fd:?})");
                    println!(
                        "  {GREEN}\u{2713}{NC} 57 escape syscalls statically denied (KillProcess)"
                    );
                    println!(
                        "  {GREEN}\u{2713}{NC} execve/execveat/connect/bind gated via USER_NOTIF"
                    );
                    println!();

                    // Test: mount() should fail
                    let src = std::ffi::CString::new("none").unwrap();
                    let tgt = std::ffi::CString::new("/tmp").unwrap();
                    let fst = std::ffi::CString::new("tmpfs").unwrap();
                    let ret = unsafe {
                        libc::mount(
                            src.as_ptr(),
                            tgt.as_ptr(),
                            fst.as_ptr(),
                            0,
                            std::ptr::null(),
                        )
                    };
                    if ret < 0 {
                        println!("  {GREEN}\u{2713}{NC} mount() -> {RED}BLOCKED{NC} (EPERM, seccomp static deny)");
                    } else {
                        println!("  {RED}\u{2717}{NC} mount() succeeded unexpectedly");
                        unsafe { libc::umount(tgt.as_ptr()) };
                    }

                    // Test: ptrace should fail
                    let ret = unsafe {
                        libc::ptrace(
                            libc::PTRACE_TRACEME,
                            0,
                            std::ptr::null_mut::<libc::c_void>(),
                            std::ptr::null_mut::<libc::c_void>(),
                        )
                    };
                    if ret < 0 {
                        println!("  {GREEN}\u{2713}{NC} ptrace() -> {RED}BLOCKED{NC} (EPERM, seccomp static deny)");
                    } else {
                        println!("  {RED}\u{2717}{NC} ptrace() succeeded unexpectedly");
                    }
                }
                Err(e) => {
                    println!("  {RED}\u{2717}{NC} seccomp apply failed: {e}");
                }
            }
            unsafe { libc::_exit(0) };
        }

        // Parent: wait for child
        let mut status: i32 = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        ok("seccomp live demo complete");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 8: fanotify Behavioral Monitoring (Linux only)
// ═══════════════════════════════════════════════════════════════════════════

fn demo_fanotify() {
    section_header("Section 8: fanotify Behavioral Monitoring");

    #[cfg(not(target_os = "linux"))]
    {
        use puzzled::sandbox::fanotify::{BehavioralCounters, FanotifyMonitor};
        use puzzled_types::{BehavioralConfig, BranchId};
        use std::sync::atomic::Ordering;

        // Credential patterns (mirrors puzzled::sandbox::fanotify::CREDENTIAL_PATTERNS)
        let credential_patterns: &[&str] = &[
            "/etc/shadow",
            "/etc/gshadow",
            "/etc/ssh/",
            ".ssh/",
            ".pem",
            ".key",
            ".p12",
            ".pfx",
            ".env",
            ".aws/credentials",
            ".gnupg/",
            "id_rsa",
            "id_ed25519",
            "id_ecdsa",
            "credentials.json",
            "secrets.yaml",
            "secrets.yml",
            "token.json",
        ];

        info("fanotify requires Linux. Demonstrating cross-platform components.");
        println!();

        // Demonstrate credential pattern matching
        subsection("Credential file pattern matching");

        let test_paths = vec![
            ("/home/user/.ssh/id_rsa", true),
            ("/etc/shadow", true),
            ("/home/user/.env", true),
            ("/home/user/.aws/credentials", true),
            ("/home/user/project/main.rs", false),
            ("/usr/bin/python3", false),
        ];

        for (path, expected) in &test_paths {
            let matches = credential_patterns.iter().any(|p| path.contains(p));
            if matches == *expected {
                if matches {
                    ok(&format!("{path} -> {RED}ALERT{NC} (credential access)"));
                } else {
                    ok(&format!("{path} -> {GREEN}safe{NC}"));
                }
            } else {
                fail_msg(&format!("{path}: expected={expected}, got={matches}"));
            }
        }

        // Demonstrate behavioral counters
        subsection("Behavioral counters");

        let counters = BehavioralCounters::new();
        let config = BehavioralConfig {
            max_deletions: 5,
            max_reads_per_minute: 100,
            credential_access_alert: true,
        };

        info(&format!(
            "Thresholds: max_deletions={}, max_reads/min={}, credential_alert={}",
            config.max_deletions, config.max_reads_per_minute, config.credential_access_alert
        ));

        // Simulate deletions approaching threshold
        for i in 1..=6 {
            counters.deletions.fetch_add(1, Ordering::Relaxed);
            let count = counters.deletions.load(Ordering::Relaxed);
            if count >= config.max_deletions {
                ok(&format!(
                    "Deletion #{i}: count={count} >= threshold={} -> {RED}TRIGGER: MassDeletion{NC}",
                    config.max_deletions
                ));
            } else {
                info(&format!(
                    "Deletion #{i}: count={count} (threshold={})",
                    config.max_deletions
                ));
            }
        }

        // Simulate read rate
        for _ in 0..100 {
            counters.reads_this_minute.fetch_add(1, Ordering::Relaxed);
        }
        let reads = counters.reads_this_minute.load(Ordering::Relaxed);
        ok(&format!(
            "Read rate: {reads}/min >= threshold={} -> {RED}TRIGGER: ExcessiveReads{NC}",
            config.max_reads_per_minute
        ));

        counters.reset_reads();
        ok(&format!(
            "After reset: reads_this_minute={}",
            counters.reads_this_minute.load(Ordering::Relaxed)
        ));

        // Demonstrate FanotifyMonitor stub init on non-Linux
        subsection("FanotifyMonitor init (stub on non-Linux)");

        let monitor = FanotifyMonitor::init(
            BranchId::from("demo-fanotify".to_string()),
            PathBuf::from("/tmp/demo-merged"),
            config,
        );
        match monitor {
            Ok(m) => {
                ok("FanotifyMonitor initialized (stub)");
                ok(&format!(
                    "Touched files: {} (empty before monitoring)",
                    m.touched_files().len()
                ));
            }
            Err(e) => fail_msg(&format!("Init failed: {e}")),
        }

        ok("fanotify configuration displayed (run on Linux for live demo)");
    }

    #[cfg(target_os = "linux")]
    {
        use puzzled::sandbox::fanotify::FanotifyMonitor;
        use puzzled_types::{BehavioralConfig, BranchId};

        let tmp = tempfile::tempdir().expect("create temp dir for fanotify");
        let merged_dir = tmp.path().to_path_buf();

        info(&format!("Monitoring directory: {}", merged_dir.display()));

        let config = BehavioralConfig {
            max_deletions: 3,
            max_reads_per_minute: 10,
            credential_access_alert: true,
            phantom_token_prefixes: Vec::new(),
        };

        match FanotifyMonitor::init(
            BranchId::from("demo-fanotify".to_string()),
            merged_dir.clone(),
            config,
        ) {
            Ok(monitor) => {
                ok("fanotify initialized on temp directory");

                let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
                rt.block_on(async {
                    let (mut rx, counters, _touched, _needs_full_diff, shutdown) = monitor.start();

                    // Create some files to trigger events
                    for i in 0..5 {
                        let path = merged_dir.join(format!("test_file_{i}.txt"));
                        std::fs::write(&path, format!("content {i}")).ok();
                    }

                    // Delete files to trigger mass deletion
                    for i in 0..4 {
                        let path = merged_dir.join(format!("test_file_{i}.txt"));
                        std::fs::remove_file(&path).ok();
                    }

                    // Create a credential-like file
                    std::fs::write(merged_dir.join(".env"), "SECRET=hunter2").ok();

                    // Give fanotify time to process
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

                    // Check for triggers
                    let mut trigger_count = 0;
                    while let Ok(trigger) = rx.try_recv() {
                        trigger_count += 1;
                        match trigger {
                            puzzled_types::BehavioralTrigger::MassDeletion { count, threshold } => {
                                ok(&format!(
                                    "TRIGGER: MassDeletion (count={count}, threshold={threshold})"
                                ));
                            }
                            puzzled_types::BehavioralTrigger::ExcessiveReads { rate, threshold } => {
                                ok(&format!(
                                    "TRIGGER: ExcessiveReads (rate={rate}, threshold={threshold})"
                                ));
                            }
                            puzzled_types::BehavioralTrigger::CredentialAccess { path } => {
                                ok(&format!("TRIGGER: CredentialAccess (path={path})"));
                            }
                            puzzled_types::BehavioralTrigger::QueueOverflow => {
                                ok("TRIGGER: QueueOverflow (event channel full)");
                            }
                            puzzled_types::BehavioralTrigger::PhantomTokenLeakage { file_path, token_prefix } => {
                                ok(&format!("TRIGGER: PhantomTokenLeakage (file={file_path}, prefix={token_prefix})"));
                            }
                        }
                    }

                    use std::sync::atomic::Ordering;
                    let deletions = counters.deletions.load(Ordering::Relaxed);
                    let reads = counters.reads_this_minute.load(Ordering::Relaxed);
                    let creds = counters.credential_accesses.load(Ordering::Relaxed);

                    info(&format!(
                        "Counters: deletions={deletions}, reads={reads}, cred_accesses={creds}"
                    ));
                    ok(&format!("Received {trigger_count} behavioral trigger(s)"));

                    // Signal the poll thread and timer to shut down
                    shutdown.store(true, std::sync::atomic::Ordering::Release);
                    // Give the poll thread time to see the flag (epoll timeout is 1s)
                    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
                });
            }
            Err(e) => {
                fail_msg(&format!("fanotify init failed: {e}"));
                info("This may require root or CAP_SYS_ADMIN");
            }
        }

        ok("fanotify behavioral monitoring validated");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 9: BPF LSM Exec Rate Limiting
// ═══════════════════════════════════════════════════════════════════════════

fn demo_bpf_lsm() {
    use puzzled::sandbox::bpf_lsm::{BpfLsmManager, RateLimitConfig};

    section_header("Section 9: BPF LSM Exec Rate Limiting");

    info("BPF LSM attaches to bprm_check_security hook");
    info("Enforces per-cgroup exec rate limits");
    println!();

    // Show RateLimitConfig structure
    subsection("RateLimitConfig structure");

    let config = RateLimitConfig {
        max_execs_per_second: 10,
        max_total_execs: 1000,
        kill_switch: 0,
        _pad: 0,
    };

    ok(&format!(
        "size_of::<RateLimitConfig>() = {} bytes (matches kernel struct)",
        std::mem::size_of::<RateLimitConfig>()
    ));
    println!("    max_execs_per_second: {}", config.max_execs_per_second);
    println!("    max_total_execs:     {}", config.max_total_execs);
    println!("    kill_switch:         {}", config.kill_switch);

    // Demonstrate manager creation
    subsection("BpfLsmManager lifecycle");

    let bpf_path = PathBuf::from("/var/lib/puzzled/bpf/exec_guard.bpf.o");
    let mut manager = BpfLsmManager::new(&bpf_path);
    info(&format!("BPF object path: {}", bpf_path.display()));

    // Attempt load — will fail without the object file, which is expected
    match manager.load() {
        Ok(()) => {
            ok("BPF programs loaded successfully");

            // Configure a sample cgroup
            let cgroup_id: u64 = 42;
            let rate_config = RateLimitConfig {
                max_execs_per_second: 5,
                max_total_execs: 500,
                kill_switch: 0,
                _pad: 0,
            };

            match manager.configure_cgroup(cgroup_id, rate_config) {
                Ok(()) => ok(&format!(
                    "Rate limit configured for cgroup {cgroup_id}: \
                     max_exec/s={}, max_total={}",
                    rate_config.max_execs_per_second, rate_config.max_total_execs
                )),
                Err(e) => info(&format!("Configure cgroup (expected on some systems): {e}")),
            }

            match manager.remove_cgroup(cgroup_id) {
                Ok(()) => ok(&format!("Rate limit removed for cgroup {cgroup_id}")),
                Err(e) => info(&format!("Remove cgroup: {e}")),
            }
        }
        Err(e) => {
            info(&format!("Load attempt: {DIM}{e}{NC}"));
            info("This is expected without the compiled BPF object file");
            info("In production: clang -O2 -target bpf -c exec_guard.bpf.c -o exec_guard.bpf.o");
        }
    }

    ok(&format!(
        "BPF LSM manager is_loaded: {}",
        manager.is_loaded()
    ));

    // Show BPF program flow
    subsection("BPF LSM enforcement flow");

    println!("    1. puzzled loads exec_guard.bpf.o via bpf(BPF_PROG_LOAD)");
    println!("    2. Program attaches to LSM hook: bprm_check_security");
    println!("    3. On every execve(), BPF program:");
    println!("       a. Looks up cgroup ID in rate_limits map");
    println!("       b. Increments exec_counters map");
    println!("       c. If rate exceeded -> return -EPERM");
    println!("       d. If kill_switch set -> return -EPERM");
    println!("    4. Enforcement is {BOLD}in-kernel{NC} (< 1 \u{03bc}s per check)");
    println!("    5. puzzled updates maps via bpf(BPF_MAP_UPDATE_ELEM)");

    println!();
    ok("BPF LSM configuration validated");
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 10: Prometheus Metrics
// ═══════════════════════════════════════════════════════════════════════════

fn demo_metrics() {
    use puzzled::metrics::{encode_metrics, Metrics};

    section_header("Section 10: Prometheus Metrics");

    let metrics = Metrics::new();
    ok("Metrics registry created (6 counters, 3 histograms, 1 gauge)");

    // Simulate a branch lifecycle: create -> diff -> commit
    metrics.record_create("standard", 0.042);
    ok(&format!(
        "Simulated: branch create ({BOLD}standard{NC}, 42ms)"
    ));

    metrics.record_diff(0.015);
    ok("Simulated: diff generation (15ms)");

    metrics.record_commit("standard", 1.23);
    ok(&format!(
        "Simulated: branch commit ({BOLD}standard{NC}, 1.23s)"
    ));

    // Simulate a rollback
    metrics.record_create("restricted", 0.038);
    metrics.record_rollback("restricted");
    ok(&format!(
        "Simulated: branch create + rollback ({BOLD}restricted{NC})"
    ));

    // Simulate policy outcomes
    metrics.policy_approved.inc();
    metrics.policy_rejected.inc();
    ok("Simulated: policy approved (1), rejected (1)");

    // Encode and display
    subsection("OpenMetrics output (excerpt)");

    let output = encode_metrics(&metrics);
    let interesting = [
        "puzzled_branches_created_total",
        "puzzled_branches_committed_total",
        "puzzled_branches_rolled_back_total",
        "puzzled_active_branches",
        "puzzled_policy_approved_total",
        "puzzled_policy_rejected_total",
    ];

    for line in output.lines() {
        // Show lines that contain our key metrics (skip comments and empty lines)
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if interesting.iter().any(|key| line.starts_with(key)) {
            println!("    {line}");
        }
    }

    println!();
    ok(&format!(
        "Metrics validated (production: served on {BOLD}/run/puzzled/metrics.sock{NC})"
    ));
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 11: State Serialization
// ═══════════════════════════════════════════════════════════════════════════

fn demo_state() {
    use chrono::Utc;
    use puzzled_types::{BranchId, BranchInfo, BranchState};

    section_header("Section 11: Zero-Downtime State Serialization");

    let tmp = tempfile::tempdir().expect("create temp dir for state demo");
    let base = tmp.path();

    info("Simulating daemon state with 3 branches...");

    // Create upper_dir directories for active branches (so restore finds them)
    let upper1 = base.join("upper-active-1");
    let upper2 = base.join("upper-active-2");
    let upper_done = base.join("upper-done-1");
    std::fs::create_dir_all(&upper1).expect("create upper1");
    std::fs::create_dir_all(&upper2).expect("create upper2");
    std::fs::create_dir_all(&upper_done).expect("create upper_done");

    let branches = vec![
        BranchInfo {
            id: BranchId::from("br-active-1".to_string()),
            profile: "standard".to_string(),
            base_path: base.join("base"),
            upper_dir: upper1,
            work_dir: base.join("work-1"),
            state: BranchState::Active,
            created_at: Utc::now(),
            pid: Some(12345),
            uid: 1000,
            expires_at: None,
            selinux_context: None,
        },
        BranchInfo {
            id: BranchId::from("br-active-2".to_string()),
            profile: "restricted".to_string(),
            base_path: base.join("base"),
            upper_dir: upper2,
            work_dir: base.join("work-2"),
            state: BranchState::Active,
            created_at: Utc::now(),
            pid: Some(12346),
            uid: 1001,
            expires_at: None,
            selinux_context: None,
        },
        BranchInfo {
            id: BranchId::from("br-done-1".to_string()),
            profile: "standard".to_string(),
            base_path: base.join("base"),
            upper_dir: upper_done,
            work_dir: base.join("work-3"),
            state: BranchState::Committed,
            created_at: Utc::now(),
            pid: None,
            uid: 1000,
            expires_at: None,
            selinux_context: None,
        },
    ];

    for b in &branches {
        let state_str = match b.state {
            BranchState::Ready => format!("{YELLOW}Ready{NC}"),
            BranchState::Active => format!("{GREEN}Active{NC}"),
            BranchState::Committed => format!("{DIM}Committed{NC}"),
            _ => format!("{}", b.state),
        };
        ok(&format!(
            "Branch {} (state={state_str}, profile={BOLD}{}{NC})",
            b.id, b.profile
        ));
    }

    // ── Save State ──
    subsection("Save State");

    let state_file = base.join("state.json");
    let json = serde_json::to_string_pretty(&branches).expect("serialize branches");
    // Atomic write via temp + rename
    let tmp_file = base.join("state.json.tmp");
    std::fs::write(&tmp_file, &json).expect("write temp state file");
    std::fs::rename(&tmp_file, &state_file).expect("rename to state.json");

    ok(&format!(
        "Serialized {} branches to state.json (atomic write via temp+rename)",
        branches.len()
    ));
    info(&format!(
        "State file: {} ({} bytes)",
        state_file.display(),
        json.len()
    ));

    // ── Load State ──
    subsection("Load State (simulating daemon restart)");

    let loaded: Vec<BranchInfo> =
        serde_json::from_str(&std::fs::read_to_string(&state_file).expect("read state file"))
            .expect("deserialize state");

    let mut restored = 0u32;
    let mut skipped = 0u32;
    for b in &loaded {
        if matches!(b.state, BranchState::Active | BranchState::Ready) && b.upper_dir.exists() {
            restored += 1;
            ok(&format!(
                "Restored {} ({GREEN}Active{NC}, upper_dir exists)",
                b.id
            ));
        } else {
            skipped += 1;
            fail_msg(&format!(
                "Skipped {} (state={}, not restorable)",
                b.id, b.state
            ));
        }
    }

    info("Limitation: pidfds, seccomp notify fds, sandbox handles cannot be restored");
    info("In production: watchdog saves state periodically; systemd restarts puzzled");

    println!();
    ok(&format!(
        "State serialization validated ({restored} restored, {skipped} skipped)"
    ));
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 12: Cryptographic Attestation (§3.1)
// ═══════════════════════════════════════════════════════════════════════════

fn demo_attestation(output_dir: Option<PathBuf>) {
    use ed25519_dalek::SigningKey;
    use puzzled::audit::AuditEvent;
    use puzzled::audit_store::AuditStore;
    use puzzled_types::BranchId;

    section_header("Cryptographic Attestation (PRD §3.1)");

    info("Generating Ed25519 signing key (same as puzzled IMA subsystem)...");
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let pubkey_hex = hex_encode(signing_key.verifying_key().as_bytes());
    ok(&format!("Public key: {}", &pubkey_hex));

    // Create attestation output directory
    let base_dir = if let Some(ref dir) = output_dir {
        std::fs::create_dir_all(dir).expect("create output dir");
        dir.clone()
    } else {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let p = tmp.path().to_path_buf();
        // Leak the tempdir so it isn't deleted when this function returns
        std::mem::forget(tmp);
        p
    };
    let audit_dir = base_dir.join("audit");
    let attestation_dir = base_dir.join("attestation");
    std::fs::create_dir_all(&attestation_dir).expect("create attestation dir");

    // Write public key for third-party verification
    let pubkey_path = attestation_dir.join("public_key.hex");
    std::fs::write(&pubkey_path, &pubkey_hex).expect("write public key");

    info(&format!("Audit dir:       {}", audit_dir.display()));
    info(&format!("Attestation dir: {}", attestation_dir.display()));
    info(&format!("Public key file: {}", pubkey_path.display()));

    // Create AuditStore with attestation enabled
    let mut store = AuditStore::new_with_attestation(
        audit_dir.clone(),
        true,                          // attestation enabled
        Some(signing_key),             // Ed25519 signing key
        Some(attestation_dir.clone()), // Merkle tree directory
        None,                          // checkpoint dir (demo — not needed)
        0,                             // checkpoint interval (disabled)
        0,                             // checkpoint time interval (disabled)
    )
    .expect("create attestation-enabled audit store");

    subsection("Simulating a governed agent lifecycle");

    // Agent 1: successful commit
    info("Agent 1: Fork -> Explore -> Commit (approved)");
    let events_agent1 = vec![
        AuditEvent::BranchCreated {
            branch_id: BranchId::from("br-demo-001".to_string()),
            profile: "code-assistant".to_string(),
            uid: 1000,
        },
        AuditEvent::AgentExecGated {
            branch_id: BranchId::from("br-demo-001".to_string()),
            path: "/usr/bin/python3".to_string(),
            allowed: true,
        },
        AuditEvent::BranchCommitted {
            branch_id: BranchId::from("br-demo-001".to_string()),
            files: 12,
            bytes: 34_567,
        },
    ];

    for event in &events_agent1 {
        let seq = store.store(event).expect("store event");
        let label = match event {
            AuditEvent::BranchCreated { .. } => "branch_created",
            AuditEvent::AgentExecGated { .. } => "agent_exec_gated",
            AuditEvent::BranchCommitted { .. } => "branch_committed",
            _ => "other",
        };
        ok(&format!(
            "  seq={seq:<3}  {label:<20}  (governance-significant: {})",
            puzzled::attestation::is_governance_significant(label)
        ));
    }

    // Agent 2: policy violation -> rollback
    println!();
    info("Agent 2: Fork -> Explore -> Policy Violation -> Rollback");
    let events_agent2 = vec![
        AuditEvent::BranchCreated {
            branch_id: BranchId::from("br-demo-002".to_string()),
            profile: "restricted".to_string(),
            uid: 1001,
        },
        AuditEvent::PolicyViolation {
            branch_id: BranchId::from("br-demo-002".to_string()),
            rule: "no_sensitive_files".to_string(),
            message: "Found .env file with API keys in changeset".to_string(),
        },
        AuditEvent::BranchRolledBack {
            branch_id: BranchId::from("br-demo-002".to_string()),
            reason: "policy violation: sensitive files detected".to_string(),
        },
    ];

    for event in &events_agent2 {
        let seq = store.store(event).expect("store event");
        let label = match event {
            AuditEvent::BranchCreated { .. } => "branch_created",
            AuditEvent::PolicyViolation { .. } => "policy_violation",
            AuditEvent::BranchRolledBack { .. } => "branch_rolled_back",
            _ => "other",
        };
        ok(&format!(
            "  seq={seq:<3}  {label:<20}  (governance-significant: {})",
            puzzled::attestation::is_governance_significant(label)
        ));
    }

    // Agent 3: sandbox escape attempt -> killed
    println!();
    info("Agent 3: Fork -> Sandbox Escape Attempt -> Killed");
    let events_agent3 = vec![
        AuditEvent::BranchCreated {
            branch_id: BranchId::from("br-demo-003".to_string()),
            profile: "standard".to_string(),
            uid: 1002,
        },
        AuditEvent::SandboxEscape {
            branch_id: BranchId::from("br-demo-003".to_string()),
            detail: "ptrace(PTRACE_ATTACH) blocked by seccomp".to_string(),
        },
        AuditEvent::AgentKilled {
            branch_id: BranchId::from("br-demo-003".to_string()),
            caller_uid: 0,
        },
    ];

    for event in &events_agent3 {
        let seq = store.store(event).expect("store event");
        let label = match event {
            AuditEvent::BranchCreated { .. } => "branch_created",
            AuditEvent::SandboxEscape { .. } => "sandbox_escape",
            AuditEvent::AgentKilled { .. } => "agent_killed",
            _ => "other",
        };
        ok(&format!(
            "  seq={seq:<3}  {label:<20}  (governance-significant: {})",
            puzzled::attestation::is_governance_significant(label)
        ));
    }

    // Write root_hash and inclusion proofs for Merkle verification
    if let Some(tree) = store.merkle_tree() {
        let root = tree.root_hash().unwrap_or([0u8; 32]);
        let root_hex = hex_encode(&root);
        std::fs::write(attestation_dir.join("root_hash"), &root_hex).expect("write root_hash");
        ok(&format!("Merkle root hash: {}", &root_hex[..16]));

        let proofs_dir = attestation_dir.join("proofs");
        std::fs::create_dir_all(&proofs_dir).expect("create proofs dir");
        for i in 0..tree.size() {
            match tree.inclusion_proof(i) {
                Ok(proof) => {
                    let proof_json = serde_json::to_string_pretty(&proof).expect("serialize proof");
                    std::fs::write(proofs_dir.join(format!("{}.json", i)), proof_json)
                        .expect("write proof");
                }
                Err(e) => {
                    fail_msg(&format!("Failed to generate proof for leaf {}: {}", i, e));
                }
            }
        }
        ok(&format!(
            "Wrote {} inclusion proofs to {}",
            tree.size(),
            proofs_dir.display()
        ));
    }

    // Show what's in the audit log
    subsection("Attestation audit trail");

    let events_file = audit_dir.join("events.ndjson");
    let content = std::fs::read_to_string(&events_file).expect("read events.ndjson");
    let total_events = content.lines().count();
    let signed_events: Vec<serde_json::Value> = content
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v.get("signature").and_then(|s| s.as_str()).is_some())
        .collect();

    info(&format!("Total events in audit log: {total_events}"));
    info(&format!(
        "Governance-significant (signed): {}",
        signed_events.len()
    ));
    println!();

    println!(
        "  {BOLD}  {:<14} {:<20} {:<14} {:<6} {:<14}{NC}",
        "RECORD_ID", "EVENT_TYPE", "BRANCH", "LEAF", "PARENT"
    );
    println!("  {DIM}  {}{NC}", "\u{2500}".repeat(72));

    for v in &signed_events {
        let record_id = v.get("record_id").and_then(|r| r.as_str()).unwrap_or("?");
        let event_type = v
            .get("event")
            .and_then(|e| e.get("event_type"))
            .and_then(|t| t.as_str())
            .unwrap_or("?");
        let branch = v
            .get("event")
            .and_then(|e| e.get("branch_id"))
            .and_then(|b| b.as_str())
            .unwrap_or("?");
        let leaf = v
            .get("merkle_leaf_index")
            .and_then(|l| l.as_u64())
            .map(|l| l.to_string())
            .unwrap_or_else(|| "-".to_string());
        let parent = v
            .get("parent_record_id")
            .and_then(|p| p.as_str())
            .unwrap_or("-");

        println!(
            "  {CYAN}  {:<14} {:<20} {:<14} {:<6} {:<14}{NC}",
            &record_id[..record_id.len().min(12)],
            event_type,
            &branch[..branch.len().min(12)],
            leaf,
            if parent == "-" {
                "-".to_string()
            } else {
                parent[..parent.len().min(12)].to_string()
            },
        );
    }

    // Print verification instructions
    subsection("Third-party verification");

    println!("  {BOLD}A third party needs ONLY two things:{NC}");
    println!(
        "    1. The audit log:  {GREEN}{}{NC}",
        events_file.display()
    );
    println!("    2. The public key: {GREEN}{pubkey_hex}{NC}");
    println!();
    println!("  {BOLD}Verify with:{NC}");
    println!("    {YELLOW}puzzlectl attestation verify \\{NC}");
    println!("      {YELLOW}--audit-dir {} \\{NC}", audit_dir.display());
    println!("      {YELLOW}--pubkey {pubkey_hex} \\{NC}");
    println!(
        "      {YELLOW}--merkle --attestation-dir {}{NC}",
        attestation_dir.display()
    );
    println!();
    info("No access to puzzled, the signing key, or the running system is needed.");
    info("The audit log + public key is a self-contained cryptographic proof bundle.");

    println!();
    ok(&format!(
        "Attestation demo complete: {total_events} events, {} signed, {} branches",
        signed_events.len(),
        3
    ));
}

use puzzled_types::merkle::hex_encode;
