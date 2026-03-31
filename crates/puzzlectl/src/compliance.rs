// SPDX-License-Identifier: Apache-2.0
//! Compliance evidence generation (§3.2).
//!
//! Generates regulatory compliance evidence reports from audit data, agent
//! profiles, and governance policies. Supports EU AI Act, SOC 2, ISO 27001,
//! and NIST AI RMF frameworks.
//!
//! Architecture: runs entirely in puzzlectl (client-side). puzzled stores the
//! data; this module queries, maps, and formats evidence.
//!
//! **Data source:** Currently reads audit records directly from the local
//! NDJSON file (`/var/lib/puzzled/audit/events.ndjson`). The PRD §3.2.5
//! specifies D-Bus (`QueryAuditEvents`, `ListBranches`, `InspectBranch`)
//! as the primary data path. D-Bus support is planned but not yet
//! implemented — it requires async runtime integration in the compliance
//! codepath. The local file path requires read access to the audit store
//! (typically root). For non-root compliance queries, D-Bus support is
//! needed (UID-scoped via `QueryAuditEvents`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use puzzled_types::AgentProfile;
use puzzled_types::AuditRecord;
use serde::{Deserialize, Serialize};

/// M5: Default attestation directory — should match DaemonConfig::attestation::attestation_dir.
const DEFAULT_ATTESTATION_DIR: &str = "/var/lib/puzzled/attestation";

// ---------------------------------------------------------------------------
// Framework and control definitions
// ---------------------------------------------------------------------------

/// Static framework metadata.
pub struct FrameworkDef {
    pub id: &'static str,
    pub name: &'static str,
    pub controls: &'static [ControlDef],
}

/// Static control-to-event mapping with gap detection rules.
pub struct ControlDef {
    pub control_id: &'static str,
    pub title: &'static str,
    /// Audit event types that provide evidence for this control.
    pub event_types: &'static [&'static str],
    /// Profile-level condition required for "evidenced" (checked by gap analyzer).
    /// If None, only event counts are checked.
    pub profile_condition: Option<ProfileCondition>,
    /// Minimum number of distinct event types that must have nonzero counts
    /// for the control to be "evidenced." Controls using `ALL_EVENT_TYPES`
    /// should set this > 1 to prevent a single event type from satisfying
    /// comprehensive documentation/monitoring requirements.
    /// 0 means any nonzero total_events suffices (default for most controls).
    pub min_event_types: usize,
    /// Recommendation shown when the control is a gap.
    pub recommendation: &'static str,
}

/// Profile-level condition for gap detection (§3.2.7).
#[derive(Clone, Copy)]
pub enum ProfileCondition {
    /// All profiles must have behavioral monitoring configured.
    /// `BehavioralConfig` has no `enabled` field — monitoring is considered active
    /// when `credential_access_alert` is true (the only boolean disable path).
    /// Threshold fields (`max_deletions`, `max_reads_per_minute`) are always active
    /// at any finite value — `max_deletions: 0` means "trigger on first deletion"
    /// (strictest setting), not "disabled."
    BehavioralEnabled,
    /// All profiles must have a non-empty exec_allowlist.
    ExecAllowlistDefined,
    /// All profiles must have non-empty read_allowlist.
    ReadAllowlistDefined,
    /// All profiles must have ResourceLimits with max_pids > 0 and memory_bytes > 0.
    ResourceLimitsDefined,
}

/// All 16 audit event types (2600-2615) for controls that require full coverage.
const ALL_EVENT_TYPES: &[&str] = &[
    "agent_registered",    // 2600
    "branch_created",      // 2601
    "branch_committed",    // 2602
    "branch_rolled_back",  // 2603
    "policy_violation",    // 2604
    "commit_rejected",     // 2605
    "sandbox_escape",      // 2606
    "branch_frozen",       // 2607
    "agent_exec_gated",    // 2608
    "agent_connect_gated", // 2609
    "profile_loaded",      // 2610
    "policy_reloaded",     // 2611
    "behavioral_trigger",  // 2612
    "seccomp_decision",    // 2613
    "wal_recovery",        // 2614
    "agent_killed",        // 2615
];

// -- EU AI Act --

const EU_AI_ACT_CONTROLS: &[ControlDef] = &[
    ControlDef {
        control_id: "Art.9",
        title: "Risk management system",
        event_types: &["policy_violation", "behavioral_trigger"],
        profile_condition: None,
        min_event_types: 0,
        recommendation:
            "Ensure governance policies are active and generating violation/trigger events",
    },
    ControlDef {
        control_id: "Art.10",
        title: "Data governance",
        event_types: &["agent_exec_gated", "seccomp_decision"],
        profile_condition: None,
        min_event_types: 0,
        recommendation: "Enable seccomp and exec gating in agent profiles",
    },
    ControlDef {
        control_id: "Art.11",
        title: "Technical documentation",
        event_types: ALL_EVENT_TYPES,
        profile_condition: None,
        min_event_types: 4,
        recommendation:
            "Ensure diverse governance activity — at least 4 distinct event types required for comprehensive documentation",
    },
    ControlDef {
        control_id: "Art.12",
        title: "Record-keeping",
        event_types: ALL_EVENT_TYPES,
        profile_condition: None,
        min_event_types: 4,
        recommendation:
            "Ensure diverse audit coverage — at least 4 distinct event types required for comprehensive record-keeping",
    },
    ControlDef {
        control_id: "Art.13",
        title: "Transparency",
        event_types: &["branch_created", "branch_committed"],
        profile_condition: None,
        min_event_types: 0,
        recommendation: "Create and commit branches to generate transparency records",
    },
    ControlDef {
        control_id: "Art.14",
        title: "Human oversight",
        event_types: &["branch_committed", "commit_rejected", "agent_killed"],
        profile_condition: None,
        min_event_types: 0,
        recommendation: "Use manual approve/reject workflow (puzzlectl branch approve/reject)",
    },
    ControlDef {
        control_id: "Art.15",
        title: "Accuracy, robustness, cybersecurity",
        event_types: &["sandbox_escape", "seccomp_decision"],
        profile_condition: None,
        min_event_types: 0,
        recommendation: "Enable seccomp enforcement and sandbox monitoring",
    },
];

// -- SOC 2 --

const SOC2_CONTROLS: &[ControlDef] = &[
    ControlDef {
        control_id: "CC6.1",
        title: "Logical access security",
        event_types: &[
            "profile_loaded",
            "seccomp_decision",
            "agent_exec_gated",
            "agent_connect_gated",
        ],
        profile_condition: Some(ProfileCondition::ReadAllowlistDefined),
        min_event_types: 0,
        recommendation: "Define filesystem read_allowlist in all active profiles",
    },
    ControlDef {
        control_id: "CC6.2",
        title: "Access restrictions",
        event_types: &["policy_violation"],
        profile_condition: None,
        min_event_types: 0,
        recommendation: "Ensure OPA/Rego policies are loaded and enforcing",
    },
    ControlDef {
        control_id: "CC6.3",
        title: "Registration and authorization",
        event_types: &["agent_registered", "branch_created"],
        profile_condition: None,
        min_event_types: 0,
        recommendation: "Register agents with UID binding before creating branches",
    },
    ControlDef {
        control_id: "CC6.6",
        title: "System boundaries",
        event_types: &["branch_created"],
        profile_condition: Some(ProfileCondition::ResourceLimitsDefined),
        min_event_types: 0,
        recommendation: "Set resource_limits.max_pids > 0 and memory_bytes > 0 in all profiles",
    },
    ControlDef {
        control_id: "CC6.8",
        title: "Malicious software prevention",
        event_types: &["agent_exec_gated", "seccomp_decision"],
        profile_condition: Some(ProfileCondition::ExecAllowlistDefined),
        min_event_types: 0,
        recommendation: "Define exec_allowlist in all active profiles",
    },
    ControlDef {
        control_id: "CC7.1",
        title: "Monitoring",
        event_types: &["behavioral_trigger"],
        profile_condition: Some(ProfileCondition::BehavioralEnabled),
        min_event_types: 0,
        recommendation:
            "Enable behavioral monitoring (set credential_access_alert = true) in all profiles",
    },
    ControlDef {
        control_id: "CC7.2",
        title: "Anomaly detection",
        event_types: &["behavioral_trigger"],
        profile_condition: Some(ProfileCondition::BehavioralEnabled),
        min_event_types: 0,
        recommendation:
            "Enable behavioral monitoring in all profiles and ensure trigger events are generated",
    },
    ControlDef {
        control_id: "CC7.3",
        title: "Incident evaluation",
        event_types: &["policy_violation", "sandbox_escape", "agent_killed"],
        profile_condition: None,
        min_event_types: 0,
        recommendation: "Ensure incident-related events are logged and reviewed",
    },
    ControlDef {
        control_id: "CC8.1",
        title: "Change management",
        event_types: &[
            "branch_committed",
            "commit_rejected",
            "branch_rolled_back",
            "policy_reloaded",
            "wal_recovery",
        ],
        profile_condition: None,
        min_event_types: 0,
        recommendation: "Use Fork/Explore/Commit workflow for all agent changes",
    },
];

// -- ISO 27001 --

const ISO27001_CONTROLS: &[ControlDef] = &[
    ControlDef {
        control_id: "A.5.1",
        title: "Information security policies",
        event_types: &["policy_violation", "policy_reloaded"],
        profile_condition: None,
        min_event_types: 0,
        recommendation: "Load and enforce OPA/Rego governance policies",
    },
    ControlDef {
        control_id: "A.8.2",
        title: "Privileged access rights",
        event_types: &["agent_registered", "branch_created"],
        profile_condition: None,
        min_event_types: 0,
        recommendation: "Register agents with UID-scoped privileges",
    },
    ControlDef {
        control_id: "A.8.3",
        title: "Information access restriction",
        event_types: &["agent_exec_gated", "seccomp_decision"],
        profile_condition: Some(ProfileCondition::ReadAllowlistDefined),
        min_event_types: 0,
        recommendation: "Define filesystem read/write allowlists in profiles",
    },
    ControlDef {
        control_id: "A.8.5",
        title: "Secure authentication",
        event_types: &["agent_registered"],
        profile_condition: None,
        min_event_types: 0,
        recommendation: "Ensure agents are registered with UID binding",
    },
    ControlDef {
        control_id: "A.8.16",
        title: "Monitoring activities",
        event_types: ALL_EVENT_TYPES,
        profile_condition: None,
        min_event_types: 4,
        recommendation:
            "Ensure diverse monitoring coverage — at least 4 distinct event types required",
    },
    ControlDef {
        control_id: "A.8.24",
        title: "Use of cryptography",
        event_types: &["branch_committed"],
        profile_condition: None,
        min_event_types: 0,
        recommendation: "Ensure attestation signing is active for commits",
    },
    ControlDef {
        control_id: "A.8.25",
        title: "Secure development lifecycle",
        event_types: &[
            "branch_committed",
            "commit_rejected",
            "branch_rolled_back",
            "wal_recovery",
        ],
        profile_condition: None,
        min_event_types: 0,
        recommendation: "Use Fork/Explore/Commit governance workflow",
    },
];

// -- NIST AI RMF --

const NIST_AI_RMF_CONTROLS: &[ControlDef] = &[
    ControlDef {
        control_id: "GOVERN.1",
        title: "Policies and accountability",
        event_types: &["policy_violation", "policy_reloaded"],
        profile_condition: None,
        min_event_types: 0,
        recommendation: "Load and enforce OPA/Rego governance policies",
    },
    ControlDef {
        control_id: "MAP.3",
        title: "AI risks and impacts",
        event_types: &["policy_violation", "behavioral_trigger"],
        profile_condition: None,
        min_event_types: 0,
        recommendation: "Enable policy enforcement and behavioral monitoring",
    },
    ControlDef {
        control_id: "MEASURE.2",
        title: "AI systems evaluated",
        event_types: &["behavioral_trigger"],
        profile_condition: Some(ProfileCondition::BehavioralEnabled),
        min_event_types: 0,
        recommendation: "Enable behavioral monitoring for continuous evaluation",
    },
    ControlDef {
        control_id: "MANAGE.1",
        title: "AI risks prioritized and responded to",
        event_types: &["behavioral_trigger", "policy_violation"],
        profile_condition: None,
        min_event_types: 0,
        recommendation: "Enable graduated trust and behavioral triggers for risk response",
    },
    ControlDef {
        control_id: "MANAGE.4",
        title: "Risk treatments documented",
        event_types: &["branch_committed", "commit_rejected", "branch_rolled_back"],
        profile_condition: None,
        min_event_types: 0,
        recommendation: "Use Fork/Explore/Commit workflow to document all governance decisions",
    },
];

/// All supported frameworks.
pub const FRAMEWORKS: &[FrameworkDef] = &[
    FrameworkDef {
        id: "eu-ai-act",
        name: "EU AI Act (Regulation 2024/1689)",
        controls: EU_AI_ACT_CONTROLS,
    },
    FrameworkDef {
        id: "soc2",
        name: "SOC 2 Type II (Trust Service Criteria)",
        controls: SOC2_CONTROLS,
    },
    FrameworkDef {
        id: "iso27001",
        name: "ISO 27001:2022 (Annex A Controls)",
        controls: ISO27001_CONTROLS,
    },
    FrameworkDef {
        id: "nist-ai-rmf",
        name: "NIST AI Risk Management Framework 1.0",
        controls: NIST_AI_RMF_CONTROLS,
    },
];

pub fn get_framework(id: &str) -> Result<&'static FrameworkDef> {
    FRAMEWORKS.iter().find(|f| f.id == id).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown framework '{}'. Supported: {}",
            id,
            FRAMEWORKS
                .iter()
                .map(|f| f.id)
                .collect::<Vec<_>>()
                .join(", ")
        )
    })
}

// ---------------------------------------------------------------------------
// Audit record loading
// ---------------------------------------------------------------------------

// V49: AuditRecord and AuditRecordEvent are now unified in puzzled_types::audit.

/// Result of loading audit records, including parse statistics.
pub struct AuditLoadResult {
    pub records: Vec<AuditRecord>,
    /// Lines that failed to parse as valid NDJSON records.
    pub parse_failures: usize,
    /// Records that had unparseable timestamps (included in records but not time-filtered).
    pub timestamp_parse_failures: usize,
    /// Total non-empty lines in the NDJSON file.
    pub total_lines: usize,
}

/// Load audit records from NDJSON file, optionally filtering by time.
///
/// Returns parse statistics alongside records so callers can warn about data
/// quality issues. For compliance evidence, silently dropping records would
/// risk marking controls as "Gap" when evidence actually exists but is
/// malformed.
pub fn load_audit_records(audit_dir: &Path, since_secs: Option<u64>) -> Result<AuditLoadResult> {
    let log_path = audit_dir.join("events.ndjson");
    if !log_path.exists() {
        return Ok(AuditLoadResult {
            records: Vec::new(),
            parse_failures: 0,
            timestamp_parse_failures: 0,
            total_lines: 0,
        });
    }

    // G26: Check file size before read_to_string to prevent OOM on large audit logs
    const MAX_AUDIT_LOG_SIZE: u64 = 500 * 1024 * 1024; // 500 MB
    let file_size = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);
    if file_size > MAX_AUDIT_LOG_SIZE {
        anyhow::bail!(
            "G26: audit log too large ({} bytes > {} byte limit). \
             Consider truncating or archiving old events.",
            file_size,
            MAX_AUDIT_LOG_SIZE
        );
    }

    let contents = std::fs::read_to_string(&log_path)
        .with_context(|| format!("reading {}", log_path.display()))?;

    let cutoff = since_secs.map(|s| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("F8: system clock before Unix epoch")
            .as_secs();
        now.saturating_sub(s)
    });

    let mut records = Vec::new();
    let mut parse_failures = 0usize;
    let mut timestamp_parse_failures = 0usize;
    let mut total_lines = 0usize;

    for line in contents.lines() {
        if line.trim().is_empty() {
            continue;
        }
        total_lines += 1;
        match serde_json::from_str::<AuditRecord>(line) {
            Ok(record) => {
                if let Some(cutoff_ts) = cutoff {
                    match parse_rfc3339_approx(&record.timestamp) {
                        Some(record_ts) if record_ts < cutoff_ts => continue,
                        None => timestamp_parse_failures += 1,
                        _ => {}
                    }
                }
                records.push(record);
            }
            Err(_) => {
                parse_failures += 1;
            }
        }
    }
    Ok(AuditLoadResult {
        records,
        parse_failures,
        timestamp_parse_failures,
        total_lines,
    })
}

/// Count events by event_type.
pub fn count_events_by_type(records: &[AuditRecord]) -> HashMap<String, u64> {
    let mut counts: HashMap<String, u64> = HashMap::new();
    for r in records {
        *counts.entry(r.event.event_type.clone()).or_insert(0) += 1;
    }
    counts
}

/// Parse a period string like "30d", "90d", "1y" into seconds.
pub fn parse_period_secs(period: &str) -> Result<u64> {
    // H67: Minimum length check for clear error on single-char or empty input
    if period.len() < 2 {
        anyhow::bail!(
            "period too short: '{}' — expected format like '30d', '1y'",
            period
        );
    }
    let (num_str, unit) = period.split_at(period.len().saturating_sub(1));
    let num: u64 = num_str
        .parse()
        .with_context(|| format!("invalid period number: {}", num_str))?;
    // L1: Use checked_mul to return a clear error on overflow instead of
    // panicking or silently wrapping when the user supplies a huge number.
    let secs = match unit {
        "d" => num.checked_mul(86400),
        "w" => num.checked_mul(604800),
        "m" => num.checked_mul(2_592_000), // 30-day months
        "y" => num.checked_mul(31_536_000),
        _ => anyhow::bail!(
            "invalid period unit '{}'. Use d (days), w (weeks), m (months), y (years)",
            unit
        ),
    };
    secs.ok_or_else(|| anyhow::anyhow!("L1: period '{}' overflows u64 seconds", period))
}

/// Parse RFC 3339 timestamp to unix epoch seconds.
///
/// Uses the same year-by-year leap year counting as `epoch_to_rfc3339` to
/// guarantee round-trip correctness: `epoch_to_rfc3339(parse_rfc3339(ts)) == ts`.
pub fn parse_rfc3339_approx(ts: &str) -> Option<u64> {
    if ts.len() < 19 {
        return None;
    }
    // Use .get() instead of direct indexing to avoid panics on non-ASCII
    // input. Direct byte-range indexing (`ts[0..4]`) panics if the range
    // cuts a multi-byte UTF-8 character.
    let year: u64 = ts.get(0..4)?.parse().ok()?;
    let month: u64 = ts.get(5..7)?.parse().ok()?;
    let day: u64 = ts.get(8..10)?.parse().ok()?;
    let hour: u64 = ts.get(11..13)?.parse().ok()?;
    let min: u64 = ts.get(14..16)?.parse().ok()?;
    let sec: u64 = ts.get(17..19)?.parse().ok()?;

    // J44: Validate year range to prevent unbounded loop in day counting below
    if !(1970..=9999).contains(&year) {
        return None;
    }
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    // Count days from 1970-01-01 to the target date, year-by-year
    // (matches epoch_to_rfc3339's inverse algorithm exactly).
    let mut total_days = 0u64;
    for y in 1970..year {
        total_days += if is_leap_year(y) { 366 } else { 365 };
    }

    // Add days for completed months in the target year
    let leap = is_leap_year(year);
    let month_days: [u64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    for &md in &month_days[..(month - 1) as usize] {
        total_days += md;
    }
    total_days += day - 1;

    // L2: Use checked arithmetic throughout to prevent silent overflow.
    total_days
        .checked_mul(86400)?
        .checked_add(hour.checked_mul(3600)?)?
        .checked_add(min.checked_mul(60)?)?
        .checked_add(sec)
}

// ---------------------------------------------------------------------------
// Profile loading
// ---------------------------------------------------------------------------

/// Result of loading profiles, including parse statistics.
pub struct ProfileLoadResult {
    pub profiles: Vec<ProfileSummary>,
    /// YAML files that failed to read or parse.
    pub parse_failures: usize,
    /// Total `.yaml` files found in the directory.
    pub total_files: usize,
}

/// Load all agent profiles from a directory.
///
/// Returns parse statistics alongside profiles so callers can warn about
/// data quality issues. For compliance evidence, silently failing to load
/// a profile could cause false gaps (e.g., `ExecAllowlistDefined` fails
/// with "no profiles found" when profiles exist but failed to parse).
pub fn load_profiles(profiles_dir: &Path) -> ProfileLoadResult {
    if !profiles_dir.exists() {
        return ProfileLoadResult {
            profiles: Vec::new(),
            parse_failures: 0,
            total_files: 0,
        };
    }
    let mut profiles = Vec::new();
    let mut parse_failures = 0usize;
    let mut total_files = 0usize;
    if let Ok(entries) = std::fs::read_dir(profiles_dir) {
        // F25: Explicitly handle directory entry errors instead of silently
        // skipping them via filter_map with ok().
        let mut dir_errors = 0usize;
        for entry in entries {
            match entry {
                Ok(entry) => {
                    let path = entry.path();
                    if path.extension().and_then(|x| x.to_str()) != Some("yaml") {
                        continue;
                    }
                    total_files += 1;
                    match std::fs::read_to_string(&path) {
                        Ok(contents) => match serde_yaml::from_str::<AgentProfile>(&contents) {
                            Ok(profile) => profiles.push(ProfileSummary::from_profile(&profile)),
                            Err(_) => parse_failures += 1,
                        },
                        Err(_) => parse_failures += 1,
                    }
                }
                Err(e) => {
                    dir_errors += 1;
                    eprintln!("F25: failed to read directory entry: {e}");
                }
            }
        }
        if dir_errors > 0 {
            eprintln!("F25: {dir_errors} directory entries could not be read");
        }
    }
    ProfileLoadResult {
        profiles,
        parse_failures,
        total_files,
    }
}

/// Summary of a profile's security-relevant fields for compliance evidence.
#[derive(Serialize, Clone)]
pub struct ProfileSummary {
    pub profile: String,
    pub filesystem_read_allowlist_entries: usize,
    pub filesystem_write_allowlist_entries: usize,
    pub exec_allowlist_entries: usize,
    pub exec_denylist_entries: usize,
    pub network_mode: String,
    pub fail_mode: String,
    pub max_pids: u32,
    pub memory_bytes: u64,
    pub behavioral_max_deletions: u32,
    pub behavioral_max_reads_per_minute: u32,
    pub behavioral_credential_alert: bool,
    pub capabilities_count: usize,
    pub seccomp_mode: String,
}

impl ProfileSummary {
    fn from_profile(p: &AgentProfile) -> Self {
        Self {
            profile: p.name.clone(),
            filesystem_read_allowlist_entries: p.filesystem.read_allowlist.len(),
            filesystem_write_allowlist_entries: p.filesystem.write_allowlist.len(),
            exec_allowlist_entries: p.exec_allowlist.len(),
            exec_denylist_entries: p.exec_denylist.len(),
            network_mode: format!("{:?}", p.network.mode),
            fail_mode: format!("{:?}", p.fail_mode),
            max_pids: p.resource_limits.max_pids,
            memory_bytes: p.resource_limits.memory_bytes,
            behavioral_max_deletions: p.behavioral.max_deletions,
            behavioral_max_reads_per_minute: p.behavioral.max_reads_per_minute,
            behavioral_credential_alert: p.behavioral.credential_access_alert,
            capabilities_count: p.capabilities.len(),
            seccomp_mode: format!("{:?}", p.seccomp_mode),
        }
    }
}

// ---------------------------------------------------------------------------
// Control evaluation (§3.2.5 step 7)
// ---------------------------------------------------------------------------

/// Evidence status for a control (3 states per PRD §3.2.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Evidenced,
    PartiallyEvidenced,
    Gap,
}

impl EvidenceStatus {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Evidenced => "evidenced",
            Self::PartiallyEvidenced => "partially_evidenced",
            Self::Gap => "gap",
        }
    }
}

/// Evaluated control with evidence details.
#[derive(Serialize)]
pub struct ControlEvidence {
    pub control_id: String,
    pub title: String,
    pub status: EvidenceStatus,
    pub total_events: u64,
    pub event_counts: HashMap<String, u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub recommendation: String,
}

/// Check whether a profile condition is satisfied across all profiles.
fn check_profile_condition(
    condition: ProfileCondition,
    profiles: &[ProfileSummary],
) -> (bool, Option<String>) {
    if profiles.is_empty() {
        return (false, Some("no profiles found".to_string()));
    }
    match condition {
        ProfileCondition::BehavioralEnabled => {
            // Behavioral monitoring is "not configured" when credential_access_alert
            // is disabled — this is the only boolean that can truly disable a
            // detection path. Threshold fields (max_deletions, max_reads_per_minute)
            // are always active at any finite value.
            let failing: Vec<&str> = profiles
                .iter()
                .filter(|p| !p.behavioral_credential_alert)
                .map(|p| p.profile.as_str())
                .collect();
            if failing.is_empty() {
                (true, None)
            } else {
                (
                    false,
                    Some(format!(
                        "behavioral monitoring not configured (credential_access_alert disabled) in profile(s): {}",
                        failing.join(", ")
                    )),
                )
            }
        }
        ProfileCondition::ExecAllowlistDefined => {
            let failing: Vec<&str> = profiles
                .iter()
                .filter(|p| p.exec_allowlist_entries == 0)
                .map(|p| p.profile.as_str())
                .collect();
            if failing.is_empty() {
                (true, None)
            } else {
                (
                    false,
                    Some(format!(
                        "exec_allowlist not defined in profile(s): {}",
                        failing.join(", ")
                    )),
                )
            }
        }
        ProfileCondition::ReadAllowlistDefined => {
            let failing: Vec<&str> = profiles
                .iter()
                .filter(|p| p.filesystem_read_allowlist_entries == 0)
                .map(|p| p.profile.as_str())
                .collect();
            if failing.is_empty() {
                (true, None)
            } else {
                (
                    false,
                    Some(format!(
                        "read_allowlist not defined in profile(s): {}",
                        failing.join(", ")
                    )),
                )
            }
        }
        ProfileCondition::ResourceLimitsDefined => {
            let failing: Vec<&str> = profiles
                .iter()
                .filter(|p| p.max_pids == 0 || p.memory_bytes == 0)
                .map(|p| p.profile.as_str())
                .collect();
            if failing.is_empty() {
                (true, None)
            } else {
                (
                    false,
                    Some(format!(
                        "resource limits (max_pids/memory_bytes) missing in profile(s): {}",
                        failing.join(", ")
                    )),
                )
            }
        }
    }
}

/// Evaluate all controls for a framework against event counts and profiles.
pub fn evaluate_controls(
    fw: &FrameworkDef,
    event_counts: &HashMap<String, u64>,
    profiles: &[ProfileSummary],
) -> Vec<ControlEvidence> {
    fw.controls
        .iter()
        .map(|ctrl| {
            let mut total_events = 0u64;
            let mut event_detail = HashMap::new();
            for et in ctrl.event_types {
                let count = event_counts.get(*et).copied().unwrap_or(0);
                total_events += count;
                event_detail.insert(et.to_string(), count);
            }

            // Check minimum event type diversity (for ALL_EVENT_TYPES controls)
            let distinct_types = event_detail.values().filter(|&&c| c > 0).count();
            let diversity_ok = ctrl.min_event_types == 0 || distinct_types >= ctrl.min_event_types;
            let diversity_reason = if !diversity_ok && total_events > 0 {
                Some(format!(
                    "only {} of {} required distinct event types observed",
                    distinct_types, ctrl.min_event_types
                ))
            } else {
                None
            };

            // Determine status: 3-state evaluation per PRD §3.2.7
            let (status, reason) = if let Some(condition) = ctrl.profile_condition {
                let (profile_ok, profile_reason) = check_profile_condition(condition, profiles);
                if total_events > 0 && profile_ok && diversity_ok {
                    (EvidenceStatus::Evidenced, None)
                } else if total_events > 0 && (!profile_ok || !diversity_ok) {
                    // Events exist but profile config is incomplete or diversity insufficient
                    let reason = match (profile_ok, diversity_ok) {
                        (false, false) => {
                            let pr = profile_reason.unwrap_or_default();
                            let dr = diversity_reason.unwrap_or_default();
                            Some(format!("{}; {}", pr, dr))
                        }
                        (false, true) => profile_reason,
                        (true, false) => diversity_reason,
                        _ => None,
                    };
                    (EvidenceStatus::PartiallyEvidenced, reason)
                } else if profile_ok {
                    // Profile is configured but no events generated yet
                    (
                        EvidenceStatus::PartiallyEvidenced,
                        Some("profile configured but no events in reporting period".to_string()),
                    )
                } else {
                    (EvidenceStatus::Gap, profile_reason)
                }
            } else {
                // No profile condition — purely event-based
                if total_events > 0 && diversity_ok {
                    (EvidenceStatus::Evidenced, None)
                } else if total_events > 0 {
                    // Events exist but not enough distinct types
                    (EvidenceStatus::PartiallyEvidenced, diversity_reason)
                } else {
                    (
                        EvidenceStatus::Gap,
                        Some("no events in reporting period".to_string()),
                    )
                }
            };

            ControlEvidence {
                control_id: ctrl.control_id.to_string(),
                title: ctrl.title.to_string(),
                status,
                total_events,
                event_counts: event_detail,
                reason,
                recommendation: ctrl.recommendation.to_string(),
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Branch lifecycle statistics
// ---------------------------------------------------------------------------

/// Compute branch lifecycle statistics from audit events.
///
/// Returns global counts plus a per-profile breakdown (PRD §3.2.6:
/// "Create/commit/reject/rollback counts per profile"). Profile is
/// extracted from the `branch_created` event's `details.profile` field;
/// subsequent lifecycle events are attributed to the same profile via
/// branch_id correlation.
pub fn compute_branch_stats(records: &[AuditRecord]) -> serde_json::Value {
    let mut created = 0u64;
    let mut committed = 0u64;
    let mut rejected = 0u64;
    let mut rolled_back = 0u64;
    let mut frozen = 0u64;

    // Map branch_id → profile name (from branch_created events)
    let mut branch_profile: HashMap<String, String> = HashMap::new();
    // Per-profile counters: profile → {created, committed, rejected, rolled_back}
    let mut per_profile: HashMap<String, [u64; 4]> = HashMap::new();

    for r in records {
        let profile_for_branch = r
            .event
            .branch_id
            .as_ref()
            .and_then(|bid| branch_profile.get(bid))
            .cloned();

        match r.event.event_type.as_str() {
            "branch_created" => {
                created += 1;
                // Extract profile from details (puzzled writes { "profile": "..." })
                let profile = r
                    .event
                    .details
                    .get("profile")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                if let Some(ref bid) = r.event.branch_id {
                    branch_profile.insert(bid.clone(), profile.clone());
                }
                per_profile.entry(profile).or_insert([0; 4])[0] += 1;
            }
            "branch_committed" => {
                committed += 1;
                if let Some(p) = profile_for_branch {
                    per_profile.entry(p).or_insert([0; 4])[1] += 1;
                }
            }
            "commit_rejected" => {
                rejected += 1;
                if let Some(p) = profile_for_branch {
                    per_profile.entry(p).or_insert([0; 4])[2] += 1;
                }
            }
            "branch_rolled_back" => {
                rolled_back += 1;
                if let Some(p) = profile_for_branch {
                    per_profile.entry(p).or_insert([0; 4])[3] += 1;
                }
            }
            "branch_frozen" => frozen += 1,
            _ => {}
        }
    }

    let per_profile_json: HashMap<String, serde_json::Value> = per_profile
        .into_iter()
        .map(|(profile, counts)| {
            (
                profile,
                serde_json::json!({
                    "created": counts[0],
                    "committed": counts[1],
                    "rejected": counts[2],
                    "rolled_back": counts[3],
                }),
            )
        })
        .collect();

    serde_json::json!({
        "branches_created": created,
        "branches_committed": committed,
        "commits_rejected": rejected,
        "branches_rolled_back": rolled_back,
        "branches_frozen": frozen,
        "per_profile": per_profile_json,
    })
}

/// Compute violation statistics including resolutions (PRD §3.2.6:
/// "Violation types, frequencies, resolutions").
///
/// Resolutions are determined by correlating violation branch_ids with
/// terminal branch states (committed, rejected, rolled_back).
pub fn compute_violation_stats(records: &[AuditRecord]) -> serde_json::Value {
    let mut total_violations = 0u64;
    let mut violation_types: HashMap<String, u64> = HashMap::new();
    let mut violation_branches: std::collections::HashSet<String> =
        std::collections::HashSet::new();

    // First pass: collect violation info
    for r in records {
        if r.event.event_type == "policy_violation" {
            total_violations += 1;
            if let Some(reason) = r.event.details.get("reason").and_then(|v| v.as_str()) {
                *violation_types.entry(reason.to_string()).or_insert(0) += 1;
            }
            if let Some(ref bid) = r.event.branch_id {
                violation_branches.insert(bid.clone());
            }
        }
    }

    // Second pass: determine resolution of violation branches
    let mut resolved_rejected = 0u64;
    let mut resolved_rolled_back = 0u64;
    let mut resolved_committed = 0u64;
    let mut unresolved = 0u64;
    for bid in &violation_branches {
        let terminal = records
            .iter()
            .filter(|r| r.event.branch_id.as_deref() == Some(bid))
            .find(|r| {
                matches!(
                    r.event.event_type.as_str(),
                    "commit_rejected" | "branch_rolled_back" | "branch_committed"
                )
            });
        match terminal.map(|r| r.event.event_type.as_str()) {
            Some("commit_rejected") => resolved_rejected += 1,
            Some("branch_rolled_back") => resolved_rolled_back += 1,
            Some("branch_committed") => resolved_committed += 1,
            _ => unresolved += 1,
        }
    }

    serde_json::json!({
        "total_violations": total_violations,
        "violation_types": violation_types,
        "resolutions": {
            "violation_branches": violation_branches.len(),
            "rejected": resolved_rejected,
            "rolled_back": resolved_rolled_back,
            "committed_despite_violation": resolved_committed,
            "unresolved": unresolved,
        },
    })
}

/// Build a branch summary from audit records (since D-Bus branch queries are
/// not available in local/offline mode). Extracts branch IDs from audit events
/// and summarizes their lifecycle state.
pub fn compute_branch_summary(records: &[AuditRecord]) -> serde_json::Value {
    use std::collections::HashSet;

    let mut branches_seen: HashSet<String> = HashSet::new();
    let mut committed: HashSet<String> = HashSet::new();
    let mut rejected: HashSet<String> = HashSet::new();
    let mut rolled_back: HashSet<String> = HashSet::new();

    for r in records {
        if let Some(ref bid) = r.event.branch_id {
            branches_seen.insert(bid.clone());
            match r.event.event_type.as_str() {
                "branch_committed" => {
                    committed.insert(bid.clone());
                }
                "commit_rejected" => {
                    rejected.insert(bid.clone());
                }
                "branch_rolled_back" => {
                    rolled_back.insert(bid.clone());
                }
                _ => {}
            }
        }
    }

    let branch_list: Vec<serde_json::Value> = branches_seen
        .iter()
        .map(|bid| {
            let state = if committed.contains(bid) {
                "committed"
            } else if rolled_back.contains(bid) {
                "rolled_back"
            } else if rejected.contains(bid) {
                "rejected"
            } else {
                "active_or_unknown"
            };
            serde_json::json!({
                "branch_id": bid,
                "state": state,
            })
        })
        .collect();

    serde_json::json!({
        "branches_total": branches_seen.len(),
        "branches_committed": committed.len(),
        "branches_rejected": rejected.len(),
        "branches_rolled_back": rolled_back.len(),
        "branches": branch_list,
    })
}

// ---------------------------------------------------------------------------
// Report metadata
// ---------------------------------------------------------------------------

/// Build report metadata (§3.2.6 metadata.json).
pub fn build_metadata(
    period: &str,
    framework_ids: &[String],
    records_count: usize,
    branches_count: usize,
    profiles_count: usize,
    policy_count: usize,
    attestation_chains_count: usize,
) -> serde_json::Value {
    let now = chrono_now_rfc3339();
    let period_secs = parse_period_secs(period).unwrap_or(30 * 86400);
    let start = epoch_to_rfc3339(now_epoch().saturating_sub(period_secs));

    let (hostname, arch, kernel) = host_info();

    serde_json::json!({
        // M6: Use crate version instead of hardcoded "1.0"
        "report_version": env!("CARGO_PKG_VERSION"),
        "generated_at": now,
        "generator": "puzzlectl",
        "generator_version": env!("CARGO_PKG_VERSION"),
        "period": {
            "start": start,
            "end": now,
        },
        "frameworks": framework_ids,
        "host": {
            "hostname": hostname,
            "arch": arch,
            "kernel": kernel,
        },
        "data_sources": {
            "audit_events_count": records_count,
            "branches_count": branches_count,
            "profiles_count": profiles_count,
            "policy_files_count": policy_count,
            "attestation_chains_count": attestation_chains_count,
        }
    })
}

// N10: Gracefully handle system clock error instead of panicking
fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_secs()
}

fn host_info() -> (String, String, String) {
    let hostname = std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let arch = std::env::consts::ARCH.to_string();
    let kernel = std::fs::read_to_string("/proc/version")
        .ok()
        .and_then(|v| v.split_whitespace().nth(2).map(|s| s.to_string()))
        .unwrap_or_else(|| "unknown".to_string());
    (hostname, arch, kernel)
}

// ---------------------------------------------------------------------------
// Package signing (§3.2.5 step 9)
// ---------------------------------------------------------------------------

/// Compute SHA-256 manifest for all files in a directory tree.
pub fn compute_sha256_manifest(dir: &Path) -> Result<Vec<(String, String)>> {
    use sha2::{Digest, Sha256};

    let mut entries = Vec::new();
    walk_dir_files(dir, dir, &mut entries)?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut manifest = Vec::new();
    for (rel_path, abs_path) in &entries {
        let data =
            std::fs::read(abs_path).with_context(|| format!("reading {}", abs_path.display()))?;
        let hash = hex::encode(Sha256::digest(&data));
        manifest.push((rel_path.clone(), hash));
    }
    Ok(manifest)
}

// Q10: Max recursion depth to prevent stack overflow from symlink cycles
const MAX_WALK_DEPTH: usize = 10;

fn walk_dir_files(base: &Path, current: &Path, out: &mut Vec<(String, PathBuf)>) -> Result<()> {
    walk_dir_files_inner(base, current, out, 0)
}

fn walk_dir_files_inner(
    base: &Path,
    current: &Path,
    out: &mut Vec<(String, PathBuf)>,
    depth: usize,
) -> Result<()> {
    // Q10: Use symlink_metadata to avoid following symlinks
    // R1: Replace fragile unwrap()-after-is_err() with is_ok_and()
    if !current.symlink_metadata().is_ok_and(|m| m.is_dir()) {
        return Ok(());
    }
    if depth > MAX_WALK_DEPTH {
        anyhow::bail!(
            "Q10: directory walk exceeded max depth {} at {}",
            MAX_WALK_DEPTH,
            current.display()
        );
    }
    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        // Q10: Use symlink_metadata to avoid following symlinks
        let entry_meta = path.symlink_metadata()?;
        if entry_meta.is_dir() {
            walk_dir_files_inner(base, &path, out, depth + 1)?;
        } else if entry_meta.is_file() {
            let rel = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            out.push((rel, path));
        }
        // Q10: Symlinks are silently skipped (not dir, not regular file)
    }
    Ok(())
}

/// Write SHA-256 manifest and Ed25519 signature.
///
/// The manifest lists SHA-256 hashes of all files (excluding signatures/).
/// The signature is computed over the manifest bytes directly (Ed25519
/// internally hashes with SHA-512, so double-hashing is unnecessary).
pub fn sign_package(dir: &Path, signing_key_path: &Path) -> Result<()> {
    use ed25519_dalek::{Signer, SigningKey};

    let sig_dir = dir.join("signatures");
    std::fs::create_dir_all(&sig_dir)?;

    // Compute manifest (exclude signatures/ directory itself)
    let manifest = compute_sha256_manifest(dir)?;
    let manifest_lines: Vec<String> = manifest
        .iter()
        .filter(|(p, _)| !p.starts_with("signatures/"))
        .map(|(path, hash)| format!("{}  {}", hash, path))
        .collect();
    let manifest_text = manifest_lines.join("\n") + "\n";

    std::fs::write(sig_dir.join("package.sha256"), &manifest_text)?;

    // Sign if key is available
    if signing_key_path.exists() {
        let key_hex = std::fs::read_to_string(signing_key_path).context("reading signing key")?;
        let key_bytes = hex::decode(key_hex.trim()).context("decoding signing key hex")?;
        if key_bytes.len() != 32 {
            anyhow::bail!(
                "signing key must be exactly 32 bytes (got {} bytes from {})",
                key_bytes.len(),
                signing_key_path.display()
            );
        }
        // V14: Replace unwrap with error propagation for defense-in-depth
        let key_bytes_arr: [u8; 32] = key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("signing key must be exactly 32 bytes"))?;
        let signing_key = SigningKey::from_bytes(&key_bytes_arr);
        // Sign the manifest text directly — Ed25519 internally hashes with
        // SHA-512, so pre-hashing with SHA-256 would be redundant and
        // non-standard (breaks interop with standard Ed25519 verifiers).
        let sig = signing_key.sign(manifest_text.as_bytes());
        std::fs::write(sig_dir.join("package.sig"), hex::encode(sig.to_bytes()))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Executive summary (§3.2.6)
// ---------------------------------------------------------------------------

/// Generate a markdown executive summary.
pub fn generate_executive_summary(
    period: &str,
    records_count: usize,
    framework_results: &[(&FrameworkDef, Vec<ControlEvidence>)],
) -> String {
    let mut md = String::new();
    md.push_str("# Compliance Evidence Report — Executive Summary\n\n");
    md.push_str(&format!(
        "**Reporting period:** {}  \n**Audit events analyzed:** {}  \n**Generated:** {}  \n\n",
        period,
        records_count,
        chrono_now_rfc3339(),
    ));

    for (fw, controls) in framework_results {
        let evidenced = controls
            .iter()
            .filter(|c| c.status == EvidenceStatus::Evidenced)
            .count();
        let partial = controls
            .iter()
            .filter(|c| c.status == EvidenceStatus::PartiallyEvidenced)
            .count();
        let gaps = controls
            .iter()
            .filter(|c| c.status == EvidenceStatus::Gap)
            .count();

        md.push_str(&format!("## {} ({})\n\n", fw.name, fw.id));
        md.push_str(&format!(
            "| Status | Count |\n|---|---|\n| Evidenced | {} |\n| Partially Evidenced | {} |\n| Gap | {} |\n| **Total** | **{}** |\n\n",
            evidenced, partial, gaps, controls.len()
        ));

        if gaps > 0 || partial > 0 {
            md.push_str("### Attention Required\n\n");
            for ctrl in controls {
                if ctrl.status != EvidenceStatus::Evidenced {
                    md.push_str(&format!(
                        "- **{}** ({}): {}\n",
                        ctrl.control_id,
                        ctrl.status.label(),
                        ctrl.reason.as_deref().unwrap_or(&ctrl.recommendation),
                    ));
                }
            }
            md.push('\n');
        }
    }

    md
}

// ---------------------------------------------------------------------------
// Full report generation (§3.2.5 + §3.2.6)
// ---------------------------------------------------------------------------

/// Generate a full compliance evidence package to a directory.
#[allow(clippy::too_many_arguments)]
pub fn generate_report_package(
    output_dir: &Path,
    frameworks: &[&FrameworkDef],
    records: &[AuditRecord],
    event_counts: &HashMap<String, u64>,
    profiles: &[ProfileSummary],
    profiles_dir: &Path,
    policies_dir: &Path,
    period: &str,
    signing_key_path: Option<&Path>,
) -> Result<()> {
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("creating output directory {}", output_dir.display()))?;

    // Count policy files
    let policy_count = count_files_with_ext(policies_dir, "rego");

    // 1. Evaluate controls for each framework
    let mut framework_results: Vec<(&FrameworkDef, Vec<ControlEvidence>)> = Vec::new();
    for fw in frameworks {
        let controls = evaluate_controls(fw, event_counts, profiles);
        framework_results.push((fw, controls));
    }

    // 2. Write metadata.json
    let branches_count = records
        .iter()
        .filter_map(|r| r.event.branch_id.as_ref())
        .collect::<std::collections::HashSet<_>>()
        .len();
    let attestation_chains_count =
        count_files_with_ext(&Path::new(DEFAULT_ATTESTATION_DIR).join("chains"), "json");
    let metadata = build_metadata(
        period,
        &frameworks
            .iter()
            .map(|f| f.id.to_string())
            .collect::<Vec<_>>(),
        records.len(),
        branches_count,
        profiles.len(),
        policy_count,
        attestation_chains_count,
    );
    write_json(output_dir, "metadata.json", &metadata)?;

    // 3. Write executive-summary.md
    let summary = generate_executive_summary(period, records.len(), &framework_results);
    std::fs::write(output_dir.join("executive-summary.md"), &summary)?;

    // 4. Write per-framework evidence
    let fw_dir = output_dir.join("framework");
    for (fw, controls) in &framework_results {
        let fw_out = fw_dir.join(fw.id);
        let evidence_dir = fw_out.join("evidence");
        std::fs::create_dir_all(&evidence_dir)?;

        // control-mapping.json
        write_json(&fw_out, "control-mapping.json", controls)?;

        // Per-control evidence files
        let unique_profiles: Vec<&str> = profiles.iter().map(|p| p.profile.as_str()).collect();
        let branches_total = records
            .iter()
            .filter_map(|r| r.event.branch_id.as_ref())
            .collect::<std::collections::HashSet<_>>()
            .len();

        for ctrl in controls {
            let filename = format!("{}.json", ctrl.control_id.to_lowercase().replace('.', "-"));
            let evidence = serde_json::json!({
                "framework": fw.id,
                "criterion": ctrl.control_id,
                "title": ctrl.title,
                "status": ctrl.status,
                "evidence": {
                    "summary": build_evidence_summary(ctrl, profiles),
                    "metrics": {
                        "total_events": ctrl.total_events,
                        "branches_total": branches_total,
                        "unique_profiles_used": unique_profiles,
                    },
                    "audit_events_referenced": ctrl.event_counts.keys().collect::<Vec<_>>(),
                    "event_counts": ctrl.event_counts,
                    "profile_evidence": profiles,
                },
                "recommendation": ctrl.recommendation,
            });
            write_json(&evidence_dir, &filename, &evidence)?;
        }

        // gaps.json
        let gaps: Vec<serde_json::Value> = controls
            .iter()
            .filter(|c| c.status != EvidenceStatus::Evidenced)
            .map(|c| {
                serde_json::json!({
                    "criterion": c.control_id,
                    "title": c.title,
                    "status": c.status,
                    "reason": c.reason,
                    "recommendation": c.recommendation,
                })
            })
            .collect();
        write_json(&fw_out, "gaps.json", &gaps)?;
    }

    // 5. Write raw-data/
    let raw_dir = output_dir.join("raw-data");
    std::fs::create_dir_all(&raw_dir)?;
    write_json(&raw_dir, "audit-events.json", records)?;
    write_json(
        &raw_dir,
        "branch-summary.json",
        &compute_branch_summary(records),
    )?;

    // Copy profiles
    let raw_profiles_dir = raw_dir.join("profiles");
    copy_dir_files(profiles_dir, &raw_profiles_dir, "yaml")?;

    // Copy policies
    let raw_policies_dir = raw_dir.join("policies");
    copy_dir_files(policies_dir, &raw_policies_dir, "rego")?;

    // 5b. Copy attestation data (if available)
    // Attestation store lives at /var/lib/puzzled/attestation/ (sibling of audit/)
    let att_src = {
        let default = Path::new(DEFAULT_ATTESTATION_DIR);
        if default.exists() {
            Some(default)
        } else {
            None
        }
    };
    if let Some(att_dir) = att_src {
        let att_out = output_dir.join("attestation");
        std::fs::create_dir_all(&att_out)?;
        // Copy chains
        let chains_src = att_dir.join("chains");
        if chains_src.exists() {
            let chains_dst = att_out.join("chains");
            copy_dir_files(&chains_src, &chains_dst, "json")?;
        }
        // Copy proofs
        let proofs_src = att_dir.join("proofs");
        if proofs_src.exists() {
            let proofs_dst = att_out.join("merkle-proofs");
            copy_dir_files(&proofs_src, &proofs_dst, "json")?;
        }
        // Copy verification key
        let pubkey_path = att_dir.join("signing_key.pub");
        if pubkey_path.exists() {
            std::fs::copy(&pubkey_path, att_out.join("verification-key.pub"))?;
        }
    }

    // 6. Write statistics/
    let stats_dir = output_dir.join("statistics");
    std::fs::create_dir_all(&stats_dir)?;
    write_json(&stats_dir, "event-distribution.json", event_counts)?;
    write_json(
        &stats_dir,
        "branch-lifecycle.json",
        &compute_branch_stats(records),
    )?;
    write_json(
        &stats_dir,
        "violations.json",
        &compute_violation_stats(records),
    )?;

    // 7. Sign package
    if let Some(key_path) = signing_key_path {
        sign_package(output_dir, key_path)?;
    }

    Ok(())
}

fn build_evidence_summary(ctrl: &ControlEvidence, profiles: &[ProfileSummary]) -> String {
    match ctrl.status {
        EvidenceStatus::Evidenced => {
            let profile_names: Vec<&str> = profiles.iter().map(|p| p.profile.as_str()).collect();
            format!(
                "{} governance events observed across {} profile(s) ({}) confirming {} compliance",
                ctrl.total_events,
                profiles.len(),
                if profile_names.is_empty() {
                    "none loaded".to_string()
                } else {
                    profile_names.join(", ")
                },
                ctrl.title.to_lowercase()
            )
        }
        EvidenceStatus::PartiallyEvidenced => format!(
            "Partial evidence for {}: {}",
            ctrl.title.to_lowercase(),
            ctrl.reason.as_deref().unwrap_or("incomplete configuration")
        ),
        EvidenceStatus::Gap => format!(
            "No evidence for {}: {}",
            ctrl.title.to_lowercase(),
            ctrl.reason
                .as_deref()
                .unwrap_or("no relevant events in reporting period")
        ),
    }
}

/// Gap analysis result for a framework.
#[derive(Serialize)]
pub struct GapAnalysis {
    pub framework: String,
    pub analysis_period: String,
    pub gaps: Vec<GapEntry>,
    pub summary: GapSummary,
}

#[derive(Serialize)]
pub struct GapEntry {
    pub criterion: String,
    pub title: String,
    pub status: EvidenceStatus,
    pub reason: Option<String>,
    pub recommendation: String,
}

#[derive(Serialize)]
pub struct GapSummary {
    pub total_controls: usize,
    pub evidenced: usize,
    pub partially_evidenced: usize,
    pub gaps: usize,
}

/// Run gap analysis for a framework.
///
/// `period` is an optional human-readable period string (e.g., "30d").
/// If None, the analysis covers all available data.
pub fn analyze_gaps(
    fw: &FrameworkDef,
    event_counts: &HashMap<String, u64>,
    profiles: &[ProfileSummary],
    period: Option<&str>,
) -> GapAnalysis {
    let controls = evaluate_controls(fw, event_counts, profiles);
    let evidenced = controls
        .iter()
        .filter(|c| c.status == EvidenceStatus::Evidenced)
        .count();
    let partial = controls
        .iter()
        .filter(|c| c.status == EvidenceStatus::PartiallyEvidenced)
        .count();
    let gap_count = controls
        .iter()
        .filter(|c| c.status == EvidenceStatus::Gap)
        .count();

    let gaps: Vec<GapEntry> = controls
        .into_iter()
        .filter(|c| c.status != EvidenceStatus::Evidenced)
        .map(|c| GapEntry {
            criterion: c.control_id,
            title: c.title,
            status: c.status,
            reason: c.reason,
            recommendation: c.recommendation,
        })
        .collect();

    let analysis_period = if let Some(p) = period {
        let period_secs = parse_period_secs(p).unwrap_or(30 * 86400);
        let end = chrono_now_rfc3339();
        let start = epoch_to_rfc3339(now_epoch().saturating_sub(period_secs));
        format!("{} / {}", start, end)
    } else {
        "all available data".to_string()
    };

    GapAnalysis {
        framework: fw.id.to_string(),
        analysis_period,
        gaps,
        summary: GapSummary {
            total_controls: fw.controls.len(),
            evidenced,
            partially_evidenced: partial,
            gaps: gap_count,
        },
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn write_json<T: Serialize + ?Sized>(dir: &Path, filename: &str, data: &T) -> Result<()> {
    let path = dir.join(filename);
    let json = serde_json::to_string_pretty(data)?;
    std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))
}

fn copy_dir_files(src: &Path, dst: &Path, ext: &str) -> Result<()> {
    if !src.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(dst)?;
    if let Ok(entries) = std::fs::read_dir(src) {
        // J45: Propagate directory entry read errors instead of silently skipping
        for entry_result in entries {
            let entry = entry_result.with_context(|| {
                format!("J45: failed to read directory entry in {}", src.display())
            })?;
            let path = entry.path();
            if path.extension().and_then(|x| x.to_str()) == Some(ext) {
                if let Some(name) = path.file_name() {
                    std::fs::copy(&path, dst.join(name))?;
                }
            }
        }
    }
    Ok(())
}

fn count_files_with_ext(dir: &Path, ext: &str) -> usize {
    if !dir.exists() {
        return 0;
    }
    // V53: Silently skipping dir entry errors is acceptable for file counting —
    // errors are transient (e.g., concurrent deletion) and undercounting is benign.
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some(ext))
                .count()
        })
        .unwrap_or(0)
}

/// Approximate current time as RFC 3339 string (no chrono dependency).
pub fn chrono_now_rfc3339() -> String {
    epoch_to_rfc3339(now_epoch())
}

fn epoch_to_rfc3339(secs: u64) -> String {
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let mut year = 1970u64;
    let mut remaining_days = days;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }
    let is_leap = is_leap_year(year);
    let month_days: [u64; 12] = [
        31,
        if is_leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 0u64;
    for (i, &md) in month_days.iter().enumerate() {
        if remaining_days < md {
            month = i as u64 + 1;
            break;
        }
        remaining_days -= md;
    }
    if month == 0 {
        month = 12;
    }
    let day = remaining_days + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn is_leap_year(y: u64) -> bool {
    y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use puzzled_types::AuditRecordEvent;
    use std::io::Write as _;

    // -- Framework definitions --

    #[test]
    fn test_all_frameworks_defined() {
        assert_eq!(FRAMEWORKS.len(), 4);
        assert!(get_framework("eu-ai-act").is_ok());
        assert!(get_framework("soc2").is_ok());
        assert!(get_framework("iso27001").is_ok());
        assert!(get_framework("nist-ai-rmf").is_ok());
    }

    #[test]
    fn test_unknown_framework_error() {
        assert!(get_framework("pci-dss").is_err());
    }

    #[test]
    fn test_eu_ai_act_has_seven_controls() {
        let fw = get_framework("eu-ai-act").unwrap();
        assert_eq!(fw.controls.len(), 7);
    }

    #[test]
    fn test_soc2_has_nine_controls() {
        let fw = get_framework("soc2").unwrap();
        assert_eq!(fw.controls.len(), 9);
    }

    #[test]
    fn test_iso27001_has_seven_controls() {
        let fw = get_framework("iso27001").unwrap();
        assert_eq!(fw.controls.len(), 7);
    }

    #[test]
    fn test_nist_ai_rmf_has_five_controls() {
        let fw = get_framework("nist-ai-rmf").unwrap();
        assert_eq!(fw.controls.len(), 5);
    }

    // -- Period parsing --

    #[test]
    fn test_parse_period_days() {
        assert_eq!(parse_period_secs("30d").unwrap(), 30 * 86400);
    }

    #[test]
    fn test_parse_period_weeks() {
        assert_eq!(parse_period_secs("2w").unwrap(), 2 * 604800);
    }

    #[test]
    fn test_parse_period_months() {
        assert_eq!(parse_period_secs("3m").unwrap(), 3 * 2_592_000);
    }

    #[test]
    fn test_parse_period_years() {
        assert_eq!(parse_period_secs("1y").unwrap(), 31_536_000);
    }

    #[test]
    fn test_parse_period_invalid_unit() {
        assert!(parse_period_secs("30x").is_err());
    }

    #[test]
    fn test_parse_period_invalid_number() {
        assert!(parse_period_secs("abcd").is_err());
    }

    // -- RFC 3339 parsing --

    #[test]
    fn test_parse_rfc3339_valid() {
        let ts = parse_rfc3339_approx("2026-03-10T14:30:00Z");
        assert!(ts.is_some());
        let epoch = ts.unwrap();
        // Must round-trip exactly through epoch_to_rfc3339
        assert_eq!(epoch_to_rfc3339(epoch), "2026-03-10T14:30:00Z");
    }

    #[test]
    fn test_parse_rfc3339_roundtrip_epoch_zero() {
        assert_eq!(parse_rfc3339_approx("1970-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn test_parse_rfc3339_roundtrip_y2k() {
        // 2000-01-01T00:00:00Z = 946684800
        let epoch = parse_rfc3339_approx("2000-01-01T00:00:00Z").unwrap();
        assert_eq!(epoch, 946_684_800);
        assert_eq!(epoch_to_rfc3339(epoch), "2000-01-01T00:00:00Z");
    }

    #[test]
    fn test_parse_rfc3339_roundtrip_leap_day() {
        // 2024-02-29 is a leap day
        let epoch = parse_rfc3339_approx("2024-02-29T12:00:00Z").unwrap();
        assert_eq!(epoch_to_rfc3339(epoch), "2024-02-29T12:00:00Z");
    }

    #[test]
    fn test_parse_rfc3339_roundtrip_century_year() {
        // 1900 is NOT a leap year (divisible by 100 but not 400)
        // 2100-03-01 tests that the century-year correction works
        let epoch = parse_rfc3339_approx("2100-03-01T00:00:00Z").unwrap();
        assert_eq!(epoch_to_rfc3339(epoch), "2100-03-01T00:00:00Z");
    }

    #[test]
    fn test_parse_rfc3339_invalid_day() {
        assert!(parse_rfc3339_approx("2026-03-00T14:30:00Z").is_none());
    }

    #[test]
    fn test_parse_rfc3339_too_short() {
        assert!(parse_rfc3339_approx("2026").is_none());
    }

    #[test]
    fn test_parse_rfc3339_invalid_month() {
        assert!(parse_rfc3339_approx("2026-13-10T14:30:00Z").is_none());
    }

    // -- Epoch to RFC 3339 --

    #[test]
    fn test_epoch_to_rfc3339_epoch_zero() {
        assert_eq!(epoch_to_rfc3339(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_epoch_to_rfc3339_known_date() {
        // 2000-01-01T00:00:00Z = 946684800
        let s = epoch_to_rfc3339(946_684_800);
        assert!(s.starts_with("2000-01-01"), "got: {}", s);
    }

    // -- Event counting --

    #[test]
    fn test_count_events_by_type() {
        let records = vec![
            make_record(1, "branch_created"),
            make_record(2, "branch_created"),
            make_record(3, "policy_violation"),
        ];
        let counts = count_events_by_type(&records);
        assert_eq!(counts.get("branch_created"), Some(&2));
        assert_eq!(counts.get("policy_violation"), Some(&1));
        assert_eq!(counts.get("behavioral_trigger"), None);
    }

    // -- Control evaluation (3-state) --

    #[test]
    fn test_evaluate_controls_evidenced_when_events_exist() {
        let fw = get_framework("eu-ai-act").unwrap();
        let mut counts = HashMap::new();
        // Art.9 needs policy_violation or behavioral_trigger
        counts.insert("policy_violation".to_string(), 5);
        counts.insert("branch_created".to_string(), 10);
        counts.insert("branch_committed".to_string(), 8);
        counts.insert("sandbox_escape".to_string(), 1);

        let controls = evaluate_controls(fw, &counts, &[]);
        let art9 = controls.iter().find(|c| c.control_id == "Art.9").unwrap();
        assert_eq!(art9.status, EvidenceStatus::Evidenced);
        assert_eq!(art9.total_events, 5);
    }

    #[test]
    fn test_evaluate_controls_gap_when_no_events() {
        let fw = get_framework("eu-ai-act").unwrap();
        let counts = HashMap::new();
        let controls = evaluate_controls(fw, &counts, &[]);
        // All controls should be gaps
        for ctrl in &controls {
            assert_eq!(
                ctrl.status,
                EvidenceStatus::Gap,
                "control {} should be gap",
                ctrl.control_id
            );
        }
    }

    #[test]
    fn test_evaluate_soc2_partially_evidenced() {
        let fw = get_framework("soc2").unwrap();
        let mut counts = HashMap::new();
        counts.insert("behavioral_trigger".to_string(), 3);

        // CC7.1 needs BehavioralEnabled in profiles — but no profiles loaded
        let controls = evaluate_controls(fw, &counts, &[]);
        let cc71 = controls.iter().find(|c| c.control_id == "CC7.1").unwrap();
        // Has events but no profiles → partially_evidenced
        assert_eq!(cc71.status, EvidenceStatus::PartiallyEvidenced);
    }

    #[test]
    fn test_evaluate_soc2_evidenced_with_profiles() {
        let fw = get_framework("soc2").unwrap();
        let mut counts = HashMap::new();
        counts.insert("behavioral_trigger".to_string(), 3);

        let profiles = vec![make_profile_summary("standard", true, true, true)];
        let controls = evaluate_controls(fw, &counts, &profiles);
        let cc71 = controls.iter().find(|c| c.control_id == "CC7.1").unwrap();
        assert_eq!(cc71.status, EvidenceStatus::Evidenced);
    }

    #[test]
    fn test_evaluate_soc2_gap_exec_allowlist_missing() {
        let fw = get_framework("soc2").unwrap();
        let counts = HashMap::new();
        // Profile with no exec_allowlist
        let profiles = vec![make_profile_summary("privileged", false, true, true)];
        let controls = evaluate_controls(fw, &counts, &profiles);
        let cc68 = controls.iter().find(|c| c.control_id == "CC6.8").unwrap();
        assert_eq!(cc68.status, EvidenceStatus::Gap);
        assert!(cc68.reason.as_ref().unwrap().contains("exec_allowlist"));
    }

    #[test]
    fn test_evaluate_soc2_partially_evidenced_profile_ok_no_events() {
        let fw = get_framework("soc2").unwrap();
        let counts = HashMap::new();
        let profiles = vec![make_profile_summary("standard", true, true, true)];
        let controls = evaluate_controls(fw, &counts, &profiles);
        // CC7.1 has BehavioralEnabled condition — profile is ok but no events
        let cc71 = controls.iter().find(|c| c.control_id == "CC7.1").unwrap();
        assert_eq!(cc71.status, EvidenceStatus::PartiallyEvidenced);
        assert!(cc71.reason.as_ref().unwrap().contains("no events"));
    }

    // -- Gap analysis --

    #[test]
    fn test_gap_analysis_identifies_gaps() {
        let fw = get_framework("soc2").unwrap();
        let counts = HashMap::new();
        let profiles = vec![make_profile_summary("standard", true, true, true)];
        let analysis = analyze_gaps(fw, &counts, &profiles, None);
        assert!(!analysis.gaps.is_empty());
        assert_eq!(analysis.summary.total_controls, 9);
        assert_eq!(
            analysis.summary.evidenced
                + analysis.summary.partially_evidenced
                + analysis.summary.gaps,
            analysis.summary.total_controls
        );
    }

    #[test]
    fn test_gap_analysis_all_evidenced() {
        let fw = get_framework("soc2").unwrap();
        let mut counts = HashMap::new();
        for et in [
            "profile_loaded",
            "seccomp_decision",
            "agent_exec_gated",
            "policy_violation",
            "agent_registered",
            "branch_created",
            "behavioral_trigger",
            "sandbox_escape",
            "agent_killed",
            "branch_committed",
            "commit_rejected",
            "branch_rolled_back",
            "policy_reloaded",
            "wal_recovery",
        ] {
            counts.insert(et.to_string(), 5);
        }
        let profiles = vec![make_profile_summary("standard", true, true, true)];
        let analysis = analyze_gaps(fw, &counts, &profiles, None);
        assert_eq!(analysis.summary.evidenced, 9);
        assert_eq!(analysis.summary.gaps, 0);
        assert_eq!(analysis.summary.partially_evidenced, 0);
    }

    #[test]
    fn test_gap_entries_have_recommendations() {
        let fw = get_framework("soc2").unwrap();
        let counts = HashMap::new();
        let analysis = analyze_gaps(fw, &counts, &[], None);
        for gap in &analysis.gaps {
            assert!(
                !gap.recommendation.is_empty(),
                "gap {} missing recommendation",
                gap.criterion
            );
        }
    }

    // -- Branch lifecycle stats --

    #[test]
    fn test_branch_stats() {
        let records = vec![
            make_record(1, "branch_created"),
            make_record(2, "branch_created"),
            make_record(3, "branch_committed"),
            make_record(4, "commit_rejected"),
            make_record(5, "branch_rolled_back"),
        ];
        let stats = compute_branch_stats(&records);
        assert_eq!(stats["branches_created"], 2);
        assert_eq!(stats["branches_committed"], 1);
        assert_eq!(stats["commits_rejected"], 1);
        assert_eq!(stats["branches_rolled_back"], 1);
    }

    // -- Violation stats --

    #[test]
    fn test_violation_stats() {
        let records = vec![
            make_violation_record(1, "sensitive_file"),
            make_violation_record(2, "sensitive_file"),
            make_violation_record(3, "size_limit"),
        ];
        let stats = compute_violation_stats(&records);
        assert_eq!(stats["total_violations"], 3);
        let types = stats["violation_types"].as_object().unwrap();
        assert_eq!(types["sensitive_file"], 2);
        assert_eq!(types["size_limit"], 1);
    }

    // -- Metadata --

    #[test]
    fn test_metadata_structure() {
        let meta = build_metadata("30d", &["soc2".to_string()], 100, 89, 3, 1, 89);
        assert_eq!(meta["report_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(meta["generator"], "puzzlectl");
        assert!(meta["period"]["start"].is_string());
        assert!(meta["period"]["end"].is_string());
        assert_eq!(meta["frameworks"][0], "soc2");
        assert_eq!(meta["data_sources"]["audit_events_count"], 100);
        assert_eq!(meta["data_sources"]["branches_count"], 89);
        assert_eq!(meta["data_sources"]["profiles_count"], 3);
        assert_eq!(meta["data_sources"]["policy_files_count"], 1);
        assert_eq!(meta["data_sources"]["attestation_chains_count"], 89);
    }

    // -- Executive summary --

    #[test]
    fn test_executive_summary_contains_framework() {
        let fw = get_framework("soc2").unwrap();
        let controls = evaluate_controls(fw, &HashMap::new(), &[]);
        let summary = generate_executive_summary("30d", 100, &[(fw, controls)]);
        assert!(summary.contains("SOC 2"));
        assert!(summary.contains("Reporting period"));
        assert!(summary.contains("Gap"));
    }

    // -- Audit record loading --

    #[test]
    fn test_load_audit_records_nonexistent_dir() {
        let result = load_audit_records(Path::new("/nonexistent/path"), None).unwrap();
        assert!(result.records.is_empty());
        assert_eq!(result.parse_failures, 0);
        assert_eq!(result.total_lines, 0);
    }

    #[test]
    fn test_load_audit_records_from_ndjson() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.ndjson");
        let mut f = std::fs::File::create(&log_path).unwrap();
        writeln!(f, r#"{{"seq":1,"timestamp":"2026-03-10T10:00:00Z","event":{{"event_type":"branch_created","branch_id":"b1","details":{{}}}}}}"#).unwrap();
        writeln!(f, r#"{{"seq":2,"timestamp":"2026-03-10T11:00:00Z","event":{{"event_type":"policy_violation","branch_id":"b1","details":{{}}}}}}"#).unwrap();

        let result = load_audit_records(dir.path(), None).unwrap();
        assert_eq!(result.records.len(), 2);
        assert_eq!(result.parse_failures, 0);
        assert_eq!(result.total_lines, 2);
        assert_eq!(result.records[0].event.event_type, "branch_created");
        assert_eq!(result.records[1].event.event_type, "policy_violation");
    }

    #[test]
    fn test_load_audit_records_with_time_filter() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.ndjson");
        let mut f = std::fs::File::create(&log_path).unwrap();
        // Very old record (should be filtered)
        writeln!(f, r#"{{"seq":1,"timestamp":"2020-01-01T00:00:00Z","event":{{"event_type":"old_event","branch_id":null,"details":{{}}}}}}"#).unwrap();
        // Recent record (should be kept)
        let now_rfc = chrono_now_rfc3339();
        writeln!(f, r#"{{"seq":2,"timestamp":"{}","event":{{"event_type":"new_event","branch_id":null,"details":{{}}}}}}"#, now_rfc).unwrap();

        let result = load_audit_records(dir.path(), Some(86400)).unwrap(); // last 24h
        assert_eq!(result.records.len(), 1);
        assert_eq!(result.records[0].event.event_type, "new_event");
    }

    #[test]
    fn test_load_audit_records_counts_parse_failures() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.ndjson");
        let mut f = std::fs::File::create(&log_path).unwrap();
        writeln!(f, r#"{{"seq":1,"timestamp":"2026-03-10T10:00:00Z","event":{{"event_type":"ok","branch_id":null,"details":{{}}}}}}"#).unwrap();
        writeln!(f, r#"{{this is not valid json}}"#).unwrap();
        writeln!(f, r#"{{"seq":3,"timestamp":"2026-03-10T10:00:00Z","event":{{"event_type":"ok2","branch_id":null,"details":{{}}}}}}"#).unwrap();

        let result = load_audit_records(dir.path(), None).unwrap();
        assert_eq!(result.records.len(), 2);
        assert_eq!(result.parse_failures, 1);
        assert_eq!(result.total_lines, 3);
    }

    // -- Report package generation --

    #[test]
    fn test_report_package_structure() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("report");

        let profiles_dir = dir.path().join("profiles");
        std::fs::create_dir_all(&profiles_dir).unwrap();
        let policies_dir = dir.path().join("policies");
        std::fs::create_dir_all(&policies_dir).unwrap();

        let fw = get_framework("soc2").unwrap();
        let records = vec![
            make_record(1, "branch_created"),
            make_record(2, "policy_violation"),
        ];
        let event_counts = count_events_by_type(&records);
        let profiles = vec![make_profile_summary("standard", true, true, true)];

        generate_report_package(
            &output,
            &[fw],
            &records,
            &event_counts,
            &profiles,
            &profiles_dir,
            &policies_dir,
            "30d",
            None,
        )
        .unwrap();

        // Verify directory structure
        assert!(output.join("metadata.json").exists());
        assert!(output.join("executive-summary.md").exists());
        assert!(output.join("framework/soc2/control-mapping.json").exists());
        assert!(output.join("framework/soc2/gaps.json").exists());
        assert!(output.join("framework/soc2/evidence").is_dir());
        assert!(output.join("raw-data/audit-events.json").exists());
        assert!(output.join("raw-data/branch-summary.json").exists());
        assert!(output.join("statistics/event-distribution.json").exists());
        assert!(output.join("statistics/branch-lifecycle.json").exists());
        assert!(output.join("statistics/violations.json").exists());

        // Verify metadata content
        let meta: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(output.join("metadata.json")).unwrap())
                .unwrap();
        assert_eq!(meta["report_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(meta["frameworks"][0], "soc2");
        assert_eq!(meta["data_sources"]["audit_events_count"], 2);
    }

    #[test]
    fn test_report_per_control_evidence_files() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("report");
        let profiles_dir = dir.path().join("profiles");
        std::fs::create_dir_all(&profiles_dir).unwrap();
        let policies_dir = dir.path().join("policies");
        std::fs::create_dir_all(&policies_dir).unwrap();

        let fw = get_framework("eu-ai-act").unwrap();
        let records = vec![make_record(1, "policy_violation")];
        let event_counts = count_events_by_type(&records);

        generate_report_package(
            &output,
            &[fw],
            &records,
            &event_counts,
            &[],
            &profiles_dir,
            &policies_dir,
            "30d",
            None,
        )
        .unwrap();

        // Should have per-control evidence files
        let evidence_dir = output.join("framework/eu-ai-act/evidence");
        assert!(evidence_dir.join("art-9.json").exists());
        assert!(evidence_dir.join("art-12.json").exists());
        assert!(evidence_dir.join("art-14.json").exists());

        // Verify content of art-9 (has policy_violation events)
        let art9: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(evidence_dir.join("art-9.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(art9["criterion"], "Art.9");
        assert_eq!(art9["status"], "evidenced");
    }

    #[test]
    fn test_report_multiple_frameworks() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("report");
        let profiles_dir = dir.path().join("profiles");
        std::fs::create_dir_all(&profiles_dir).unwrap();
        let policies_dir = dir.path().join("policies");
        std::fs::create_dir_all(&policies_dir).unwrap();

        let fw1 = get_framework("soc2").unwrap();
        let fw2 = get_framework("iso27001").unwrap();
        let records = vec![make_record(1, "branch_created")];
        let event_counts = count_events_by_type(&records);

        generate_report_package(
            &output,
            &[fw1, fw2],
            &records,
            &event_counts,
            &[],
            &profiles_dir,
            &policies_dir,
            "30d",
            None,
        )
        .unwrap();

        assert!(output.join("framework/soc2/control-mapping.json").exists());
        assert!(output
            .join("framework/iso27001/control-mapping.json")
            .exists());
    }

    // -- Package signing --

    #[test]
    fn test_sha256_manifest() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file1.txt"), "hello").unwrap();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/file2.txt"), "world").unwrap();

        let manifest = compute_sha256_manifest(dir.path()).unwrap();
        assert_eq!(manifest.len(), 2);
        // Should be sorted by path
        assert!(manifest[0].0 < manifest[1].0);
        // Hashes should be 64-char hex
        assert_eq!(manifest[0].1.len(), 64);
    }

    #[test]
    fn test_sign_package_creates_manifest() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("metadata.json"), "{}").unwrap();

        sign_package(dir.path(), Path::new("/nonexistent/key")).unwrap();

        assert!(dir.path().join("signatures/package.sha256").exists());
        // No signature since key doesn't exist
        assert!(!dir.path().join("signatures/package.sig").exists());
    }

    #[test]
    fn test_sign_package_with_valid_key() {
        use ed25519_dalek::{Signature, SigningKey, Verifier};

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("metadata.json"), r#"{"test": true}"#).unwrap();

        // Generate a key
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let key_path = dir.path().join("test.key");
        std::fs::write(&key_path, hex::encode(signing_key.to_bytes())).unwrap();

        sign_package(dir.path(), &key_path).unwrap();

        assert!(dir.path().join("signatures/package.sha256").exists());
        assert!(dir.path().join("signatures/package.sig").exists());

        // Verify the signature
        let manifest_text =
            std::fs::read_to_string(dir.path().join("signatures/package.sha256")).unwrap();
        let sig_hex = std::fs::read_to_string(dir.path().join("signatures/package.sig")).unwrap();
        let sig_bytes = hex::decode(sig_hex.trim()).unwrap();
        let sig = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
        assert!(verifying_key.verify(manifest_text.as_bytes(), &sig).is_ok());
    }

    #[test]
    fn test_sign_package_rejects_invalid_key_size() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("metadata.json"), "{}").unwrap();

        // Write a key that's too short (16 bytes instead of 32)
        let key_path = dir.path().join("bad.key");
        std::fs::write(&key_path, hex::encode([0u8; 16])).unwrap();

        let result = sign_package(dir.path(), &key_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));
    }

    // -- Profile condition checks --

    #[test]
    fn test_profile_condition_behavioral_enabled() {
        let p = make_profile_summary("test", true, true, true);
        let (ok, _) = check_profile_condition(ProfileCondition::BehavioralEnabled, &[p]);
        assert!(ok);
    }

    #[test]
    fn test_profile_condition_behavioral_disabled() {
        let mut p = make_profile_summary("test", true, true, true);
        p.behavioral_credential_alert = false;
        let (ok, reason) = check_profile_condition(ProfileCondition::BehavioralEnabled, &[p]);
        assert!(!ok);
        let reason_str = reason.unwrap();
        assert!(reason_str.contains("test"));
        assert!(reason_str.contains("credential_access_alert"));
    }

    #[test]
    fn test_profile_condition_behavioral_max_deletions_zero_is_still_enabled() {
        // max_deletions == 0 means "trigger on first deletion" — strictest monitoring,
        // NOT "disabled." Ensure it passes the behavioral check.
        let mut p = make_profile_summary("test", true, true, true);
        p.behavioral_max_deletions = 0;
        let (ok, _) = check_profile_condition(ProfileCondition::BehavioralEnabled, &[p]);
        assert!(
            ok,
            "max_deletions=0 should be considered 'monitoring enabled'"
        );
    }

    #[test]
    fn test_profile_condition_exec_allowlist_missing() {
        let p = make_profile_summary("test", false, true, true);
        let (ok, reason) = check_profile_condition(ProfileCondition::ExecAllowlistDefined, &[p]);
        assert!(!ok);
        assert!(reason.unwrap().contains("exec_allowlist"));
    }

    #[test]
    fn test_profile_condition_no_profiles() {
        let (ok, reason) = check_profile_condition(ProfileCondition::BehavioralEnabled, &[]);
        assert!(!ok);
        assert!(reason.unwrap().contains("no profiles"));
    }

    #[test]
    fn test_profile_condition_multi_profile_partial_failure() {
        // 3 profiles: restricted + standard pass, privileged fails (no exec_allowlist)
        let p1 = make_profile_summary("restricted", true, true, true);
        let p2 = make_profile_summary("standard", true, true, true);
        let p3 = make_profile_summary("privileged", false, true, true);
        let (ok, reason) =
            check_profile_condition(ProfileCondition::ExecAllowlistDefined, &[p1, p2, p3]);
        assert!(!ok);
        let reason_str = reason.unwrap();
        // Should name only the failing profile
        assert!(
            reason_str.contains("privileged"),
            "should mention failing profile: {}",
            reason_str
        );
        assert!(
            !reason_str.contains("restricted"),
            "should not mention passing profiles: {}",
            reason_str
        );
        assert!(
            !reason_str.contains("standard"),
            "should not mention passing profiles: {}",
            reason_str
        );
    }

    #[test]
    fn test_profile_condition_multi_profile_all_pass() {
        let p1 = make_profile_summary("restricted", true, true, true);
        let p2 = make_profile_summary("standard", true, true, true);
        let (ok, _) = check_profile_condition(ProfileCondition::ResourceLimitsDefined, &[p1, p2]);
        assert!(ok);
    }

    // -- Branch summary --

    #[test]
    fn test_branch_summary_lifecycle_states() {
        let records = vec![
            make_record_with_branch(1, "branch_created", "b1"),
            make_record_with_branch(2, "branch_created", "b2"),
            make_record_with_branch(3, "branch_created", "b3"),
            make_record_with_branch(4, "branch_committed", "b1"),
            make_record_with_branch(5, "branch_rolled_back", "b2"),
            make_record_with_branch(6, "commit_rejected", "b3"),
        ];
        let summary = compute_branch_summary(&records);
        assert_eq!(summary["branches_total"], 3);
        assert_eq!(summary["branches_committed"], 1);
        assert_eq!(summary["branches_rolled_back"], 1);
        assert_eq!(summary["branches_rejected"], 1);

        let branches = summary["branches"].as_array().unwrap();
        let b1 = branches.iter().find(|b| b["branch_id"] == "b1").unwrap();
        assert_eq!(b1["state"], "committed");
        let b2 = branches.iter().find(|b| b["branch_id"] == "b2").unwrap();
        assert_eq!(b2["state"], "rolled_back");
        let b3 = branches.iter().find(|b| b["branch_id"] == "b3").unwrap();
        assert_eq!(b3["state"], "rejected");
    }

    #[test]
    fn test_branch_summary_active_unknown() {
        // Branch with events but no terminal state
        let records = vec![
            make_record_with_branch(1, "branch_created", "b1"),
            make_record_with_branch(2, "branch_frozen", "b1"),
        ];
        let summary = compute_branch_summary(&records);
        assert_eq!(summary["branches_total"], 1);
        let branches = summary["branches"].as_array().unwrap();
        assert_eq!(branches[0]["state"], "active_or_unknown");
    }

    // -- Evidence summary text --

    #[test]
    fn test_build_evidence_summary_evidenced() {
        let ctrl = ControlEvidence {
            control_id: "CC6.1".to_string(),
            title: "Logical access security".to_string(),
            status: EvidenceStatus::Evidenced,
            total_events: 42,
            event_counts: HashMap::new(),
            reason: None,
            recommendation: String::new(),
        };
        let profiles = vec![make_profile_summary("standard", true, true, true)];
        let summary = build_evidence_summary(&ctrl, &profiles);
        assert!(
            summary.contains("42"),
            "should contain event count: {}",
            summary
        );
        assert!(
            summary.contains("standard"),
            "should name profiles: {}",
            summary
        );
        assert!(
            summary.contains("logical access security"),
            "should reference control title: {}",
            summary
        );
    }

    #[test]
    fn test_build_evidence_summary_gap() {
        let ctrl = ControlEvidence {
            control_id: "CC7.1".to_string(),
            title: "Monitoring".to_string(),
            status: EvidenceStatus::Gap,
            total_events: 0,
            event_counts: HashMap::new(),
            reason: Some("no events in reporting period".to_string()),
            recommendation: String::new(),
        };
        let summary = build_evidence_summary(&ctrl, &[]);
        assert!(
            summary.starts_with("No evidence"),
            "gap should start with 'No evidence': {}",
            summary
        );
        assert!(
            summary.contains("no events"),
            "should contain reason: {}",
            summary
        );
    }

    #[test]
    fn test_build_evidence_summary_partial() {
        let ctrl = ControlEvidence {
            control_id: "CC6.8".to_string(),
            title: "Malicious software prevention".to_string(),
            status: EvidenceStatus::PartiallyEvidenced,
            total_events: 5,
            event_counts: HashMap::new(),
            reason: Some("exec_allowlist not defined in profile(s): privileged".to_string()),
            recommendation: String::new(),
        };
        let summary = build_evidence_summary(&ctrl, &[]);
        assert!(
            summary.starts_with("Partial evidence"),
            "partial should start with 'Partial evidence': {}",
            summary
        );
        assert!(
            summary.contains("exec_allowlist"),
            "should contain reason: {}",
            summary
        );
    }

    // -- RFC 3339 non-ASCII safety --

    #[test]
    fn test_parse_rfc3339_non_ascii_no_panic() {
        // Multi-byte UTF-8 chars — must not panic, just return None
        assert_eq!(parse_rfc3339_approx("🔥26-03-10T14:30:00Z"), None);
        assert_eq!(parse_rfc3339_approx("2026-🔥-10T14:30:00Z"), None);
        assert_eq!(
            parse_rfc3339_approx("日本語のタイムスタンプではありません"),
            None
        );
    }

    // -- min_event_types diversity --

    #[test]
    fn test_all_event_types_control_partially_evidenced_low_diversity() {
        // Art.11 requires min_event_types=4; providing only 1 type should be partial
        let fw = get_framework("eu-ai-act").unwrap();
        let mut counts = HashMap::new();
        counts.insert("branch_created".to_string(), 100);
        let controls = evaluate_controls(fw, &counts, &[]);
        let art11 = controls.iter().find(|c| c.control_id == "Art.11").unwrap();
        assert_eq!(
            art11.status,
            EvidenceStatus::PartiallyEvidenced,
            "Art.11 with 1 event type should be partial, not evidenced"
        );
        assert!(
            art11
                .reason
                .as_ref()
                .unwrap()
                .contains("distinct event types"),
            "reason should mention diversity: {:?}",
            art11.reason
        );
    }

    #[test]
    fn test_all_event_types_control_evidenced_with_diversity() {
        // Art.11 requires min_event_types=4; providing 4+ types should be evidenced
        let fw = get_framework("eu-ai-act").unwrap();
        let mut counts = HashMap::new();
        counts.insert("branch_created".to_string(), 10);
        counts.insert("branch_committed".to_string(), 8);
        counts.insert("policy_violation".to_string(), 3);
        counts.insert("agent_registered".to_string(), 5);
        let controls = evaluate_controls(fw, &counts, &[]);
        let art11 = controls.iter().find(|c| c.control_id == "Art.11").unwrap();
        assert_eq!(
            art11.status,
            EvidenceStatus::Evidenced,
            "Art.11 with 4 event types should be evidenced"
        );
    }

    // -- Per-profile branch stats --

    #[test]
    fn test_branch_stats_per_profile() {
        let records = vec![
            make_record_with_details(
                1,
                "branch_created",
                "b1",
                serde_json::json!({"profile": "restricted"}),
            ),
            make_record_with_details(
                2,
                "branch_created",
                "b2",
                serde_json::json!({"profile": "standard"}),
            ),
            make_record_with_details(
                3,
                "branch_created",
                "b3",
                serde_json::json!({"profile": "restricted"}),
            ),
            make_record_with_branch(4, "branch_committed", "b1"),
            make_record_with_branch(5, "commit_rejected", "b2"),
            make_record_with_branch(6, "branch_rolled_back", "b3"),
        ];
        let stats = compute_branch_stats(&records);
        assert_eq!(stats["branches_created"], 3);

        let per_profile = &stats["per_profile"];
        assert_eq!(per_profile["restricted"]["created"], 2);
        assert_eq!(per_profile["restricted"]["committed"], 1);
        assert_eq!(per_profile["restricted"]["rolled_back"], 1);
        assert_eq!(per_profile["standard"]["created"], 1);
        assert_eq!(per_profile["standard"]["rejected"], 1);
    }

    // -- Violation resolutions --

    #[test]
    fn test_violation_stats_with_resolutions() {
        let records = vec![
            make_violation_record_with_branch(1, "sensitive_file", "b1"),
            make_violation_record_with_branch(2, "size_limit", "b2"),
            make_violation_record_with_branch(3, "sensitive_file", "b3"),
            make_record_with_branch(4, "commit_rejected", "b1"),
            make_record_with_branch(5, "branch_rolled_back", "b2"),
            // b3 has no terminal state — unresolved
        ];
        let stats = compute_violation_stats(&records);
        assert_eq!(stats["total_violations"], 3);
        let res = &stats["resolutions"];
        assert_eq!(res["violation_branches"], 3);
        assert_eq!(res["rejected"], 1);
        assert_eq!(res["rolled_back"], 1);
        assert_eq!(res["unresolved"], 1);
        assert_eq!(res["committed_despite_violation"], 0);
    }

    // -- Helpers --

    fn make_record(seq: u64, event_type: &str) -> AuditRecord {
        AuditRecord {
            seq,
            timestamp: "2026-03-10T10:00:00Z".to_string(),
            event: AuditRecordEvent {
                event_type: event_type.to_string(),
                branch_id: Some("test-branch".to_string()),
                details: serde_json::json!({}),
            },
            ..Default::default()
        }
    }

    fn make_record_with_branch(seq: u64, event_type: &str, branch_id: &str) -> AuditRecord {
        AuditRecord {
            seq,
            timestamp: "2026-03-10T10:00:00Z".to_string(),
            event: AuditRecordEvent {
                event_type: event_type.to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({}),
            },
            ..Default::default()
        }
    }

    fn make_record_with_details(
        seq: u64,
        event_type: &str,
        branch_id: &str,
        details: serde_json::Value,
    ) -> AuditRecord {
        AuditRecord {
            seq,
            timestamp: "2026-03-10T10:00:00Z".to_string(),
            event: AuditRecordEvent {
                event_type: event_type.to_string(),
                branch_id: Some(branch_id.to_string()),
                details,
            },
            ..Default::default()
        }
    }

    fn make_violation_record(seq: u64, reason: &str) -> AuditRecord {
        AuditRecord {
            seq,
            timestamp: "2026-03-10T10:00:00Z".to_string(),
            event: AuditRecordEvent {
                event_type: "policy_violation".to_string(),
                branch_id: Some("test-branch".to_string()),
                details: serde_json::json!({"reason": reason}),
            },
            ..Default::default()
        }
    }

    fn make_violation_record_with_branch(seq: u64, reason: &str, branch_id: &str) -> AuditRecord {
        AuditRecord {
            seq,
            timestamp: "2026-03-10T10:00:00Z".to_string(),
            event: AuditRecordEvent {
                event_type: "policy_violation".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({"reason": reason}),
            },
            ..Default::default()
        }
    }

    fn make_profile_summary(
        name: &str,
        has_exec_allowlist: bool,
        has_read_allowlist: bool,
        has_behavioral: bool,
    ) -> ProfileSummary {
        ProfileSummary {
            profile: name.to_string(),
            filesystem_read_allowlist_entries: if has_read_allowlist { 5 } else { 0 },
            filesystem_write_allowlist_entries: 2,
            exec_allowlist_entries: if has_exec_allowlist { 10 } else { 0 },
            exec_denylist_entries: 3,
            network_mode: "Gated".to_string(),
            fail_mode: "FailClosed".to_string(),
            max_pids: 100,
            memory_bytes: 512 * 1024 * 1024,
            behavioral_max_deletions: if has_behavioral { 50 } else { 0 },
            behavioral_max_reads_per_minute: 1000,
            behavioral_credential_alert: true,
            capabilities_count: 0,
            seccomp_mode: "Permissive".to_string(),
        }
    }

    /// F8: Ensure duration_since(UNIX_EPOCH) calls use .expect() with a
    /// diagnostic message instead of bare .unwrap().
    #[test]
    fn test_f8_system_time_no_bare_unwrap() {
        let source = include_str!("compliance.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // The UNIX_EPOCH and .unwrap() may be on different lines, so we
        // search for the pattern: duration_since(…UNIX_EPOCH…) followed
        // by .unwrap() before any semicolon (i.e., in the same expression).
        let lines: Vec<&str> = prod_source.lines().collect();
        let mut in_duration_since = false;
        for (i, line) in lines.iter().enumerate() {
            if line.contains("UNIX_EPOCH") {
                in_duration_since = true;
            }
            if in_duration_since && line.contains(".unwrap()") {
                panic!(
                    "F8: compliance.rs line {} uses duration_since(UNIX_EPOCH).unwrap() \
                     which panics without a diagnostic message if the system clock is \
                     before the Unix epoch. Use .expect(\"F8: ...\") instead.\nLine: {}",
                    i + 1,
                    line.trim()
                );
            }
            if in_duration_since && line.contains(';') {
                in_duration_since = false;
            }
        }
    }

    /// G26: read_to_string on audit log must have a size check to prevent OOM.
    #[test]
    fn test_g26_audit_log_read_has_size_check() {
        let source = include_str!("compliance.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // Find the load_audit_records function body
        let fn_start = prod_source
            .find("fn load_audit_records")
            .expect("load_audit_records function must exist");
        let fn_block = &prod_source[fn_start..];
        let fn_end = fn_block
            .find("\npub fn ")
            .or_else(|| fn_block.find("\nfn "))
            .unwrap_or(fn_block.len());
        let fn_body = &fn_block[..fn_end];

        // Must contain a size check before reading
        assert!(
            fn_body.contains("metadata") && fn_body.contains("len()"),
            "G26: load_audit_records must check file size via metadata().len() \
             before read_to_string to prevent OOM on large files"
        );
    }

    /// H67: parse_period_secs must reject single-char input with a clear error.
    #[test]
    fn test_h67_parse_period_secs_single_char() {
        let result = parse_period_secs("d");
        assert!(
            result.is_err(),
            "H67: single-char input 'd' should produce an error"
        );
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("period too short"),
            "H67: error message should mention 'period too short', got: {}",
            err_msg
        );
    }

    /// H67: parse_period_secs must reject empty input with a clear error.
    #[test]
    fn test_h67_parse_period_secs_empty() {
        let result = parse_period_secs("");
        assert!(result.is_err(), "H67: empty input should produce an error");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("period too short"),
            "H67: error message should mention 'period too short', got: {}",
            err_msg
        );
    }

    /// H67: parse_period_secs should still parse valid inputs correctly.
    #[test]
    fn test_h67_parse_period_secs_valid() {
        assert_eq!(parse_period_secs("30d").unwrap(), 30 * 86400);
        assert_eq!(parse_period_secs("1y").unwrap(), 31_536_000);
        assert_eq!(parse_period_secs("2w").unwrap(), 2 * 604800);
        assert_eq!(parse_period_secs("3m").unwrap(), 3 * 2_592_000);
    }

    /// F25: Ensure directory entry iteration in profile loading does not use
    /// filter_map(|e| e.ok()) which silently skips errors.
    #[test]
    fn test_f25_dir_entries_not_silently_skipped() {
        let source = include_str!("compliance.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // Find the load_profiles function and check it doesn't use filter_map(|e| e.ok())
        let in_load_profiles = prod_source
            .split("fn load_profiles")
            .nth(1)
            .and_then(|rest| rest.split("\nfn ").next())
            .unwrap_or("");

        assert!(
            !in_load_profiles.contains("filter_map(|e| e.ok())"),
            "F25: load_profiles uses filter_map(|e| e.ok()) which silently skips \
             directory entries that fail to read. Use explicit error handling instead."
        );
    }

    #[test]
    fn j44_parse_rfc3339_approx_rejects_huge_year() {
        // J44: A year value far in the future (or before 1970) must return None
        // instead of looping for millions of iterations.
        assert!(
            parse_rfc3339_approx("9999-12-31T23:59:59Z").is_some(),
            "J44: year 9999 should be valid"
        );
        assert!(
            parse_rfc3339_approx("99999-01-01T00:00:00Z").is_none(),
            "J44: year > 9999 must return None (would cause unbounded loop)"
        );
        assert!(
            parse_rfc3339_approx("1969-12-31T23:59:59Z").is_none(),
            "J44: year < 1970 must return None (pre-epoch)"
        );
        assert!(
            parse_rfc3339_approx("1970-01-01T00:00:00Z").is_some(),
            "J44: year 1970 (epoch) should be valid"
        );
    }

    #[test]
    fn j45_copy_dir_files_does_not_use_filter_map_ok() {
        // J45: copy_dir_files must not silently swallow directory read errors
        // via .filter_map(|e| e.ok()). It should propagate errors.
        let source = include_str!("compliance.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        let in_copy_dir = prod_source
            .split("fn copy_dir_files")
            .nth(1)
            .and_then(|rest| rest.split("\nfn ").next())
            .unwrap_or("");

        assert!(
            !in_copy_dir.contains("filter_map(|e| e.ok())"),
            "J45: copy_dir_files must not use filter_map(|e| e.ok()) — \
             directory read errors must be propagated, not silently swallowed"
        );
    }

    // L1: parse_period_secs must return an error on overflow instead of wrapping
    #[test]
    fn l1_parse_period_secs_overflow() {
        // u64::MAX / 86400 + 1 will overflow when multiplied by 86400
        let huge_days = format!("{}d", u64::MAX / 86400 + 1);
        let result = parse_period_secs(&huge_days);
        assert!(
            result.is_err(),
            "L1: parse_period_secs should return Err on overflow, got {:?}",
            result
        );

        let huge_years = format!("{}y", u64::MAX / 31_536_000 + 1);
        let result = parse_period_secs(&huge_years);
        assert!(
            result.is_err(),
            "L1: parse_period_secs should return Err on overflow for years, got {:?}",
            result
        );
    }

    // L2: parse_rfc3339_approx arithmetic chain must use checked operations
    #[test]
    fn l2_parse_rfc3339_approx_uses_checked_arithmetic() {
        // Verify the function still works correctly at the max valid boundary
        let result = parse_rfc3339_approx("9999-12-31T23:59:59Z");
        assert!(
            result.is_some(),
            "L2: valid max date should parse successfully"
        );

        // L2: Verify that the source code uses checked arithmetic in the
        // final computation (total_days * 86400 + hour * 3600 + ...).
        let source = include_str!("compliance.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // Find the parse_rfc3339_approx function body
        let in_fn = prod_source
            .split("fn parse_rfc3339_approx")
            .nth(1)
            .and_then(|rest| rest.split("\nfn ").next())
            .unwrap_or("");
        assert!(
            in_fn.contains("checked_mul") && in_fn.contains("checked_add"),
            "L2: parse_rfc3339_approx must use checked_mul and checked_add — \
             unchecked arithmetic on user-parsed values risks silent overflow"
        );
    }

    /// M5: Verify attestation path uses a named constant, not hardcoded strings.
    #[test]
    fn test_m5_attestation_path_uses_constant() {
        let source = include_str!("compliance.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // The constant must be defined
        assert!(
            prod_source.contains("DEFAULT_ATTESTATION_DIR"),
            "M5: Must define DEFAULT_ATTESTATION_DIR constant for attestation path"
        );
        // No bare hardcoded "/var/lib/puzzled/attestation" outside the constant definition
        let mut bare_count = 0;
        for (i, line) in prod_source.lines().enumerate() {
            if line.contains("\"/var/lib/puzzled/attestation\"")
                || line.contains("\"/var/lib/puzzled/attestation/")
            {
                // Allow the constant definition line
                if line.contains("const DEFAULT_ATTESTATION_DIR") {
                    continue;
                }
                bare_count += 1;
                eprintln!(
                    "M5: hardcoded attestation path at line {}: {}",
                    i + 1,
                    line.trim()
                );
            }
        }
        assert_eq!(
            bare_count, 0,
            "M5: Found {} hardcoded attestation paths — use DEFAULT_ATTESTATION_DIR",
            bare_count
        );
    }

    /// M6: Verify report_version uses CARGO_PKG_VERSION, not hardcoded "1.0".
    #[test]
    fn test_m6_report_version_not_hardcoded() {
        let source = include_str!("compliance.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // Find the build_metadata function
        let in_fn = prod_source
            .split("fn build_metadata")
            .nth(1)
            .and_then(|rest| rest.split("\nfn ").next())
            .unwrap_or("");
        assert!(
            !in_fn.contains("\"report_version\": \"1.0\""),
            "M6: report_version must use env!(\"CARGO_PKG_VERSION\"), not hardcoded \"1.0\""
        );
    }
}
