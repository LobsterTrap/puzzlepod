// SPDX-License-Identifier: Apache-2.0
use puzzled_types::BranchId;
use serde::Serialize;

// m3: Audit event type code ranges for Linux Audit netlink (PRD 15.1):
//
// Stable (committed API — do not renumber):
//   2600  AgentRegistered      — Agent registered with puzzled
//   2601  BranchCreated        — Branch created
//   2602  BranchCommitted      — Branch committed (governance approved)
//   2603  BranchRolledBack     — Branch rolled back
//   2604  PolicyViolation      — Policy violation detected
//   2605  CommitRejected       — Commit rejected by governance
//
// Unstable (may change until Phase 2 stabilization):
//   2606  NetworkGate          — Network write gated by proxy
//   2607  OomRollback          — Branch rolled back due to OOM
//   2608  TimeoutRollback      — Branch rolled back due to timeout
//   2609  Conflict             — Conflict detected between branches
//   2610  ProfileLoaded        — Agent profile loaded
//   2611  PolicyReloaded       — Policies reloaded
//   2612  BehavioralTrigger    — Behavioral trigger fired
//   2613  SeccompDecision      — Seccomp notification decision
//   2614  WalRecovery          — WAL recovery completed
//   2615  AgentKilled          — Agent killed via D-Bus
//   2616  SandboxEscape        — Sandbox escape detected
//   2617  BranchFrozen         — Branch frozen for commit
//   2618  ExecGated            — Agent exec gated
//   2619  ConnectGated         — Agent connect gated
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_AGENT_REGISTERED: u16 = 2600;
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_BRANCH_CREATED: u16 = 2601;
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_BRANCH_COMMITTED: u16 = 2602;
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_BRANCH_ROLLED_BACK: u16 = 2603;
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_POLICY_VIOLATION: u16 = 2604;
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_COMMIT_REJECTED: u16 = 2605;
// PRD 15.1 event codes 2606-2609: governance lifecycle events
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_NETWORK_GATE: u16 = 2606;
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_OOM_ROLLBACK: u16 = 2607;
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_TIMEOUT_ROLLBACK: u16 = 2608;
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_CONFLICT: u16 = 2609;
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_PROFILE_LOADED: u16 = 2610;
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_POLICY_RELOADED: u16 = 2611;
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_BEHAVIORAL_TRIGGER: u16 = 2612;
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_SECCOMP_DECISION: u16 = 2613;
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_WAL_RECOVERY: u16 = 2614;
/// M-db5: Agent killed by operator via KillAgent D-Bus method.
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_AGENT_KILLED: u16 = 2615;
// Operational events (renumbered from 2606-2609 to 2616+)
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_SANDBOX_ESCAPE: u16 = 2616;
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_BRANCH_FROZEN: u16 = 2617;
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_EXEC_GATED: u16 = 2618;
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_CONNECT_GATED: u16 = 2619;
/// DLP rule blocked a request.
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_DLP_BLOCKED: u16 = 2620;
/// DLP detected content but allowed (LogAndAllow action).
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_DLP_DETECTED: u16 = 2621;
/// DLP rule redacted content from request/response.
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_DLP_REDACTED: u16 = 2622;
/// DLP triggered quarantine (cgroup.freeze).
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_DLP_QUARANTINE: u16 = 2623;
/// Phantom token resolved and credential injected (PRD §3.4).
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_CREDENTIAL_INJECTED: u16 = 2626;
/// Credential injection denied (PRD §3.4).
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_CREDENTIAL_DENIED: u16 = 2627;
/// Credential stored via D-Bus management API (§3.4/Gap44).
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_CREDENTIAL_STORED: u16 = 2628;
/// Credential removed via D-Bus management API (§3.4/Gap44).
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_CREDENTIAL_REMOVED: u16 = 2629;
/// Credential rotated via D-Bus management API (§3.4/Gap44).
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_CREDENTIAL_ROTATED: u16 = 2630;
/// §3.4 G29: Credential provisioned for a branch.
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_CREDENTIAL_PROVISIONED: u16 = 2631;
/// §3.4 G29: Credential resolve failed (backend error, expired, etc.).
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_CREDENTIAL_RESOLVE_FAILED: u16 = 2632;
/// §3.4 G29: Real credential value found in upstream response body.
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_CREDENTIAL_RESPONSE_LEAK: u16 = 2633;
/// §3.4 G29: Credential revoked (branch cleanup).
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_CREDENTIAL_REVOKED: u16 = 2634;
/// §3.4 G29: Proxy bypass attempt detected (direct connection to gateway).
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_CREDENTIAL_BYPASS_ATTEMPT: u16 = 2635;
/// §3.4 G29: Phantom token found in commit changeset.
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_PHANTOM_TOKEN_IN_COMMIT: u16 = 2636;
/// §3.4 G29/F5: Phantom token stripped from response header.
#[cfg(target_os = "linux")]
const AUDIT_PUZZLEPOD_PHANTOM_TOKEN_STRIPPED: u16 = 2637;

/// Audit event types emitted by puzzled.
///
/// Events are logged via `tracing::info!()` (always-on fallback) and optionally
/// sent to the Linux Audit subsystem via netlink when CAP_AUDIT_WRITE is available.
#[derive(Debug, Serialize)]
#[serde(tag = "event_type")]
pub enum AuditEvent {
    /// M20: PRD 15.1 event 2600 — Agent registered with puzzled.
    AgentRegistered {
        agent_id: String,
        profile: String,
    },
    BranchCreated {
        branch_id: BranchId,
        profile: String,
        uid: u32,
    },
    BranchCommitted {
        branch_id: BranchId,
        files: u64,
        bytes: u64,
    },
    BranchRolledBack {
        branch_id: BranchId,
        reason: String,
    },
    PolicyViolation {
        branch_id: BranchId,
        rule: String,
        message: String,
    },
    /// M20: PRD 15.1 event 2605 — Commit rejected by governance policy.
    CommitRejected {
        branch_id: BranchId,
        reason: String,
    },
    SandboxEscape {
        branch_id: BranchId,
        detail: String,
    },
    BranchFrozen {
        branch_id: BranchId,
    },
    AgentExecGated {
        branch_id: BranchId,
        path: String,
        allowed: bool,
    },
    AgentConnectGated {
        branch_id: BranchId,
        address: String,
        allowed: bool,
    },
    ProfileLoaded {
        profile: String,
    },
    PolicyReloaded {
        policies_loaded: u32,
    },
    BehavioralTrigger {
        branch_id: BranchId,
        trigger: String,
    },
    SeccompDecision {
        branch_id: BranchId,
        syscall: String,
        allowed: bool,
    },
    WalRecovery {
        branches_recovered: u32,
    },
    /// M-db5: Emitted when an agent is killed via KillAgent D-Bus method.
    AgentKilled {
        branch_id: BranchId,
        caller_uid: u32,
    },
    /// PRD 15.1 event 2606 — Network write operation gated by proxy.
    NetworkGate {
        branch_id: BranchId,
        address: String,
        method: String,
        allowed: bool,
    },
    /// PRD 15.1 event 2607 — Branch rolled back due to OOM kill.
    OomRollback {
        branch_id: BranchId,
    },
    /// PRD 15.1 event 2608 — Branch rolled back due to timeout.
    TimeoutRollback {
        branch_id: BranchId,
        timeout_seconds: u64,
    },
    /// PRD 15.1 event 2609 — Conflict detected between branches.
    Conflict {
        branch_id: BranchId,
        conflicting_branch: String,
        paths: Vec<String>,
    },
    /// DLP rule blocked a request.
    DlpBlocked {
        branch_id: BranchId,
        rule_name: String,
        domain: String,
        direction: String,
    },
    /// DLP rule redacted content from request/response.
    DlpRedacted {
        branch_id: BranchId,
        rule_name: String,
        redactions: u32,
    },
    /// DLP triggered quarantine (cgroup.freeze).
    DlpQuarantine {
        branch_id: BranchId,
        rule_name: String,
        domain: String,
    },
    /// DLP detected content but allowed per LogAndAllow action.
    DlpDetected {
        branch_id: BranchId,
        rule_name: String,
        domain: String,
        match_count: u32,
    },
    /// Phantom token resolved and credential injected.
    /// Logs credential name (NOT value) and target domain per PRD §3.4.
    CredentialInjected {
        branch_id: BranchId,
        credential_name: String,
        domain: String,
    },
    /// Credential injection denied (invalid token, domain mismatch, etc.).
    CredentialDenied {
        branch_id: BranchId,
        credential_name: String,
        domain: String,
        reason: String,
    },
    /// §3.4/Gap44: Credential stored via D-Bus management API.
    CredentialStored {
        credential_name: String,
        caller_uid: u32,
    },
    /// §3.4/Gap44: Credential removed via D-Bus management API.
    CredentialRemoved {
        credential_name: String,
        caller_uid: u32,
    },
    /// §3.4/Gap44: Credential rotated via D-Bus management API.
    CredentialRotated {
        credential_name: String,
        caller_uid: u32,
    },
    /// §3.4 G29: Credentials provisioned for a branch.
    CredentialProvisioned {
        branch_id: BranchId,
        credential_count: usize,
    },
    /// §3.4 G29: Credential resolve failed (phantom token could not be swapped).
    CredentialResolveFailed {
        branch_id: BranchId,
        credential_name: String,
        reason: String,
    },
    /// §3.4 G29: Real credential value detected in upstream response body.
    CredentialResponseLeak {
        branch_id: BranchId,
        domain: String,
    },
    /// §3.4 G29: All credentials revoked for a branch (cleanup).
    CredentialRevoked {
        branch_id: BranchId,
    },
    /// §3.4 G29: Phantom token stripped from request (defense-in-depth).
    PhantomTokenStripped {
        branch_id: BranchId,
        header_name: String,
    },
    /// §3.4 G29: Agent attempted to bypass proxy (direct gateway connection).
    CredentialBypassAttempt {
        branch_id: BranchId,
        target_ip: String,
        target_port: u16,
    },
    /// §3.4 G29: Phantom token found in commit changeset (data leak).
    PhantomTokenInCommit {
        branch_id: BranchId,
        file_path: String,
    },
}

/// M4: Sanitize a user-provided field for safe inclusion in audit/tracing output.
/// Replaces characters that could enable log injection:
/// - `"` (quote) — could break field delimiters
/// - `\n`, `\r` — could inject new log lines
/// - `=` — could inject fake key=value pairs
/// - All control characters (0x00-0x1F, 0x7F) — could confuse log parsers
/// - Non-printable ASCII — could confuse log parsers
///
/// Also validates and replaces invalid UTF-8 replacement characters.
///
/// This is a module-level function so it can be used by both the tracing
/// fallback and the Linux Audit netlink backend.
fn sanitize_audit_field(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '"'
                || c == '='
                || c.is_control()
                || c == '\u{FFFD}'
                || (!c.is_ascii_graphic() && c != ' ' && !c.is_alphanumeric())
            {
                '_'
            } else {
                c
            }
        })
        .collect()
}

/// Audit subsystem — emits structured events via tracing, with optional
/// Linux Audit netlink backend.
pub struct AuditLogger {
    /// Linux Audit netlink socket (if available).
    #[cfg(target_os = "linux")]
    netlink: Option<NetlinkAudit>,
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLogger {
    pub fn new() -> Self {
        #[cfg(target_os = "linux")]
        {
            let netlink = match NetlinkAudit::connect() {
                Ok(nl) => {
                    tracing::info!("Linux Audit netlink connected");
                    Some(nl)
                }
                Err(e) => {
                    tracing::info!(
                        error = %e,
                        "Linux Audit netlink unavailable (using tracing fallback only)"
                    );
                    None
                }
            };
            Self { netlink }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self {}
        }
    }

    /// Emit an audit event via tracing and optionally Linux Audit netlink.
    pub fn log(&self, event: AuditEvent) {
        // Always log via tracing (syslog-compatible)
        self.log_tracing(&event);

        // On Linux, also send via netlink if available
        #[cfg(target_os = "linux")]
        if let Some(nl) = &self.netlink {
            if let Err(e) = nl.send_event(&event) {
                tracing::warn!(error = %e, "failed to send audit event via netlink");
            }
        }
    }

    /// M4: All user-controlled fields are sanitized via `sanitize_audit_field()`
    /// before being included in tracing output, preventing log injection attacks
    /// through the tracing/journal code path (not just the netlink path).
    fn log_tracing(&self, event: &AuditEvent) {
        match event {
            AuditEvent::AgentRegistered { agent_id, profile } => {
                tracing::info!(
                    audit_type = "agent_registered",
                    agent_id = %sanitize_audit_field(agent_id),
                    profile = %sanitize_audit_field(profile),
                    "audit: agent registered"
                );
            }
            AuditEvent::BranchCreated {
                branch_id,
                profile,
                uid,
            } => {
                tracing::info!(
                    audit_type = "branch_created",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    profile = %sanitize_audit_field(profile),
                    uid = uid,
                    "audit: branch created"
                );
            }
            AuditEvent::BranchCommitted {
                branch_id,
                files,
                bytes,
            } => {
                tracing::info!(
                    audit_type = "branch_committed",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    files = files,
                    bytes = bytes,
                    "audit: branch committed"
                );
            }
            AuditEvent::BranchRolledBack { branch_id, reason } => {
                tracing::info!(
                    audit_type = "branch_rolled_back",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    reason = %sanitize_audit_field(reason),
                    "audit: branch rolled back"
                );
            }
            AuditEvent::PolicyViolation {
                branch_id,
                rule,
                message,
            } => {
                tracing::warn!(
                    audit_type = "policy_violation",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    rule = %sanitize_audit_field(rule),
                    message = %sanitize_audit_field(message),
                    "audit: policy violation"
                );
            }
            AuditEvent::CommitRejected { branch_id, reason } => {
                tracing::warn!(
                    audit_type = "commit_rejected",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    reason = %sanitize_audit_field(reason),
                    "audit: commit rejected"
                );
            }
            AuditEvent::SandboxEscape { branch_id, detail } => {
                tracing::error!(
                    audit_type = "sandbox_escape",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    detail = %sanitize_audit_field(detail),
                    "audit: sandbox escape detected"
                );
            }
            AuditEvent::BranchFrozen { branch_id } => {
                tracing::info!(
                    audit_type = "branch_frozen",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    "audit: branch frozen for commit"
                );
            }
            AuditEvent::AgentExecGated {
                branch_id,
                path,
                allowed,
            } => {
                tracing::info!(
                    audit_type = "agent_exec_gated",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    path = %sanitize_audit_field(path),
                    allowed = allowed,
                    "audit: agent exec gated"
                );
            }
            AuditEvent::AgentConnectGated {
                branch_id,
                address,
                allowed,
            } => {
                tracing::info!(
                    audit_type = "agent_connect_gated",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    address = %sanitize_audit_field(address),
                    allowed = allowed,
                    "audit: agent connect gated"
                );
            }
            AuditEvent::ProfileLoaded { profile } => {
                tracing::info!(
                    audit_type = "profile_loaded",
                    profile = %sanitize_audit_field(profile),
                    "audit: profile loaded"
                );
            }
            AuditEvent::PolicyReloaded { policies_loaded } => {
                tracing::info!(
                    audit_type = "policy_reloaded",
                    policies_loaded = policies_loaded,
                    "audit: policies reloaded"
                );
            }
            AuditEvent::BehavioralTrigger { branch_id, trigger } => {
                tracing::warn!(
                    audit_type = "behavioral_trigger",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    trigger = %sanitize_audit_field(trigger),
                    "audit: behavioral trigger fired"
                );
            }
            AuditEvent::SeccompDecision {
                branch_id,
                syscall,
                allowed,
            } => {
                tracing::info!(
                    audit_type = "seccomp_decision",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    syscall = %sanitize_audit_field(syscall),
                    allowed = allowed,
                    "audit: seccomp decision"
                );
            }
            AuditEvent::WalRecovery { branches_recovered } => {
                tracing::info!(
                    audit_type = "wal_recovery",
                    branches_recovered = branches_recovered,
                    "audit: WAL recovery completed"
                );
            }
            AuditEvent::AgentKilled {
                branch_id,
                caller_uid,
            } => {
                // R3: sanitize branch_id to match all other event variants
                tracing::info!(
                    audit_type = "agent_killed",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    caller_uid = caller_uid,
                    "audit: agent killed"
                );
            }
            AuditEvent::NetworkGate {
                branch_id,
                address,
                method,
                allowed,
            } => {
                tracing::info!(
                    audit_type = "network_gate",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    address = %sanitize_audit_field(address),
                    method = %sanitize_audit_field(method),
                    allowed = allowed,
                    "audit: network write gated"
                );
            }
            AuditEvent::OomRollback { branch_id } => {
                tracing::warn!(
                    audit_type = "oom_rollback",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    "audit: branch rolled back due to OOM"
                );
            }
            AuditEvent::TimeoutRollback {
                branch_id,
                timeout_seconds,
            } => {
                tracing::warn!(
                    audit_type = "timeout_rollback",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    timeout_seconds = timeout_seconds,
                    "audit: branch rolled back due to timeout"
                );
            }
            AuditEvent::Conflict {
                branch_id,
                conflicting_branch,
                paths,
            } => {
                tracing::warn!(
                    audit_type = "conflict",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    conflicting_branch = %sanitize_audit_field(conflicting_branch),
                    path_count = paths.len(),
                    "audit: conflict detected between branches"
                );
            }
            AuditEvent::DlpBlocked {
                branch_id,
                rule_name,
                domain,
                direction,
            } => {
                tracing::warn!(
                    audit_type = "dlp_blocked",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    rule_name = %sanitize_audit_field(rule_name),
                    domain = %sanitize_audit_field(domain),
                    direction = %sanitize_audit_field(direction),
                    "audit: DLP rule blocked request"
                );
            }
            AuditEvent::DlpRedacted {
                branch_id,
                rule_name,
                redactions,
            } => {
                tracing::warn!(
                    audit_type = "dlp_redacted",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    rule_name = %sanitize_audit_field(rule_name),
                    redactions = redactions,
                    "audit: DLP rule redacted content"
                );
            }
            AuditEvent::DlpQuarantine {
                branch_id,
                rule_name,
                domain,
            } => {
                tracing::error!(
                    audit_type = "dlp_quarantine",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    rule_name = %sanitize_audit_field(rule_name),
                    domain = %sanitize_audit_field(domain),
                    "audit: DLP triggered quarantine"
                );
            }
            AuditEvent::DlpDetected {
                branch_id,
                rule_name,
                domain,
                match_count,
            } => {
                tracing::info!(
                    audit_type = "dlp_detected",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    rule_name = %sanitize_audit_field(rule_name),
                    domain = %sanitize_audit_field(domain),
                    match_count = match_count,
                    "audit: DLP detected content (allowed)"
                );
            }
            AuditEvent::CredentialInjected {
                branch_id,
                credential_name,
                domain,
            } => {
                tracing::info!(
                    audit_type = "credential_injected",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    credential_name = %sanitize_audit_field(credential_name),
                    domain = %sanitize_audit_field(domain),
                    "audit: credential injected"
                );
            }
            AuditEvent::CredentialDenied {
                branch_id,
                credential_name,
                domain,
                reason,
            } => {
                tracing::info!(
                    audit_type = "credential_denied",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    credential_name = %sanitize_audit_field(credential_name),
                    domain = %sanitize_audit_field(domain),
                    reason = %sanitize_audit_field(reason),
                    "audit: credential injection denied"
                );
            }
            AuditEvent::CredentialStored {
                credential_name,
                caller_uid,
            } => {
                tracing::info!(
                    audit_type = "credential_stored",
                    credential_name = %sanitize_audit_field(credential_name),
                    caller_uid = caller_uid,
                    "audit: credential stored"
                );
            }
            AuditEvent::CredentialRemoved {
                credential_name,
                caller_uid,
            } => {
                tracing::info!(
                    audit_type = "credential_removed",
                    credential_name = %sanitize_audit_field(credential_name),
                    caller_uid = caller_uid,
                    "audit: credential removed"
                );
            }
            AuditEvent::CredentialRotated {
                credential_name,
                caller_uid,
            } => {
                tracing::info!(
                    audit_type = "credential_rotated",
                    credential_name = %sanitize_audit_field(credential_name),
                    caller_uid = caller_uid,
                    "audit: credential rotated"
                );
            }
            // §3.4 G29: Extended credential audit events
            AuditEvent::CredentialProvisioned {
                branch_id,
                credential_count,
            } => {
                tracing::info!(
                    audit_type = "credential_provisioned",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    credential_count = credential_count,
                    "audit: credentials provisioned for branch"
                );
            }
            AuditEvent::CredentialResolveFailed {
                branch_id,
                credential_name,
                reason,
            } => {
                tracing::warn!(
                    audit_type = "credential_resolve_failed",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    credential_name = %sanitize_audit_field(credential_name),
                    reason = %sanitize_audit_field(reason),
                    "audit: credential resolve failed"
                );
            }
            AuditEvent::CredentialResponseLeak { branch_id, domain } => {
                tracing::error!(
                    audit_type = "credential_response_leak",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    domain = %sanitize_audit_field(domain),
                    "audit: CRITICAL — real credential value detected in upstream response"
                );
            }
            AuditEvent::CredentialRevoked { branch_id } => {
                tracing::info!(
                    audit_type = "credential_revoked",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    "audit: credentials revoked for branch"
                );
            }
            AuditEvent::PhantomTokenStripped {
                branch_id,
                header_name,
            } => {
                tracing::info!(
                    audit_type = "phantom_token_stripped",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    header_name = %sanitize_audit_field(header_name),
                    "audit: phantom token stripped from request"
                );
            }
            AuditEvent::CredentialBypassAttempt {
                branch_id,
                target_ip,
                target_port,
            } => {
                tracing::error!(
                    audit_type = "credential_bypass_attempt",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    target_ip = %sanitize_audit_field(target_ip),
                    target_port = target_port,
                    "audit: CRITICAL — proxy bypass attempt detected"
                );
            }
            AuditEvent::PhantomTokenInCommit {
                branch_id,
                file_path,
            } => {
                tracing::error!(
                    audit_type = "phantom_token_in_commit",
                    branch_id = %sanitize_audit_field(branch_id.as_str()),
                    file_path = %sanitize_audit_field(file_path),
                    "audit: phantom token found in commit changeset"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Linux Audit netlink backend
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
struct NetlinkAudit {
    fd: i32,
}

#[cfg(target_os = "linux")]
impl NetlinkAudit {
    /// Open a netlink audit socket.
    ///
    /// Requires CAP_AUDIT_WRITE capability.
    fn connect() -> std::result::Result<Self, String> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_AUDIT,
            )
        };

        if fd < 0 {
            return Err(format!(
                "socket(AF_NETLINK, NETLINK_AUDIT) failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Bind to the netlink socket
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        // M10: Use nl_pid = 0 to let the kernel assign a unique port ID.
        // Using std::process::id() can conflict with other netlink sockets
        // in the same process (e.g., from libraries or other subsystems).
        addr.nl_pid = 0;

        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(format!(
                "bind(NETLINK_AUDIT) failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(Self { fd })
    }

    /// Send an audit event via the netlink socket.
    fn send_event(&self, event: &AuditEvent) -> std::result::Result<(), String> {
        let (type_code, message) = match event {
            AuditEvent::AgentRegistered { agent_id, profile } => (
                AUDIT_PUZZLEPOD_AGENT_REGISTERED,
                format!(
                    "puzzlepod agent_registered agent_id={} profile={}",
                    sanitize_audit_field(agent_id),
                    sanitize_audit_field(profile)
                ),
            ),
            AuditEvent::BranchCreated {
                branch_id,
                profile,
                uid,
            } => (
                AUDIT_PUZZLEPOD_BRANCH_CREATED,
                format!(
                    "puzzlepod branch_created branch_id={} profile={} uid={}",
                    sanitize_audit_field(branch_id.as_str()),
                    sanitize_audit_field(profile),
                    uid
                ),
            ),
            AuditEvent::BranchCommitted {
                branch_id,
                files,
                bytes,
            } => (
                AUDIT_PUZZLEPOD_BRANCH_COMMITTED,
                format!(
                    "puzzlepod branch_committed branch_id={} files={} bytes={}",
                    sanitize_audit_field(branch_id.as_str()),
                    files,
                    bytes
                ),
            ),
            AuditEvent::BranchRolledBack { branch_id, reason } => (
                AUDIT_PUZZLEPOD_BRANCH_ROLLED_BACK,
                format!(
                    "puzzlepod branch_rolled_back branch_id={} reason=\"{}\"",
                    sanitize_audit_field(branch_id.as_str()),
                    sanitize_audit_field(reason)
                ),
            ),
            AuditEvent::PolicyViolation {
                branch_id,
                rule,
                message,
            } => (
                AUDIT_PUZZLEPOD_POLICY_VIOLATION,
                format!(
                    "puzzlepod policy_violation branch_id={} rule=\"{}\" message=\"{}\"",
                    sanitize_audit_field(branch_id.as_str()),
                    sanitize_audit_field(rule),
                    sanitize_audit_field(message)
                ),
            ),
            AuditEvent::CommitRejected { branch_id, reason } => (
                AUDIT_PUZZLEPOD_COMMIT_REJECTED,
                format!(
                    "puzzlepod commit_rejected branch_id={} reason=\"{}\"",
                    sanitize_audit_field(branch_id.as_str()),
                    sanitize_audit_field(reason)
                ),
            ),
            AuditEvent::SandboxEscape { branch_id, detail } => (
                AUDIT_PUZZLEPOD_SANDBOX_ESCAPE,
                format!(
                    "puzzlepod sandbox_escape branch_id={} detail=\"{}\"",
                    sanitize_audit_field(branch_id.as_str()),
                    sanitize_audit_field(detail)
                ),
            ),
            AuditEvent::BranchFrozen { branch_id } => (
                AUDIT_PUZZLEPOD_BRANCH_FROZEN,
                format!(
                    "puzzlepod branch_frozen branch_id={}",
                    sanitize_audit_field(branch_id.as_str())
                ),
            ),
            AuditEvent::AgentExecGated {
                branch_id,
                path,
                allowed,
            } => (
                AUDIT_PUZZLEPOD_EXEC_GATED,
                format!(
                    "puzzlepod exec_gated branch_id={} path=\"{}\" allowed={}",
                    sanitize_audit_field(branch_id.as_str()),
                    sanitize_audit_field(path),
                    allowed
                ),
            ),
            AuditEvent::AgentConnectGated {
                branch_id,
                address,
                allowed,
            } => (
                AUDIT_PUZZLEPOD_CONNECT_GATED,
                format!(
                    "puzzlepod connect_gated branch_id={} address=\"{}\" allowed={}",
                    sanitize_audit_field(branch_id.as_str()),
                    sanitize_audit_field(address),
                    allowed
                ),
            ),
            AuditEvent::ProfileLoaded { profile } => (
                AUDIT_PUZZLEPOD_PROFILE_LOADED,
                format!(
                    "puzzlepod profile_loaded profile={}",
                    sanitize_audit_field(profile)
                ),
            ),
            AuditEvent::PolicyReloaded { policies_loaded } => (
                AUDIT_PUZZLEPOD_POLICY_RELOADED,
                format!(
                    "puzzlepod policy_reloaded policies_loaded={}",
                    policies_loaded
                ),
            ),
            AuditEvent::BehavioralTrigger { branch_id, trigger } => (
                AUDIT_PUZZLEPOD_BEHAVIORAL_TRIGGER,
                format!(
                    "puzzlepod behavioral_trigger branch_id={} trigger=\"{}\"",
                    sanitize_audit_field(branch_id.as_str()),
                    sanitize_audit_field(trigger)
                ),
            ),
            AuditEvent::SeccompDecision {
                branch_id,
                syscall,
                allowed,
            } => (
                AUDIT_PUZZLEPOD_SECCOMP_DECISION,
                format!(
                    "puzzlepod seccomp_decision branch_id={} syscall=\"{}\" allowed={}",
                    sanitize_audit_field(branch_id.as_str()),
                    sanitize_audit_field(syscall),
                    allowed
                ),
            ),
            AuditEvent::WalRecovery { branches_recovered } => (
                AUDIT_PUZZLEPOD_WAL_RECOVERY,
                format!(
                    "puzzlepod wal_recovery branches_recovered={}",
                    branches_recovered
                ),
            ),
            AuditEvent::AgentKilled {
                branch_id,
                caller_uid,
            } => (
                AUDIT_PUZZLEPOD_AGENT_KILLED,
                format!(
                    "puzzlepod agent_killed branch_id={} caller_uid={}",
                    sanitize_audit_field(&branch_id.to_string()),
                    caller_uid
                ),
            ),
            AuditEvent::NetworkGate {
                branch_id,
                address,
                method,
                allowed,
            } => (
                AUDIT_PUZZLEPOD_NETWORK_GATE,
                format!(
                    "puzzlepod network_gate branch_id={} address=\"{}\" method=\"{}\" allowed={}",
                    sanitize_audit_field(branch_id.as_str()),
                    sanitize_audit_field(address),
                    sanitize_audit_field(method),
                    allowed
                ),
            ),
            AuditEvent::OomRollback { branch_id } => (
                AUDIT_PUZZLEPOD_OOM_ROLLBACK,
                format!(
                    "puzzlepod oom_rollback branch_id={}",
                    sanitize_audit_field(branch_id.as_str())
                ),
            ),
            AuditEvent::TimeoutRollback {
                branch_id,
                timeout_seconds,
            } => (
                AUDIT_PUZZLEPOD_TIMEOUT_ROLLBACK,
                format!(
                    "puzzlepod timeout_rollback branch_id={} timeout_seconds={}",
                    sanitize_audit_field(branch_id.as_str()),
                    timeout_seconds
                ),
            ),
            AuditEvent::Conflict {
                branch_id,
                conflicting_branch,
                paths,
            } => (
                AUDIT_PUZZLEPOD_CONFLICT,
                format!(
                    "puzzlepod conflict branch_id={} conflicting_branch=\"{}\" path_count={}",
                    sanitize_audit_field(branch_id.as_str()),
                    sanitize_audit_field(conflicting_branch),
                    paths.len()
                ),
            ),
            AuditEvent::DlpBlocked {
                branch_id,
                rule_name,
                domain,
                direction,
            } => (
                AUDIT_PUZZLEPOD_DLP_BLOCKED,
                format!(
                    "puzzlepod dlp_blocked branch_id={} rule_name=\"{}\" domain=\"{}\" direction={}",
                    sanitize_audit_field(branch_id.as_str()),
                    sanitize_audit_field(rule_name),
                    sanitize_audit_field(domain),
                    sanitize_audit_field(direction)
                ),
            ),
            AuditEvent::DlpRedacted {
                branch_id,
                rule_name,
                redactions,
            } => (
                AUDIT_PUZZLEPOD_DLP_REDACTED,
                format!(
                    "puzzlepod dlp_redacted branch_id={} rule_name=\"{}\" redactions={}",
                    sanitize_audit_field(branch_id.as_str()),
                    sanitize_audit_field(rule_name),
                    redactions
                ),
            ),
            AuditEvent::DlpQuarantine {
                branch_id,
                rule_name,
                domain,
            } => (
                AUDIT_PUZZLEPOD_DLP_QUARANTINE,
                format!(
                    "puzzlepod dlp_quarantine branch_id={} rule_name=\"{}\" domain=\"{}\"",
                    sanitize_audit_field(branch_id.as_str()),
                    sanitize_audit_field(rule_name),
                    sanitize_audit_field(domain)
                ),
            ),
            AuditEvent::DlpDetected {
                branch_id,
                rule_name,
                domain,
                match_count,
            } => (
                AUDIT_PUZZLEPOD_DLP_DETECTED,
                format!(
                    "puzzlepod dlp_detected branch_id={} rule_name=\"{}\" domain=\"{}\" match_count={}",
                    sanitize_audit_field(branch_id.as_str()),
                    sanitize_audit_field(rule_name),
                    sanitize_audit_field(domain),
                    match_count
                ),
            ),
            AuditEvent::CredentialInjected {
                branch_id,
                credential_name,
                domain,
            } => (
                AUDIT_PUZZLEPOD_CREDENTIAL_INJECTED,
                format!(
                    "puzzlepod credential_injected branch_id={} credential_name=\"{}\" domain=\"{}\"",
                    sanitize_audit_field(branch_id.as_str()),
                    sanitize_audit_field(credential_name),
                    sanitize_audit_field(domain)
                ),
            ),
            AuditEvent::CredentialDenied {
                branch_id,
                credential_name,
                domain,
                reason,
            } => (
                AUDIT_PUZZLEPOD_CREDENTIAL_DENIED,
                format!(
                    "puzzlepod credential_denied branch_id={} credential_name=\"{}\" domain=\"{}\" reason=\"{}\"",
                    sanitize_audit_field(branch_id.as_str()),
                    sanitize_audit_field(credential_name),
                    sanitize_audit_field(domain),
                    sanitize_audit_field(reason)
                ),
            ),
            AuditEvent::CredentialStored {
                credential_name,
                caller_uid,
            } => (
                AUDIT_PUZZLEPOD_CREDENTIAL_STORED,
                format!(
                    "puzzlepod credential_stored credential_name=\"{}\" caller_uid={}",
                    sanitize_audit_field(credential_name),
                    caller_uid
                ),
            ),
            AuditEvent::CredentialRemoved {
                credential_name,
                caller_uid,
            } => (
                AUDIT_PUZZLEPOD_CREDENTIAL_REMOVED,
                format!(
                    "puzzlepod credential_removed credential_name=\"{}\" caller_uid={}",
                    sanitize_audit_field(credential_name),
                    caller_uid
                ),
            ),
            AuditEvent::CredentialRotated {
                credential_name,
                caller_uid,
            } => (
                AUDIT_PUZZLEPOD_CREDENTIAL_ROTATED,
                format!(
                    "puzzlepod credential_rotated credential_name=\"{}\" caller_uid={}",
                    sanitize_audit_field(credential_name),
                    caller_uid
                ),
            ),
            // §3.4 G29: Extended credential audit events
            AuditEvent::CredentialProvisioned { branch_id, credential_count } => (
                AUDIT_PUZZLEPOD_CREDENTIAL_PROVISIONED,
                format!(
                    "puzzlepod credential_provisioned branch_id={} credential_count={}",
                    sanitize_audit_field(branch_id.as_str()),
                    credential_count
                ),
            ),
            AuditEvent::CredentialResolveFailed { branch_id, credential_name, reason } => (
                AUDIT_PUZZLEPOD_CREDENTIAL_RESOLVE_FAILED,
                format!(
                    "puzzlepod credential_resolve_failed branch_id={} credential_name=\"{}\" reason=\"{}\"",
                    sanitize_audit_field(branch_id.as_str()),
                    sanitize_audit_field(credential_name),
                    sanitize_audit_field(reason)
                ),
            ),
            AuditEvent::CredentialResponseLeak { branch_id, domain } => (
                AUDIT_PUZZLEPOD_CREDENTIAL_RESPONSE_LEAK,
                format!(
                    "puzzlepod credential_response_leak branch_id={} domain=\"{}\"",
                    sanitize_audit_field(branch_id.as_str()),
                    sanitize_audit_field(domain)
                ),
            ),
            AuditEvent::CredentialRevoked { branch_id } => (
                AUDIT_PUZZLEPOD_CREDENTIAL_REVOKED,
                format!(
                    "puzzlepod credential_revoked branch_id={}",
                    sanitize_audit_field(branch_id.as_str())
                ),
            ),
            AuditEvent::PhantomTokenStripped { branch_id, header_name } => (
                AUDIT_PUZZLEPOD_PHANTOM_TOKEN_STRIPPED, // F5: unique audit code
                format!(
                    "puzzlepod phantom_token_stripped branch_id={} header_name=\"{}\"",
                    sanitize_audit_field(branch_id.as_str()),
                    sanitize_audit_field(header_name)
                ),
            ),
            AuditEvent::CredentialBypassAttempt { branch_id, target_ip, target_port } => (
                AUDIT_PUZZLEPOD_CREDENTIAL_BYPASS_ATTEMPT,
                format!(
                    "puzzlepod credential_bypass_attempt branch_id={} target_ip=\"{}\" target_port={}",
                    sanitize_audit_field(branch_id.as_str()),
                    sanitize_audit_field(target_ip),
                    target_port
                ),
            ),
            AuditEvent::PhantomTokenInCommit { branch_id, file_path } => (
                AUDIT_PUZZLEPOD_PHANTOM_TOKEN_IN_COMMIT,
                format!(
                    "puzzlepod phantom_token_in_commit branch_id={} file_path=\"{}\"",
                    sanitize_audit_field(branch_id.as_str()),
                    sanitize_audit_field(file_path)
                ),
            ),
        };

        self.send_raw(type_code, &message)
    }

    /// Send a raw audit message via netlink.
    fn send_raw(&self, msg_type: u16, message: &str) -> std::result::Result<(), String> {
        // Audit netlink message format:
        // nlmsghdr + audit message string (null-terminated)
        let msg_bytes = message.as_bytes();
        let nlmsg_len = std::mem::size_of::<libc::nlmsghdr>() + msg_bytes.len() + 1;

        // F27: Bounds check before u32 cast to prevent truncation on huge messages.
        debug_assert!(
            nlmsg_len <= u32::MAX as usize,
            "F27: audit message too large for nlmsg_len"
        );
        if nlmsg_len > u32::MAX as usize {
            return Err("F27: audit message too large for nlmsg_len".into());
        }

        let mut buf = vec![0u8; nlmsg_len];

        // H51: Write nlmsghdr fields byte-by-byte using to_ne_bytes() to avoid
        // alignment assumptions. Vec<u8> is only guaranteed 1-byte alignment,
        // but nlmsghdr requires 4-byte alignment. Using field-level writes
        // instead of a pointer cast avoids undefined behavior.
        let nlmsg_len_bytes = (nlmsg_len as u32).to_ne_bytes();
        let nlmsg_type_bytes = msg_type.to_ne_bytes();
        let nlmsg_flags_bytes = (libc::NLM_F_REQUEST as u16).to_ne_bytes();
        // nlmsg_seq and nlmsg_pid are 0, already zero-initialized in buf

        buf[0..4].copy_from_slice(&nlmsg_len_bytes);
        buf[4..6].copy_from_slice(&nlmsg_type_bytes);
        buf[6..8].copy_from_slice(&nlmsg_flags_bytes);
        // bytes 8..12 = nlmsg_seq = 0 (already zeroed)
        // bytes 12..16 = nlmsg_pid = 0 (already zeroed)

        // Copy message after header
        let payload_offset = std::mem::size_of::<libc::nlmsghdr>();
        buf[payload_offset..payload_offset + msg_bytes.len()].copy_from_slice(msg_bytes);
        // Null terminator is already 0 from vec initialization

        let ret = unsafe { libc::send(self.fd, buf.as_ptr() as *const libc::c_void, nlmsg_len, 0) };

        if ret < 0 {
            return Err(format!(
                "send(NETLINK_AUDIT) failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for NetlinkAudit {
    fn drop(&mut self) {
        // G21: Guard against double-close by checking fd validity and
        // setting fd = -1 after close.
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
            self.fd = -1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn test_branch_id() -> BranchId {
        BranchId::from("test-branch-001".to_string())
    }

    #[test]
    fn test_audit_logger_new() {
        // On non-Linux (macOS), this should succeed without netlink.
        // On Linux, it will attempt netlink and fall back gracefully.
        let _logger = AuditLogger::new();
    }

    #[test]
    fn test_audit_event_serialization() {
        let events: Vec<AuditEvent> = vec![
            AuditEvent::BranchCreated {
                branch_id: test_branch_id(),
                profile: "standard".to_string(),
                uid: 1000,
            },
            AuditEvent::BranchCommitted {
                branch_id: test_branch_id(),
                files: 42,
                bytes: 8192,
            },
            AuditEvent::BranchRolledBack {
                branch_id: test_branch_id(),
                reason: "test rollback".to_string(),
            },
            AuditEvent::PolicyViolation {
                branch_id: test_branch_id(),
                rule: "no_credentials".to_string(),
                message: "found .env file".to_string(),
            },
            AuditEvent::SandboxEscape {
                branch_id: test_branch_id(),
                detail: "ptrace attempt".to_string(),
            },
            AuditEvent::BranchFrozen {
                branch_id: test_branch_id(),
            },
            AuditEvent::AgentExecGated {
                branch_id: test_branch_id(),
                path: "/usr/bin/curl".to_string(),
                allowed: false,
            },
            AuditEvent::AgentConnectGated {
                branch_id: test_branch_id(),
                address: "10.0.0.1:443".to_string(),
                allowed: true,
            },
            AuditEvent::ProfileLoaded {
                profile: "restricted".to_string(),
            },
            AuditEvent::PolicyReloaded { policies_loaded: 5 },
            AuditEvent::AgentRegistered {
                agent_id: "agent-001".to_string(),
                profile: "standard".to_string(),
            },
            AuditEvent::CommitRejected {
                branch_id: test_branch_id(),
                reason: "policy violation".to_string(),
            },
            AuditEvent::DlpBlocked {
                branch_id: test_branch_id(),
                rule_name: "block_api_keys".to_string(),
                domain: "api.example.com".to_string(),
                direction: "request".to_string(),
            },
            AuditEvent::DlpRedacted {
                branch_id: test_branch_id(),
                rule_name: "redact_ssn".to_string(),
                redactions: 3,
            },
            AuditEvent::DlpQuarantine {
                branch_id: test_branch_id(),
                rule_name: "exfiltration_detected".to_string(),
                domain: "evil.example.com".to_string(),
            },
            AuditEvent::DlpDetected {
                branch_id: test_branch_id(),
                rule_name: "detect_pii_email".to_string(),
                domain: "api.example.com".to_string(),
                match_count: 2,
            },
            AuditEvent::CredentialInjected {
                branch_id: test_branch_id(),
                credential_name: "anthropic-api-key".to_string(),
                domain: "api.example.com".to_string(),
            },
            AuditEvent::CredentialDenied {
                branch_id: test_branch_id(),
                credential_name: "anthropic-api-key".to_string(),
                domain: "untrusted.example.com".to_string(),
                reason: "domain mismatch".to_string(),
            },
        ];

        for event in &events {
            let json = serde_json::to_string(event).unwrap();
            let parsed: Value = serde_json::from_str(&json).unwrap();
            // Every event should have an "event_type" field from #[serde(tag = "event_type")]
            assert!(
                parsed.get("event_type").is_some(),
                "missing event_type in: {}",
                json
            );
        }
    }

    #[test]
    fn test_audit_logger_log_no_panic() {
        let logger = AuditLogger::new();

        let events: Vec<AuditEvent> = vec![
            AuditEvent::BranchCreated {
                branch_id: test_branch_id(),
                profile: "standard".to_string(),
                uid: 1000,
            },
            AuditEvent::BranchCommitted {
                branch_id: test_branch_id(),
                files: 10,
                bytes: 4096,
            },
            AuditEvent::BranchRolledBack {
                branch_id: test_branch_id(),
                reason: "test rollback".to_string(),
            },
            AuditEvent::PolicyViolation {
                branch_id: test_branch_id(),
                rule: "size_limit".to_string(),
                message: "too large".to_string(),
            },
            AuditEvent::SandboxEscape {
                branch_id: test_branch_id(),
                detail: "namespace escape".to_string(),
            },
            AuditEvent::BranchFrozen {
                branch_id: test_branch_id(),
            },
            AuditEvent::AgentExecGated {
                branch_id: test_branch_id(),
                path: "/bin/sh".to_string(),
                allowed: true,
            },
            AuditEvent::AgentConnectGated {
                branch_id: test_branch_id(),
                address: "example.com:80".to_string(),
                allowed: false,
            },
            AuditEvent::ProfileLoaded {
                profile: "privileged".to_string(),
            },
            AuditEvent::PolicyReloaded { policies_loaded: 3 },
            AuditEvent::DlpBlocked {
                branch_id: test_branch_id(),
                rule_name: "block_secrets".to_string(),
                domain: "api.example.com".to_string(),
                direction: "response".to_string(),
            },
            AuditEvent::DlpRedacted {
                branch_id: test_branch_id(),
                rule_name: "redact_pii".to_string(),
                redactions: 5,
            },
            AuditEvent::DlpQuarantine {
                branch_id: test_branch_id(),
                rule_name: "data_exfil".to_string(),
                domain: "malicious.example.com".to_string(),
            },
            AuditEvent::DlpDetected {
                branch_id: test_branch_id(),
                rule_name: "detect_ssn".to_string(),
                domain: "reporting.example.com".to_string(),
                match_count: 1,
            },
            AuditEvent::CredentialInjected {
                branch_id: test_branch_id(),
                credential_name: "service-api-key".to_string(),
                domain: "service.example.com".to_string(),
            },
            AuditEvent::CredentialDenied {
                branch_id: test_branch_id(),
                credential_name: "unknown-cred".to_string(),
                domain: "unknown.example.com".to_string(),
                reason: "invalid token".to_string(),
            },
        ];

        for event in events {
            logger.log(event);
        }
    }

    #[test]
    fn test_audit_event_branch_created_json() {
        let event = AuditEvent::BranchCreated {
            branch_id: BranchId::from("br-abc-123".to_string()),
            profile: "restricted".to_string(),
            uid: 1001,
        };
        let json: Value = serde_json::to_value(&event).unwrap();

        assert_eq!(json["event_type"], "BranchCreated");
        assert_eq!(json["branch_id"], "br-abc-123");
        assert_eq!(json["profile"], "restricted");
        assert_eq!(json["uid"], 1001);
    }

    #[test]
    fn test_audit_event_creation_correct_fields() {
        // Phase 1.14: Each event variant carries the expected fields.
        let event = AuditEvent::BranchCommitted {
            branch_id: test_branch_id(),
            files: 42,
            bytes: 8192,
        };
        let json: Value = serde_json::to_value(&event).unwrap();
        assert_eq!(json["event_type"], "BranchCommitted");
        assert_eq!(json["files"], 42);
        assert_eq!(json["bytes"], 8192);
        assert_eq!(json["branch_id"], "test-branch-001");

        let event2 = AuditEvent::AgentRegistered {
            agent_id: "agent-99".to_string(),
            profile: "restricted".to_string(),
        };
        let json2: Value = serde_json::to_value(&event2).unwrap();
        assert_eq!(json2["event_type"], "AgentRegistered");
        assert_eq!(json2["agent_id"], "agent-99");
        assert_eq!(json2["profile"], "restricted");
    }

    #[test]
    fn test_audit_event_commit_rejected_json() {
        // Phase 1.14: CommitRejected event carries branch_id and reason.
        let event = AuditEvent::CommitRejected {
            branch_id: BranchId::from("rej-branch".to_string()),
            reason: "policy denied".to_string(),
        };
        let json: Value = serde_json::to_value(&event).unwrap();
        assert_eq!(json["event_type"], "CommitRejected");
        assert_eq!(json["branch_id"], "rej-branch");
        assert_eq!(json["reason"], "policy denied");
    }

    #[test]
    fn test_sanitize_audit_field_strips_dangerous_chars() {
        // Phase 1.14: sanitize_audit_field replaces injection characters.
        let sanitized = sanitize_audit_field("hello\nworld");
        assert!(!sanitized.contains('\n'));

        let sanitized = sanitize_audit_field("key=\"value\"");
        assert!(!sanitized.contains('"'));
        assert!(!sanitized.contains('='));

        let sanitized = sanitize_audit_field("normal text");
        assert_eq!(sanitized, "normal text");
    }

    #[test]
    fn test_audit_event_policy_violation_json() {
        let event = AuditEvent::PolicyViolation {
            branch_id: BranchId::from("br-xyz-789".to_string()),
            rule: "no_ssh_keys".to_string(),
            message: "found id_rsa in changeset".to_string(),
        };
        let json: Value = serde_json::to_value(&event).unwrap();

        assert_eq!(json["event_type"], "PolicyViolation");
        assert_eq!(json["branch_id"], "br-xyz-789");
        assert_eq!(json["rule"], "no_ssh_keys");
        assert_eq!(json["message"], "found id_rsa in changeset");
    }

    // R3: Verify AgentKilled variant uses sanitize_audit_field on branch_id.
    #[test]
    fn test_r3_agent_killed_sanitizes_branch_id() {
        let source = include_str!("audit.rs");
        // Find the AgentKilled match arm in the log_event function
        let agent_killed_pos = source
            .find("AuditEvent::AgentKilled")
            .expect("AgentKilled variant must exist");
        // Get the block after AgentKilled up to the next AuditEvent variant
        let after = &source[agent_killed_pos..];
        let block_end = after
            .find("AuditEvent::NetworkGate")
            .or_else(|| after.find("AuditEvent::DlpBlocked"))
            .unwrap_or(500.min(after.len()));
        let block = &after[..block_end];
        assert!(
            block.contains("sanitize_audit_field"),
            "R3: AgentKilled must use sanitize_audit_field on branch_id, \
             but the match arm does not contain it. Block:\n{}",
            block
        );
    }

    /// F27: Verify nlmsg_len has a bounds check before u32 cast.
    #[test]
    fn test_f27_nlmsg_len_bounded() {
        let source = include_str!("audit.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // The production code must check nlmsg_len against u32::MAX before casting
        assert!(
            prod_source.contains("u32::MAX"),
            "F27: audit.rs must check nlmsg_len against u32::MAX before casting \
             to prevent truncation on huge messages."
        );
    }

    /// G21: NetlinkAudit Drop must set fd = -1 after close to prevent double-close.
    #[test]
    fn test_g21_netlink_drop_sets_fd_negative() {
        let source = include_str!("audit.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // The Drop impl must set fd to -1 after closing
        assert!(
            prod_source.contains("self.fd = -1"),
            "G21: NetlinkAudit::Drop must set self.fd = -1 after close \
             to prevent double-close on the file descriptor"
        );

        // The Drop impl must guard the close with a >= 0 check
        assert!(
            prod_source.contains("self.fd >= 0"),
            "G21: NetlinkAudit::Drop must check self.fd >= 0 before calling close \
             to prevent closing an invalid file descriptor"
        );
    }

    // -----------------------------------------------------------------------
    // H51: nlmsghdr must be written byte-by-byte to avoid alignment issues
    // -----------------------------------------------------------------------
    #[test]
    fn test_h51_nlmsghdr_alignment_safe() {
        let source = include_str!("audit.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // The old pattern was: unsafe { &mut *(buf.as_mut_ptr() as *mut libc::nlmsghdr) }
        // H51 replaces it with byte-level writes using to_ne_bytes()
        assert!(
            prod_source.contains("to_ne_bytes"),
            "H51: send_raw must write nlmsghdr fields using to_ne_bytes() \
             instead of casting Vec<u8> to *mut nlmsghdr, which has \
             alignment requirements that Vec<u8> does not guarantee."
        );
        assert!(
            !prod_source.contains("as *mut libc::nlmsghdr"),
            "H51: send_raw must not cast buf pointer to *mut libc::nlmsghdr. \
             Use byte-level field writes instead."
        );
    }
}
