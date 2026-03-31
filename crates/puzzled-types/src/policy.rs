// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zbus::zvariant::Type;

use crate::branch::BranchId;

// ---------------------------------------------------------------------------
// Commit / policy
// ---------------------------------------------------------------------------

/// Result of a branch commit operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommitResult {
    pub branch_id: BranchId,
    pub files_committed: u64,
    pub bytes_committed: u64,
    pub policy_result: PolicyDecision,
}

/// Outcome of OPA/Rego policy evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PolicyDecision {
    Approved,
    Rejected(Vec<Violation>),
    Error(String),
}

/// A single policy violation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Violation {
    /// Rego rule that triggered the violation.
    pub rule: String,
    /// Human-readable description.
    pub message: String,
    pub severity: ViolationSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
pub enum ViolationSeverity {
    Warning,
    Error,
    Critical,
}

// ---------------------------------------------------------------------------
// Conflict detection
// ---------------------------------------------------------------------------

/// A conflict between concurrent branches.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Conflict {
    /// The conflicting file path.
    pub path: PathBuf,
    /// Branch IDs that modified this path.
    pub conflicting_branches: Vec<BranchId>,
    /// Type of conflict.
    pub kind: ConflictKind,
}

/// Type of cross-branch conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
pub enum ConflictKind {
    /// Both branches modified the same file.
    BothModified,
    /// One branch modified, another deleted.
    ModifiedAndDeleted,
    /// Both branches created the same new file.
    BothCreated,
}

/// Strategy for resolving cross-branch conflicts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Type)]
pub enum ConflictResolution {
    /// Default: reject the commit.
    #[default]
    Reject,
    /// Last writer wins (overwrite silently).
    LastWriterWins,
    /// Three-way merge for text files, reject for binary.
    MergeIfText,
    /// Non-overlapping path prefixes per branch.
    ScopePartition,
}

// ---------------------------------------------------------------------------
// Audit (persistent storage)
// ---------------------------------------------------------------------------

/// Filter for querying audit events.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AuditFilter {
    /// Filter by branch ID.
    pub branch_id: Option<String>,
    /// Filter by event type.
    pub event_type: Option<String>,
    /// Filter events since this timestamp (RFC 3339).
    pub since: Option<String>,
    /// Maximum number of events to return.
    pub limit: Option<u32>,
}

// ---------------------------------------------------------------------------
// Governance significance classification
// ---------------------------------------------------------------------------

/// Determine which audit event types are governance-significant and
/// should receive attestation signatures.
///
/// Governance-significant events are those that represent material state
/// transitions or security incidents. High-frequency operational events
/// (e.g., `exec_gated`, `connect_gated`) are excluded to avoid excessive
/// attestation overhead.
pub fn is_governance_significant(event_type: &str) -> bool {
    matches!(
        event_type,
        "branch_created"
            | "branch_committed"
            | "branch_rolled_back"
            | "policy_violation"
            | "commit_rejected"
            | "sandbox_escape"
            | "behavioral_trigger"
            | "agent_killed"
    )
}
