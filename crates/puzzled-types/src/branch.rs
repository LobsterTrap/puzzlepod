// SPDX-License-Identifier: Apache-2.0
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;
use zbus::zvariant::Type;

// ---------------------------------------------------------------------------
// Branch identity
// ---------------------------------------------------------------------------

/// Unique identifier for a branch (OverlayFS upper-layer instance).
///
/// The inner `String` field is private to enforce validation on construction.
/// Use `BranchId::new()` for fresh IDs, `BranchId::validated()` for untrusted
/// input, or `BranchId::from()` for trusted internal strings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Type)]
pub struct BranchId(String);

/// Custom `Deserialize` for `BranchId` that validates input via `validated()`.
/// Rejects malformed IDs (path traversal, control chars, etc.) at deserialization
/// time rather than silently accepting them.
impl<'de> Deserialize<'de> for BranchId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        BranchId::validated(s).map_err(serde::de::Error::custom)
    }
}

impl BranchId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Create a BranchId from an externally-provided string, with validation.
    ///
    /// Rejects strings that could enable path traversal or other injection:
    /// - Empty strings
    /// - Strings containing `/`, `..`, `\0`, `\n`, or other control characters
    /// - Strings with non-alphanumeric characters (except `-` and `_`)
    /// - Strings longer than 256 characters
    pub fn validated(s: String) -> std::result::Result<Self, String> {
        if s.is_empty() {
            return Err("BranchId must not be empty".to_string());
        }
        if s.len() > 256 {
            return Err(format!(
                "BranchId exceeds maximum length of 256 characters (got {})",
                s.len()
            ));
        }
        for c in s.chars() {
            if c == '/' {
                return Err("BranchId must not contain '/'".to_string());
            }
            if c == '\0' {
                return Err("BranchId must not contain null bytes".to_string());
            }
            if c.is_control() {
                return Err(format!(
                    "BranchId must not contain control characters (found U+{:04X})",
                    c as u32
                ));
            }
            if !(c.is_alphanumeric() || c == '-' || c == '_') {
                return Err(format!(
                    "BranchId contains invalid character '{}' (allowed: alphanumeric, '-', '_')",
                    c
                ));
            }
        }
        if s.contains("..") {
            return Err("BranchId must not contain '..'".to_string());
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for BranchId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for BranchId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for BranchId {
    /// Create a BranchId from a string.
    ///
    /// G28: Always validates input. Panics on invalid input in both debug and
    /// release builds to prevent silently accepting path-traversal or injection
    /// attacks. This is intended for internal/trusted use (e.g., UUIDs generated
    /// by `BranchId::new()`, test fixtures). For external/untrusted input
    /// (D-Bus, CLI arguments), use `BranchId::validated()` instead.
    fn from(s: String) -> Self {
        match Self::validated(s.clone()) {
            Ok(id) => id,
            Err(e) => {
                // G28: Always validate — do not silently accept invalid input
                // in release builds. Panic to surface misuse immediately.
                eprintln!(
                    "ERROR: G28: BranchId::from() called with invalid input '{}': {}",
                    s, e
                );
                panic!("G28: BranchId::from() called with invalid input: {e}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Branch lifecycle
// ---------------------------------------------------------------------------

/// State machine for a branch's lifecycle.
///
/// ```text
/// E3: Valid state transitions:
///
///   Creating ──→ Ready ──→ Active ──→ Frozen ──→ Committing ──→ Committed
///                  │  │      │  ↑        │  ↑        │
///                  │  │      │  │        │  └────────┘ (WAL failure → Active)
///                  │  │      │  │        │
///                  │  │      │  │        ├──→ GovernanceReview ──→ Committed (approved)
///                  │  │      │  │        │                    └──→ RolledBack (rejected/timeout)
///                  │  │      │  │        ├──→ RolledBack (policy rejected)
///                  │  │      │  │        ├──→ Committed  (empty changeset)
///                  │  │      │  │        └──→ Terminated (OOM during freeze)
///                  │  │      │  │
///                  │  │      │  └──────── Frozen (FailSilent/FailOperational recovery)
///                  │  │      │
///                  │  │      ├──→ RolledBack (user-initiated)
///                  │  │      ├──→ Exited     (clean exit, code 0)
///                  │  │      └──→ Terminated (signal or non-zero exit)
///                  │  │
///                  │  └──→ Frozen (direct-mode commit, no process to freeze)
///                  └──→ RolledBack (workspace cancelled before activation)
///
///   Exited ──→ Frozen (freeze after clean exit for commit)
///   Terminated ──→ RolledBack (cleanup after termination)
///   Committing ──→ Failed (fatal commit error)
///   Any ──→ Degraded (FailOperational/FailSilent — branch tracked but not active)
///   Any ──→ Failed (fail-closed default)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
pub enum BranchState {
    /// Sandbox is being set up (namespaces, OverlayFS, Landlock, seccomp, cgroup).
    Creating,
    /// Workspace directories are provisioned; no sandbox is active yet.
    /// Waiting for `activate_branch()` to spawn the sandboxed process.
    Ready,
    /// Agent is running inside the sandbox.
    Active,
    /// Agent processes are frozen via cgroup.freeze for TOCTOU-free diff.
    Frozen,
    /// Commit is in progress (WAL write → apply → mark complete).
    Committing,
    /// H-9: Awaiting human reviewer approval (governance review).
    /// Policy approved but `require_human_approval` is enabled.
    GovernanceReview,
    /// Changes have been committed to the base filesystem.
    Committed,
    /// Changes have been discarded (upper layer removed).
    RolledBack,
    /// An error occurred during the branch lifecycle.
    Failed,
    /// H-26: Branch is tracked but in a degraded state.
    /// Used by FailOperational/FailSilent modes instead of removing the branch.
    /// The agent process may still be running with reduced capability (FailOperational)
    /// or frozen holding last safe state (FailSilent).
    Degraded,
    /// Agent process exited normally (exit code 0).
    Exited,
    /// Agent process was terminated (signal or non-zero exit).
    Terminated,
}

impl std::fmt::Display for BranchState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Creating => "creating",
            Self::Ready => "ready",
            Self::Active => "active",
            Self::Frozen => "frozen",
            Self::Committing => "committing",
            Self::GovernanceReview => "governance_review",
            Self::Committed => "committed",
            Self::RolledBack => "rolled_back",
            Self::Failed => "failed",
            Self::Degraded => "degraded",
            Self::Exited => "exited",
            Self::Terminated => "terminated",
        };
        f.write_str(s)
    }
}

/// Metadata about an active or completed branch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BranchInfo {
    pub id: BranchId,
    pub profile: String,
    pub base_path: PathBuf,
    pub upper_dir: PathBuf,
    pub work_dir: PathBuf,
    pub state: BranchState,
    pub created_at: DateTime<Utc>,
    /// M4: Expiration time derived from created_at + profile.lifetime_minutes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// PID of the agent init process (PID 1 inside the namespace).
    pub pid: Option<u32>,
    /// UID of the agent owner.
    pub uid: u32,
    /// Cached SELinux context at branch creation (avoids repeated /proc reads).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selinux_context: Option<String>,
}

impl BranchInfo {
    /// Construct an `AgentIdentity` from this branch's metadata.
    ///
    /// Used by the attestation bridge to record identity alongside audit events.
    pub fn agent_identity(&self) -> crate::AgentIdentity {
        crate::AgentIdentity {
            uid: self.uid,
            profile: self.profile.clone(),
            selinux_context: self.selinux_context.clone(),
            framework: None,
        }
    }
}
