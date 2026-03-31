// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Attestation (§3.1 — Cryptographic Attestation of Governance)
// ---------------------------------------------------------------------------

/// Identity of the agent that produced a governance event.
///
/// Included in attestation records for third-party verifiability.
/// Contains only metadata (UID, profile, SELinux context) — no PII.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// POSIX UID of the agent process.
    pub uid: u32,
    /// Agent profile name (e.g., "restricted", "standard").
    pub profile: String,
    /// SELinux context if available (e.g., "puzzlepod_t:s0:c42,c99").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selinux_context: Option<String>,
    /// Agent framework if reported by SDK (e.g., "langchain", "crewai").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
}

/// Governance decision recorded in an attestation record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceDecision {
    Approved,
    Rejected,
    Rollback,
    Violation,
    Escape,
    Killed,
    Created,
}

impl std::fmt::Display for GovernanceDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Approved => write!(f, "approved"),
            Self::Rejected => write!(f, "rejected"),
            Self::Rollback => write!(f, "rollback"),
            Self::Violation => write!(f, "violation"),
            Self::Escape => write!(f, "escape"),
            Self::Killed => write!(f, "killed"),
            Self::Created => write!(f, "created"),
        }
    }
}

/// Merkle tree inclusion proof for a single attestation record.
///
/// Given the leaf hash, the proof hashes, and the root hash at `tree_size`,
/// a verifier can confirm that the record exists in the log without
/// downloading the entire tree.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Index of the leaf in the Merkle tree.
    pub leaf_index: u64,
    /// Tree size at the time the proof was generated.
    pub tree_size: u64,
    /// Sibling hashes from leaf to root (each 32 bytes, hex-encoded).
    pub proof_hashes: Vec<String>,
}

/// Merkle tree consistency proof between two tree sizes.
///
/// Proves that the log at `new_size` is a strict append-only extension
/// of the log at `old_size` — no records were deleted or modified.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsistencyProof {
    /// Tree size of the earlier checkpoint.
    pub old_size: u64,
    /// Tree size of the later checkpoint.
    pub new_size: u64,
    /// Proof hashes (each 32 bytes, hex-encoded).
    pub proof_hashes: Vec<String>,
}
