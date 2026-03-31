// SPDX-License-Identifier: Apache-2.0
//! Unified audit record types for NDJSON deserialization.
//!
//! V49: Previously duplicated in `puzzlectl/src/main.rs` (extended version with
//! attestation fields) and `puzzlectl/src/compliance.rs` (minimal 3-field version).
//! Unified here as the superset: compliance consumers simply ignore the optional
//! attestation fields, while attestation verification has access to all fields.
//! All optional fields use `#[serde(default, skip_serializing_if = "Option::is_none")]`
//! to maintain wire compatibility with both the minimal and extended NDJSON formats.

use crate::{AgentIdentity, GovernanceDecision};

/// Deserialization struct for audit events read from NDJSON.
///
/// Mirrors `StoredAuditEvent` in puzzled. The three core fields (`seq`,
/// `timestamp`, `event`) are always present; the remaining fields are
/// populated only for governance-significant records that carry attestation
/// metadata.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AuditRecord {
    pub seq: u64,
    pub timestamp: String,
    pub event: AuditRecordEvent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_identity: Option<AgentIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changeset_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_decision: Option<GovernanceDecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_record_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// HMAC chain signature (puzzled stores this as "hmac" in NDJSON).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_leaf_index: Option<u64>,
}

/// The event payload within an [`AuditRecord`].
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AuditRecordEvent {
    pub event_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch_id: Option<String>,
    pub details: serde_json::Value,
}
