// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Identity (§4.5 -- Agent Workload Identity)
// ---------------------------------------------------------------------------

/// Delegation metadata for sub-agent workflows (§4.5).
///
/// Every delegation has a `delegated_by_uid` — at depth 0 this is the human
/// operator who started the agent; at depth > 0 it is the parent agent's UID.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DelegationMetadata {
    pub depth: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_branch_id: Option<String>,
    pub delegated_by_uid: u32,
}

/// JWT-SVID governance claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GovernanceClaims {
    pub sub: String,
    pub iss: String,
    pub aud: Vec<String>,
    pub iat: i64,
    pub exp: i64,
    pub branch_id: String,
    pub agent_profile: String,
    pub trust_level: String,
    pub trust_score: u32,
    pub governance: GovernanceClaimsMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub containment: Option<ContainmentClaims>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<DelegationMetadata>,
}

/// Metadata about governance enforcement layers embedded in JWT claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GovernanceClaimsMetadata {
    pub enforcement_layers: Vec<String>,
    pub policy_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_chain_hash: Option<String>,
    pub attestation_chain_length: u32,
}

/// Containment scope claims embedded in JWT.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContainmentClaims {
    pub filesystem_scope: String,
    pub network_mode: String,
    pub allowed_domains: Vec<String>,
    pub exec_allowlist_count: u32,
}

/// Identity injection mode for puzzle-proxy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityInjectionMode {
    JwtSvid,
    MtlsClientCert,
    Both,
    #[default]
    Disabled,
}
