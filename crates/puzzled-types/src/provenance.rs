// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};

use crate::change::FileChangeKind;

// ---------------------------------------------------------------------------
// Provenance (§4.3 — Full Provenance Chain)
// ---------------------------------------------------------------------------

/// A provenance record linking cause to effect.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    pub id: String,
    pub record_type: ProvenanceType,
    pub branch_id: String,
    pub timestamp: String,
}

/// Provenance record type -- each variant captures a different stage of the chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProvenanceType {
    /// Reported by agent framework SDK.
    Request {
        request_id: String,
        user_uid: u32,
        prompt_hash: String,
    },
    /// Reported by agent framework SDK.
    Inference {
        inference_id: String,
        request_id: String,
        model: String,
        token_count: u32,
        tool_calls: Vec<String>,
    },
    /// From seccomp USER_NOTIF handler + optional SDK enrichment.
    ToolInvocation {
        invocation_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        inference_id: Option<String>,
        tool_path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        arguments_hash: Option<String>,
        pid: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
        /// Timestamp when the tool invocation started (RFC 3339).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        started_at: Option<String>,
        /// Timestamp when the tool invocation exited (RFC 3339).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exited_at: Option<String>,
    },
    /// From DiffEngine + fanotify correlation.
    FileChange {
        change_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        invocation_id: Option<String>,
        path: String,
        kind: FileChangeKind,
        size: u64,
        checksum: String,
    },
    /// From policy evaluation + CommitManifest.
    Governance {
        decision_id: String,
        change_ids: Vec<String>,
        policy_version: String,
        result: String,
        violations: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        manifest_hash: Option<String>,
    },
}
