// SPDX-License-Identifier: Apache-2.0
//! §4.3 Full Provenance Chain — persistent provenance storage for branch activity.
//!
//! Records the causal chain of events (request → inference → tool invocation →
//! file change → governance) for each branch as NDJSON (newline-delimited JSON).
//! This enables full traceability from an external request through LLM inference
//! to the resulting file changes and governance decisions.
//!
//! # Thread Safety
//!
//! `ProvenanceStore` uses an internal `Mutex` to serialize writes to branch
//! NDJSON files, preventing interleaved partial JSON lines from concurrent
//! callers.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use uuid::Uuid;

use crate::error::{PuzzledError, Result};
use puzzled_types::{FileChange, ProvenanceRecord, ProvenanceType};

/// K83: Maximum number of write lock entries before eviction of stale entries.
const MAX_WRITE_LOCKS: usize = 10_000;

/// Reconstructed causal chain for a branch, grouped by event type.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProvenanceChain {
    pub branch_id: String,
    pub requests: Vec<ProvenanceRecord>,
    pub inferences: Vec<ProvenanceRecord>,
    pub tool_invocations: Vec<ProvenanceRecord>,
    pub file_changes: Vec<ProvenanceRecord>,
    pub governance: Vec<ProvenanceRecord>,
}

/// Persistent store for provenance records, backed by NDJSON files on disk.
///
/// Each branch gets its own directory under `base_dir`, with a `records.jsonl`
/// file containing one JSON object per line.
///
/// All public methods validate `branch_id` to prevent path traversal attacks
/// (e.g., `../../etc` as branch_id).
pub struct ProvenanceStore {
    base_dir: PathBuf,
    /// Per-branch write locks to prevent interleaved NDJSON lines from
    /// concurrent callers while allowing independent branches to write
    /// in parallel.
    write_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl ProvenanceStore {
    /// Create a new provenance store rooted at `base_dir`.
    pub fn new(base_dir: PathBuf) -> Self {
        Self {
            base_dir,
            write_locks: Mutex::new(HashMap::new()),
        }
    }

    /// Validate a branch_id to prevent path traversal attacks.
    ///
    /// Rejects empty strings, strings containing `/`, `..`, `\0`, or
    /// control characters — the same rules as `BranchId::validated()`.
    // V28: Backslash is valid on Linux. SPIFFE IDs (identity.rs) are stricter (alnum + - + _ only).
    // If cross-platform provenance transfer is needed, add backslash rejection here.
    fn validate_branch_id(branch_id: &str) -> Result<()> {
        if branch_id.is_empty() {
            return Err(PuzzledError::Provenance(
                "branch_id must not be empty".into(),
            ));
        }
        if branch_id.contains('/') || branch_id.contains("..") || branch_id.contains('\0') {
            return Err(PuzzledError::Provenance(format!(
                "branch_id contains unsafe characters: '{branch_id}'"
            )));
        }
        if branch_id.chars().any(|c| c.is_control()) {
            return Err(PuzzledError::Provenance(format!(
                "branch_id contains control characters: '{branch_id}'"
            )));
        }
        Ok(())
    }

    /// Obtain the per-branch write lock, creating it on first access.
    ///
    /// K83: Evicts entries with `Arc::strong_count() == 1` when the map exceeds
    /// `MAX_WRITE_LOCKS` to prevent unbounded growth.
    fn branch_lock(&self, branch_id: &str) -> Result<Arc<Mutex<()>>> {
        let mut locks = self
            .write_locks
            .lock()
            .map_err(|e| PuzzledError::Provenance(format!("branch lock map poisoned: {e}")))?;
        // K83: Evict stale entries when map exceeds MAX_WRITE_LOCKS
        if locks.len() >= MAX_WRITE_LOCKS {
            locks.retain(|_, v| Arc::strong_count(v) > 1);
        }
        Ok(locks
            .entry(branch_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone())
    }

    /// Path to the records file for a given branch.
    fn records_path(&self, branch_id: &str) -> PathBuf {
        self.base_dir.join(branch_id).join("records.jsonl")
    }

    /// Append a provenance record to the branch's NDJSON file.
    ///
    /// Creates the branch directory and file if they do not exist.
    /// Does NOT fsync per record (PRD §4.3.7: "no fsync per record") —
    /// provenance is traceability data where losing a few records on crash
    /// is acceptable.  Use `record_batch()` for multi-record writes that
    /// need a single fsync at the end.
    /// Serializes concurrent writes via an internal per-branch mutex.
    pub fn record(&self, record: &ProvenanceRecord) -> Result<()> {
        Self::validate_branch_id(&record.branch_id)?;
        let lock = self.branch_lock(&record.branch_id)?;
        let _guard = lock
            .lock()
            .map_err(|e| PuzzledError::Provenance(format!("branch write lock poisoned: {e}")))?;

        self.append_unlocked(&record.branch_id, record)
    }

    /// Append multiple provenance records atomically under a single lock
    /// acquisition, with a single fsync at the end.
    ///
    /// More efficient than calling `record()` N times for batch operations
    /// like `record_file_changes()`.
    pub fn record_batch(&self, branch_id: &str, records: &[ProvenanceRecord]) -> Result<()> {
        Self::validate_branch_id(branch_id)?;
        if records.is_empty() {
            return Ok(());
        }
        let lock = self.branch_lock(branch_id)?;
        let _guard = lock
            .lock()
            .map_err(|e| PuzzledError::Provenance(format!("branch write lock poisoned: {e}")))?;

        // Open file once for the entire batch (not per-record).
        let path = self.records_path(branch_id);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                PuzzledError::Provenance(format!(
                    "failed to create provenance dir {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| {
                PuzzledError::Provenance(format!(
                    "failed to open provenance file {}: {}",
                    path.display(),
                    e
                ))
            })?;

        for record in records {
            let mut line = serde_json::to_string(record).map_err(|e| {
                PuzzledError::Provenance(format!("failed to serialize provenance record: {}", e))
            })?;
            line.push('\n');
            file.write_all(line.as_bytes()).map_err(|e| {
                PuzzledError::Provenance(format!(
                    "failed to write provenance record to {}: {}",
                    path.display(),
                    e
                ))
            })?;
        }

        // Single fsync for the entire batch — propagate errors.
        file.sync_all().map_err(|e| {
            PuzzledError::Provenance(format!(
                "failed to fsync provenance batch to {}: {}",
                path.display(),
                e
            ))
        })?;

        Ok(())
    }

    /// Internal: append a single record without acquiring the lock.
    /// Caller must hold the per-branch lock.
    fn append_unlocked(&self, branch_id: &str, record: &ProvenanceRecord) -> Result<()> {
        let path = self.records_path(branch_id);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                PuzzledError::Provenance(format!(
                    "failed to create provenance dir {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        let mut line = serde_json::to_string(record).map_err(|e| {
            PuzzledError::Provenance(format!("failed to serialize provenance record: {}", e))
        })?;
        line.push('\n');

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| {
                PuzzledError::Provenance(format!(
                    "failed to open provenance file {}: {}",
                    path.display(),
                    e
                ))
            })?;

        file.write_all(line.as_bytes()).map_err(|e| {
            PuzzledError::Provenance(format!(
                "failed to write provenance record to {}: {}",
                path.display(),
                e
            ))
        })?;

        Ok(())
    }

    /// Read all provenance records for a branch.
    ///
    /// Returns an empty vec if the branch has no provenance data.
    pub fn get_records(&self, branch_id: &str) -> Result<Vec<ProvenanceRecord>> {
        Self::validate_branch_id(branch_id)?;
        let path = self.records_path(branch_id);
        let file = match fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(PuzzledError::Provenance(format!(
                    "failed to open provenance file {}: {}",
                    path.display(),
                    e
                )))
            }
        };

        let reader = BufReader::new(file);
        let mut records = Vec::new();

        for (line_num, line_result) in reader.lines().enumerate() {
            let line = line_result.map_err(|e| {
                PuzzledError::Provenance(format!(
                    "failed to read line {} from {}: {}",
                    line_num + 1,
                    path.display(),
                    e
                ))
            })?;

            if line.trim().is_empty() {
                continue;
            }

            let record: ProvenanceRecord = serde_json::from_str(&line).map_err(|e| {
                PuzzledError::Provenance(format!(
                    "failed to parse provenance record at {}:{}: {}",
                    path.display(),
                    line_num + 1,
                    e
                ))
            })?;

            records.push(record);
        }

        Ok(records)
    }

    /// Find all provenance records related to a specific file path.
    ///
    /// Matches FileChange records whose `path` field equals the given path.
    pub fn trace_file(&self, branch_id: &str, file_path: &str) -> Result<Vec<ProvenanceRecord>> {
        // validate_branch_id is called by get_records
        let records = self.get_records(branch_id)?;
        Ok(records
            .into_iter()
            .filter(|r| matches!(&r.record_type, ProvenanceType::FileChange { path, .. } if path == file_path))
            .collect())
    }

    /// Trace the full causal chain for a specific file path.
    ///
    /// Traverses the provenance DAG upward from FileChange records:
    /// FileChange → ToolInvocation (via invocation_id) → Inference (via
    /// inference_id) → Request (via request_id).  Also includes any
    /// Governance records that reference the matched file changes.
    ///
    /// Returns an empty vec if no FileChange records match the path.
    pub fn trace_chain(&self, branch_id: &str, file_path: &str) -> Result<Vec<ProvenanceRecord>> {
        let records = self.get_records(branch_id)?;
        let mut chain = Vec::new();
        // Track seen record IDs to avoid duplicates when multiple
        // FileChange records share upstream links (e.g., 3 files
        // modified by the same tool invocation).
        let mut seen = std::collections::HashSet::new();

        // Find matching FileChange records and traverse upward.
        let file_changes: Vec<&ProvenanceRecord> = records
            .iter()
            .filter(|r| {
                matches!(&r.record_type, ProvenanceType::FileChange { path, .. } if path == file_path)
            })
            .collect();

        for fc in &file_changes {
            if seen.insert(fc.id.clone()) {
                chain.push((*fc).clone());
            }

            // Follow invocation_id → ToolInvocation.
            if let ProvenanceType::FileChange {
                invocation_id: Some(inv_id),
                ..
            } = &fc.record_type
            {
                if let Some(inv) = records.iter().find(|r| {
                    matches!(&r.record_type, ProvenanceType::ToolInvocation { invocation_id, .. } if invocation_id == inv_id)
                }) {
                    if seen.insert(inv.id.clone()) {
                        chain.push(inv.clone());
                    }

                    // Follow inference_id → Inference.
                    if let ProvenanceType::ToolInvocation {
                        inference_id: Some(inf_id),
                        ..
                    } = &inv.record_type
                    {
                        if let Some(inf) = records.iter().find(|r| {
                            matches!(&r.record_type, ProvenanceType::Inference { inference_id, .. } if inference_id == inf_id)
                        }) {
                            if seen.insert(inf.id.clone()) {
                                chain.push(inf.clone());
                            }

                            // Follow request_id → Request.
                            if let ProvenanceType::Inference { request_id, .. } =
                                &inf.record_type
                            {
                                if let Some(req) = records.iter().find(|r| {
                                    matches!(&r.record_type, ProvenanceType::Request { request_id: rid, .. } if rid == request_id)
                                }) {
                                    if seen.insert(req.id.clone()) {
                                        chain.push(req.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Find Governance records that reference matched file changes.
        let change_ids: Vec<String> = chain
            .iter()
            .filter_map(|r| match &r.record_type {
                ProvenanceType::FileChange { change_id, .. } => Some(change_id.clone()),
                _ => None,
            })
            .collect();

        for r in &records {
            if let ProvenanceType::Governance {
                change_ids: gov_change_ids,
                ..
            } = &r.record_type
            {
                if gov_change_ids.iter().any(|id| change_ids.contains(id))
                    && seen.insert(r.id.clone())
                {
                    chain.push(r.clone());
                }
            }
        }

        Ok(chain)
    }

    /// Reconstruct the full causal chain for a branch, grouped by event type.
    pub fn get_chain(&self, branch_id: &str) -> Result<ProvenanceChain> {
        let records = self.get_records(branch_id)?;

        let mut chain = ProvenanceChain {
            branch_id: branch_id.to_string(),
            requests: Vec::new(),
            inferences: Vec::new(),
            tool_invocations: Vec::new(),
            file_changes: Vec::new(),
            governance: Vec::new(),
        };

        for record in records {
            match &record.record_type {
                ProvenanceType::Request { .. } => chain.requests.push(record),
                ProvenanceType::Inference { .. } => chain.inferences.push(record),
                ProvenanceType::ToolInvocation { .. } => chain.tool_invocations.push(record),
                ProvenanceType::FileChange { .. } => chain.file_changes.push(record),
                ProvenanceType::Governance { .. } => chain.governance.push(record),
            }
        }

        Ok(chain)
    }

    /// Remove all provenance data for a branch and release its write lock.
    pub fn cleanup_branch(&self, branch_id: &str) -> Result<()> {
        Self::validate_branch_id(branch_id)?;
        let dir = self.base_dir.join(branch_id);
        match fs::remove_dir_all(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(PuzzledError::Provenance(format!(
                    "failed to remove provenance dir {}: {}",
                    dir.display(),
                    e
                )))
            }
        }
        // Release the per-branch lock entry to avoid unbounded growth.
        if let Ok(mut locks) = self.write_locks.lock() {
            locks.remove(branch_id);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Generate a time-ordered UUID v7 (chronologically sortable).
fn new_id() -> String {
    Uuid::now_v7().to_string()
}

/// Convert a slice of `FileChange` values to provenance records and append them.
///
/// Accepts an optional `invocation_id` to link file changes to the tool
/// invocation that produced them (for causal chain traversal).
///
/// Uses `record_batch()` to write all records under a single lock with a
/// single fsync, avoiding per-record overhead for large changesets.
pub fn record_file_changes(
    store: &ProvenanceStore,
    branch_id: &str,
    changes: &[FileChange],
    invocation_id: Option<&str>,
) -> Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    let records: Vec<ProvenanceRecord> = changes
        .iter()
        .map(|change| ProvenanceRecord {
            id: new_id(),
            branch_id: branch_id.to_string(),
            record_type: ProvenanceType::FileChange {
                change_id: new_id(),
                invocation_id: invocation_id.map(|s| s.to_string()),
                path: change.path.to_string_lossy().to_string(),
                kind: change.kind,
                size: change.size,
                checksum: change.checksum.clone(),
            },
            timestamp: now.clone(),
        })
        .collect();

    store.record_batch(branch_id, &records)
}

/// Record a governance decision and return the decision ID.
pub fn record_governance(
    store: &ProvenanceStore,
    branch_id: &str,
    policy_version: &str,
    result: &str,
    violations: &[String],
    manifest_hash: Option<String>,
    change_ids: &[String],
) -> Result<String> {
    let decision_id = new_id();

    let record = ProvenanceRecord {
        id: decision_id.clone(),
        branch_id: branch_id.to_string(),
        record_type: ProvenanceType::Governance {
            decision_id: decision_id.clone(),
            change_ids: change_ids.to_vec(),
            policy_version: policy_version.to_string(),
            result: result.to_string(),
            violations: violations.to_vec(),
            manifest_hash,
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    store.record(&record)?;
    Ok(decision_id)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use puzzled_types::FileChangeKind;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Helper: create a store backed by a temporary directory.
    fn temp_store() -> (ProvenanceStore, TempDir) {
        let dir = TempDir::new().expect("failed to create tempdir");
        let store = ProvenanceStore::new(dir.path().to_path_buf());
        (store, dir)
    }

    /// Helper: create a simple provenance record with a Request type.
    fn make_request_record(branch_id: &str) -> ProvenanceRecord {
        ProvenanceRecord {
            id: new_id(),
            branch_id: branch_id.to_string(),
            record_type: ProvenanceType::Request {
                request_id: new_id(),
                user_uid: 1000,
                prompt_hash: "sha256:abc".to_string(),
            },
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn make_inference_record(branch_id: &str, request_id: &str) -> ProvenanceRecord {
        ProvenanceRecord {
            id: new_id(),
            branch_id: branch_id.to_string(),
            record_type: ProvenanceType::Inference {
                inference_id: new_id(),
                request_id: request_id.to_string(),
                model: "test-model".to_string(),
                token_count: 100,
                tool_calls: vec![],
            },
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn make_tool_record(branch_id: &str) -> ProvenanceRecord {
        ProvenanceRecord {
            id: new_id(),
            branch_id: branch_id.to_string(),
            record_type: ProvenanceType::ToolInvocation {
                invocation_id: new_id(),
                inference_id: None,
                tool_path: "/usr/bin/echo".to_string(),
                arguments_hash: None,
                pid: 1234,
                exit_code: Some(0),
                started_at: Some(chrono::Utc::now().to_rfc3339()),
                exited_at: Some(chrono::Utc::now().to_rfc3339()),
            },
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn make_file_change_record(branch_id: &str, path: &str) -> ProvenanceRecord {
        ProvenanceRecord {
            id: new_id(),
            branch_id: branch_id.to_string(),
            record_type: ProvenanceType::FileChange {
                change_id: new_id(),
                invocation_id: None,
                path: path.to_string(),
                kind: FileChangeKind::Modified,
                size: 1024,
                checksum: "sha256:def".to_string(),
            },
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn make_governance_record(branch_id: &str, result: &str) -> ProvenanceRecord {
        ProvenanceRecord {
            id: new_id(),
            branch_id: branch_id.to_string(),
            record_type: ProvenanceType::Governance {
                decision_id: new_id(),
                change_ids: vec![],
                policy_version: "v1.0.0".to_string(),
                result: result.to_string(),
                violations: vec![],
                manifest_hash: None,
            },
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn record_append_and_read() {
        let (store, _dir) = temp_store();
        let branch = "branch-001";

        let r1 = make_request_record(branch);
        let r2 = make_inference_record(branch, "req-1");

        let r1_id = r1.id.clone();
        let r2_id = r2.id.clone();

        store.record(&r1).unwrap();
        store.record(&r2).unwrap();

        let records = store.get_records(branch).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].id, r1_id);
        assert_eq!(records[1].id, r2_id);
    }

    #[test]
    fn trace_file_finds_related_records() {
        let (store, _dir) = temp_store();
        let branch = "branch-trace";

        let r1 = make_file_change_record(branch, "src/main.rs");
        let r2 = make_file_change_record(branch, "src/lib.rs");
        let r3 = make_request_record(branch);

        let r1_id = r1.id.clone();

        store.record(&r1).unwrap();
        store.record(&r2).unwrap();
        store.record(&r3).unwrap();

        let traced = store.trace_file(branch, "src/main.rs").unwrap();
        assert_eq!(traced.len(), 1);
        assert_eq!(traced[0].id, r1_id);

        let traced_lib = store.trace_file(branch, "src/lib.rs").unwrap();
        assert_eq!(traced_lib.len(), 1);

        let traced_none = store.trace_file(branch, "nonexistent.rs").unwrap();
        assert!(traced_none.is_empty());
    }

    #[test]
    fn trace_chain_traverses_causal_links() {
        let (store, _dir) = temp_store();
        let branch = "branch-chain-trace";

        // Build a full causal chain:
        // Request → Inference → ToolInvocation → FileChange → Governance
        let req_id = new_id();
        let inf_id = new_id();
        let inv_id = new_id();
        let change_id = new_id();

        let request = ProvenanceRecord {
            id: new_id(),
            branch_id: branch.to_string(),
            record_type: ProvenanceType::Request {
                request_id: req_id.clone(),
                user_uid: 1000,
                prompt_hash: "sha256:abc".to_string(),
            },
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let inference = ProvenanceRecord {
            id: new_id(),
            branch_id: branch.to_string(),
            record_type: ProvenanceType::Inference {
                inference_id: inf_id.clone(),
                request_id: req_id.clone(),
                model: "test-model".to_string(),
                token_count: 100,
                tool_calls: vec!["write_file".to_string()],
            },
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let invocation = ProvenanceRecord {
            id: new_id(),
            branch_id: branch.to_string(),
            record_type: ProvenanceType::ToolInvocation {
                invocation_id: inv_id.clone(),
                inference_id: Some(inf_id.clone()),
                tool_path: "/usr/bin/python3".to_string(),
                arguments_hash: None,
                pid: 1234,
                exit_code: Some(0),
                started_at: None,
                exited_at: None,
            },
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let file_change = ProvenanceRecord {
            id: new_id(),
            branch_id: branch.to_string(),
            record_type: ProvenanceType::FileChange {
                change_id: change_id.clone(),
                invocation_id: Some(inv_id.clone()),
                path: "src/main.rs".to_string(),
                kind: FileChangeKind::Modified,
                size: 2048,
                checksum: "sha256:xyz".to_string(),
            },
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let governance = ProvenanceRecord {
            id: new_id(),
            branch_id: branch.to_string(),
            record_type: ProvenanceType::Governance {
                decision_id: new_id(),
                change_ids: vec![change_id.clone()],
                policy_version: "v1.0.0".to_string(),
                result: "approved".to_string(),
                violations: vec![],
                manifest_hash: None,
            },
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        // Record all (order doesn't matter — trace_chain traverses by ID links).
        store.record(&request).unwrap();
        store.record(&inference).unwrap();
        store.record(&invocation).unwrap();
        store.record(&file_change).unwrap();
        store.record(&governance).unwrap();

        // Trace the chain for src/main.rs.
        let chain = store.trace_chain(branch, "src/main.rs").unwrap();

        // Should find all 5 records in the causal chain.
        assert_eq!(chain.len(), 5, "chain: {chain:?}");

        // Verify each type is present.
        assert!(chain
            .iter()
            .any(|r| matches!(&r.record_type, ProvenanceType::FileChange { .. })));
        assert!(chain
            .iter()
            .any(|r| matches!(&r.record_type, ProvenanceType::ToolInvocation { .. })));
        assert!(chain
            .iter()
            .any(|r| matches!(&r.record_type, ProvenanceType::Inference { .. })));
        assert!(chain
            .iter()
            .any(|r| matches!(&r.record_type, ProvenanceType::Request { .. })));
        assert!(chain
            .iter()
            .any(|r| matches!(&r.record_type, ProvenanceType::Governance { .. })));
    }

    #[test]
    fn trace_chain_empty_for_unlinked_file() {
        let (store, _dir) = temp_store();
        let branch = "branch-no-links";

        // Record a file change with no invocation_id link.
        store
            .record(&make_file_change_record(branch, "src/main.rs"))
            .unwrap();

        let chain = store.trace_chain(branch, "src/main.rs").unwrap();
        // Should find the FileChange but no upstream links.
        assert_eq!(chain.len(), 1);
        assert!(matches!(
            &chain[0].record_type,
            ProvenanceType::FileChange { .. }
        ));
    }

    #[test]
    fn trace_chain_nonexistent_file() {
        let (store, _dir) = temp_store();
        let chain = store.trace_chain("branch-x", "no-such-file.rs").unwrap();
        assert!(chain.is_empty());
    }

    #[test]
    fn get_chain_groups_by_type() {
        let (store, _dir) = temp_store();
        let branch = "branch-chain";

        store.record(&make_request_record(branch)).unwrap();
        store.record(&make_inference_record(branch, "r1")).unwrap();
        store.record(&make_inference_record(branch, "r2")).unwrap();
        store.record(&make_tool_record(branch)).unwrap();
        store
            .record(&make_file_change_record(branch, "f.rs"))
            .unwrap();
        store
            .record(&make_governance_record(branch, "approved"))
            .unwrap();

        let chain = store.get_chain(branch).unwrap();
        assert_eq!(chain.branch_id, branch);
        assert_eq!(chain.requests.len(), 1);
        assert_eq!(chain.inferences.len(), 2);
        assert_eq!(chain.tool_invocations.len(), 1);
        assert_eq!(chain.file_changes.len(), 1);
        assert_eq!(chain.governance.len(), 1);
    }

    #[test]
    fn cleanup_branch_removes_data() {
        let (store, _dir) = temp_store();
        let branch = "branch-cleanup";

        store.record(&make_request_record(branch)).unwrap();
        assert_eq!(store.get_records(branch).unwrap().len(), 1);

        store.cleanup_branch(branch).unwrap();
        assert!(store.get_records(branch).unwrap().is_empty());

        // Cleanup of already-cleaned branch is idempotent.
        store.cleanup_branch(branch).unwrap();
    }

    #[test]
    fn cleanup_nonexistent_branch_is_idempotent() {
        let (store, _dir) = temp_store();
        // Should not error on a branch that was never created.
        store.cleanup_branch("never-existed").unwrap();
    }

    #[test]
    fn record_file_changes_helper() {
        let (store, _dir) = temp_store();
        let branch = "branch-fc";

        let changes = vec![
            FileChange {
                path: PathBuf::from("src/main.rs"),
                kind: FileChangeKind::Modified,
                size: 1024,
                checksum: "abc123".to_string(),
                old_size: None,
                old_mode: None,
                new_mode: None,
                timestamp: None,
                target: None,
                entropy: None,
                has_base64_blocks: None,
            },
            FileChange {
                path: PathBuf::from("README.md"),
                kind: FileChangeKind::Added,
                size: 256,
                checksum: "def456".to_string(),
                old_size: None,
                old_mode: None,
                new_mode: None,
                timestamp: None,
                target: None,
                entropy: None,
                has_base64_blocks: None,
            },
            FileChange {
                path: PathBuf::from("old.txt"),
                kind: FileChangeKind::Deleted,
                size: 0,
                checksum: String::new(),
                old_size: None,
                old_mode: None,
                new_mode: None,
                timestamp: None,
                target: None,
                entropy: None,
                has_base64_blocks: None,
            },
        ];

        record_file_changes(&store, branch, &changes, None).unwrap();

        let records = store.get_records(branch).unwrap();
        assert_eq!(records.len(), 3);

        // All should be FileChange type.
        for r in &records {
            assert!(matches!(r.record_type, ProvenanceType::FileChange { .. }));
        }

        // Check specific paths in the FileChange variants.
        if let ProvenanceType::FileChange {
            path,
            kind,
            size,
            checksum,
            ..
        } = &records[0].record_type
        {
            assert_eq!(path, "src/main.rs");
            assert_eq!(*kind, FileChangeKind::Modified);
            assert_eq!(*size, 1024);
            assert_eq!(checksum, "abc123");
        } else {
            panic!("expected FileChange");
        }

        if let ProvenanceType::FileChange { kind, .. } = &records[1].record_type {
            assert_eq!(*kind, FileChangeKind::Added);
        }

        if let ProvenanceType::FileChange { kind, .. } = &records[2].record_type {
            assert_eq!(*kind, FileChangeKind::Deleted);
        }
    }

    #[test]
    fn record_file_changes_with_invocation_id() {
        let (store, _dir) = temp_store();
        let branch = "branch-fc-inv";
        let inv_id = "inv-123";

        let changes = vec![FileChange {
            path: PathBuf::from("src/main.rs"),
            kind: FileChangeKind::Modified,
            size: 512,
            checksum: "abc".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
            entropy: None,
            has_base64_blocks: None,
        }];

        record_file_changes(&store, branch, &changes, Some(inv_id)).unwrap();

        let records = store.get_records(branch).unwrap();
        assert_eq!(records.len(), 1);
        if let ProvenanceType::FileChange { invocation_id, .. } = &records[0].record_type {
            assert_eq!(invocation_id.as_deref(), Some(inv_id));
        } else {
            panic!("expected FileChange");
        }
    }

    #[test]
    fn record_governance_helper() {
        let (store, _dir) = temp_store();
        let branch = "branch-gov";

        let decision_id = record_governance(
            &store,
            branch,
            "v1.2.0",
            "approved",
            &[],
            Some("sha256:abc123".to_string()),
            &["change-1".to_string(), "change-2".to_string()],
        )
        .unwrap();

        assert!(!decision_id.is_empty());

        let records = store.get_records(branch).unwrap();
        assert_eq!(records.len(), 1);

        let r = &records[0];
        assert_eq!(r.id, decision_id);
        if let ProvenanceType::Governance {
            policy_version,
            result,
            violations,
            manifest_hash,
            change_ids,
            ..
        } = &r.record_type
        {
            assert_eq!(policy_version, "v1.2.0");
            assert_eq!(result, "approved");
            assert!(violations.is_empty());
            assert_eq!(manifest_hash.as_deref(), Some("sha256:abc123"));
            assert_eq!(change_ids, &["change-1", "change-2"]);
        } else {
            panic!("expected Governance");
        }
    }

    #[test]
    fn record_governance_with_violations() {
        let (store, _dir) = temp_store();
        let branch = "branch-gov-v";

        record_governance(
            &store,
            branch,
            "v1.0.0",
            "rejected",
            &[
                "sensitive file in changeset".to_string(),
                "executable permission change".to_string(),
            ],
            None,
            &[],
        )
        .unwrap();

        let records = store.get_records(branch).unwrap();
        assert_eq!(records.len(), 1);
        if let ProvenanceType::Governance {
            result,
            violations,
            manifest_hash,
            ..
        } = &records[0].record_type
        {
            assert_eq!(result, "rejected");
            assert_eq!(violations.len(), 2);
            assert!(violations[0].contains("sensitive file"));
            assert!(manifest_hash.is_none());
        } else {
            panic!("expected Governance");
        }
    }

    #[test]
    fn empty_branch_returns_empty_records() {
        let (store, _dir) = temp_store();
        let records = store.get_records("nonexistent-branch").unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn serialization_roundtrip() {
        let (store, _dir) = temp_store();
        let branch = "branch-roundtrip";

        let r1 = make_request_record(branch);
        let r2 = make_inference_record(branch, "req-1");
        let r3 = make_tool_record(branch);
        let r4 = make_file_change_record(branch, "test.rs");
        let r5 = make_governance_record(branch, "approved");

        let ids: Vec<String> = [&r1, &r2, &r3, &r4, &r5]
            .iter()
            .map(|r| r.id.clone())
            .collect();

        store.record(&r1).unwrap();
        store.record(&r2).unwrap();
        store.record(&r3).unwrap();
        store.record(&r4).unwrap();
        store.record(&r5).unwrap();

        let records = store.get_records(branch).unwrap();
        assert_eq!(records.len(), 5);

        for (i, r) in records.iter().enumerate() {
            assert_eq!(r.id, ids[i]);
            assert_eq!(r.branch_id, branch);
        }
    }

    #[test]
    fn sequential_writes_do_not_corrupt() {
        let (store, _dir) = temp_store();
        let branch = "branch-seq";
        let count = 50;

        for _ in 0..count {
            let r = make_tool_record(branch);
            store.record(&r).unwrap();
        }

        let records = store.get_records(branch).unwrap();
        assert_eq!(records.len(), count);

        for r in &records {
            assert!(matches!(
                r.record_type,
                ProvenanceType::ToolInvocation { .. }
            ));
        }
    }

    #[test]
    fn uuid_v7_ids_are_time_ordered() {
        // UUID v7 should produce chronologically ordered IDs.
        let id1 = new_id();
        let id2 = new_id();
        let id3 = new_id();
        // String comparison of UUID v7 preserves chronological order.
        assert!(id1 <= id2);
        assert!(id2 <= id3);
    }

    #[test]
    fn tool_invocation_started_at_exited_at() {
        let (store, _dir) = temp_store();
        let branch = "branch-timestamps";

        let r = make_tool_record(branch);
        store.record(&r).unwrap();

        let records = store.get_records(branch).unwrap();
        assert_eq!(records.len(), 1);
        if let ProvenanceType::ToolInvocation {
            started_at,
            exited_at,
            ..
        } = &records[0].record_type
        {
            assert!(started_at.is_some());
            assert!(exited_at.is_some());
        } else {
            panic!("expected ToolInvocation");
        }
    }

    // -----------------------------------------------------------------------
    // Path traversal rejection (Fix 1)
    // -----------------------------------------------------------------------

    #[test]
    fn rejects_path_traversal_in_branch_id() {
        let (store, _dir) = temp_store();

        // Direct traversal
        let r = ProvenanceRecord {
            id: new_id(),
            branch_id: "../../etc".to_string(),
            record_type: ProvenanceType::Request {
                request_id: new_id(),
                user_uid: 1000,
                prompt_hash: "sha256:abc".to_string(),
            },
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        assert!(store.record(&r).is_err());

        // Slash in branch_id
        assert!(store.get_records("foo/bar").is_err());

        // Null byte
        assert!(store.cleanup_branch("foo\0bar").is_err());

        // Empty
        assert!(store.record_batch("", &[]).is_err());

        // Control character
        assert!(store.get_records("foo\nbar").is_err());
    }

    #[test]
    fn accepts_valid_branch_ids() {
        let (store, _dir) = temp_store();
        // Normal branch IDs should work fine
        assert!(store.get_records("branch-001").unwrap().is_empty());
        assert!(store.get_records("abc_123").unwrap().is_empty());
        assert!(store
            .get_records("550e8400-e29b-41d4-a716-446655440000")
            .unwrap()
            .is_empty());
    }

    // -----------------------------------------------------------------------
    // trace_chain deduplication (Fix 2)
    // -----------------------------------------------------------------------

    #[test]
    fn trace_chain_deduplicates_shared_upstream() {
        let (store, _dir) = temp_store();
        let branch = "branch-dedup";

        // Create a scenario where 3 files are modified by the same tool
        // invocation under the same inference and request.
        let req_id = new_id();
        let inf_id = new_id();
        let inv_id = new_id();
        let change_id_1 = new_id();
        let change_id_2 = new_id();
        let change_id_3 = new_id();

        let request = ProvenanceRecord {
            id: new_id(),
            branch_id: branch.to_string(),
            record_type: ProvenanceType::Request {
                request_id: req_id.clone(),
                user_uid: 1000,
                prompt_hash: "sha256:abc".to_string(),
            },
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let inference = ProvenanceRecord {
            id: new_id(),
            branch_id: branch.to_string(),
            record_type: ProvenanceType::Inference {
                inference_id: inf_id.clone(),
                request_id: req_id.clone(),
                model: "test-model".to_string(),
                token_count: 100,
                tool_calls: vec!["write_file".to_string()],
            },
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let invocation = ProvenanceRecord {
            id: new_id(),
            branch_id: branch.to_string(),
            record_type: ProvenanceType::ToolInvocation {
                invocation_id: inv_id.clone(),
                inference_id: Some(inf_id.clone()),
                tool_path: "/usr/bin/python3".to_string(),
                arguments_hash: None,
                pid: 1234,
                exit_code: Some(0),
                started_at: None,
                exited_at: None,
            },
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        // 3 file changes from the SAME invocation, all at the same path
        // (e.g., file modified 3 times within the branch lifecycle).
        for (i, cid) in [&change_id_1, &change_id_2, &change_id_3]
            .iter()
            .enumerate()
        {
            let fc = ProvenanceRecord {
                id: new_id(),
                branch_id: branch.to_string(),
                record_type: ProvenanceType::FileChange {
                    change_id: cid.to_string(),
                    invocation_id: Some(inv_id.clone()),
                    path: "src/main.rs".to_string(),
                    kind: FileChangeKind::Modified,
                    size: 1024 + i as u64,
                    checksum: format!("sha256:{i}"),
                },
                timestamp: chrono::Utc::now().to_rfc3339(),
            };
            store.record(&fc).unwrap();
        }

        let governance = ProvenanceRecord {
            id: new_id(),
            branch_id: branch.to_string(),
            record_type: ProvenanceType::Governance {
                decision_id: new_id(),
                change_ids: vec![change_id_1, change_id_2, change_id_3],
                policy_version: "v1.0.0".to_string(),
                result: "approved".to_string(),
                violations: vec![],
                manifest_hash: None,
            },
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        store.record(&request).unwrap();
        store.record(&inference).unwrap();
        store.record(&invocation).unwrap();
        store.record(&governance).unwrap();

        let chain = store.trace_chain(branch, "src/main.rs").unwrap();

        // Should have: 3 FileChanges + 1 ToolInvocation + 1 Inference +
        // 1 Request + 1 Governance = 7 total (NOT 3+3+3+3+1 = 13).
        assert_eq!(chain.len(), 7, "chain should be deduplicated: {chain:?}");

        // Verify exactly one of each non-FileChange type.
        let tool_count = chain
            .iter()
            .filter(|r| matches!(r.record_type, ProvenanceType::ToolInvocation { .. }))
            .count();
        assert_eq!(tool_count, 1, "should have exactly 1 ToolInvocation");

        let inf_count = chain
            .iter()
            .filter(|r| matches!(r.record_type, ProvenanceType::Inference { .. }))
            .count();
        assert_eq!(inf_count, 1, "should have exactly 1 Inference");

        let req_count = chain
            .iter()
            .filter(|r| matches!(r.record_type, ProvenanceType::Request { .. }))
            .count();
        assert_eq!(req_count, 1, "should have exactly 1 Request");
    }

    /// K83: Verify that MAX_WRITE_LOCKS constant exists and bounds the write_locks map.
    #[test]
    fn k83_max_write_locks_constant_exists() {
        let source = include_str!("provenance.rs");
        assert!(
            source.contains("const MAX_WRITE_LOCKS: usize = 10_000;"),
            "K83: MAX_WRITE_LOCKS constant must be defined"
        );
        assert!(
            source.contains("Arc::strong_count(v) > 1"),
            "K83: stale entries with strong_count == 1 must be evicted"
        );
    }
}
