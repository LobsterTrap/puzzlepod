// SPDX-License-Identifier: Apache-2.0
//! Persistent audit event storage.
//!
//! Stores audit events in append-only NDJSON format for querying
//! and export. Each event is timestamped and assigned a sequence number.
//!
//! Supports filtering by branch ID, event type, and time range.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use puzzled_types::{AgentIdentity, GovernanceDecision};

use crate::attestation::{self, MerkleTree};
use crate::audit::AuditEvent;
use crate::error::{PuzzledError, Result};

/// Fsync a directory to ensure directory entries (new/renamed files) are durable.
/// This is necessary on ext4/XFS where file content fsync does not imply directory entry durability.
fn fsync_dir(dir: &Path) {
    match std::fs::File::open(dir) {
        Ok(d) => {
            if let Err(e) = d.sync_all() {
                tracing::warn!(
                    dir = %dir.display(),
                    error = %e,
                    "fsync_dir: failed to sync directory — audit durability may be reduced"
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                dir = %dir.display(),
                error = %e,
                "fsync_dir: failed to open directory for sync — audit durability may be reduced"
            );
        }
    }
}

/// A stored audit event with metadata.
///
/// When attestation is enabled, governance-significant events additionally
/// carry Ed25519 signatures and Merkle tree leaf indices for third-party
/// verifiability. All attestation fields are `Option` for backward
/// compatibility — v1.0 audit stores (without attestation) are read cleanly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAuditEvent {
    /// Monotonic sequence number.
    pub seq: u64,
    /// Timestamp (RFC 3339).
    pub timestamp: String,
    /// The audit event itself.
    pub event: AuditEventRecord,
    /// HMAC-SHA256 of this entry chained with the previous entry's HMAC.
    /// Enables tamper detection: if any entry is modified, all subsequent
    /// HMACs become invalid. Retained even when attestation is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac: Option<String>,

    // --- Attestation fields (§3.1) ---
    /// UUID v7 (time-ordered) record identifier. `None` if attestation disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,
    /// Identity of the agent that produced this event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_identity: Option<AgentIdentity>,
    /// SHA-256 of the active policy set at the time of the event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
    /// SHA-256 of the changeset (commit/reject events only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changeset_hash: Option<String>,
    /// Governance decision ("approved", "rejected", "rollback", etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_decision: Option<GovernanceDecision>,
    /// Links to the preceding attestation record in this branch's chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_record_id: Option<String>,
    /// Ed25519 signature (hex) over canonical form of all attestation fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Position in the global Merkle tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_leaf_index: Option<u64>,
}

/// Serializable audit event record (mirrors AuditEvent but with string fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEventRecord {
    pub event_type: String,
    pub branch_id: Option<String>,
    pub details: serde_json::Value,
}

/// Persistent audit event store.
pub struct AuditStore {
    store_dir: PathBuf,
    next_seq: u64,
    /// HMAC key for chain integrity (generated on first use).
    hmac_key: [u8; 32],
    /// Previous entry's HMAC for chaining.
    prev_hmac: String,

    // --- Attestation state (§3.1) ---
    /// Whether attestation signing is enabled.
    attestation_enabled: bool,
    /// Ed25519 signing key for attestation records (shared with IMA).
    signing_key: Option<ed25519_dalek::SigningKey>,
    /// Merkle tree for append-only attestation log.
    merkle_tree: Option<MerkleTree>,
    /// Per-branch chain tracker: maps branch_id → most recent record_id.
    branch_chains: HashMap<String, String>,
    /// SHA-256 hash of the currently loaded policy set.
    current_policy_hash: Option<String>,
    /// §3.1: Count of governance-significant events since last checkpoint.
    events_since_checkpoint: u64,
    /// §3.1: Checkpoint interval (number of governance-significant records).
    checkpoint_interval: u64,
    /// §3.1: Directory for attestation checkpoints.
    checkpoint_dir: Option<PathBuf>,
    /// §3.1: Timestamp of last checkpoint (for time-based triggering).
    last_checkpoint_time: std::time::Instant,
    /// §3.1: Time interval for automatic checkpoints (seconds, 0 = disabled).
    checkpoint_time_interval_secs: u64,
}

impl AuditStore {
    /// Create a new audit store without attestation.
    pub fn new(store_dir: PathBuf) -> Result<Self> {
        Self::new_with_attestation(store_dir, false, None, None, None, 0, 0)
    }

    /// Create a new audit store with optional attestation support.
    ///
    /// When `attestation_enabled` is `true`, governance-significant events
    /// are signed with Ed25519 and appended to a Merkle tree.
    pub fn new_with_attestation(
        store_dir: PathBuf,
        attestation_enabled: bool,
        signing_key: Option<ed25519_dalek::SigningKey>,
        attestation_dir: Option<PathBuf>,
        checkpoint_dir: Option<PathBuf>,
        checkpoint_interval: u64,
        checkpoint_time_interval_secs: u64,
    ) -> Result<Self> {
        if !store_dir.exists() {
            std::fs::create_dir_all(&store_dir)
                .map_err(|e| PuzzledError::AuditStore(format!("creating audit dir: {}", e)))?;
        }

        // Determine next sequence number from existing events
        let next_seq = Self::count_existing_events(&store_dir);

        tracing::info!(
            store_dir = %store_dir.display(),
            next_seq,
            attestation = attestation_enabled,
            "audit store initialized"
        );

        // Generate or load HMAC key for chain integrity
        let key_path = store_dir.join(".hmac_key");
        let hmac_key = if key_path.exists() {
            let key_bytes = std::fs::read(&key_path)
                .map_err(|e| PuzzledError::AuditStore(format!("reading HMAC key: {}", e)))?;
            if key_bytes.len() < 32 {
                return Err(PuzzledError::AuditStore(format!(
                    "HMAC key file {} is truncated: {} bytes (expected >= 32). \
                     This indicates corruption — refusing to use a weak key.",
                    key_path.display(),
                    key_bytes.len()
                )));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes[..32]);
            key
        } else {
            let mut key = [0u8; 32];
            getrandom::getrandom(&mut key)
                .map_err(|e| PuzzledError::AuditStore(format!("generating HMAC key: {}", e)))?;

            // A-C1: Create HMAC key file atomically with restricted permissions (0600)
            // to prevent TOCTOU race where a local attacker could read the key between
            // create (default umask, typically 0644) and chmod.
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&key_path)
                    .map_err(|e| PuzzledError::AuditStore(format!("creating HMAC key: {}", e)))?;
                file.write_all(&key)
                    .map_err(|e| PuzzledError::AuditStore(format!("writing HMAC key: {}", e)))?;
                file.sync_all()
                    .map_err(|e| PuzzledError::AuditStore(format!("fsync HMAC key: {}", e)))?;
            }
            #[cfg(not(unix))]
            {
                std::fs::write(&key_path, key)
                    .map_err(|e| PuzzledError::AuditStore(format!("saving HMAC key: {}", e)))?;
            }

            key
        };

        // R7: Recover previous HMAC from last entry with explicit logging
        let prev_hmac = Self::last_hmac(&store_dir).unwrap_or_else(|| {
            tracing::warn!("R7: no previous HMAC found — starting fresh audit chain");
            String::new()
        });

        // Initialize Merkle tree if attestation is enabled
        let mut merkle_tree = if attestation_enabled {
            let tree_dir = attestation_dir.unwrap_or_else(|| store_dir.join("attestation"));
            Some(MerkleTree::new(tree_dir)?)
        } else {
            None
        };

        // Recover per-branch chain state from existing events
        let branch_chains = if attestation_enabled {
            Self::recover_branch_chains(&store_dir)
        } else {
            HashMap::new()
        };

        // A-C1: Reconcile NDJSON records with Merkle tree on startup.
        // If puzzled crashed between NDJSON write and Merkle append, the NDJSON
        // will have records with merkle_leaf_index >= tree.size(). We re-append
        // their canonical forms to the tree to restore consistency.
        if let Some(ref mut tree) = merkle_tree {
            let size_before = tree.size();
            Self::reconcile_ndjson_merkle(&store_dir, tree);

            // A-I2: If reconciliation appended records, update the root_hash file
            // via checkpoint so it reflects the reconciled tree state.
            if tree.size() > size_before {
                if let Some(ref cp_dir) = checkpoint_dir {
                    if let Err(e) = tree.checkpoint(cp_dir) {
                        tracing::warn!(
                            error = %e,
                            "A-I2: post-reconciliation checkpoint failed — root_hash may be stale"
                        );
                    }
                }
            }
        }

        Ok(Self {
            store_dir,
            next_seq,
            hmac_key,
            prev_hmac,
            attestation_enabled,
            signing_key,
            merkle_tree,
            branch_chains,
            current_policy_hash: None,
            events_since_checkpoint: 0,
            checkpoint_interval,
            checkpoint_dir,
            last_checkpoint_time: std::time::Instant::now(),
            checkpoint_time_interval_secs,
        })
    }

    /// Set the current policy hash (called when policies are loaded/reloaded).
    pub fn set_policy_hash(&mut self, hash: String) {
        self.current_policy_hash = Some(hash);
    }

    /// Get the current policy hash (set via `set_policy_hash`).
    pub fn policy_hash(&self) -> Option<&str> {
        self.current_policy_hash.as_deref()
    }

    /// Get a reference to the Merkle tree (if attestation is enabled).
    pub fn merkle_tree(&self) -> Option<&MerkleTree> {
        self.merkle_tree.as_ref()
    }

    /// Count existing events to determine the next sequence number.
    /// If the last line is truncated (invalid JSON from a crash), it is removed.
    ///
    /// A-I1: Uses `BufRead::read_line()` instead of `BufReader::lines()` to preserve
    /// the exact line terminator (`\n` or `\r\n`), giving accurate byte offset tracking
    /// for file truncation on crash recovery.
    // H41: Open file once with read+write and reuse the same handle for
    // counting and truncation, eliminating the TOCTOU race where the file
    // could be swapped between the read pass and the truncation open.
    fn count_existing_events(store_dir: &Path) -> u64 {
        use std::io::BufRead;
        // J25: Compile-time assertion that usize fits in u64, making the
        // `bytes_read as u64` casts below safe on all supported platforms
        // (x86_64 and aarch64 where usize is 64-bit).
        const _: () = assert!(std::mem::size_of::<usize>() <= std::mem::size_of::<u64>());

        let log_path = store_dir.join("events.ndjson");
        if !log_path.exists() {
            return 0;
        }
        // H41: Single open with read+write for both counting and truncation
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&log_path)
        {
            Ok(f) => f,
            Err(_) => return 0,
        };
        let mut reader = std::io::BufReader::new(&file);
        let mut count: u64 = 0;
        let mut last_valid_offset: u64 = 0;
        let mut current_offset: u64 = 0;
        let mut line = String::new();
        let mut last_line_valid = true;

        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break, // EOF
                Ok(bytes_read) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        current_offset += bytes_read as u64;
                        continue;
                    }
                    if serde_json::from_str::<serde_json::Value>(trimmed).is_ok() {
                        count += 1;
                        last_valid_offset = current_offset + bytes_read as u64;
                        last_line_valid = true;
                    } else {
                        last_line_valid = false;
                    }
                    current_offset += bytes_read as u64;
                }
                Err(_) => break,
            }
        }

        if !last_line_valid && count > 0 {
            // H41: Truncate using the same file handle — no second open needed
            if file.set_len(last_valid_offset).is_ok() {
                tracing::warn!(
                    path = %log_path.display(),
                    truncated_to = last_valid_offset,
                    "truncated corrupt final line from NDJSON audit log"
                );
            }
        } else if !last_line_valid && count == 0 {
            // Entire file is corrupt — truncate to empty
            tracing::warn!(
                path = %log_path.display(),
                "audit store: no valid events found, truncating corrupt file"
            );
            if let Err(e) = file.set_len(0) {
                tracing::error!(
                    path = %log_path.display(),
                    error = %e,
                    "S32: failed to truncate corrupted audit store"
                );
            }
        }

        count
    }

    /// Compute HMAC-SHA256 of data chained with the previous HMAC.
    fn compute_hmac(&self, data: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        // H53: This .expect() is safe because hmac_key is always exactly 32 bytes.
        // The key is validated during AuditStore::new() — a truncated key (< 32 bytes)
        // causes an error before this code is ever reached. HMAC-SHA256 accepts
        // any key length, so 32 bytes is always valid for new_from_slice().
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key)
            .expect("HMAC key length is always valid (32 bytes)");
        mac.update(self.prev_hmac.as_bytes());
        mac.update(data.as_bytes());
        format!("{:x}", mac.finalize().into_bytes())
    }

    /// Read the last HMAC from the events file for chain recovery.
    fn last_hmac(store_dir: &Path) -> Option<String> {
        use std::io::BufRead;

        let events_file = store_dir.join("events.ndjson");
        if !events_file.exists() {
            return None;
        }

        let file = std::fs::File::open(&events_file).ok()?;
        let reader = std::io::BufReader::new(file);
        let mut last_hmac = None;
        for line in reader.lines().map_while(|l| l.ok()) {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(stored) = serde_json::from_str::<StoredAuditEvent>(&line) {
                last_hmac = stored.hmac;
            }
        }
        last_hmac
    }

    /// S34: Constant-time comparison for HMAC values to prevent timing attacks.
    ///
    /// Standard `!=` on strings short-circuits on the first differing byte,
    /// leaking information about how many prefix bytes match. This XOR-based
    /// comparison always examines every byte.
    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        a.iter()
            .zip(b.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
    }

    /// Verify the HMAC chain integrity of the audit log.
    /// Returns Ok(count) if all entries are valid, Err with the first invalid seq.
    pub fn verify_chain(&self) -> Result<u64> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        use std::io::BufRead;

        type HmacSha256 = Hmac<Sha256>;

        let events_file = self.store_dir.join("events.ndjson");
        if !events_file.exists() {
            return Ok(0);
        }

        let file = std::fs::File::open(&events_file)
            .map_err(|e| PuzzledError::AuditStore(format!("reading events: {}", e)))?;
        let reader = std::io::BufReader::new(file);

        let mut prev_hmac = String::new();
        let mut count = 0u64;

        for line in reader.lines() {
            let line = line.map_err(|e| PuzzledError::AuditStore(format!("reading line: {}", e)))?;
            if line.trim().is_empty() {
                continue;
            }

            let stored: StoredAuditEvent = serde_json::from_str(&line)
                .map_err(|e| PuzzledError::AuditStore(format!("parsing event: {}", e)))?;

            // M19: HMAC is mandatory on every audit entry. A missing HMAC
            // indicates possible tampering or a corrupt/truncated log.
            let expected_hmac = match stored.hmac {
                Some(ref h) => h.clone(),
                None => {
                    return Err(PuzzledError::AuditStore(format!(
                        "missing HMAC on audit entry {} — possible tampering",
                        stored.seq
                    )));
                }
            };

            // Re-serialize without hmac (and without attestation fields, which
            // are populated after HMAC computation) to compute expected value.
            let mut verify_entry = stored.clone();
            verify_entry.hmac = None;
            verify_entry.record_id = None;
            verify_entry.agent_identity = None;
            verify_entry.policy_version = None;
            verify_entry.changeset_hash = None;
            verify_entry.governance_decision = None;
            verify_entry.parent_record_id = None;
            verify_entry.signature = None;
            verify_entry.merkle_leaf_index = None;
            let verify_json = serde_json::to_string(&verify_entry)
                .map_err(|e| PuzzledError::AuditStore(format!("serializing: {}", e)))?;

            let mut mac = HmacSha256::new_from_slice(&self.hmac_key)
                .expect("HMAC key length is always valid");
            mac.update(prev_hmac.as_bytes());
            mac.update(verify_json.as_bytes());
            let computed = format!("{:x}", mac.finalize().into_bytes());

            // S34: Use constant-time comparison to prevent timing attacks
            if !Self::constant_time_eq(computed.as_bytes(), expected_hmac.as_bytes()) {
                // J26: Do not expose expected/computed hash values in error messages
                // to prevent information leakage that could aid forgery attacks.
                return Err(PuzzledError::AuditStore(format!(
                    "HMAC chain broken at seq {}",
                    stored.seq
                )));
            }

            prev_hmac = expected_hmac;

            count += 1;
        }

        Ok(count)
    }

    /// Store an audit event.
    ///
    /// When attestation is enabled, governance-significant events are
    /// additionally signed with Ed25519 and appended to the Merkle tree.
    pub fn store(&mut self, event: &AuditEvent) -> Result<u64> {
        self.store_with_context(event, None, None)
    }

    /// Store an audit event with optional attestation context.
    ///
    /// `agent_identity` and `changeset_hash` provide context for attestation
    /// records. When `None`, the attestation record omits these fields.
    pub fn store_with_context(
        &mut self,
        event: &AuditEvent,
        agent_identity: Option<AgentIdentity>,
        changeset_hash: Option<String>,
    ) -> Result<u64> {
        let mut record = self.event_to_record(event);
        // H40: Inject uid from agent_identity into event details so that
        // non-root users can see their own BranchCommitted events via PH2 filtering.
        if let Some(ref identity) = agent_identity {
            if let serde_json::Value::Object(ref mut map) = record.details {
                map.entry("uid").or_insert(serde_json::json!(identity.uid));
            }
        }
        let mut stored = StoredAuditEvent {
            seq: self.next_seq,
            timestamp: now_rfc3339(),
            event: record,
            hmac: None,
            // Attestation fields default to None
            record_id: None,
            agent_identity: None,
            policy_version: None,
            changeset_hash: None,
            governance_decision: None,
            parent_record_id: None,
            signature: None,
            merkle_leaf_index: None,
        };

        // Compute HMAC chain: serialize without hmac, then add hmac
        let pre_hmac_json = serde_json::to_string(&stored)
            .map_err(|e| PuzzledError::AuditStore(format!("serializing event: {}", e)))?;
        let hmac = self.compute_hmac(&pre_hmac_json);
        stored.hmac = Some(hmac.clone());
        self.prev_hmac = hmac;

        // Attestation: sign governance-significant events.
        // A-M2: The canonical form is computed once and saved for reuse in both
        // signing and Merkle tree append, avoiding redundant serialization.
        let canonical_for_merkle = if self.attestation_enabled
            && attestation::is_governance_significant(&stored.event.event_type)
        {
            let record_id = uuid::Uuid::now_v7().to_string();
            let branch_id_str = stored.event.branch_id.clone();

            stored.record_id = Some(record_id.clone());
            stored.agent_identity = agent_identity;
            stored.policy_version = self.current_policy_hash.clone();
            stored.changeset_hash = changeset_hash;
            stored.governance_decision = Some(Self::extract_decision(&stored.event.event_type));
            stored.parent_record_id = branch_id_str
                .as_deref()
                .and_then(|bid| self.branch_chains.get(bid))
                .cloned();

            // Build canonical form once for both signing and Merkle tree append
            let canonical = Self::build_canonical_attestation(&stored);

            // Sign: canonical JSON of attestation fields (excluding
            // signature and merkle_leaf_index to avoid circular dependency)
            if let Some(ref signing_key) = self.signing_key {
                let signature = ed25519_dalek::Signer::sign(signing_key, canonical.as_bytes());
                stored.signature = Some(hex_encode_bytes(&signature.to_bytes()));
            }

            // Set Merkle leaf index BEFORE NDJSON write so the record is complete on disk.
            // The actual Merkle append happens AFTER the NDJSON write to ensure that
            // if we crash between the two operations, the NDJSON has the record but the
            // tree just needs re-appending (recoverable), rather than the tree having a
            // phantom leaf with no NDJSON record (unrecoverable).
            if let Some(ref tree) = self.merkle_tree {
                stored.merkle_leaf_index = Some(tree.size());
            }

            // Update per-branch chain tracker
            if let Some(bid) = branch_id_str {
                // J23: Evict oldest entry if at capacity to prevent unbounded growth.
                // HashMap iteration order is arbitrary, so "oldest" is approximate.
                if self.branch_chains.len() >= Self::MAX_BRANCH_CHAINS
                    && !self.branch_chains.contains_key(&bid)
                {
                    if let Some(evict_key) = self.branch_chains.keys().next().cloned() {
                        self.branch_chains.remove(&evict_key);
                    }
                }
                self.branch_chains.insert(bid, record_id);
            }

            Some(canonical)
        } else {
            None
        };

        // === NDJSON write FIRST (durable before Merkle append) ===
        // This ordering ensures that if puzzled crashes between NDJSON write and
        // Merkle append, the audit record exists on disk (recoverable by re-appending
        // to tree on restart). The reverse order would leave a phantom Merkle leaf
        // with no corresponding NDJSON record (unrecoverable).
        let json = serde_json::to_string(&stored)
            .map_err(|e| PuzzledError::AuditStore(format!("serializing event: {}", e)))?;

        let events_file = self.store_dir.join("events.ndjson");

        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&events_file)
            .map_err(|e| PuzzledError::AuditStore(format!("opening events file: {}", e)))?;

        writeln!(file, "{}", json)
            .map_err(|e| PuzzledError::AuditStore(format!("writing event: {}", e)))?;

        // Fsync to ensure audit events are durable
        file.sync_all()
            .map_err(|e| PuzzledError::AuditStore(format!("fsync events file: {}", e)))?;
        // Fsync parent directory to ensure the directory entry is durable
        // (important on first write when events.ndjson is newly created)
        fsync_dir(&self.store_dir);

        // === Merkle append AFTER NDJSON write ===
        // A-M2: Reuse the canonical form computed above for signing, avoiding
        // a redundant rebuild of the deterministic JSON representation.
        if let Some(ref canonical) = canonical_for_merkle {
            if let Some(ref mut tree) = self.merkle_tree {
                let leaf_index = tree.append(canonical.as_bytes())?;
                // A-I4: Write inclusion proof for this leaf with explicit fsync.
                // Use File::create + write_all + sync_all instead of std::fs::write
                // to ensure proof files are durable. Log warnings on errors instead
                // of silently discarding them.
                if let Ok(proof) = tree.inclusion_proof(leaf_index) {
                    let proofs_dir = tree.data_dir().join("proofs");
                    if !proofs_dir.exists() {
                        if let Err(e) = std::fs::create_dir_all(&proofs_dir) {
                            tracing::warn!(
                                error = %e,
                                "failed to create proofs directory"
                            );
                        }
                    }
                    match serde_json::to_string(&proof) {
                        Ok(proof_json) => {
                            let proof_path = proofs_dir.join(format!("{}.json", leaf_index));
                            match std::fs::File::create(&proof_path) {
                                Ok(mut f) => {
                                    use std::io::Write as _;
                                    if let Err(e) = f.write_all(proof_json.as_bytes()) {
                                        tracing::warn!(
                                            path = %proof_path.display(),
                                            error = %e,
                                            "failed to write inclusion proof file"
                                        );
                                    } else if let Err(e) = f.sync_all() {
                                        tracing::warn!(
                                            path = %proof_path.display(),
                                            error = %e,
                                            "failed to fsync inclusion proof file"
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        path = %proof_path.display(),
                                        error = %e,
                                        "failed to create inclusion proof file"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                leaf_index,
                                error = %e,
                                "failed to serialize inclusion proof"
                            );
                        }
                    }
                }
            }

            // §3.1: Periodic checkpoint triggering
            self.events_since_checkpoint += 1;
            let time_elapsed = self.checkpoint_time_interval_secs > 0
                && self.last_checkpoint_time.elapsed().as_secs()
                    >= self.checkpoint_time_interval_secs;
            let count_reached = self.checkpoint_interval > 0
                && self.events_since_checkpoint >= self.checkpoint_interval;

            if (count_reached || time_elapsed) && self.merkle_tree.is_some() {
                if let Some(ref checkpoint_dir) = self.checkpoint_dir {
                    if let Some(ref tree) = self.merkle_tree {
                        if let Err(e) = tree.checkpoint(checkpoint_dir) {
                            tracing::warn!(
                                error = %e,
                                "§3.1: automatic Merkle checkpoint failed"
                            );
                        } else {
                            tracing::info!(
                                events_since_checkpoint = self.events_since_checkpoint,
                                "§3.1: automatic Merkle checkpoint written"
                            );
                        }
                    }
                }
                self.events_since_checkpoint = 0;
                self.last_checkpoint_time = std::time::Instant::now();
            }
        }

        // H48: Safety invariant — next_seq is monotonically increasing and only
        // mutated here under the AuditStore's exclusive (&mut self) borrow.
        // AuditStore is always accessed under tokio::sync::Mutex in production
        // (see ManagerInterface.audit_store), so concurrent increments are impossible.
        let seq = self.next_seq;
        // J24: Use checked_add to detect sequence number overflow instead of wrapping
        self.next_seq = self.next_seq.checked_add(1).ok_or_else(|| {
            PuzzledError::AuditStore("sequence number overflow: u64::MAX reached".into())
        })?;
        Ok(seq)
    }

    /// H47: Maximum number of events returned by a single query.
    /// Prevents unbounded memory allocation when callers omit or set a large limit.
    const MAX_QUERY_LIMIT: u32 = 10_000;

    /// J23: Maximum number of tracked branch chains to prevent unbounded HashMap growth.
    const MAX_BRANCH_CHAINS: usize = 10_000;

    /// J23: Remove a branch's chain entry (called when a branch is committed/rolled back).
    pub fn remove_branch_chain(&mut self, branch_id: &str) {
        self.branch_chains.remove(branch_id);
    }

    /// Query audit events with optional filters.
    ///
    /// M9: Uses streaming BufReader instead of read_to_string to avoid loading
    /// the entire audit log into memory (unbounded growth protection).
    pub fn query(
        &self,
        branch_id: Option<&str>,
        event_type: Option<&str>,
        since: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Vec<StoredAuditEvent>> {
        use std::io::BufRead;

        let events_file = self.store_dir.join("events.ndjson");
        if !events_file.exists() {
            return Ok(Vec::new());
        }

        let file = std::fs::File::open(&events_file)
            .map_err(|e| PuzzledError::AuditStore(format!("reading events: {}", e)))?;
        let reader = std::io::BufReader::new(file);

        let mut results = Vec::new();
        // J20: `None` limit means unbounded (used by internal callers like
        // verify_attestation_chain / export_attestation_bundle that need the
        // full chain). `Some(n)` is capped at MAX_QUERY_LIMIT (D-Bus callers).
        let max: usize = match limit {
            Some(l) => l.min(Self::MAX_QUERY_LIMIT) as usize,
            None => usize::MAX,
        };

        for line in reader.lines() {
            let line =
                line.map_err(|e| PuzzledError::AuditStore(format!("reading event line: {}", e)))?;
            if line.trim().is_empty() {
                continue;
            }

            let stored: StoredAuditEvent = serde_json::from_str(&line)
                .map_err(|e| PuzzledError::AuditStore(format!("parsing event: {}", e)))?;

            // Apply filters
            if let Some(bid) = branch_id {
                if stored.event.branch_id.as_deref() != Some(bid) {
                    continue;
                }
            }

            if let Some(etype) = event_type {
                if stored.event.event_type != etype {
                    continue;
                }
            }

            // G8: Use proper datetime comparison instead of lexicographic string comparison.
            // Lexicographic comparison can produce wrong results when timezone offsets differ
            // (e.g., "+00:00" vs "Z") or when fractional seconds have varying precision.
            if let Some(since_ts) = since {
                let since_dt = chrono::DateTime::parse_from_rfc3339(since_ts).map_err(|e| {
                    PuzzledError::AuditStore(format!("G8: invalid since timestamp: {e}"))
                })?;
                if let Ok(stored_dt) = chrono::DateTime::parse_from_rfc3339(&stored.timestamp) {
                    if stored_dt < since_dt {
                        continue;
                    }
                }
            }

            results.push(stored);

            if results.len() >= max {
                break;
            }
        }

        Ok(results)
    }

    /// G20/K25: Maximum audit log file size for export (100 MB).
    /// Reduced from 500 MB to account for pretty-print JSON expansion
    /// (serde_json::to_string_pretty can 3-5x expand compact NDJSON).
    /// Prevents OOM when exporting large audit logs.
    const MAX_EXPORT_FILE_SIZE: u64 = 100 * 1024 * 1024;

    /// Export events in JSON or CSV format.
    /// G20: Checks file size before loading to prevent OOM on large audit logs.
    pub fn export(&self, format: &str) -> Result<String> {
        // G20: Check file size before loading all events into memory
        let events_path = self.store_dir.join("events.ndjson");
        if events_path.exists() {
            let file_size = std::fs::metadata(&events_path)
                .map(|m| m.len())
                .unwrap_or(0);
            if file_size > Self::MAX_EXPORT_FILE_SIZE {
                return Err(PuzzledError::AuditStore(format!(
                    "G20: audit log too large for in-memory export ({} bytes > {} byte limit). \
                     Use streaming export or reduce log retention.",
                    file_size,
                    Self::MAX_EXPORT_FILE_SIZE
                )));
            }
        }
        let events = self.query(None, None, None, None)?;

        match format {
            "json" => serde_json::to_string_pretty(&events)
                .map_err(|e| PuzzledError::AuditStore(format!("serializing: {}", e))),
            "csv" => {
                let mut csv = String::from("seq,timestamp,event_type,branch_id,details\n");
                for event in &events {
                    csv.push_str(&format!(
                        "{},{},{},{},{}\n",
                        event.seq,
                        csv_escape(&event.timestamp),
                        csv_escape(&event.event.event_type),
                        csv_escape(event.event.branch_id.as_deref().unwrap_or("")),
                        csv_escape(&event.event.details.to_string()),
                    ));
                }
                Ok(csv)
            }
            _ => Err(PuzzledError::AuditStore(format!(
                "unsupported export format: {}",
                format
            ))),
        }
    }

    /// Recursively sort all JSON object keys and strip null values for
    /// deterministic serialization.
    ///
    /// serde_json::Value::Object uses either BTreeMap or IndexMap depending
    /// on the `preserve_order` feature flag. This function normalizes all
    /// nested objects to sorted key order and removes null values (matching
    /// `skip_serializing_if = "Option::is_none"` behavior), ensuring canonical
    /// forms are identical regardless of feature flags or serialization path.
    fn sort_json_keys(val: serde_json::Value) -> serde_json::Value {
        match val {
            serde_json::Value::Object(map) => {
                let sorted: serde_json::Map<String, serde_json::Value> = map
                    .into_iter()
                    .filter(|(_, v)| !v.is_null())
                    .map(|(k, v)| (k, Self::sort_json_keys(v)))
                    .collect::<std::collections::BTreeMap<_, _>>()
                    .into_iter()
                    .collect();
                serde_json::Value::Object(sorted)
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.into_iter().map(Self::sort_json_keys).collect())
            }
            other => other,
        }
    }

    /// Build canonical JSON for attestation signing.
    ///
    /// Includes all fields except `signature` and `merkle_leaf_index`
    /// (to avoid circular dependency). Uses BTreeMap for deterministic
    /// key ordering, matching the pattern in `ima.rs`. Nested objects
    /// (details, agent_identity) have keys recursively sorted to ensure
    /// deterministic output regardless of serde_json feature flags.
    pub fn build_canonical_attestation(stored: &StoredAuditEvent) -> String {
        use std::collections::BTreeMap;

        let mut canonical = BTreeMap::new();
        canonical.insert("seq", serde_json::json!(stored.seq));
        canonical.insert("timestamp", serde_json::json!(stored.timestamp));
        canonical.insert("event_type", serde_json::json!(stored.event.event_type));
        if let Some(ref bid) = stored.event.branch_id {
            canonical.insert("branch_id", serde_json::json!(bid));
        }
        if let Some(ref rid) = stored.record_id {
            canonical.insert("record_id", serde_json::json!(rid));
        }
        if let Some(ref identity) = stored.agent_identity {
            // H42: Avoid bare .unwrap() on serde_json::to_value — use Null fallback
            canonical.insert(
                "agent_identity",
                Self::sort_json_keys(
                    serde_json::to_value(identity).unwrap_or(serde_json::Value::Null),
                ),
            );
        }
        if let Some(ref pv) = stored.policy_version {
            canonical.insert("policy_version", serde_json::json!(pv));
        }
        if let Some(ref ch) = stored.changeset_hash {
            canonical.insert("changeset_hash", serde_json::json!(ch));
        }
        if let Some(ref gd) = stored.governance_decision {
            // A-C2: Apply sort_json_keys to match the verifier (build_canonical_from_value),
            // which also applies sort_json_keys to governance_decision.
            // H42: Avoid bare .unwrap() on serde_json::to_value — use Null fallback
            canonical.insert(
                "governance_decision",
                Self::sort_json_keys(serde_json::to_value(gd).unwrap_or(serde_json::Value::Null)),
            );
        }
        if let Some(ref pid) = stored.parent_record_id {
            canonical.insert("parent_record_id", serde_json::json!(pid));
        }
        // N1/N10: Include event details in canonical form so the Ed25519
        // signature covers the substantive event payload (not just metadata).
        if !stored.event.details.is_null() {
            canonical.insert(
                "details",
                Self::sort_json_keys(stored.event.details.clone()),
            );
        }

        // H43: Replace .expect() with graceful fallback — log and return empty JSON object
        serde_json::to_string(&canonical).unwrap_or_else(|e| {
            tracing::error!(error = %e, "H43: BTreeMap serialization failed unexpectedly");
            "{}".to_string()
        })
    }

    /// Map event type string to a GovernanceDecision.
    fn extract_decision(event_type: &str) -> GovernanceDecision {
        match event_type {
            "branch_created" => GovernanceDecision::Created,
            "branch_committed" => GovernanceDecision::Approved,
            "branch_rolled_back" => GovernanceDecision::Rollback,
            "policy_violation" => GovernanceDecision::Violation,
            "commit_rejected" => GovernanceDecision::Rejected,
            "sandbox_escape" => GovernanceDecision::Escape,
            "agent_killed" => GovernanceDecision::Killed,
            "behavioral_trigger" => GovernanceDecision::Violation,
            _ => GovernanceDecision::Violation,
        }
    }

    /// Recover per-branch chain state from existing NDJSON events.
    fn recover_branch_chains(store_dir: &Path) -> HashMap<String, String> {
        use std::io::BufRead;

        let events_file = store_dir.join("events.ndjson");
        let mut chains = HashMap::new();

        if !events_file.exists() {
            return chains;
        }

        let file = match std::fs::File::open(&events_file) {
            Ok(f) => f,
            Err(_) => return chains,
        };

        // G11: Use filter_map instead of map_while to skip corrupted lines
        // without stopping iteration. map_while stops at the first I/O error,
        // losing all subsequent branch chain state.
        for line in std::io::BufReader::new(file)
            .lines()
            .filter_map(|l| match l {
                Ok(line) => Some(line),
                Err(e) => {
                    tracing::warn!("G11: skipping corrupted audit line during recovery: {e}");
                    None
                }
            })
        {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(stored) = serde_json::from_str::<StoredAuditEvent>(&line) {
                if let (Some(bid), Some(rid)) = (stored.event.branch_id, stored.record_id) {
                    chains.insert(bid, rid);
                }
            }
        }

        chains
    }

    /// A-C1: Reconcile NDJSON records with Merkle tree after a potential crash.
    ///
    /// Scans the NDJSON events file for records whose `merkle_leaf_index` is
    /// >= the current tree size (meaning the Merkle append never completed).
    ///
    /// Re-appends their canonical forms to the tree to restore consistency.
    fn reconcile_ndjson_merkle(store_dir: &Path, tree: &mut MerkleTree) {
        use std::io::BufRead;

        let events_file = store_dir.join("events.ndjson");
        if !events_file.exists() {
            return;
        }

        let file = match std::fs::File::open(&events_file) {
            Ok(f) => f,
            Err(_) => return,
        };

        let tree_size = tree.size();
        let mut reconciled_count = 0u64;

        for line in std::io::BufReader::new(file).lines().map_while(|l| l.ok()) {
            if line.trim().is_empty() {
                continue;
            }
            let stored: StoredAuditEvent = match serde_json::from_str(&line) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if let Some(leaf_index) = stored.merkle_leaf_index {
                if leaf_index >= tree_size {
                    // This record's Merkle append was lost — re-append.
                    // A-I5: The actual_leaf_index returned by tree.append() may
                    // differ from the expected_leaf_index stored in the NDJSON
                    // record if multiple records were lost and re-appended in a
                    // different order than originally written.  We cannot update
                    // the NDJSON record inline (append-only file), so we log the
                    // inconsistency at error level when indices diverge.
                    let canonical = Self::build_canonical_attestation(&stored);
                    match tree.append(canonical.as_bytes()) {
                        Ok(new_index) => {
                            if new_index != leaf_index {
                                // A-I5: The stored merkle_leaf_index in the
                                // NDJSON file is now stale — it records
                                // `leaf_index` but the tree assigned
                                // `new_index`.  Inclusion proofs for this
                                // record must use `new_index`, not the value
                                // stored in the NDJSON file.
                                tracing::error!(
                                    seq = stored.seq,
                                    stored_leaf_index = leaf_index,
                                    actual_leaf_index = new_index,
                                    "A-I5: reconciled NDJSON record but leaf index \
                                     diverged — NDJSON merkle_leaf_index is stale; \
                                     inclusion proofs must use actual_leaf_index"
                                );
                            } else {
                                tracing::warn!(
                                    seq = stored.seq,
                                    leaf_index = new_index,
                                    "A-C1: reconciled NDJSON record with Merkle tree \
                                     (crash between NDJSON write and Merkle append)"
                                );
                            }
                            reconciled_count += 1;
                        }
                        Err(e) => {
                            tracing::error!(
                                seq = stored.seq,
                                error = %e,
                                "A-C1: failed to reconcile NDJSON record with Merkle tree"
                            );
                        }
                    }
                }
            }
        }

        if reconciled_count > 0 {
            tracing::warn!(
                reconciled_count,
                "A-C1: reconciled {} NDJSON record(s) with Merkle tree on startup",
                reconciled_count
            );
        }
    }

    /// Convert an AuditEvent to a storable record.
    fn event_to_record(&self, event: &AuditEvent) -> AuditEventRecord {
        match event {
            AuditEvent::AgentRegistered { agent_id, profile } => AuditEventRecord {
                event_type: "agent_registered".to_string(),
                branch_id: None,
                details: serde_json::json!({
                    "agent_id": agent_id,
                    "profile": profile,
                }),
            },
            AuditEvent::BranchCreated {
                branch_id,
                profile,
                uid,
            } => AuditEventRecord {
                event_type: "branch_created".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({
                    "profile": profile,
                    "uid": uid,
                }),
            },
            AuditEvent::BranchCommitted {
                branch_id,
                files,
                bytes,
            } => AuditEventRecord {
                event_type: "branch_committed".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({
                    "files": files,
                    "bytes": bytes,
                }),
            },
            AuditEvent::BranchRolledBack { branch_id, reason } => AuditEventRecord {
                event_type: "branch_rolled_back".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({
                    "reason": reason,
                }),
            },
            AuditEvent::PolicyViolation {
                branch_id,
                rule,
                message,
            } => AuditEventRecord {
                event_type: "policy_violation".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({
                    "rule": rule,
                    "message": message,
                }),
            },
            AuditEvent::CommitRejected { branch_id, reason } => AuditEventRecord {
                event_type: "commit_rejected".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({
                    "reason": reason,
                }),
            },
            AuditEvent::SandboxEscape { branch_id, detail } => AuditEventRecord {
                event_type: "sandbox_escape".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({
                    "detail": detail,
                }),
            },
            AuditEvent::BranchFrozen { branch_id } => AuditEventRecord {
                event_type: "branch_frozen".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({}),
            },
            AuditEvent::AgentExecGated {
                branch_id,
                path,
                allowed,
            } => AuditEventRecord {
                event_type: "exec_gated".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({
                    "path": path,
                    "allowed": allowed,
                }),
            },
            AuditEvent::AgentConnectGated {
                branch_id,
                address,
                allowed,
            } => AuditEventRecord {
                event_type: "connect_gated".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({
                    "address": address,
                    "allowed": allowed,
                }),
            },
            AuditEvent::ProfileLoaded { profile } => AuditEventRecord {
                event_type: "profile_loaded".to_string(),
                branch_id: None,
                details: serde_json::json!({
                    "profile": profile,
                }),
            },
            AuditEvent::PolicyReloaded { policies_loaded } => AuditEventRecord {
                event_type: "policy_reloaded".to_string(),
                branch_id: None,
                details: serde_json::json!({
                    "policies_loaded": policies_loaded,
                }),
            },
            AuditEvent::BehavioralTrigger { branch_id, trigger } => AuditEventRecord {
                event_type: "behavioral_trigger".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({
                    "trigger": trigger,
                }),
            },
            AuditEvent::SeccompDecision {
                branch_id,
                syscall,
                allowed,
            } => AuditEventRecord {
                event_type: "seccomp_decision".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({
                    "syscall": syscall,
                    "allowed": allowed,
                }),
            },
            AuditEvent::WalRecovery { branches_recovered } => AuditEventRecord {
                event_type: "wal_recovery".to_string(),
                branch_id: None,
                details: serde_json::json!({
                    "branches_recovered": branches_recovered,
                }),
            },
            AuditEvent::AgentKilled {
                branch_id,
                caller_uid,
            } => AuditEventRecord {
                event_type: "agent_killed".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({
                    "caller_uid": caller_uid,
                    "uid": caller_uid,
                }),
            },
            AuditEvent::NetworkGate {
                branch_id,
                address,
                method,
                allowed,
            } => AuditEventRecord {
                event_type: "network_gate".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({
                    "address": address,
                    "method": method,
                    "allowed": allowed,
                }),
            },
            AuditEvent::OomRollback { branch_id } => AuditEventRecord {
                event_type: "oom_rollback".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({}),
            },
            AuditEvent::TimeoutRollback {
                branch_id,
                timeout_seconds,
            } => AuditEventRecord {
                event_type: "timeout_rollback".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({
                    "timeout_seconds": timeout_seconds,
                }),
            },
            AuditEvent::Conflict {
                branch_id,
                conflicting_branch,
                paths,
            } => AuditEventRecord {
                event_type: "conflict".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({
                    "conflicting_branch": conflicting_branch,
                    "paths": paths,
                }),
            },
            AuditEvent::DlpBlocked {
                branch_id,
                rule_name,
                domain,
                direction,
            } => AuditEventRecord {
                event_type: "dlp_blocked".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({
                    "rule_name": rule_name,
                    "domain": domain,
                    "direction": direction,
                }),
            },
            AuditEvent::DlpRedacted {
                branch_id,
                rule_name,
                redactions,
            } => AuditEventRecord {
                event_type: "dlp_redacted".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({
                    "rule_name": rule_name,
                    "redactions": redactions,
                }),
            },
            AuditEvent::DlpQuarantine {
                branch_id,
                rule_name,
                domain,
            } => AuditEventRecord {
                event_type: "dlp_quarantine".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({
                    "rule_name": rule_name,
                    "domain": domain,
                }),
            },
            AuditEvent::DlpDetected {
                branch_id,
                rule_name,
                domain,
                match_count,
            } => AuditEventRecord {
                event_type: "dlp_detected".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({
                    "rule_name": rule_name,
                    "domain": domain,
                    "match_count": match_count,
                }),
            },
            AuditEvent::CredentialInjected {
                branch_id,
                credential_name,
                domain,
            } => AuditEventRecord {
                event_type: "credential_injected".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({
                    "credential_name": credential_name,
                    "domain": domain,
                }),
            },
            AuditEvent::CredentialDenied {
                branch_id,
                credential_name,
                domain,
                reason,
            } => AuditEventRecord {
                event_type: "credential_denied".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({
                    "credential_name": credential_name,
                    "domain": domain,
                    "reason": reason,
                }),
            },
            AuditEvent::CredentialStored {
                credential_name,
                caller_uid,
            } => AuditEventRecord {
                event_type: "credential_stored".to_string(),
                branch_id: None,
                details: serde_json::json!({
                    "credential_name": credential_name,
                    "uid": caller_uid,
                }),
            },
            AuditEvent::CredentialRemoved {
                credential_name,
                caller_uid,
            } => AuditEventRecord {
                event_type: "credential_removed".to_string(),
                branch_id: None,
                details: serde_json::json!({
                    "credential_name": credential_name,
                    "uid": caller_uid,
                }),
            },
            AuditEvent::CredentialRotated {
                credential_name,
                caller_uid,
            } => AuditEventRecord {
                event_type: "credential_rotated".to_string(),
                branch_id: None,
                details: serde_json::json!({
                    "credential_name": credential_name,
                    "uid": caller_uid,
                }),
            },
            // §3.4 G29: Extended credential audit events
            AuditEvent::CredentialProvisioned {
                branch_id,
                credential_count,
            } => AuditEventRecord {
                event_type: "credential_provisioned".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({ "credential_count": credential_count }),
            },
            AuditEvent::CredentialResolveFailed {
                branch_id,
                credential_name,
                reason,
            } => AuditEventRecord {
                event_type: "credential_resolve_failed".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({ "credential_name": credential_name, "reason": reason }),
            },
            AuditEvent::CredentialResponseLeak { branch_id, domain } => AuditEventRecord {
                event_type: "credential_response_leak".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({ "domain": domain }),
            },
            AuditEvent::CredentialRevoked { branch_id } => AuditEventRecord {
                event_type: "credential_revoked".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({}),
            },
            AuditEvent::PhantomTokenStripped {
                branch_id,
                header_name,
            } => AuditEventRecord {
                event_type: "phantom_token_stripped".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({ "header_name": header_name }),
            },
            AuditEvent::CredentialBypassAttempt {
                branch_id,
                target_ip,
                target_port,
            } => AuditEventRecord {
                event_type: "credential_bypass_attempt".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({ "target_ip": target_ip, "target_port": target_port }),
            },
            AuditEvent::PhantomTokenInCommit {
                branch_id,
                file_path,
            } => AuditEventRecord {
                event_type: "phantom_token_in_commit".to_string(),
                branch_id: Some(branch_id.to_string()),
                details: serde_json::json!({ "file_path": file_path }),
            },
        }
    }
}

use puzzled_types::merkle::hex_encode as hex_encode_bytes;

/// Escape a string for safe CSV output, preventing CSV injection attacks.
/// Wraps values containing special characters in quotes and escapes embedded quotes.
/// Prefixes formula-triggering characters (=, +, -, @, |) with quoting.
fn csv_escape(s: &str) -> String {
    let is_formula = s.starts_with('=')
        || s.starts_with('+')
        || s.starts_with('-')
        || s.starts_with('@')
        || s.starts_with('|');
    let needs_quoting = s.contains(',') || s.contains('"') || s.contains('\n') || is_formula;

    if needs_quoting {
        // G9: Neutralize formula injection by prefixing with a single quote.
        // Spreadsheet applications (Excel, LibreOffice Calc) treat a leading
        // single quote as a text-force prefix, preventing formula execution.
        let safe = if is_formula {
            format!("'{s}")
        } else {
            s.to_string()
        };
        format!("\"{}\"", safe.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;
    use puzzled_types::BranchId;

    #[test]
    fn test_store_and_query() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = AuditStore::new(dir.path().to_path_buf()).unwrap();

        let event = AuditEvent::BranchCreated {
            branch_id: BranchId::from("test-branch".to_string()),
            profile: "standard".to_string(),
            uid: 1000,
        };

        store.store(&event).unwrap();

        let results = store.query(None, None, None, None).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event.event_type, "branch_created");
        assert_eq!(results[0].event.branch_id.as_deref(), Some("test-branch"));
    }

    #[test]
    fn test_verify_chain_valid() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = AuditStore::new(dir.path().to_path_buf()).unwrap();

        store
            .store(&AuditEvent::BranchCreated {
                branch_id: BranchId::from("chain-test".to_string()),
                profile: "standard".to_string(),
                uid: 1000,
            })
            .unwrap();

        store
            .store(&AuditEvent::BranchCommitted {
                branch_id: BranchId::from("chain-test".to_string()),
                files: 5,
                bytes: 1024,
            })
            .unwrap();

        let count = store.verify_chain().unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_verify_chain_rejects_missing_hmac() {
        // M19: verify_chain must reject entries with missing HMAC.
        let dir = tempfile::tempdir().unwrap();
        let events_file = dir.path().join("events.ndjson");

        // Write an entry without HMAC directly to the file
        let entry = StoredAuditEvent {
            seq: 0,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            event: AuditEventRecord {
                event_type: "branch_created".to_string(),
                branch_id: Some("tampered-branch".to_string()),
                details: serde_json::json!({"profile": "standard", "uid": 1000}),
            },
            hmac: None,
            record_id: None,
            agent_identity: None,
            policy_version: None,
            changeset_hash: None,
            governance_decision: None,
            parent_record_id: None,
            signature: None,
            merkle_leaf_index: None,
        };

        let json = serde_json::to_string(&entry).unwrap();
        std::fs::write(&events_file, format!("{}\n", json)).unwrap();

        let store = AuditStore::new(dir.path().to_path_buf()).unwrap();
        let result = store.verify_chain();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("missing HMAC"),
            "expected 'missing HMAC' in error: {}",
            err_msg
        );
    }

    #[test]
    fn test_filter_by_branch() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = AuditStore::new(dir.path().to_path_buf()).unwrap();

        store
            .store(&AuditEvent::BranchCreated {
                branch_id: BranchId::from("branch-1".to_string()),
                profile: "standard".to_string(),
                uid: 1000,
            })
            .unwrap();

        store
            .store(&AuditEvent::BranchCreated {
                branch_id: BranchId::from("branch-2".to_string()),
                profile: "restricted".to_string(),
                uid: 1001,
            })
            .unwrap();

        let results = store.query(Some("branch-1"), None, None, None).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_export_json() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = AuditStore::new(dir.path().to_path_buf()).unwrap();

        store
            .store(&AuditEvent::BranchCreated {
                branch_id: BranchId::from("json-branch".to_string()),
                profile: "standard".to_string(),
                uid: 1000,
            })
            .unwrap();

        store
            .store(&AuditEvent::BranchCommitted {
                branch_id: BranchId::from("json-branch".to_string()),
                files: 3,
                bytes: 512,
            })
            .unwrap();

        let output = store.export("json").unwrap();
        // Should be valid JSON array
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0]["event"]["event_type"], "branch_created");
        assert_eq!(parsed[1]["event"]["event_type"], "branch_committed");
    }

    #[test]
    fn test_export_csv() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = AuditStore::new(dir.path().to_path_buf()).unwrap();

        store
            .store(&AuditEvent::BranchCreated {
                branch_id: BranchId::from("csv-branch".to_string()),
                profile: "standard".to_string(),
                uid: 1000,
            })
            .unwrap();

        let output = store.export("csv").unwrap();
        let lines: Vec<&str> = output.lines().collect();
        // First line is header
        assert_eq!(lines[0], "seq,timestamp,event_type,branch_id,details");
        // Second line is data row
        assert!(lines[1].contains("branch_created"));
        assert!(lines[1].contains("csv-branch"));
    }

    #[test]
    fn test_export_unsupported_format() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::new(dir.path().to_path_buf()).unwrap();

        let result = store.export("xml");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("unsupported export format"),
            "expected 'unsupported export format' in error: {}",
            err_msg
        );
    }

    #[test]
    fn test_csv_escape_special_chars() {
        // Commas should be quoted
        assert_eq!(csv_escape("hello,world"), "\"hello,world\"");
        // Embedded quotes should be doubled
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
        // Newlines should be quoted
        assert_eq!(csv_escape("line1\nline2"), "\"line1\nline2\"");
        // G9: Formula-triggering characters should be quoted AND prefixed with single quote
        assert_eq!(csv_escape("=cmd"), "\"'=cmd\"");
        assert_eq!(csv_escape("+cmd"), "\"'+cmd\"");
        assert_eq!(csv_escape("-cmd"), "\"'-cmd\"");
        assert_eq!(csv_escape("@cmd"), "\"'@cmd\"");
        assert_eq!(csv_escape("|cmd"), "\"'|cmd\"");
        // Plain string should pass through
        assert_eq!(csv_escape("hello"), "hello");
    }

    #[test]
    fn test_query_with_limit() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = AuditStore::new(dir.path().to_path_buf()).unwrap();

        for i in 0..5 {
            store
                .store(&AuditEvent::BranchCreated {
                    branch_id: BranchId::from(format!("limit-branch-{}", i)),
                    profile: "standard".to_string(),
                    uid: 1000,
                })
                .unwrap();
        }

        let results = store.query(None, None, None, Some(2)).unwrap();
        assert_eq!(results.len(), 2);
        // Should be the first two events
        assert_eq!(results[0].seq, 0);
        assert_eq!(results[1].seq, 1);
    }

    #[test]
    fn test_query_by_event_type() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = AuditStore::new(dir.path().to_path_buf()).unwrap();

        store
            .store(&AuditEvent::BranchCreated {
                branch_id: BranchId::from("type-branch".to_string()),
                profile: "standard".to_string(),
                uid: 1000,
            })
            .unwrap();

        store
            .store(&AuditEvent::BranchCommitted {
                branch_id: BranchId::from("type-branch".to_string()),
                files: 1,
                bytes: 100,
            })
            .unwrap();

        store
            .store(&AuditEvent::BranchRolledBack {
                branch_id: BranchId::from("type-branch-2".to_string()),
                reason: "test".to_string(),
            })
            .unwrap();

        let results = store
            .query(None, Some("branch_committed"), None, None)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event.event_type, "branch_committed");
    }

    #[test]
    fn test_empty_store_query() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::new(dir.path().to_path_buf()).unwrap();

        let results = store.query(None, None, None, None).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_query_filter_by_time_range() {
        // Phase 1.14: Query filtering by time range (since parameter).
        let dir = tempfile::tempdir().unwrap();
        let mut store = AuditStore::new(dir.path().to_path_buf()).unwrap();

        // Store two events — they will get timestamps close to "now"
        store
            .store(&AuditEvent::BranchCreated {
                branch_id: BranchId::from("time-branch-1".to_string()),
                profile: "standard".to_string(),
                uid: 1000,
            })
            .unwrap();

        store
            .store(&AuditEvent::BranchCommitted {
                branch_id: BranchId::from("time-branch-1".to_string()),
                files: 1,
                bytes: 100,
            })
            .unwrap();

        // Query with a "since" far in the past — should return all events.
        let results = store
            .query(None, None, Some("2000-01-01T00:00:00Z"), None)
            .unwrap();
        assert_eq!(results.len(), 2);

        // Query with a "since" far in the future — should return no events.
        let results = store
            .query(None, None, Some("2099-01-01T00:00:00Z"), None)
            .unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_stored_events_contain_hmac() {
        // Phase 1.14: Every stored NDJSON line must carry an HMAC field.
        let dir = tempfile::tempdir().unwrap();
        let mut store = AuditStore::new(dir.path().to_path_buf()).unwrap();

        store
            .store(&AuditEvent::BranchCreated {
                branch_id: BranchId::from("hmac-check".to_string()),
                profile: "standard".to_string(),
                uid: 1000,
            })
            .unwrap();

        store
            .store(&AuditEvent::PolicyViolation {
                branch_id: BranchId::from("hmac-check".to_string()),
                rule: "no_creds".to_string(),
                message: "found secret".to_string(),
            })
            .unwrap();

        // Read raw NDJSON and verify every line has a non-null hmac field
        let events_file = dir.path().join("events.ndjson");
        let contents = std::fs::read_to_string(&events_file).unwrap();
        for line in contents.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(
                parsed.get("hmac").is_some(),
                "NDJSON line missing 'hmac' field: {}",
                line
            );
            assert!(
                !parsed["hmac"].is_null(),
                "NDJSON line has null hmac: {}",
                line
            );
            // HMAC should be a non-empty hex string
            let hmac_str = parsed["hmac"].as_str().unwrap();
            assert!(!hmac_str.is_empty(), "HMAC should not be empty");
            assert!(
                hmac_str.chars().all(|c| c.is_ascii_hexdigit()),
                "HMAC should be hex: {}",
                hmac_str
            );
        }
    }

    #[test]
    fn test_verify_chain_detects_tampering() {
        // Phase 1.14: If a stored event is modified, verify_chain must fail.
        let dir = tempfile::tempdir().unwrap();
        let mut store = AuditStore::new(dir.path().to_path_buf()).unwrap();

        store
            .store(&AuditEvent::BranchCreated {
                branch_id: BranchId::from("tamper-test".to_string()),
                profile: "standard".to_string(),
                uid: 1000,
            })
            .unwrap();

        store
            .store(&AuditEvent::BranchCommitted {
                branch_id: BranchId::from("tamper-test".to_string()),
                files: 3,
                bytes: 512,
            })
            .unwrap();

        // Tamper with the first line of the events file
        let events_file = dir.path().join("events.ndjson");
        let contents = std::fs::read_to_string(&events_file).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert!(lines.len() >= 2);

        // Modify the first event's branch_id in the JSON
        let tampered_line = lines[0].replace("tamper-test", "tamper-CHANGED");
        let new_contents = format!("{}\n{}\n", tampered_line, lines[1]);
        std::fs::write(&events_file, new_contents).unwrap();

        let result = store.verify_chain();
        assert!(result.is_err(), "verify_chain should detect tampering");
    }

    #[test]
    fn test_persistent_storage_append_and_readback() {
        // Phase 1.14: Events survive store recreation (persistence).
        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path().to_path_buf();

        // Write events in one store instance
        {
            let mut store = AuditStore::new(store_path.clone()).unwrap();
            store
                .store(&AuditEvent::BranchCreated {
                    branch_id: BranchId::from("persist-1".to_string()),
                    profile: "standard".to_string(),
                    uid: 1000,
                })
                .unwrap();
            store
                .store(&AuditEvent::BranchCommitted {
                    branch_id: BranchId::from("persist-1".to_string()),
                    files: 5,
                    bytes: 2048,
                })
                .unwrap();
        }

        // Re-open the store and verify events are still there
        let store2 = AuditStore::new(store_path).unwrap();
        let results = store2.query(None, None, None, None).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].event.event_type, "branch_created");
        assert_eq!(results[1].event.event_type, "branch_committed");
        assert_eq!(results[0].seq, 0);
        assert_eq!(results[1].seq, 1);

        // HMAC chain should still be valid after reopening
        let count = store2.verify_chain().unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_verify_chain_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::new(dir.path().to_path_buf()).unwrap();

        let count = store.verify_chain().unwrap();
        assert_eq!(count, 0);
    }

    // -----------------------------------------------------------------------
    // Attestation-enabled tests (§3.1)
    // -----------------------------------------------------------------------

    fn make_signing_key() -> ed25519_dalek::SigningKey {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).unwrap();
        ed25519_dalek::SigningKey::from_bytes(&bytes)
    }

    #[test]
    fn test_attestation_signs_governance_events() {
        let dir = tempfile::tempdir().unwrap();
        let key = make_signing_key();
        let att_dir = dir.path().join("attestation");

        let mut store = AuditStore::new_with_attestation(
            dir.path().to_path_buf(),
            true,
            Some(key),
            Some(att_dir),
            None,
            0,
            0,
        )
        .unwrap();

        // Governance-significant event should get attestation fields
        store
            .store(&AuditEvent::BranchCreated {
                branch_id: BranchId::from("att-test".to_string()),
                profile: "standard".to_string(),
                uid: 1000,
            })
            .unwrap();

        let results = store.query(None, None, None, None).unwrap();
        assert_eq!(results.len(), 1);
        let event = &results[0];

        // Attestation fields should be populated
        assert!(event.record_id.is_some(), "record_id should be set");
        assert!(event.signature.is_some(), "signature should be set");
        assert!(
            event.merkle_leaf_index.is_some(),
            "merkle_leaf_index should be set"
        );
        assert_eq!(event.governance_decision, Some(GovernanceDecision::Created));
        // First event in branch chain has no parent
        assert!(event.parent_record_id.is_none());

        // HMAC should also still be present
        assert!(event.hmac.is_some(), "HMAC should still be present");
    }

    #[test]
    fn test_attestation_skips_non_governance_events() {
        let dir = tempfile::tempdir().unwrap();
        let key = make_signing_key();
        let att_dir = dir.path().join("attestation");

        let mut store = AuditStore::new_with_attestation(
            dir.path().to_path_buf(),
            true,
            Some(key),
            Some(att_dir),
            None,
            0,
            0,
        )
        .unwrap();

        // Non-governance event (exec_gated is high-frequency, not signed)
        store
            .store(&AuditEvent::AgentExecGated {
                branch_id: BranchId::from("att-test".to_string()),
                path: "/usr/bin/ls".to_string(),
                allowed: true,
            })
            .unwrap();

        let results = store.query(None, None, None, None).unwrap();
        let event = &results[0];

        // Attestation fields should NOT be set
        assert!(event.record_id.is_none());
        assert!(event.signature.is_none());
        assert!(event.merkle_leaf_index.is_none());
        // HMAC should still be present
        assert!(event.hmac.is_some());
    }

    #[test]
    fn test_attestation_chain_linking() {
        let dir = tempfile::tempdir().unwrap();
        let key = make_signing_key();
        let att_dir = dir.path().join("attestation");

        let mut store = AuditStore::new_with_attestation(
            dir.path().to_path_buf(),
            true,
            Some(key),
            Some(att_dir),
            None,
            0,
            0,
        )
        .unwrap();

        let bid = BranchId::from("chain-test".to_string());

        // First event: BranchCreated (no parent)
        store
            .store(&AuditEvent::BranchCreated {
                branch_id: bid.clone(),
                profile: "standard".to_string(),
                uid: 1000,
            })
            .unwrap();

        // Second event: PolicyViolation (parent = BranchCreated)
        store
            .store(&AuditEvent::PolicyViolation {
                branch_id: bid.clone(),
                rule: "no_creds".to_string(),
                message: "found .env".to_string(),
            })
            .unwrap();

        // Third event: CommitRejected (parent = PolicyViolation)
        store
            .store(&AuditEvent::CommitRejected {
                branch_id: bid.clone(),
                reason: "policy violation".to_string(),
            })
            .unwrap();

        let results = store.query(None, None, None, None).unwrap();
        assert_eq!(results.len(), 3);

        // First event has no parent
        assert!(results[0].parent_record_id.is_none());

        // Second event's parent is the first event's record_id
        assert_eq!(
            results[1].parent_record_id.as_ref(),
            results[0].record_id.as_ref()
        );

        // Third event's parent is the second event's record_id
        assert_eq!(
            results[2].parent_record_id.as_ref(),
            results[1].record_id.as_ref()
        );
    }

    #[test]
    fn test_attestation_verify_chain_still_works() {
        // HMAC chain verification must work even with attestation fields present
        let dir = tempfile::tempdir().unwrap();
        let key = make_signing_key();
        let att_dir = dir.path().join("attestation");

        let mut store = AuditStore::new_with_attestation(
            dir.path().to_path_buf(),
            true,
            Some(key),
            Some(att_dir),
            None,
            0,
            0,
        )
        .unwrap();

        store
            .store(&AuditEvent::BranchCreated {
                branch_id: BranchId::from("hmac-chain".to_string()),
                profile: "standard".to_string(),
                uid: 1000,
            })
            .unwrap();

        store
            .store(&AuditEvent::BranchCommitted {
                branch_id: BranchId::from("hmac-chain".to_string()),
                files: 5,
                bytes: 1024,
            })
            .unwrap();

        // Non-governance event in between
        store
            .store(&AuditEvent::ProfileLoaded {
                profile: "standard".to_string(),
            })
            .unwrap();

        let count = store.verify_chain().unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn test_attestation_merkle_tree_grows() {
        let dir = tempfile::tempdir().unwrap();
        let key = make_signing_key();
        let att_dir = dir.path().join("attestation");

        let mut store = AuditStore::new_with_attestation(
            dir.path().to_path_buf(),
            true,
            Some(key),
            Some(att_dir),
            None,
            0,
            0,
        )
        .unwrap();

        // Store 4 governance-significant events
        for i in 0..4 {
            store
                .store(&AuditEvent::BranchCreated {
                    branch_id: BranchId::from(format!("merkle-{}", i)),
                    profile: "standard".to_string(),
                    uid: 1000,
                })
                .unwrap();
        }

        let tree = store.merkle_tree().unwrap();
        assert_eq!(tree.size(), 4);

        // Verify inclusion proof for each leaf
        let root = tree.root_hash().unwrap();
        for i in 0..4u64 {
            let proof = tree.inclusion_proof(i).unwrap();
            let results = store.query(None, None, None, None).unwrap();
            let event = &results[i as usize];
            assert_eq!(event.merkle_leaf_index, Some(i));

            // The leaf hash can be recomputed from the canonical form
            let canonical = AuditStore::build_canonical_attestation(event);
            let leaf_hash = crate::attestation::MerkleTree::hash_leaf(canonical.as_bytes());
            assert!(
                crate::attestation::verify_inclusion(&leaf_hash, &proof, &root).unwrap(),
                "inclusion proof failed for event {}",
                i
            );
        }
    }

    #[test]
    fn test_disabled_attestation_produces_no_fields() {
        // With attestation disabled, all new fields should be None
        let dir = tempfile::tempdir().unwrap();
        let mut store = AuditStore::new(dir.path().to_path_buf()).unwrap();

        store
            .store(&AuditEvent::BranchCreated {
                branch_id: BranchId::from("no-att".to_string()),
                profile: "standard".to_string(),
                uid: 1000,
            })
            .unwrap();

        let results = store.query(None, None, None, None).unwrap();
        let event = &results[0];

        assert!(event.record_id.is_none());
        assert!(event.signature.is_none());
        assert!(event.merkle_leaf_index.is_none());
        assert!(event.governance_decision.is_none());
        assert!(event.parent_record_id.is_none());
    }

    #[test]
    fn test_hmac_chain_valid_with_attestation_enabled() {
        // A-I1: Verify that HMAC chain integrity is preserved when attestation
        // fields (record_id, signature, merkle_leaf_index, etc.) are populated.
        // The HMAC is computed BEFORE attestation fields are set, and verify_chain
        // must clear those fields before re-computing the HMAC. If any attestation
        // field's skip_serializing_if is missing, the HMAC would include the field
        // value that wasn't present during original computation, breaking the chain.
        let dir = tempfile::tempdir().unwrap();
        let signing_key = make_signing_key();
        let att_dir = dir.path().join("attestation");
        let mut store = AuditStore::new_with_attestation(
            dir.path().to_path_buf(),
            true,
            Some(signing_key),
            Some(att_dir),
            None,
            0,
            0,
        )
        .unwrap();

        // Store governance-significant events (these get attestation fields populated)
        store
            .store(&AuditEvent::BranchCreated {
                branch_id: BranchId::from("att-hmac-test".to_string()),
                profile: "standard".to_string(),
                uid: 1000,
            })
            .unwrap();

        store
            .store(&AuditEvent::BranchCommitted {
                branch_id: BranchId::from("att-hmac-test".to_string()),
                files: 3,
                bytes: 512,
            })
            .unwrap();

        // Verify the stored events have attestation fields populated
        let results = store.query(None, None, None, None).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].record_id.is_some(), "record_id should be set");
        assert!(results[0].signature.is_some(), "signature should be set");
        assert!(
            results[0].governance_decision.is_some(),
            "governance_decision should be set"
        );

        // The critical test: verify_chain must succeed despite attestation fields
        // being present. This confirms HMAC computation excludes attestation fields
        // via skip_serializing_if and that verify_chain correctly clears them.
        let count = store.verify_chain().unwrap();
        assert_eq!(
            count, 2,
            "HMAC chain should verify with attestation-enabled events"
        );
    }

    #[test]
    fn test_truncated_hmac_key_rejected() {
        // A-C1: If the HMAC key file exists but has < 32 bytes, AuditStore::new
        // must return an error instead of silently using zero-padded key.
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join(".hmac_key");

        // Write a truncated key (16 bytes instead of 32)
        std::fs::write(&key_path, [0x42u8; 16]).unwrap();

        let result = AuditStore::new(dir.path().to_path_buf());
        assert!(result.is_err(), "should reject truncated HMAC key file");
        let err_msg = match result {
            Err(e) => format!("{}", e),
            Ok(_) => unreachable!(),
        };
        assert!(
            err_msg.contains("truncated"),
            "error should mention truncation, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_empty_hmac_key_file_rejected() {
        // Edge case: empty key file (0 bytes)
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join(".hmac_key");
        std::fs::write(&key_path, []).unwrap();

        let result = AuditStore::new(dir.path().to_path_buf());
        assert!(result.is_err(), "should reject empty HMAC key file");
    }

    #[test]
    fn test_valid_hmac_key_accepted() {
        // A valid 32-byte key file should work fine
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join(".hmac_key");
        std::fs::write(&key_path, [0x42u8; 32]).unwrap();

        let result = AuditStore::new(dir.path().to_path_buf());
        assert!(result.is_ok(), "should accept valid 32-byte HMAC key");
    }

    #[test]
    fn test_oversized_hmac_key_accepted() {
        // A key file > 32 bytes should be accepted (first 32 bytes used)
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join(".hmac_key");
        std::fs::write(&key_path, [0x42u8; 64]).unwrap();

        let result = AuditStore::new(dir.path().to_path_buf());
        assert!(
            result.is_ok(),
            "should accept oversized HMAC key (first 32 bytes used)"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_hmac_key_created_with_restricted_permissions() {
        // A-C1: Verify that the HMAC key file is created atomically with 0600 permissions.
        // There must be no window where the file is readable by other users.
        let dir = tempfile::tempdir().unwrap();

        // No key file exists yet — AuditStore::new will generate one
        let result = AuditStore::new(dir.path().to_path_buf());
        assert!(result.is_ok(), "AuditStore::new should succeed");

        let key_path = dir.path().join(".hmac_key");
        assert!(key_path.exists(), "HMAC key file should be created");

        // Verify permissions are 0600 (owner read/write only)
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(&key_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "HMAC key file should have mode 0600, got {:o}",
            mode
        );

        // Verify the key is 32 bytes
        let key_bytes = std::fs::read(&key_path).unwrap();
        assert_eq!(key_bytes.len(), 32, "HMAC key should be 32 bytes");
    }

    #[cfg(unix)]
    #[test]
    fn test_hmac_key_create_new_does_not_overwrite() {
        // A-C1: Verify that create_new prevents overwriting an existing key file.
        // If the key file already exists, it should be read, not regenerated.
        let dir = tempfile::tempdir().unwrap();

        // Create the store (generates key file)
        let store1 = AuditStore::new(dir.path().to_path_buf()).unwrap();
        let key_path = dir.path().join(".hmac_key");
        let key_bytes_1 = std::fs::read(&key_path).unwrap();

        // Re-create the store (should load existing key, not regenerate)
        drop(store1);
        let _store2 = AuditStore::new(dir.path().to_path_buf()).unwrap();
        let key_bytes_2 = std::fs::read(&key_path).unwrap();

        assert_eq!(
            key_bytes_1, key_bytes_2,
            "HMAC key should be the same after reopening (loaded, not regenerated)"
        );
    }

    // -----------------------------------------------------------------------
    // A-C1: NDJSON/Merkle reconciliation on startup
    // -----------------------------------------------------------------------

    #[test]
    fn test_ndjson_merkle_reconciliation_on_startup() {
        // Simulate a crash between NDJSON write and Merkle append:
        // 1. Create a store with attestation, store an event (both NDJSON + Merkle OK)
        // 2. Manually write a second NDJSON record with merkle_leaf_index=1,
        //    but do NOT append to merkle.dat (simulating crash before Merkle append)
        // 3. Re-open the store — reconciliation should re-append the missing leaf

        let dir = tempfile::tempdir().unwrap();
        let store_dir = dir.path().to_path_buf();
        let att_dir = dir.path().join("attestation");
        let key = make_signing_key();

        // Step 1: Store one event normally (NDJSON + Merkle both written)
        {
            let mut store = AuditStore::new_with_attestation(
                store_dir.clone(),
                true,
                Some(key.clone()),
                Some(att_dir.clone()),
                None,
                0,
                0,
            )
            .unwrap();

            store
                .store(&AuditEvent::BranchCreated {
                    branch_id: BranchId::from("recon-test".to_string()),
                    profile: "standard".to_string(),
                    uid: 1000,
                })
                .unwrap();

            // Verify: tree has 1 leaf, NDJSON has 1 record with merkle_leaf_index=0
            assert_eq!(store.merkle_tree().unwrap().size(), 1);
        }

        // Step 2: Manually append a second NDJSON record with merkle_leaf_index=1,
        // but do NOT write to merkle.dat (simulating crash between NDJSON write
        // and Merkle append).
        {
            let orphan_record = StoredAuditEvent {
                seq: 1,
                timestamp: "2026-03-15T00:00:01Z".to_string(),
                event: AuditEventRecord {
                    event_type: "branch_committed".to_string(),
                    branch_id: Some("recon-test".to_string()),
                    details: serde_json::json!({"files": 3, "bytes": 512}),
                },
                hmac: Some("fake_hmac_for_test".to_string()),
                record_id: Some("orphan-record-id".to_string()),
                agent_identity: None,
                policy_version: None,
                changeset_hash: None,
                governance_decision: Some(GovernanceDecision::Approved),
                parent_record_id: None,
                signature: None,
                merkle_leaf_index: Some(1), // Claims leaf index 1, but tree only has 1 leaf (index 0)
            };

            let events_file = store_dir.join("events.ndjson");
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&events_file)
                .unwrap();
            writeln!(file, "{}", serde_json::to_string(&orphan_record).unwrap()).unwrap();
        }

        // Confirm merkle.dat still has only 1 leaf (32 bytes)
        let merkle_path = att_dir.join("merkle.dat");
        let merkle_before = std::fs::read(&merkle_path).unwrap();
        assert_eq!(
            merkle_before.len(),
            32,
            "merkle.dat should have exactly 1 leaf (32 bytes) before reconciliation"
        );

        // Step 3: Re-open the store — reconciliation should detect the orphan
        // NDJSON record and re-append its canonical form to the Merkle tree.
        let store2 = AuditStore::new_with_attestation(
            store_dir.clone(),
            true,
            Some(key),
            Some(att_dir.clone()),
            None,
            0,
            0,
        )
        .unwrap();

        // After reconciliation: tree should have 2 leaves
        assert_eq!(
            store2.merkle_tree().unwrap().size(),
            2,
            "Merkle tree should have 2 leaves after reconciliation"
        );

        // Verify merkle.dat now has 2 leaves (64 bytes)
        let merkle_after = std::fs::read(&merkle_path).unwrap();
        assert_eq!(
            merkle_after.len(),
            64,
            "merkle.dat should have 2 leaves (64 bytes) after reconciliation"
        );
    }

    /// S32: Verify that set_len(0) on corrupt audit store is not silently
    /// discarded with `let _ =`. Truncation failure must be logged.
    #[test]
    fn test_s32_set_len_not_silent() {
        let source = include_str!("audit_store.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        for (i, line) in prod_source.lines().enumerate() {
            if line.contains("set_len(0)") && line.trim().starts_with("let _ =") {
                panic!(
                    "S32: set_len(0) at line {} uses `let _ =` which silently \
                     discards truncation errors. Use `if let Err(e) = ...` with \
                     logging instead.\nLine: {}",
                    i + 1,
                    line.trim()
                );
            }
        }
    }

    /// S34: Verify that HMAC comparison uses constant_time_eq, not `!=`.
    #[test]
    fn test_s34_hmac_constant_time() {
        let source = include_str!("audit_store.rs");
        // Verify the constant_time_eq function exists in production code
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            prod_source.contains("fn constant_time_eq"),
            "S34: constant_time_eq function must exist in production code"
        );
        // Verify verify_chain uses constant_time_eq, not !=
        let verify_chain_start = prod_source
            .find("fn verify_chain")
            .expect("verify_chain function must exist");
        let verify_chain_body = &prod_source[verify_chain_start..];
        assert!(
            verify_chain_body.contains("constant_time_eq"),
            "S34: verify_chain must use constant_time_eq for HMAC comparison"
        );
        // Verify the function logic is correct by testing it directly
        assert!(AuditStore::constant_time_eq(b"abc", b"abc"));
        assert!(!AuditStore::constant_time_eq(b"abc", b"abd"));
        assert!(!AuditStore::constant_time_eq(b"abc", b"ab"));
        assert!(!AuditStore::constant_time_eq(b"", b"a"));
        assert!(AuditStore::constant_time_eq(b"", b""));
    }

    /// G20: export() must have a size limit to prevent OOM on large audit logs.
    #[test]
    fn test_g20_export_has_size_limit() {
        let source = include_str!("audit_store.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        assert!(
            prod_source.contains("MAX_EXPORT_FILE_SIZE"),
            "G20: audit_store.rs must define MAX_EXPORT_FILE_SIZE constant \
             to prevent OOM when exporting large audit logs"
        );
    }

    // R7: HMAC chain recovery must NOT use silent default on missing HMAC.
    #[test]
    fn test_r7_hmac_chain_recovery_no_unwrap_or_default() {
        let source = include_str!("audit_store.rs");
        // Only check production code, not the test module
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        for (i, line) in prod_source.lines().enumerate() {
            if line.contains("last_hmac") && line.contains("unwrap_or_default") {
                panic!(
                    "R7: HMAC chain recovery at line {} uses unwrap_or_default() which \
                     silently swallows recovery errors. Use unwrap_or_else with logging instead.\n\
                     Line: {}",
                    i + 1,
                    line.trim()
                );
            }
        }
    }

    /// G8: Audit query must use proper datetime comparison, not lexicographic string comparison.
    #[test]
    fn test_g8_audit_query_uses_datetime_comparison() {
        let source = include_str!("audit_store.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];

        // Must use parse_from_rfc3339 for proper datetime comparison
        assert!(
            production_code.contains("parse_from_rfc3339"),
            "G8: audit_store.rs query function must use chrono::DateTime::parse_from_rfc3339 \
             for timestamp comparison instead of lexicographic string comparison"
        );

        // Must NOT contain the old lexicographic comparison pattern
        assert!(
            !production_code.contains("stored.timestamp.as_str() < since_ts"),
            "G8: audit_store.rs must not use lexicographic string comparison for timestamps"
        );
    }

    /// G8 functional: Verify datetime comparison handles timezone offsets correctly.
    #[test]
    fn test_g8_audit_query_datetime_functional() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = AuditStore::new(dir.path().to_path_buf()).unwrap();

        // Store two events
        store
            .store(&AuditEvent::BranchCreated {
                branch_id: BranchId::from("g8-test".to_string()),
                profile: "standard".to_string(),
                uid: 1000,
            })
            .unwrap();

        // Query with a "since" timestamp in the far future — should return nothing
        let results = store
            .query(None, None, Some("2099-01-01T00:00:00+00:00"), None)
            .unwrap();
        assert!(
            results.is_empty(),
            "G8: query with future since should return no events"
        );

        // Query with a "since" timestamp in the past — should return events
        let results = store
            .query(None, None, Some("2000-01-01T00:00:00+00:00"), None)
            .unwrap();
        assert!(
            !results.is_empty(),
            "G8: query with past since should return events"
        );

        // Query with an invalid timestamp should return an error
        let result = store.query(None, None, Some("not-a-timestamp"), None);
        assert!(
            result.is_err(),
            "G8: query with invalid since timestamp should return an error"
        );
    }

    /// G9: csv_escape must neutralize formula injection characters.
    #[test]
    fn test_g9_csv_escape_neutralizes_formula_injection() {
        // Formula-triggering prefixes must be neutralized with a single-quote prefix
        let cases = vec![
            ("=cmd()", "'=cmd()"),
            ("+cmd()", "'+cmd()"),
            ("-cmd()", "'-cmd()"),
            ("@cmd()", "'@cmd()"),
            ("|cmd()", "'|cmd()"),
        ];

        for (input, expected_prefix) in &cases {
            let escaped = csv_escape(input);
            // The result should be quoted and contain the single-quote prefix
            assert!(
                escaped.starts_with('"'),
                "G9: csv_escape({input:?}) should be quoted, got: {escaped}"
            );
            assert!(
                escaped.contains(expected_prefix),
                "G9: csv_escape({input:?}) should contain {expected_prefix:?} \
                 to neutralize formula injection, got: {escaped}"
            );
        }

        // Normal strings should NOT get a single-quote prefix
        let normal = csv_escape("hello world");
        assert_eq!(
            normal, "hello world",
            "G9: normal strings should pass through unchanged"
        );

        // Strings with commas should be quoted but not single-quote-prefixed
        let comma = csv_escape("hello,world");
        assert!(comma.starts_with('"'), "G9: comma strings should be quoted");
        assert!(
            !comma.contains("'hello"),
            "G9: comma strings should not get single-quote prefix"
        );
    }

    // ===================================================================
    // H-series Round 6: Security findings H40-H53
    // ===================================================================

    // -----------------------------------------------------------------------
    // H40: store_with_context must inject uid from agent_identity into details
    // -----------------------------------------------------------------------
    #[test]
    fn test_h40_store_with_context_injects_uid() {
        let source = include_str!("audit_store.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            prod_source.contains("H40") && prod_source.contains(r#"entry("uid")"#),
            "H40: store_with_context must inject uid from agent_identity into \
             event details so non-root users can see their own events via PH2 filtering."
        );
    }

    #[test]
    fn test_h40_branch_committed_has_uid_in_details() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = AuditStore::new(dir.path().to_path_buf()).unwrap();

        let identity = AgentIdentity {
            uid: 1001,
            profile: "standard".to_string(),
            selinux_context: None,
            framework: None,
        };
        store
            .store_with_context(
                &AuditEvent::BranchCommitted {
                    branch_id: BranchId::from("h40-test".to_string()),
                    files: 5,
                    bytes: 1024,
                },
                Some(identity),
                None,
            )
            .unwrap();

        let events = store.query(None, None, None, None).unwrap();
        assert_eq!(events.len(), 1);
        let uid_val = events[0].event.details.get("uid");
        assert!(
            uid_val.is_some(),
            "H40: BranchCommitted details must include uid field"
        );
        assert_eq!(uid_val.unwrap().as_u64(), Some(1001));
    }

    // -----------------------------------------------------------------------
    // H41: count_existing_events uses single file open for count+truncate
    // -----------------------------------------------------------------------
    #[test]
    fn test_h41_single_file_open_for_count_and_truncate() {
        let source = include_str!("audit_store.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // Find count_existing_events function
        let fn_start = prod_source
            .find("fn count_existing_events(")
            .expect("count_existing_events must exist");
        let fn_body = &prod_source[fn_start..fn_start + 1500.min(prod_source.len() - fn_start)];

        // Must use OpenOptions with read+write (single open)
        assert!(
            fn_body.contains(".read(true)") && fn_body.contains(".write(true)"),
            "H41: count_existing_events must open the file once with read+write \
             to eliminate TOCTOU between counting and truncation."
        );

        // Must NOT have a second OpenOptions::new().write(true).open() for truncation
        let after_first_open = fn_body
            .find("OpenOptions::new()")
            .map(|p| &fn_body[p + 20..])
            .unwrap_or("");
        assert!(
            !after_first_open.contains("OpenOptions::new()"),
            "H41: count_existing_events must not open the file a second time. \
             Use the same file handle for both counting and truncation."
        );
    }

    // -----------------------------------------------------------------------
    // H42: No bare .unwrap() on serde_json::to_value in production code
    // -----------------------------------------------------------------------
    #[test]
    fn test_h42_no_bare_unwrap_on_to_value() {
        let source = include_str!("audit_store.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            !prod_source.contains("to_value(identity).unwrap()")
                && !prod_source.contains("to_value(gd).unwrap()"),
            "H42: production code must not use bare .unwrap() on serde_json::to_value. \
             Use .unwrap_or(serde_json::Value::Null) instead."
        );
    }

    // -----------------------------------------------------------------------
    // H43: No .expect() on BTreeMap serialization
    // -----------------------------------------------------------------------
    #[test]
    fn test_h43_no_expect_on_btreemap_serialization() {
        let source = include_str!("audit_store.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            !prod_source.contains(r#".expect("BTreeMap serialization cannot fail")"#),
            "H43: production code must not use .expect() on BTreeMap serialization. \
             Use .unwrap_or_else() with tracing::error fallback."
        );
        assert!(
            prod_source.contains("H43") && prod_source.contains("unwrap_or_else"),
            "H43: build_canonical_attestation must use unwrap_or_else with error logging."
        );
    }

    // -----------------------------------------------------------------------
    // H47: query() must have a default limit (MAX_QUERY_LIMIT) for Some(n)
    // -----------------------------------------------------------------------
    #[test]
    fn test_h47_query_has_default_limit() {
        let source = include_str!("audit_store.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            prod_source.contains("MAX_QUERY_LIMIT"),
            "H47: AuditStore must define MAX_QUERY_LIMIT constant."
        );
        assert!(
            prod_source.contains(".min(Self::MAX_QUERY_LIMIT)"),
            "H47: query() must cap the limit to MAX_QUERY_LIMIT."
        );
    }

    // -----------------------------------------------------------------------
    // J20: None limit returns all events (unbounded for internal callers)
    // -----------------------------------------------------------------------
    #[test]
    fn test_j20_none_limit_returns_all_events() {
        let source = include_str!("audit_store.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // J20: verify that None limit uses usize::MAX (unbounded)
        assert!(
            prod_source.contains("None => usize::MAX"),
            "J20: query() with limit=None must be unbounded (usize::MAX) \
             for internal callers like verify_attestation_chain."
        );
    }

    // -----------------------------------------------------------------------
    // H48: Sequence number invariant comment
    // -----------------------------------------------------------------------
    #[test]
    fn test_h48_sequence_number_invariant_documented() {
        let source = include_str!("audit_store.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            prod_source.contains("H48") && prod_source.contains("next_seq"),
            "H48: The sequence number increment must have a comment documenting \
             the invariant that AuditStore is always accessed under the mutex."
        );
    }

    // -----------------------------------------------------------------------
    // H53: HMAC key .expect() has safety comment
    // -----------------------------------------------------------------------
    #[test]
    fn test_h53_hmac_key_expect_has_safety_comment() {
        let source = include_str!("audit_store.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            prod_source.contains("H53") && prod_source.contains("32 bytes"),
            "H53: The HMAC key .expect() must have a comment explaining why \
             the expect is safe (key is validated to 32 bytes in AuditStore::new)."
        );
    }

    // -----------------------------------------------------------------------
    // J23: remove_branch_chain method and MAX_BRANCH_CHAINS cap
    // -----------------------------------------------------------------------
    #[test]
    fn test_j23_remove_branch_chain_exists() {
        let source = include_str!("audit_store.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            prod_source.contains("fn remove_branch_chain("),
            "J23: AuditStore must have a remove_branch_chain() method."
        );
        assert!(
            prod_source.contains("MAX_BRANCH_CHAINS"),
            "J23: AuditStore must define MAX_BRANCH_CHAINS constant."
        );
    }

    // -----------------------------------------------------------------------
    // J24: Sequence number overflow uses checked_add
    // -----------------------------------------------------------------------
    #[test]
    fn test_j24_sequence_number_uses_checked_add() {
        let source = include_str!("audit_store.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            prod_source.contains("checked_add(1)"),
            "J24: next_seq increment must use checked_add to detect overflow."
        );
    }

    // -----------------------------------------------------------------------
    // J25: bytes_read as u64 cast has compile-time assertion
    // -----------------------------------------------------------------------
    #[test]
    fn test_j25_bytes_read_cast_has_compile_time_assert() {
        let source = include_str!("audit_store.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            prod_source
                .contains("assert!(std::mem::size_of::<usize>() <= std::mem::size_of::<u64>())"),
            "J25: count_existing_events must have a compile-time assertion that \
             usize fits in u64 for the bytes_read cast."
        );
    }

    // -----------------------------------------------------------------------
    // J26: HMAC error must not expose hash values
    // -----------------------------------------------------------------------
    #[test]
    fn test_j26_hmac_error_no_hash_exposure() {
        let source = include_str!("audit_store.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // Find the HMAC chain broken error message and ensure it does NOT contain
        // "expected" and "got" which would leak hash values.
        let hmac_broken_section = prod_source
            .find("HMAC chain broken")
            .expect("must have HMAC chain broken error");
        let error_context = &prod_source[hmac_broken_section..hmac_broken_section + 100];
        assert!(
            !error_context.contains("expected") && !error_context.contains(", got"),
            "J26: HMAC chain broken error must not expose expected/computed hash values. \
             Found: {}",
            error_context
        );
    }
}
