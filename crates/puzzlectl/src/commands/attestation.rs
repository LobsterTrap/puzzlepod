// SPDX-License-Identifier: Apache-2.0
use anyhow::{Context, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use puzzled_types::{AuditRecord, InclusionProof};
use std::collections::HashMap;
use std::path::Path;

use crate::output::validate_branch_id;

// A-M1: Merkle crypto functions are now in puzzled_types::merkle.
use puzzled_types::merkle::{hash_leaf, hex_decode, verify_merkle_inclusion};

/// Re-use the canonical governance-significance check from puzzled-types.
use puzzled_types::is_governance_significant;

// V49: AuditRecord and AuditRecordEvent are now unified in puzzled_types::audit.

// --- Shared verification helpers ---

/// Counters for attestation verification results.
#[derive(Default)]
struct VerificationCounters {
    sig_ok: u64,
    sig_fail: u64,
    sig_skip: u64,
    chain_ok: u64,
    chain_fail: u64,
    merkle_ok: u64,
    merkle_fail: u64,
    merkle_skip: u64,
}

impl VerificationCounters {
    /// Total failures across signature, chain, and Merkle checks.
    fn total_failures(&self) -> u64 {
        self.sig_fail + self.chain_fail + self.merkle_fail
    }
}

/// Result of a single signature verification attempt.
enum SignatureResult {
    /// Signature verified successfully.
    Ok,
    /// Signature verification failed (with error message for the user).
    Fail(String),
    /// Skipped (no verifying key provided).
    Skip,
}

/// Verify an Ed25519 signature against a canonical string.
///
/// Returns `SignatureResult::Skip` if `vk` is `None`. Otherwise decodes the
/// hex signature, checks length == 64, constructs `Signature`, and calls
/// `vk.verify()`.
fn verify_signature(
    canonical: &str,
    signature_hex: &str,
    vk: Option<&VerifyingKey>,
    record_id: &str,
) -> SignatureResult {
    let vk = match vk {
        Some(vk) => vk,
        None => return SignatureResult::Skip,
    };

    let sig_bytes = hex_decode(signature_hex).unwrap_or_else(|e| {
        eprintln!("S44: hex decode failed for record {}: {}", record_id, e);
        Vec::new()
    });
    if sig_bytes.len() != 64 {
        return SignatureResult::Fail(format!(
            "  FAIL: signature wrong length ({} bytes) for record {}",
            sig_bytes.len(),
            record_id
        ));
    }
    match Signature::from_slice(&sig_bytes) {
        Ok(sig) => {
            use ed25519_dalek::Verifier;
            if vk.verify(canonical.as_bytes(), &sig).is_ok() {
                SignatureResult::Ok
            } else {
                SignatureResult::Fail(format!(
                    "  FAIL: signature invalid for record {}",
                    record_id
                ))
            }
        }
        Err(_) => SignatureResult::Fail(format!(
            "  FAIL: malformed signature for record {}",
            record_id
        )),
    }
}

/// Apply a `SignatureResult` to the verification counters, printing any failure message.
fn apply_signature_result(result: SignatureResult, counters: &mut VerificationCounters) {
    match result {
        SignatureResult::Ok => counters.sig_ok += 1,
        SignatureResult::Fail(msg) => {
            counters.sig_fail += 1;
            eprintln!("{}", msg);
        }
        SignatureResult::Skip => counters.sig_skip += 1,
    }
}

/// Verify chain continuity: check that `parent_record_id` (if present) exists in `known_ids`.
///
/// Returns `true` (chain ok) if parent is found or there is no parent (first record in chain).
/// Returns `false` (chain broken) if parent references a missing record.
fn verify_chain_link(
    record_id: &str,
    parent_record_id: Option<&str>,
    known_ids: &impl ChainIndex,
    counters: &mut VerificationCounters,
) {
    match parent_record_id {
        Some(parent_id) => {
            if known_ids.contains(parent_id) {
                counters.chain_ok += 1;
            } else {
                counters.chain_fail += 1;
                eprintln!(
                    "  FAIL: chain broken — record {} references parent {} which is missing",
                    record_id, parent_id
                );
            }
        }
        None => {
            // First record in a branch chain has no parent — that's OK
            counters.chain_ok += 1;
        }
    }
}

/// Trait abstracting over different chain index types (HashMap vs HashSet).
trait ChainIndex {
    fn contains(&self, id: &str) -> bool;
}

impl ChainIndex for HashMap<&str, usize> {
    fn contains(&self, id: &str) -> bool {
        self.contains_key(id)
    }
}

impl ChainIndex for std::collections::HashSet<String> {
    fn contains(&self, id: &str) -> bool {
        self.contains(id)
    }
}

/// Q3/S11: Check file size before reading (defense-in-depth).
fn check_file_size(path: &Path, max_bytes: u64) -> Result<()> {
    let file_size = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .len();
    if file_size > max_bytes {
        anyhow::bail!(
            "Q3: file {} is {} bytes, exceeds maximum {} bytes",
            path.display(),
            file_size,
            max_bytes
        );
    }
    Ok(())
}

/// Recursively sort all JSON object keys and strip null values for
/// deterministic serialization. Mirrors `AuditStore::sort_json_keys` in puzzled.
fn sort_json_keys(val: serde_json::Value) -> serde_json::Value {
    match val {
        serde_json::Value::Object(map) => {
            let sorted: serde_json::Map<String, serde_json::Value> = map
                .into_iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k, sort_json_keys(v)))
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .collect();
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(sort_json_keys).collect())
        }
        other => other,
    }
}

/// Build canonical attestation string (matches puzzled's `build_canonical_attestation`).
///
/// Works with both `AuditRecord` (via direct call) and `serde_json::Value`
/// (by first deserializing to `AuditRecord` — see `build_canonical_from_value`).
// N7: Returns Result to propagate serialization errors instead of unwrap()
fn build_canonical(record: &AuditRecord) -> Result<String> {
    use std::collections::BTreeMap;

    let mut canonical = BTreeMap::new();
    canonical.insert("seq", serde_json::json!(record.seq));
    canonical.insert("timestamp", serde_json::json!(record.timestamp));
    canonical.insert("event_type", serde_json::json!(record.event.event_type));
    if let Some(ref bid) = record.event.branch_id {
        canonical.insert("branch_id", serde_json::json!(bid));
    }
    if let Some(ref rid) = record.record_id {
        canonical.insert("record_id", serde_json::json!(rid));
    }
    if let Some(ref identity) = record.agent_identity {
        canonical.insert(
            "agent_identity",
            // N7: Propagate serialization error
            sort_json_keys(serde_json::to_value(identity)?),
        );
    }
    if let Some(ref pv) = record.policy_version {
        canonical.insert("policy_version", serde_json::json!(pv));
    }
    if let Some(ref ch) = record.changeset_hash {
        canonical.insert("changeset_hash", serde_json::json!(ch));
    }
    if let Some(ref gd) = record.governance_decision {
        // A-C2: Apply sort_json_keys for consistency with puzzled's build_canonical_attestation.
        canonical.insert(
            "governance_decision",
            // N7: Propagate serialization error
            sort_json_keys(serde_json::to_value(gd)?),
        );
    }
    if let Some(ref pid) = record.parent_record_id {
        canonical.insert("parent_record_id", serde_json::json!(pid));
    }
    // N1/N10: Include event details in canonical form to match puzzled's signing canonical.
    if !record.event.details.is_null() {
        canonical.insert("details", sort_json_keys(record.event.details.clone()));
    }

    Ok(serde_json::to_string(&canonical)?)
}

/// Build canonical attestation string from a JSON value (for bundle verification).
///
/// Deserializes the value to `AuditRecord` and delegates to `build_canonical`.
/// Returns `None` if deserialization fails (malformed record).
fn build_canonical_from_value(record: &serde_json::Value) -> Option<String> {
    let audit_record: AuditRecord = serde_json::from_value(record.clone()).ok()?;
    build_canonical(&audit_record).ok()
}

/// Verify attestation chain integrity in the audit log.
pub fn cmd_attestation_verify(
    audit_dir: &Path,
    pubkey_path: Option<&Path>,
    branch_filter: Option<&str>,
    verify_merkle: bool,
    attestation_dir: &Path,
) -> Result<()> {
    // Load the audit log
    let log_path = audit_dir.join("events.ndjson");
    if !log_path.exists() {
        anyhow::bail!("audit log not found: {}", log_path.display());
    }

    // Q3: Check file size before reading (defense-in-depth, matches N8/G26 pattern)
    const MAX_ATTESTATION_FILE_BYTES: u64 = 500 * 1024 * 1024;
    check_file_size(&log_path, MAX_ATTESTATION_FILE_BYTES)?;

    let contents = std::fs::read_to_string(&log_path)
        .with_context(|| format!("reading {}", log_path.display()))?;

    let mut records: Vec<AuditRecord> = Vec::new();
    for (line_num, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditRecord>(line) {
            Ok(record) => records.push(record),
            Err(e) => {
                eprintln!("Warning: skipping line {}: {}", line_num + 1, e);
            }
        }
    }

    println!(
        "Loaded {} audit records from {}",
        records.len(),
        log_path.display()
    );

    // Filter to attestation records (governance-significant events with signatures or HMAC)
    let attestation_records: Vec<&AuditRecord> = records
        .iter()
        .filter(|r| {
            is_governance_significant(&r.event.event_type)
                && (r.signature.is_some() || r.hmac.is_some())
        })
        .filter(|r| {
            if let Some(filter) = branch_filter {
                r.event.branch_id.as_deref() == Some(filter)
            } else {
                true
            }
        })
        .collect();

    if attestation_records.is_empty() {
        println!("No attestation records found.");
        if let Some(bid) = branch_filter {
            println!("  (filtered by branch_id={})", bid);
        }
        // A-M5: Warn that 0 governance-significant records were found.
        eprintln!(
            "Warning: 0 governance-significant records found — attestation may not be enabled."
        );
        return Ok(());
    }

    println!(
        "Found {} attestation records to verify",
        attestation_records.len()
    );

    // Load public key if provided
    let verifying_key = if let Some(pk_path) = pubkey_path {
        let hex_str = std::fs::read_to_string(pk_path)
            .with_context(|| format!("reading public key {}", pk_path.display()))?;
        let key_bytes = hex_decode(hex_str.trim())
            .map_err(|e| anyhow::anyhow!("decoding public key hex: {}", e))?;
        if key_bytes.len() != 32 {
            anyhow::bail!("public key must be 32 bytes, got {}", key_bytes.len());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_bytes);
        Some(VerifyingKey::from_bytes(&arr).context("invalid Ed25519 public key")?)
    } else {
        None
    };

    let mut counters = VerificationCounters::default();

    // Build record_id -> record index for chain verification
    let record_id_map: HashMap<&str, usize> = attestation_records
        .iter()
        .enumerate()
        .filter_map(|(i, r)| r.record_id.as_deref().map(|rid| (rid, i)))
        .collect();

    // Verify each attestation record
    for record in &attestation_records {
        let rid = record.record_id.as_deref().unwrap_or("(none)");
        let sig_hex = record.signature.as_deref().unwrap_or("");

        // 1. Verify Ed25519 signature
        let canonical = build_canonical(record)?;
        let sig_result = verify_signature(&canonical, sig_hex, verifying_key.as_ref(), rid);
        apply_signature_result(sig_result, &mut counters);

        // 2. Verify per-branch chain (parent_record_id linkage)
        verify_chain_link(
            rid,
            record.parent_record_id.as_deref(),
            &record_id_map,
            &mut counters,
        );
    }

    // 3. Verify Merkle inclusion proofs (if requested)
    if verify_merkle {
        let root_path = attestation_dir.join("root_hash");
        if root_path.exists() {
            let root_hex = std::fs::read_to_string(&root_path)
                .with_context(|| format!("reading {}", root_path.display()))?;
            let root_bytes = hex_decode(root_hex.trim())
                .map_err(|e| anyhow::anyhow!("decoding root hash: {}", e))?;
            if root_bytes.len() != 32 {
                anyhow::bail!("root hash must be 32 bytes, got {}", root_bytes.len());
            }
            let mut expected_root = [0u8; 32];
            expected_root.copy_from_slice(&root_bytes);

            for record in &attestation_records {
                if let Some(leaf_idx) = record.merkle_leaf_index {
                    let canonical = build_canonical(record)?;
                    let leaf_hash = hash_leaf(canonical.as_bytes());

                    // Look for proof file: <attestation_dir>/proofs/<leaf_idx>.json
                    let proof_path = attestation_dir
                        .join("proofs")
                        .join(format!("{}.json", leaf_idx));
                    if proof_path.exists() {
                        let proof_json = std::fs::read_to_string(&proof_path)
                            .with_context(|| format!("reading {}", proof_path.display()))?;
                        let proof: InclusionProof = serde_json::from_str(&proof_json)
                            .with_context(|| format!("parsing {}", proof_path.display()))?;

                        match verify_merkle_inclusion(&leaf_hash, &proof, &expected_root) {
                            Ok(true) => counters.merkle_ok += 1,
                            Ok(false) => {
                                counters.merkle_fail += 1;
                                let rid = record.record_id.as_deref().unwrap_or("(none)");
                                eprintln!(
                                    "  FAIL: Merkle proof invalid for record {} (leaf {})",
                                    rid, leaf_idx
                                );
                            }
                            Err(e) => {
                                counters.merkle_fail += 1;
                                let rid = record.record_id.as_deref().unwrap_or("(none)");
                                eprintln!("  FAIL: Merkle proof error for record {}: {}", rid, e);
                            }
                        }
                    } else {
                        counters.merkle_skip += 1;
                    }
                } else {
                    counters.merkle_skip += 1;
                }
            }
        } else {
            println!(
                "Warning: no root_hash file found in {}; skipping Merkle verification",
                attestation_dir.display()
            );
            // N9: Safe cast avoiding truncation on 32-bit platforms
            counters.merkle_skip = u64::try_from(attestation_records.len()).unwrap_or(u64::MAX);
        }
    }

    // 4. Verify expected event sequences per branch
    //    Each branch must start with branch_created and end with a terminal event.
    let mut seq_ok = 0u64;
    let mut seq_fail = 0u64;
    {
        // Group attestation records by branch_id
        let mut branch_events: HashMap<String, Vec<&str>> = HashMap::new();
        for record in &attestation_records {
            if let Some(ref bid) = record.event.branch_id {
                branch_events
                    .entry(bid.clone())
                    .or_default()
                    .push(&record.event.event_type);
            }
        }

        for (bid, events) in &branch_events {
            let mut ok = true;

            // Must start with branch_created
            if events.first().copied() != Some("branch_created") {
                eprintln!(
                    "  FAIL: branch {} chain does not start with branch_created (starts with {})",
                    bid,
                    events.first().unwrap_or(&"(empty)")
                );
                ok = false;
            }

            // Must end with a terminal event (or be in-progress)
            let terminal_events = ["branch_committed", "branch_rolled_back", "agent_killed"];
            if let Some(last) = events.last() {
                if !terminal_events.contains(last) {
                    // Not an error if the branch is still active — just a warning
                    eprintln!(
                        "  WARN: branch {} chain does not end with a terminal event (ends with {})",
                        bid, last
                    );
                }
            }

            if ok {
                seq_ok += 1;
            } else {
                seq_fail += 1;
            }
        }
    }

    // Print summary
    println!("\n--- Attestation Verification Summary ---");
    println!("Total attestation records: {}", attestation_records.len());

    if verifying_key.is_some() {
        println!(
            "Signatures:  {} ok, {} failed",
            counters.sig_ok, counters.sig_fail
        );
    } else {
        println!("Signatures:  skipped (no --pubkey provided)");
    }

    println!(
        "Chain links: {} ok, {} broken",
        counters.chain_ok, counters.chain_fail
    );
    println!("Sequences:   {} ok, {} invalid", seq_ok, seq_fail);

    if verify_merkle {
        println!(
            "Merkle:      {} ok, {} failed, {} skipped",
            counters.merkle_ok, counters.merkle_fail, counters.merkle_skip
        );
    }

    let total_failures = counters.total_failures() + seq_fail;
    if total_failures > 0 {
        println!("\nRESULT: FAILED ({} issues found)", total_failures);
        return Err(anyhow::anyhow!(
            "attestation verification failed ({} issues found)",
            total_failures
        ));
    } else {
        println!("\nRESULT: PASSED");
    }

    Ok(())
}

/// Verify an exported attestation bundle file (Gap 23).
///
/// Loads the bundle JSON, extracts the public key, records, and Merkle proofs,
/// then verifies:
/// 1. Ed25519 signature on each record using the bundle's public_key
/// 2. Merkle inclusion proofs against the bundle's merkle_root
/// 3. parent_record_id chain continuity
pub fn cmd_attestation_verify_bundle(bundle_path: &Path) -> Result<()> {
    // S11: Check file size before reading to prevent OOM on huge files
    const MAX_BUNDLE_SIZE: u64 = 50 * 1024 * 1024; // 50 MiB
    check_file_size(bundle_path, MAX_BUNDLE_SIZE)?;

    let contents = std::fs::read_to_string(bundle_path)
        .with_context(|| format!("reading bundle {}", bundle_path.display()))?;
    let bundle: serde_json::Value = serde_json::from_str(&contents)
        .with_context(|| format!("parsing bundle {}", bundle_path.display()))?;

    let public_key_hex = bundle["public_key"].as_str().unwrap_or("");
    let merkle_root_hex = bundle["merkle_root"].as_str();
    let records = bundle["records"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("bundle missing 'records' array"))?;
    let merkle_proofs = bundle["merkle_inclusion_proofs"].as_array();

    println!("Verifying attestation bundle: {}", bundle_path.display());
    println!(
        "  Branch: {}",
        bundle["branch_id"].as_str().unwrap_or("(unknown)")
    );
    println!("  Records: {}", records.len());

    // Load public key
    let verifying_key = if !public_key_hex.is_empty() {
        let key_bytes = hex_decode(public_key_hex)
            .map_err(|e| anyhow::anyhow!("decoding public key from bundle: {}", e))?;
        if key_bytes.len() != 32 {
            anyhow::bail!(
                "bundle public key must be 32 bytes, got {}",
                key_bytes.len()
            );
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_bytes);
        Some(VerifyingKey::from_bytes(&arr).context("invalid Ed25519 public key in bundle")?)
    } else {
        println!("  Warning: no public_key in bundle, skipping signature verification");
        None
    };

    // Load Merkle root
    let expected_root = if let Some(root_hex) = merkle_root_hex {
        let root_bytes =
            hex_decode(root_hex).map_err(|e| anyhow::anyhow!("decoding merkle_root: {}", e))?;
        if root_bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&root_bytes);
            Some(arr)
        } else {
            None
        }
    } else {
        None
    };

    // Build index of Merkle proofs by record_seq (PRD §3.1.4 bundle format)
    let mut proof_by_seq: HashMap<u64, &serde_json::Value> = HashMap::new();
    if let Some(proofs) = merkle_proofs {
        for p in proofs {
            if let Some(seq) = p["record_seq"].as_u64() {
                proof_by_seq.insert(seq, p);
            }
        }
    }

    let mut counters = VerificationCounters::default();
    let mut timestamp_violations = 0u64;
    let mut prev_timestamp: Option<String> = None;

    // Build a set of record_ids for chain verification
    let record_id_set: std::collections::HashSet<String> = records
        .iter()
        .filter_map(|r| r["record_id"].as_str().map(|s| s.to_string()))
        .collect();

    for record in records {
        let rid = record["record_id"].as_str().unwrap_or("(none)");
        let seq = record["seq"].as_u64().unwrap_or(0);

        // 1. Verify Ed25519 signature
        if verifying_key.is_some() {
            if let Some(sig_hex) = record["signature"].as_str() {
                // Build canonical attestation string from the record fields
                let canonical = match build_canonical_from_value(record) {
                    Some(c) => c,
                    None => {
                        counters.sig_fail += 1;
                        eprintln!("  Record {}: malformed (missing seq/timestamp)", rid);
                        continue;
                    }
                };
                let sig_result = verify_signature(&canonical, sig_hex, verifying_key.as_ref(), rid);
                apply_signature_result(sig_result, &mut counters);
            } else {
                counters.sig_fail += 1;
                eprintln!("  FAIL: no signature for record {}", rid);
            }
        }

        // 2. Verify Merkle inclusion proof
        if let Some(ref root) = expected_root {
            if let Some(proof_val) = proof_by_seq.get(&seq) {
                let proof_result: std::result::Result<InclusionProof, _> =
                    serde_json::from_value((*proof_val).clone());
                match proof_result {
                    Ok(proof) => {
                        let canonical = match build_canonical_from_value(record) {
                            Some(c) => c,
                            None => {
                                counters.merkle_fail += 1;
                                eprintln!("  Record {}: malformed (missing seq/timestamp)", rid);
                                continue;
                            }
                        };
                        let leaf_hash = hash_leaf(canonical.as_bytes());
                        match verify_merkle_inclusion(&leaf_hash, &proof, root) {
                            Ok(true) => counters.merkle_ok += 1,
                            Ok(false) => {
                                counters.merkle_fail += 1;
                                eprintln!(
                                    "  FAIL: Merkle proof invalid for record {} (seq {})",
                                    rid, seq
                                );
                            }
                            Err(e) => {
                                counters.merkle_fail += 1;
                                eprintln!("  FAIL: Merkle proof error for record {}: {}", rid, e);
                            }
                        }
                    }
                    Err(e) => {
                        counters.merkle_fail += 1;
                        eprintln!("  FAIL: cannot parse Merkle proof for seq {}: {}", seq, e);
                    }
                }
            } else {
                counters.merkle_skip += 1;
            }
        } else {
            counters.merkle_skip += 1;
        }

        // 3. Verify parent_record_id chain continuity
        verify_chain_link(
            rid,
            record["parent_record_id"].as_str(),
            &record_id_set,
            &mut counters,
        );

        // 4. §3.1.8: Verify timestamp ordering (timestamp >= parent's timestamp)
        if let Some(ts) = record["timestamp"].as_str() {
            if let Some(ref prev_ts) = prev_timestamp {
                if ts < prev_ts.as_str() {
                    timestamp_violations += 1;
                    eprintln!(
                        "  FAIL: timestamp regression — record {} has {} < parent {}",
                        rid, ts, prev_ts
                    );
                }
            }
            prev_timestamp = Some(ts.to_string());
        }
    }

    // 5. §3.1.5: Verify expected event sequencing
    let mut sequencing_issues = Vec::new();
    if !records.is_empty() {
        let first_event_type = records[0]["event"]["event_type"].as_str().unwrap_or("");
        if first_event_type != "branch_created" {
            sequencing_issues.push(format!(
                "chain must start with branch_created, got '{}'",
                first_event_type
            ));
        }
        let last_event_type = records
            .last()
            .and_then(|r| r["event"]["event_type"].as_str())
            .unwrap_or("");
        let terminal_events = ["branch_committed", "branch_rolled_back", "agent_killed"];
        if !terminal_events.contains(&last_event_type) {
            sequencing_issues.push(format!(
                "chain should end with terminal event (branch_committed/branch_rolled_back/agent_killed), got '{}'",
                last_event_type
            ));
        }
    }

    // 6. §3.1.5 item 6: Verify changeset_hash matches SHA-256 of commit_manifest canonical JSON
    let mut manifest_hash_ok = true;
    let commit_manifest = &bundle["commit_manifest"];
    if !commit_manifest.is_null() {
        // Find the branch_committed record
        for record in records {
            let event_type = record["event"]["event_type"].as_str().unwrap_or("");
            if event_type == "branch_committed" {
                if let Some(claimed_hash) = record["changeset_hash"].as_str() {
                    use sha2::{Digest, Sha256};
                    // Use sort_json_keys for canonical deterministic serialization
                    // to match puzzled's BTreeMap-based serialization regardless of
                    // serde_json's internal key ordering.
                    let canonical_manifest =
                        serde_json::to_string(&sort_json_keys(commit_manifest.clone()))
                            .unwrap_or_else(|e| {
                                eprintln!("F7: failed to serialize manifest for hash: {e}");
                                "{}".to_string()
                            });
                    let mut hasher = Sha256::new();
                    hasher.update(canonical_manifest.as_bytes());
                    let computed_hash = format!("{:x}", hasher.finalize());
                    if claimed_hash != computed_hash {
                        manifest_hash_ok = false;
                        eprintln!(
                            "  FAIL: changeset_hash mismatch — record claims {}, manifest hashes to {}",
                            claimed_hash, computed_hash
                        );
                    }
                }
                break;
            }
        }
    }

    // Print summary
    println!("\n--- Bundle Verification Summary ---");
    println!("Total records: {}", records.len());

    if verifying_key.is_some() {
        println!(
            "Signatures:  {} ok, {} failed",
            counters.sig_ok, counters.sig_fail
        );
    } else {
        println!("Signatures:  skipped (no public_key in bundle)");
    }

    println!(
        "Chain links: {} ok, {} broken",
        counters.chain_ok, counters.chain_fail
    );
    println!("Timestamps:  {} violations", timestamp_violations);

    if expected_root.is_some() {
        println!(
            "Merkle:      {} ok, {} failed, {} skipped",
            counters.merkle_ok, counters.merkle_fail, counters.merkle_skip
        );
    } else {
        println!("Merkle:      skipped (no merkle_root in bundle)");
    }

    if !sequencing_issues.is_empty() {
        println!("Sequencing:  {} issues", sequencing_issues.len());
        for issue in &sequencing_issues {
            eprintln!("  WARNING: {}", issue);
        }
    } else {
        println!("Sequencing:  ok");
    }

    if !commit_manifest.is_null() {
        println!(
            "Manifest:    {}",
            if manifest_hash_ok {
                "hash verified"
            } else {
                "HASH MISMATCH"
            }
        );
    }

    let total_failures = counters.total_failures()
        + timestamp_violations
        + u64::try_from(sequencing_issues.len()).unwrap_or(u64::MAX) // Q11: safe cast
        + if manifest_hash_ok { 0 } else { 1 };
    if total_failures > 0 {
        println!("\nRESULT: FAILED ({} issues found)", total_failures);
        return Err(anyhow::anyhow!(
            "attestation bundle verification failed ({} issues found)",
            total_failures
        ));
    } else {
        println!("\nRESULT: PASSED");
    }

    Ok(())
}

// --- Attestation bundle export (§3.1.4) ---

/// Load and parse audit records from an NDJSON file, optionally filtering by branch_id.
fn load_attestation_records(
    audit_dir: &Path,
    branch_filter: Option<&str>,
) -> Result<Vec<AuditRecord>> {
    // N8: Maximum attestation file size (defense-in-depth, matches G26 pattern)
    const MAX_ATTESTATION_FILE_BYTES: u64 = 500 * 1024 * 1024;

    let log_path = audit_dir.join("events.ndjson");
    if !log_path.exists() {
        anyhow::bail!("audit log not found: {}", log_path.display());
    }

    // N8: Check file size before reading to prevent unbounded memory allocation
    let file_size = std::fs::metadata(&log_path)
        .with_context(|| format!("N8: stat {}", log_path.display()))?
        .len();
    if file_size > MAX_ATTESTATION_FILE_BYTES {
        anyhow::bail!(
            "N8: attestation file {} is {} bytes, exceeds limit of {} bytes",
            log_path.display(),
            file_size,
            MAX_ATTESTATION_FILE_BYTES
        );
    }

    let contents = std::fs::read_to_string(&log_path)
        .with_context(|| format!("reading {}", log_path.display()))?;

    let mut records: Vec<AuditRecord> = Vec::new();
    for (line_num, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditRecord>(line) {
            Ok(record) => {
                // Filter to governance-significant events with signatures or HMAC
                let has_auth = record.signature.is_some() || record.hmac.is_some();
                if is_governance_significant(&record.event.event_type) && has_auth {
                    if let Some(filter) = branch_filter {
                        if record.event.branch_id.as_deref() == Some(filter) {
                            records.push(record);
                        }
                    } else {
                        records.push(record);
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: skipping line {}: {}", line_num + 1, e);
            }
        }
    }

    Ok(records)
}

/// Build key rotation history by scanning for archived public key files.
///
/// Archived keys are stored as `<keyname>.pub.<timestamp>` (e.g., `public_key.hex.1710500000`)
/// in the attestation directory. Each entry records the hex-encoded public key and the
/// timestamp at which it was archived (i.e., rotated out).
fn build_key_rotation_history(attestation_dir: &Path) -> Vec<serde_json::Value> {
    let mut history: Vec<(u64, serde_json::Value)> = Vec::new();

    let read_dir = match std::fs::read_dir(attestation_dir) {
        Ok(rd) => rd,
        Err(_) => return Vec::new(),
    };

    for entry in read_dir.flatten() {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        // Match files like "public_key.hex.1710500000"
        if let Some(rest) = name.strip_prefix("public_key.hex.") {
            if let Ok(timestamp) = rest.parse::<u64>() {
                // Read the archived public key
                if let Ok(contents) = std::fs::read_to_string(entry.path()) {
                    let pubkey_hex = contents.trim().to_string();
                    if !pubkey_hex.is_empty() {
                        history.push((
                            timestamp,
                            serde_json::json!({
                                "public_key": pubkey_hex,
                                "valid_from": null,
                                "valid_until": timestamp,
                            }),
                        ));
                    }
                }
            }
        }
    }

    // Sort by timestamp ascending
    history.sort_by_key(|(ts, _)| *ts);

    // Fill in valid_from: each key's valid_from is the previous key's valid_until
    let mut result: Vec<serde_json::Value> = Vec::with_capacity(history.len());
    let mut prev_until: Option<u64> = None;
    for (ts, mut entry) in history {
        if let Some(prev) = prev_until {
            entry["valid_from"] = serde_json::json!(prev);
        }
        prev_until = Some(ts);
        result.push(entry);
    }

    result
}

/// Load the IMA commit manifest for a branch, if it exists.
///
/// Looks for `<attestation_dir>/manifests/<branch_id>.manifest.yaml`. If found,
/// parses the YAML and returns it as a JSON value. Returns `null` if not found.
fn load_commit_manifest(attestation_dir: &Path, branch_id: &str) -> serde_json::Value {
    let manifest_path = attestation_dir
        .join("manifests")
        .join(format!("{}.manifest.yaml", branch_id));

    if !manifest_path.exists() {
        // Also check the legacy location under /var/lib/puzzled/branches/manifests/
        let legacy_path = Path::new("/var/lib/puzzled/branches/manifests")
            .join(format!("{}.manifest.yaml", branch_id));
        if legacy_path.exists() {
            return load_manifest_file(&legacy_path);
        }
        return serde_json::Value::Null;
    }

    load_manifest_file(&manifest_path)
}

/// Read and parse a YAML manifest file, returning it as a JSON value.
fn load_manifest_file(path: &Path) -> serde_json::Value {
    match std::fs::read_to_string(path) {
        Ok(contents) => match serde_yaml::from_str::<serde_json::Value>(&contents) {
            Ok(value) => value,
            Err(e) => {
                eprintln!(
                    "Warning: failed to parse manifest {}: {}",
                    path.display(),
                    e
                );
                serde_json::Value::Null
            }
        },
        Err(e) => {
            eprintln!("Warning: failed to read manifest {}: {}", path.display(), e);
            serde_json::Value::Null
        }
    }
}

/// Export a self-contained, offline-verifiable attestation bundle for a branch (PRD §3.1.4).
pub fn cmd_attestation_export(
    branch_id: &str,
    output_path: Option<&str>,
    audit_dir: &Path,
    attestation_dir: &Path,
) -> Result<()> {
    // T26: Validate branch_id to prevent path traversal (matches M-ctl2 pattern)
    validate_branch_id(branch_id)?;

    let records = load_attestation_records(audit_dir, Some(branch_id))?;

    if records.is_empty() {
        anyhow::bail!(
            "no attestation records found for branch '{}' in {}",
            branch_id,
            audit_dir.display()
        );
    }

    // Load public key if available
    let pubkey_path = attestation_dir.join("public_key.hex");
    let public_key = if pubkey_path.exists() {
        let hex_str = std::fs::read_to_string(&pubkey_path)
            .with_context(|| format!("reading {}", pubkey_path.display()))?;
        hex_str.trim().to_string()
    } else {
        String::new()
    };

    // Load Merkle root hash if available
    let root_path = attestation_dir.join("root_hash");
    let merkle_root = if root_path.exists() {
        let hex_str = std::fs::read_to_string(&root_path)
            .with_context(|| format!("reading {}", root_path.display()))?;
        Some(hex_str.trim().to_string())
    } else {
        None
    };

    // Build Merkle inclusion proofs for records that have leaf indices
    let mut inclusion_proofs: Vec<serde_json::Value> = Vec::new();
    for record in &records {
        if let Some(leaf_idx) = record.merkle_leaf_index {
            let proof_path = attestation_dir
                .join("proofs")
                .join(format!("{}.json", leaf_idx));
            if proof_path.exists() {
                let proof_json = std::fs::read_to_string(&proof_path)
                    .with_context(|| format!("reading {}", proof_path.display()))?;
                let proof: serde_json::Value = serde_json::from_str(&proof_json)
                    .with_context(|| format!("parsing {}", proof_path.display()))?;
                // Match D-Bus export format: flat structure with record_seq,
                // leaf_index, tree_size, proof_hashes (not nested "proof").
                inclusion_proofs.push(serde_json::json!({
                    "record_seq": record.seq,
                    "leaf_index": leaf_idx,
                    "tree_size": proof.get("tree_size").cloned().unwrap_or(serde_json::Value::Null),
                    "proof_hashes": proof.get("proof_hashes").cloned().unwrap_or(serde_json::json!([])),
                }));
            }
        }
    }

    // Serialize records via serde to match the D-Bus export format (nested `event`
    // structure). This ensures `build_canonical_from_value` can find `event_type`,
    // `branch_id`, and `details` under `record["event"]`.
    let record_values: Vec<serde_json::Value> = records
        .iter()
        .filter_map(|r| serde_json::to_value(r).ok())
        .collect();

    // Gap 18: Scan for archived public key files to build key_rotation_history.
    // Archived keys are stored as <keyname>.pub.<timestamp> in the same directory
    // as public_key.hex (the attestation_dir).
    let key_rotation_history = build_key_rotation_history(attestation_dir);

    // Gap 19: Attempt to load IMA commit manifest for this branch.
    // Look for <attestation_dir>/manifests/<branch_id>.manifest.yaml
    let commit_manifest = load_commit_manifest(attestation_dir, branch_id);

    // Build the attestation bundle (PRD §3.1.4 format)
    let bundle = serde_json::json!({
        "version": 1,
        "branch_id": branch_id,
        "public_key": public_key,
        "key_rotation_history": key_rotation_history,
        "records": record_values,
        "commit_manifest": commit_manifest,
        "merkle_inclusion_proofs": inclusion_proofs,
        "merkle_root": merkle_root,
        "tpm_quote": null,
    });

    let json_output =
        serde_json::to_string_pretty(&bundle).context("serializing attestation bundle")?;

    if let Some(path) = output_path {
        std::fs::write(path, &json_output)
            .with_context(|| format!("writing attestation bundle to {}", path))?;
        println!(
            "Attestation bundle written to {} ({} records)",
            path,
            records.len()
        );
    } else {
        println!("{}", json_output);
    }

    Ok(())
}

/// Show the Merkle inclusion proof for a specific audit event sequence number.
pub fn cmd_attestation_inclusion(seq: u64, attestation_dir: &Path) -> Result<()> {
    let proof_path = attestation_dir.join("proofs").join(format!("{}.json", seq));

    if !proof_path.exists() {
        anyhow::bail!(
            "no inclusion proof found for seq {} at {}",
            seq,
            proof_path.display()
        );
    }

    let proof_json = std::fs::read_to_string(&proof_path)
        .with_context(|| format!("reading {}", proof_path.display()))?;
    let proof: InclusionProof = serde_json::from_str(&proof_json)
        .with_context(|| format!("parsing {}", proof_path.display()))?;

    println!(
        "Merkle inclusion proof for leaf index {}:",
        proof.leaf_index
    );
    println!("  Tree size: {}", proof.tree_size);
    println!("  Proof path ({} hashes):", proof.proof_hashes.len());
    for (i, hash) in proof.proof_hashes.iter().enumerate() {
        println!("    [{}] {}", i, hash);
    }

    // Verify against root hash if available
    let root_path = attestation_dir.join("root_hash");
    if root_path.exists() {
        let root_hex = std::fs::read_to_string(&root_path)
            .with_context(|| format!("reading {}", root_path.display()))?;
        let root_bytes = hex_decode(root_hex.trim())
            .map_err(|e| anyhow::anyhow!("decoding root hash: {}", e))?;
        if root_bytes.len() == 32 {
            let mut expected_root = [0u8; 32];
            expected_root.copy_from_slice(&root_bytes);
            println!("  Root hash: {}", root_hex.trim());
        }
    }

    Ok(())
}

/// Show the Merkle consistency proof between two tree sizes.
pub fn cmd_attestation_consistency(from: u64, to: u64, attestation_dir: &Path) -> Result<()> {
    if from >= to {
        anyhow::bail!("--from ({}) must be less than --to ({})", from, to);
    }

    // Look for a consistency proof file: <attestation_dir>/consistency/<from>_<to>.json
    let proof_path = attestation_dir
        .join("consistency")
        .join(format!("{}_{}.json", from, to));

    if !proof_path.exists() {
        anyhow::bail!(
            "no consistency proof found for sizes {}..{} at {}",
            from,
            to,
            proof_path.display()
        );
    }

    let proof_json = std::fs::read_to_string(&proof_path)
        .with_context(|| format!("reading {}", proof_path.display()))?;
    let proof: puzzled_types::ConsistencyProof = serde_json::from_str(&proof_json)
        .with_context(|| format!("parsing {}", proof_path.display()))?;

    println!(
        "Merkle consistency proof (tree size {} -> {}):",
        proof.old_size, proof.new_size
    );
    println!("  Proof path ({} hashes):", proof.proof_hashes.len());
    for (i, hash) in proof.proof_hashes.iter().enumerate() {
        println!("    [{}] {}", i, hash);
    }

    Ok(())
}

/// Show the current attestation public key.
pub fn cmd_attestation_pubkey(attestation_dir: &Path) -> Result<()> {
    let pubkey_path = attestation_dir.join("public_key.hex");

    if !pubkey_path.exists() {
        anyhow::bail!(
            "no public key found at {} (is puzzled running with attestation enabled?)",
            pubkey_path.display()
        );
    }

    let hex_str = std::fs::read_to_string(&pubkey_path)
        .with_context(|| format!("reading {}", pubkey_path.display()))?;
    let hex_trimmed = hex_str.trim();

    // Validate it's a valid Ed25519 public key
    let key_bytes =
        hex_decode(hex_trimmed).map_err(|e| anyhow::anyhow!("decoding public key hex: {}", e))?;
    if key_bytes.len() != 32 {
        anyhow::bail!("public key must be 32 bytes, got {} bytes", key_bytes.len());
    }

    // Verify it's a valid Ed25519 point
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key_bytes);
    VerifyingKey::from_bytes(&arr).context("invalid Ed25519 public key")?;

    println!("{}", hex_trimmed);

    Ok(())
}
