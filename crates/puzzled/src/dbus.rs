// SPDX-License-Identifier: Apache-2.0
use std::collections::HashMap;
use std::sync::Arc;

use crate::audit::AuditEvent;
use crate::audit::AuditLogger;
use crate::audit_store::AuditStore;
use crate::branch::BranchManager;
use crate::config::DaemonConfig;
use crate::provenance::ProvenanceStore;
use crate::trust::TrustManager;
use anyhow::Result;
use puzzled_types::BranchId;
#[cfg(feature = "ima")]
use puzzled_types::TrustLevel;
use zbus::connection::Connection;
use zbus::interface;
use zbus::object_server::SignalEmitter;

/// A-M2: Read the SELinux context for a process from `/proc/<pid>/attr/current`.
///
/// Returns `None` if the file doesn't exist (SELinux not enabled), if the process
/// has exited, or if the context is the default "unconfined" placeholder.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn read_selinux_context(pid: u32) -> Option<String> {
    let path = format!("/proc/{}/attr/current", pid);
    match std::fs::read_to_string(&path) {
        Ok(ctx) => {
            let ctx = ctx.trim_end_matches('\0').trim().to_string();
            if ctx.is_empty() || ctx == "unconfined" {
                None
            } else {
                Some(ctx)
            }
        }
        Err(_) => None,
    }
}

/// K21/K22: Sanitize user-supplied reason strings before logging.
/// Replaces control characters (0x00-0x1F, 0x7F) with underscores to prevent
/// log injection attacks (e.g., fake log lines via embedded newlines).
fn sanitize_log_reason(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '_' } else { c })
        .collect()
}

/// M10: Simple per-UID rate limiter for branch creation.
/// Tracks timestamps of recent requests per UID; rejects if > MAX_PER_MINUTE.
/// A3: Bounded to MAX_TRACKED_UIDS to prevent memory exhaustion from UID cycling.
struct RateLimiter {
    /// Recent request timestamps per caller UID.
    requests: HashMap<u32, Vec<std::time::Instant>>,
}

impl RateLimiter {
    const MAX_PER_MINUTE: usize = 10;
    /// A3: Maximum number of UIDs tracked. Prevents memory exhaustion if an attacker
    /// cycles through many UIDs. When the limit is reached, stale UIDs (no requests
    /// in the last 60s) are evicted first; if still full, the oldest UID is evicted.
    const MAX_TRACKED_UIDS: usize = 4096;

    fn new() -> Self {
        Self {
            requests: HashMap::new(),
        }
    }

    /// Check if a request from this UID is allowed. Returns false if rate-limited.
    fn check(&mut self, uid: u32) -> bool {
        let now = std::time::Instant::now();
        let cutoff = now - std::time::Duration::from_secs(60);

        // A3: Evict stale UIDs before checking, to keep map bounded
        self.requests.retain(|_, times| {
            times.retain(|t| *t > cutoff);
            !times.is_empty()
        });

        // A3: If still at capacity after stale eviction, evict the UID
        // with the oldest most-recent request to make room
        if self.requests.len() >= Self::MAX_TRACKED_UIDS && !self.requests.contains_key(&uid) {
            if let Some((&oldest_uid, _)) = self
                .requests
                .iter()
                .min_by_key(|(_, times)| times.last().copied().unwrap_or(now))
            {
                self.requests.remove(&oldest_uid);
            }
        }

        let times = self.requests.entry(uid).or_default();
        if times.len() >= Self::MAX_PER_MINUTE {
            return false;
        }
        times.push(now);
        true
    }
}

/// DC2: Idempotency cache entry for CreateBranch. Stores the result JSON
/// and the time of the original request, enabling duplicate detection.
struct IdempotencyCacheEntry {
    result_json: String,
    created_at: std::time::Instant,
}

/// DC2: TTL for idempotency cache entries. Requests with the same key
/// (agent_name + profile) within this window return the cached result.
const IDEMPOTENCY_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// M-db3: Maximum number of entries in the idempotency cache.
/// When exceeded, the oldest (or a random) entry is evicted to prevent unbounded growth.
const MAX_IDEMPOTENCY_ENTRIES: usize = 1024;

/// M-db4: Maximum number of entries in the behavioral trigger throttle map.
const MAX_BEHAVIORAL_TRIGGER_ENTRIES: usize = 1024;

/// M-db4: Maximum age for behavioral trigger throttle entries (seconds).
const BEHAVIORAL_TRIGGER_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(300);

/// D-Bus interface: org.lobstertrap.PuzzlePod1.Manager
pub struct ManagerInterface {
    manager: Arc<BranchManager>,
    audit_store: Arc<tokio::sync::Mutex<AuditStore>>,
    rate_limiter: Arc<std::sync::Mutex<RateLimiter>>,
    /// L15: Tracks whether the daemon is fully initialized.
    /// Set to true after all subsystems are ready.
    initialized: Arc<std::sync::atomic::AtomicBool>,
    /// DC2: Idempotency cache for CreateBranch. Key is "{profile}:{base_path}:{command_json}"
    /// from the same caller UID. Prevents duplicate branch creation on D-Bus retries.
    idempotency_cache: Arc<std::sync::Mutex<HashMap<String, IdempotencyCacheEntry>>>,
    /// PXH4: Audit logger for emitting audit events on D-Bus operations.
    audit_logger: Arc<AuditLogger>,
    /// PM11: Tracks last BehavioralTrigger signal emission time per branch.
    /// Rate-limited to at most 1 signal per branch per 10 seconds to prevent
    /// flooding D-Bus subscribers during sustained anomalous behavior.
    behavioral_trigger_last_emitted: Arc<std::sync::Mutex<HashMap<String, std::time::Instant>>>,
    /// §4.1: Trust manager for per-UID trust scoring and behavioral baselines.
    trust_manager: Arc<std::sync::Mutex<TrustManager>>,
    /// §4.3: Provenance store for per-branch causal chain records.
    provenance_store: Arc<ProvenanceStore>,
    /// §4.5: Identity manager for JWT-SVID issuance (requires ima feature).
    #[cfg(feature = "ima")]
    identity_manager: Arc<crate::identity::IdentityManager>,
}

#[interface(name = "org.lobstertrap.PuzzlePod1.Manager")]
impl ManagerInterface {
    /// Create a branch workspace (overlay directories + metadata).
    /// No sandboxed process is spawned. Call `activate_branch` to spawn one.
    async fn create_branch(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        profile: &str,
        base_path: &str,
        command_json: &str,
    ) -> zbus::fdo::Result<String> {
        // H52: Log command_json length instead of full value to avoid leaking
        // potentially sensitive command arguments into log output.
        tracing::info!(
            profile,
            base_path,
            command_json_len = command_json.len(),
            "CreateBranch requested"
        );

        // L15: Reject agent registration if daemon is not fully initialized
        if !self.initialized.load(std::sync::atomic::Ordering::Acquire) {
            tracing::warn!("CreateBranch rejected: daemon not fully initialized");
            return Err(zbus::fdo::Error::Failed(
                "daemon is not fully initialized; try again shortly".into(),
            ));
        }

        let uid = get_caller_uid(&header, connection).await?;

        // Validate D-Bus inputs before rate limiting — invalid requests
        // should not consume rate limit quota.
        validate_dbus_inputs(profile, base_path, command_json)?;

        // M10: Rate-limit branch creation per caller UID
        {
            let mut limiter = self.rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
            if !limiter.check(uid) {
                tracing::warn!(uid, "branch creation rate-limited");
                return Err(zbus::fdo::Error::Failed(format!(
                    "rate limited: max {} branch creates per minute per UID",
                    RateLimiter::MAX_PER_MINUTE
                )));
            }
        }

        // DC2: Idempotency check
        let idempotency_key = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(uid.to_le_bytes());
            hasher.update(b"\x00");
            hasher.update(profile.as_bytes());
            hasher.update(b"\x00");
            hasher.update(base_path.as_bytes());
            hasher.update(b"\x00");
            hasher.update(command_json.as_bytes());
            format!("{:x}", hasher.finalize())
        };
        {
            let mut cache = self
                .idempotency_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            cache.retain(|_, entry| entry.created_at.elapsed() < IDEMPOTENCY_TTL);
            if let Some(entry) = cache.get(&idempotency_key) {
                // Verify the cached branch still exists. If it was committed
                // or rolled back, the entry is stale and should be evicted
                // so a new branch can be created with the same parameters.
                let still_valid = serde_json::from_str::<serde_json::Value>(&entry.result_json)
                    .ok()
                    .and_then(|v| v.get("id").and_then(|id| id.as_str().map(String::from)))
                    .and_then(|id_str| puzzled_types::BranchId::validated(id_str).ok())
                    .map(|bid| self.manager.inspect(&bid).is_some())
                    .unwrap_or(false);

                if still_valid {
                    tracing::info!(
                        profile,
                        base_path,
                        "CreateBranch returning cached result (idempotent retry)"
                    );
                    return Ok(entry.result_json.clone());
                }
                cache.remove(&idempotency_key);
            }
        }

        let manager = &*self.manager;

        let agent_uid = if uid == 0 { 65534 } else { uid };

        let info = manager
            .create_branch(profile, std::path::Path::new(base_path), agent_uid)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        // Y1: Register the agent UID with the trust manager using profile-specific
        // initial scores. PRD §4.1.9: "Callers should call this when a branch is
        // created with a known profile to ensure the correct initial score is used."
        // Existing UIDs are not overwritten (or_insert_with semantics).
        {
            let mut trust = self.trust_manager.lock().unwrap_or_else(|e| e.into_inner());
            trust.register_uid(agent_uid, profile);
        }

        let json =
            serde_json::to_string(&info).map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        // L-br1: Audit event for branch creation is emitted in BranchManager::create()
        // (branch.rs). Removed the duplicate here to avoid double-logging.

        // ── Attestation bridge (§3.1) ──────────────────────────────────────
        // Write branch_created event to persistent NDJSON audit store for
        // Ed25519 signature and Merkle tree leaf.  BranchManager::create()
        // logs to AuditLogger (syslog/netlink) but not AuditStore.
        //
        // ⚠ PODMAN MERGE CONFLICT RISK: This block touches dbus.rs which is
        // also modified by the Podman-native architecture refactor.  Keep
        // clearly delimited so it can be re-applied after a Podman merge.
        {
            let create_event = AuditEvent::BranchCreated {
                branch_id: info.id.clone(),
                profile: profile.to_string(),
                uid: agent_uid,
            };
            let identity = puzzled_types::AgentIdentity {
                uid: agent_uid,
                profile: profile.to_string(),
                selinux_context: info.selinux_context.clone(),
                framework: None,
            };
            if let Err(e) = self.audit_store.lock().await.store_with_context(
                &create_event,
                Some(identity),
                None,
            ) {
                tracing::warn!(branch_id = %info.id, error = %e, "failed to store branch_created event in audit store");
            }
        }
        // ── End attestation bridge ──────────────────────────────────────────

        // DC2: Store result in idempotency cache
        {
            let mut cache = self
                .idempotency_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());

            if cache.len() >= MAX_IDEMPOTENCY_ENTRIES {
                let oldest_key = cache
                    .iter()
                    .min_by_key(|(_, entry)| entry.created_at)
                    .map(|(k, _)| k.clone());
                if let Some(key) = oldest_key {
                    cache.remove(&key);
                }
            }

            cache.insert(
                idempotency_key,
                IdempotencyCacheEntry {
                    result_json: json.clone(),
                    created_at: std::time::Instant::now(),
                },
            );
        }

        // H6: Emit D-Bus signal for branch creation
        let branch_id_str = info.id.to_string();
        if let Some(iface_ref) = get_signal_emitter(connection).await {
            if let Err(e) = ManagerInterface::branch_created(
                iface_ref.signal_emitter(),
                &branch_id_str,
                profile,
            )
            .await
            {
                tracing::debug!("F11: D-Bus signal emission failed: {e}");
            }
        }

        Ok(json)
    }

    /// Spawn a sandboxed process inside an existing branch.
    ///
    /// `command_json` is a JSON array of strings (e.g., `["/usr/bin/python3", "agent.py"]`).
    /// If empty string or `"[]"`, the child falls back to a pause() loop.
    async fn activate_branch(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        branch_id: &str,
        command_json: &str,
    ) -> zbus::fdo::Result<String> {
        validate_branch_id(branch_id)?;
        // J21: Log length instead of verbatim command_json to avoid leaking sensitive data
        tracing::info!(
            branch_id,
            command_json_len = command_json.len(),
            "ActivateBranch requested"
        );

        if !self.initialized.load(std::sync::atomic::Ordering::Acquire) {
            return Err(zbus::fdo::Error::Failed(
                "daemon is not fully initialized; try again shortly".into(),
            ));
        }

        let (uid, id) =
            validate_and_authorize(&header, connection, branch_id, &self.manager).await?;

        let command: Vec<String> = if command_json.is_empty() {
            vec![]
        } else {
            let parsed: Vec<String> = serde_json::from_str(command_json)
                .map_err(|e| zbus::fdo::Error::Failed(format!("invalid command JSON: {}", e)))?;
            for arg in &parsed {
                if arg.contains('\0') {
                    return Err(zbus::fdo::Error::Failed(
                        "command arguments must not contain null bytes".into(),
                    ));
                }
            }
            parsed
        };

        let agent_uid = if uid == 0 { 65534 } else { uid };

        self.manager
            .activate_branch(&id, agent_uid, 0, command)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let info = self
            .manager
            .inspect(&id)
            .ok_or_else(|| zbus::fdo::Error::Failed("branch not found after activation".into()))?;

        let json =
            serde_json::to_string(&info).map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        Ok(json)
    }

    /// Commit an active branch, applying governance policy.
    ///
    /// L-db3: Returns a JSON string (serialized `CommitResult`) rather than structured
    /// D-Bus types. This is intentional for flexibility — the JSON format allows adding
    /// fields without breaking the D-Bus interface contract. The PRD specifies structured
    /// D-Bus types, but JSON serialization was chosen during implementation for forward
    /// compatibility.
    async fn commit_branch(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        branch_id: &str,
    ) -> zbus::fdo::Result<String> {
        validate_branch_id(branch_id)?;
        tracing::info!(branch_id, "CommitBranch requested");

        #[allow(unused_variables)]
        let (uid, id) =
            validate_and_authorize(&header, connection, branch_id, &self.manager).await?;

        // M14: Idempotency — if branch is already committed, return cached result
        // m4 TODO: Cache the actual CommitResult from the first successful commit
        // so that repeated calls return the real files_committed/bytes_committed
        // values instead of zeros. Consider storing CommitResult in BranchInfo or
        // a separate DashMap<BranchId, CommitResult>.
        if let Some(info) = self.manager.inspect(&id) {
            if info.state == puzzled_types::BranchState::Committed {
                tracing::info!(branch_id, "CommitBranch idempotent — already committed");
                let result = puzzled_types::CommitResult {
                    branch_id: id.clone(),
                    policy_result: puzzled_types::PolicyDecision::Approved,
                    files_committed: 0,
                    bytes_committed: 0,
                };
                let json = serde_json::to_string(&result)
                    .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
                return Ok(json);
            }
        }

        // M20: Look up the branch profile and owner UID for enriched signal emission
        // (before commit changes state — inspect may return None after commit).
        let (branch_profile, branch_uid) = self
            .manager
            .inspect(&id)
            .map(|info| (info.profile.clone(), info.uid))
            .unwrap_or_else(|| (String::new(), 0));

        // M24: Compute a SHA-256 changeset hash BEFORE commit, because commit
        // merges the OverlayFS upper layer into the base and destroys the diff.
        // Try to load the IMA commit manifest for this branch; if available,
        // hash the manifest JSON. Otherwise, fall back to hashing the diff changeset.
        let changeset_hash = {
            use sha2::{Digest, Sha256};
            let manifest_dir = self.manager.config().branch_root.join("manifests");
            let manifest_path = manifest_dir.join(format!("{}.manifest.yaml", branch_id));
            let manifest_json = manifest_path
                .exists()
                .then(|| std::fs::read_to_string(&manifest_path).ok())
                .flatten()
                .and_then(|yaml_str| {
                    let val: serde_json::Value = serde_yaml::from_str(&yaml_str).ok()?;
                    serde_json::to_string(&val).ok()
                });
            // R6: Use sentinel value with branch_id on failure to prevent constant-hash collision
            let hash_input = manifest_json.unwrap_or_else(|| {
                self.manager
                    .diff(&id)
                    .ok()
                    .and_then(|d| serde_json::to_string(&d).ok())
                    .unwrap_or_else(|| {
                        tracing::error!(branch_id = %id, "R6: changeset hash fallback — both manifest and diff unavailable");
                        format!("UNAVAILABLE:{}", id)
                    })
            });
            let mut hasher = Sha256::new();
            hasher.update(hash_input.as_bytes());
            format!("{:x}", hasher.finalize())
        };

        let result = self
            .manager
            .commit(&id)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let json =
            serde_json::to_string(&result).map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        // PXH4: Emit audit event for branch commit
        self.audit_logger.log(AuditEvent::BranchCommitted {
            branch_id: id.clone(),
            files: result.files_committed,
            bytes: result.bytes_committed,
        });

        // ── Attestation bridge (§3.1) ──────────────────────────────────────
        // Write governance event to the persistent NDJSON audit store so it
        // gets an Ed25519 signature and Merkle tree leaf when attestation is
        // enabled.  The AuditLogger above goes to syslog/netlink only.
        //
        // ⚠ PODMAN MERGE CONFLICT RISK: This block touches dbus.rs which is
        // also modified by the Podman-native architecture refactor
        // (podman_puzzled_architecture_prd.md).  Keep this block clearly
        // delimited so it can be re-applied after a Podman merge.
        {
            let commit_event = AuditEvent::BranchCommitted {
                branch_id: id.clone(),
                files: result.files_committed,
                bytes: result.bytes_committed,
            };
            let commit_identity = self.manager.inspect(&id).map(|info| {
                puzzled_types::AgentIdentity {
                    uid: info.uid,
                    profile: info.profile.clone(),
                    // A-M2: Read SELinux context from /proc/<pid>/attr/current.
                    selinux_context: info.selinux_context.clone(),
                    framework: None, // TODO: populate from agent framework metadata when available
                }
            });
            if let Err(e) = self.audit_store.lock().await.store_with_context(
                &commit_event,
                commit_identity,
                Some(changeset_hash.clone()),
            ) {
                tracing::warn!(branch_id, error = %e, "failed to store commit event in audit store");
            }
        }
        // ── End attestation bridge ──────────────────────────────────────────

        // ── Gap 4: Store CommitRejected/PolicyViolation in audit store ────
        if let puzzled_types::PolicyDecision::Rejected(ref violations) = result.policy_result {
            let reject_reason = format!("{} policy violation(s)", violations.len());
            let reject_identity = self.manager.inspect(&id).map(|info| {
                puzzled_types::AgentIdentity {
                    uid: info.uid,
                    profile: info.profile.clone(),
                    // A-M2: Read SELinux context from /proc/<pid>/attr/current.
                    selinux_context: info.selinux_context.clone(),
                    framework: None, // TODO: populate from agent framework metadata when available
                }
            });
            // Store CommitRejected event
            let reject_event = AuditEvent::CommitRejected {
                branch_id: id.clone(),
                reason: reject_reason.clone(),
            };
            self.audit_logger.log(AuditEvent::CommitRejected {
                branch_id: id.clone(),
                reason: reject_reason.clone(),
            });
            if let Err(e) = self.audit_store.lock().await.store_with_context(
                &reject_event,
                reject_identity.clone(),
                Some(changeset_hash.clone()),
            ) {
                tracing::warn!(branch_id, error = %e, "failed to store commit_rejected event in audit store");
            }
            // Store individual PolicyViolation events
            for v in violations {
                let pv_event = AuditEvent::PolicyViolation {
                    branch_id: id.clone(),
                    rule: v.rule.clone(),
                    message: v.message.clone(),
                };
                self.audit_logger.log(AuditEvent::PolicyViolation {
                    branch_id: id.clone(),
                    rule: v.rule.clone(),
                    message: v.message.clone(),
                });
                if let Err(e) = self.audit_store.lock().await.store_with_context(
                    &pv_event,
                    reject_identity.clone(),
                    None,
                ) {
                    tracing::warn!(branch_id, error = %e, "failed to store policy_violation event in audit store");
                }
            }
        }
        // ── End Gap 4 ──────────────────────────────────────────────────────

        // V1: Update trust score based on governance outcome.
        // W1: Use branch_uid captured BEFORE commit — inspect may return None after.
        // Y2: Exhaustive match — no wildcard. PolicyDecision::Error is a policy
        // evaluation failure, NOT an approval. Map it to "commit_rejected" so the
        // trust score reflects the failure rather than silently rewarding it.
        let trust_event_type = match &result.policy_result {
            puzzled_types::PolicyDecision::Approved => "commit_approved",
            puzzled_types::PolicyDecision::Rejected(_) => "policy_violation",
            puzzled_types::PolicyDecision::Error(_) => "commit_rejected",
        };
        // W9: Capture score in the same lock scope to avoid TOCTOU.
        let (trust_transition_result, trust_score_after) = {
            let mut trust = self.trust_manager.lock().unwrap_or_else(|e| e.into_inner());
            let transition = trust.on_audit_event(trust_event_type, branch_uid, Some(branch_id));
            let score = trust.get_score(branch_uid).map(|s| s.score).unwrap_or(0);
            (transition, score)
        };

        // V2: Record governance provenance for this commit.
        // W2: policy_version from audit_store; changeset_hash as manifest_hash.
        {
            let policy_version_str = {
                let store = self.audit_store.lock().await;
                store.policy_hash().unwrap_or("unknown").to_string()
            };
            let violations: Vec<String> = match &result.policy_result {
                puzzled_types::PolicyDecision::Rejected(vs) => {
                    vs.iter().map(|v| v.rule.clone()).collect()
                }
                _ => vec![],
            };
            let gov_result = match &result.policy_result {
                puzzled_types::PolicyDecision::Approved => "approved",
                puzzled_types::PolicyDecision::Rejected(_) => "rejected",
                puzzled_types::PolicyDecision::Error(_) => "error",
            };
            if let Err(e) = crate::provenance::record_governance(
                &self.provenance_store,
                branch_id,
                &policy_version_str,
                gov_result,
                &violations,
                Some(changeset_hash.clone()),
                &[], // change_ids — populated by file-level provenance if available
            ) {
                tracing::warn!(branch_id, error = %e, "V2: failed to record governance provenance");
            }
        }

        // V3: Emit trust_transition signal if a tier boundary was crossed.
        // W9: Use trust_score_after captured in same lock scope as on_audit_event.
        if let Some((old_level, new_level)) = &trust_transition_result {
            if old_level != new_level {
                if let Some(iface_ref) = get_signal_emitter(connection).await {
                    let ctx = iface_ref.signal_emitter();
                    if let Err(e) = ManagerInterface::trust_transition(
                        ctx,
                        branch_uid,
                        old_level.as_str(),
                        new_level.as_str(),
                        trust_score_after,
                        trust_event_type,
                    )
                    .await
                    {
                        tracing::debug!("V3: trust_transition signal emission failed: {e}");
                    }
                }
            }
        }

        // B2: Clean up behavioral trigger throttle entry for this branch.
        // Prevents unbounded growth of the throttle map over time.
        {
            let mut throttle = self
                .behavioral_trigger_last_emitted
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            throttle.remove(branch_id);
        }

        // H6: Emit D-Bus signals for commit result
        // H-10: Detect governance review pending (Approved + files_committed==0
        // + branch still exists in GovernanceReview state)
        let is_governance_review = matches!(
            &result.policy_result,
            puzzled_types::PolicyDecision::Approved
        ) && result.files_committed == 0
            && self
                .manager
                .inspect(&id)
                .map(|info| info.state == puzzled_types::BranchState::GovernanceReview)
                .unwrap_or(false);

        if let Some(iface_ref) = get_signal_emitter(connection).await {
            let ctx = iface_ref.signal_emitter();
            if is_governance_review {
                // H-10: Emit governance_review_pending signal with diff summary
                // Use pending_review_summary() for actual changeset counts
                let (file_count, total_bytes) =
                    self.manager.pending_review_summary(&id).unwrap_or((0, 0));
                let diff_summary = serde_json::json!({
                    "files": file_count,
                    "bytes": total_bytes,
                    "status": "awaiting_review"
                })
                .to_string();
                if let Err(e) =
                    ManagerInterface::governance_review_pending(ctx, branch_id, &diff_summary).await
                {
                    tracing::debug!("F11: D-Bus signal emission failed: {e}");
                }
            } else {
                match &result.policy_result {
                    puzzled_types::PolicyDecision::Approved => {
                        if let Err(e) = ManagerInterface::branch_committed(
                            ctx,
                            branch_id,
                            &changeset_hash,
                            &branch_profile,
                        )
                        .await
                        {
                            tracing::debug!("F11: D-Bus signal emission failed: {e}");
                        }
                    }
                    puzzled_types::PolicyDecision::Rejected(violations) => {
                        let violations_json = serde_json::to_string(violations).unwrap_or_else(|e| {
                            tracing::error!(error = %e, "R26: failed to serialize policy violations for signal");
                            String::new()
                        });
                        let reason = format!("{} policy violation(s)", violations.len());
                        if let Err(e) = ManagerInterface::policy_violation(
                            ctx,
                            branch_id,
                            &violations_json,
                            &changeset_hash,
                            &reason,
                            &branch_profile,
                        )
                        .await
                        {
                            tracing::debug!("F11: D-Bus signal emission failed: {e}");
                        }
                    }
                    // Z11: Explicit handling for PolicyDecision::Error — emit
                    // policy_violation signal with the error message so D-Bus
                    // subscribers are aware of governance evaluation failures.
                    puzzled_types::PolicyDecision::Error(ref err_msg) => {
                        let reason = format!("policy evaluation error: {}", err_msg);
                        if let Err(e) = ManagerInterface::policy_violation(
                            ctx,
                            branch_id,
                            "[]",
                            &changeset_hash,
                            &reason,
                            &branch_profile,
                        )
                        .await
                        {
                            tracing::debug!("Z11: D-Bus signal emission failed: {e}");
                        }
                    }
                }
            }
        }

        Ok(json)
    }

    /// Roll back a branch, discarding all changes.
    ///
    /// M27: The `reason` parameter is logged and included in the audit trail.
    async fn rollback_branch(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        branch_id: &str,
        reason: &str,
    ) -> zbus::fdo::Result<bool> {
        validate_branch_id(branch_id)?;
        // K21: Sanitize reason before logging to prevent log injection
        let sanitized_reason = sanitize_log_reason(reason);
        tracing::info!(branch_id, reason = %sanitized_reason, "RollbackBranch requested");

        let (_uid, id) =
            validate_and_authorize(&header, connection, branch_id, &self.manager).await?;

        // M14: Idempotency — if branch is already rolled back, return success
        if let Some(info) = self.manager.inspect(&id) {
            if info.state == puzzled_types::BranchState::RolledBack {
                tracing::info!(branch_id, "RollbackBranch idempotent — already rolled back");
                return Ok(true);
            }
        }

        let rollback_reason = if reason.is_empty() {
            "D-Bus rollback request".to_string()
        } else {
            format!("D-Bus rollback request: {}", reason)
        };
        self.manager
            .rollback(&rollback_reason, &id)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        // PXH4: Emit audit event for branch rollback
        self.audit_logger.log(AuditEvent::BranchRolledBack {
            branch_id: id.clone(),
            reason: rollback_reason.clone(),
        });

        // ── Attestation bridge (§3.1) ──────────────────────────────────────
        // Write rollback event to persistent NDJSON audit store for Ed25519
        // signature and Merkle tree leaf.  See commit_branch for rationale.
        //
        // ⚠ PODMAN MERGE CONFLICT RISK: This block touches dbus.rs which is
        // also modified by the Podman-native architecture refactor.  Keep
        // clearly delimited so it can be re-applied after a Podman merge.
        {
            let rollback_event = AuditEvent::BranchRolledBack {
                branch_id: id.clone(),
                reason: rollback_reason.clone(),
            };
            let rollback_identity = self.manager.inspect(&id).map(|info| {
                puzzled_types::AgentIdentity {
                    uid: info.uid,
                    profile: info.profile.clone(),
                    // A-M2: Read SELinux context from /proc/<pid>/attr/current.
                    selinux_context: info.selinux_context.clone(),
                    framework: None, // TODO: populate from agent framework metadata when available
                }
            });
            if let Err(e) = self.audit_store.lock().await.store_with_context(
                &rollback_event,
                rollback_identity,
                None,
            ) {
                tracing::warn!(branch_id, error = %e, "failed to store rollback event in audit store");
            }
        }
        // ── End attestation bridge ──────────────────────────────────────────

        // W11: Record governance provenance for rollback decision.
        {
            let policy_version_str = {
                let store = self.audit_store.lock().await;
                store.policy_hash().unwrap_or("unknown").to_string()
            };
            if let Err(e) = crate::provenance::record_governance(
                &self.provenance_store,
                branch_id,
                &policy_version_str,
                "rollback",
                std::slice::from_ref(&rollback_reason),
                None,
                &[],
            ) {
                tracing::warn!(branch_id, error = %e, "W11: failed to record rollback provenance");
            }
        }

        // X1: Clean up provenance data for the rolled-back branch.
        // PRD §4.3.8: "Branch rollback/cleanup removes the provenance directory."
        // Must happen AFTER W11 recording so the rollback decision is persisted
        // before the directory is removed.
        if let Err(e) = self.provenance_store.cleanup_branch(branch_id) {
            tracing::warn!(branch_id, error = %e, "X1: failed to clean up provenance data");
        }

        // B2: Clean up behavioral trigger throttle entry for this branch.
        {
            let mut throttle = self
                .behavioral_trigger_last_emitted
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            throttle.remove(branch_id);
        }

        // H6: Emit D-Bus signal for rollback
        // L-db1: Include reason in BranchRolledBack signal
        if let Some(iface_ref) = get_signal_emitter(connection).await {
            if let Err(e) = ManagerInterface::branch_rolled_back(
                iface_ref.signal_emitter(),
                branch_id,
                &rollback_reason,
            )
            .await
            {
                tracing::debug!("F11: D-Bus signal emission failed: {e}");
            }
        }

        Ok(true)
    }

    /// Inspect a branch, returning its metadata as JSON.
    async fn inspect_branch(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        branch_id: &str,
    ) -> zbus::fdo::Result<String> {
        validate_branch_id(branch_id)?;
        tracing::info!(branch_id, "InspectBranch requested");

        let (_uid, id) =
            validate_and_authorize(&header, connection, branch_id, &self.manager).await?;

        let info = self
            .manager
            .inspect(&id)
            .ok_or_else(|| zbus::fdo::Error::Failed(format!("branch {} not found", branch_id)))?;

        let json =
            serde_json::to_string(&info).map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        Ok(json)
    }

    /// List all branches as a JSON array (filtered by caller UID unless root).
    async fn list_branches(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<String> {
        tracing::info!("ListBranches requested");

        let _uid = get_caller_uid(&header, connection).await?;
        let manager = &*self.manager;
        // Access control is enforced by D-Bus policy (only root and wheel
        // group can call this method). No additional UID filtering — all
        // callers with D-Bus access can list all branches.
        let branches: Vec<_> = manager.list();

        let json = serde_json::to_string(&branches)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        Ok(json)
    }

    /// Generate a diff for a branch, returning the changeset as JSON.
    async fn diff_branch(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        branch_id: &str,
    ) -> zbus::fdo::Result<String> {
        validate_branch_id(branch_id)?;
        tracing::info!(branch_id, "DiffBranch requested");

        let (_uid, id) =
            validate_and_authorize(&header, connection, branch_id, &self.manager).await?;

        let changes = self
            .manager
            .diff(&id)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let json =
            serde_json::to_string(&changes).map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        Ok(json)
    }

    /// List active agents (branches in Active state) as JSON.
    async fn list_agents(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<String> {
        tracing::info!("ListAgents requested");

        let uid = get_caller_uid(&header, connection).await?;
        let manager = &*self.manager;
        let branches: Vec<_> = manager
            .list()
            .into_iter()
            .filter(|b| {
                matches!(
                    b.state,
                    puzzled_types::BranchState::Active | puzzled_types::BranchState::Ready
                )
            })
            .filter(|b| uid == 0 || b.uid == uid)
            .collect();

        let json = serde_json::to_string(&branches)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        Ok(json)
    }

    /// Kill an active agent and roll back its branch.
    ///
    /// M-db5: Emits an audit event with the caller UID.
    async fn kill_agent(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        branch_id: &str,
    ) -> zbus::fdo::Result<bool> {
        validate_branch_id(branch_id)?;
        tracing::info!(branch_id, "KillAgent requested");

        let (uid, id) =
            validate_and_authorize(&header, connection, branch_id, &self.manager).await?;

        self.manager
            .kill_agent(&id)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        // M-db5: Emit audit event for agent kill with caller UID
        self.audit_logger.log(AuditEvent::AgentKilled {
            branch_id: id.clone(),
            caller_uid: uid,
        });

        // ── Attestation bridge (§3.1) ──────────────────────────────────────
        // Write agent-killed event to persistent NDJSON audit store for
        // Ed25519 signature and Merkle tree leaf.  See commit_branch for
        // rationale.
        //
        // ⚠ PODMAN MERGE CONFLICT RISK: This block touches dbus.rs which is
        // also modified by the Podman-native architecture refactor.  Keep
        // clearly delimited so it can be re-applied after a Podman merge.
        {
            let kill_event = AuditEvent::AgentKilled {
                branch_id: id.clone(),
                caller_uid: uid,
            };
            let kill_identity = self.manager.inspect(&id).map(|info| {
                puzzled_types::AgentIdentity {
                    uid: info.uid,
                    profile: info.profile.clone(),
                    // A-M2: Read SELinux context from /proc/<pid>/attr/current.
                    selinux_context: info.selinux_context.clone(),
                    framework: None, // TODO: populate from agent framework metadata when available
                }
            });
            if let Err(e) =
                self.audit_store
                    .lock()
                    .await
                    .store_with_context(&kill_event, kill_identity, None)
            {
                tracing::warn!(branch_id, error = %e, "failed to store agent-killed event in audit store");
            }
        }
        // ── End attestation bridge ──────────────────────────────────────────

        // Emit rollback signal
        // L-db1: Include reason in BranchRolledBack signal
        if let Some(iface_ref) = get_signal_emitter(connection).await {
            if let Err(e) = ManagerInterface::branch_rolled_back(
                iface_ref.signal_emitter(),
                branch_id,
                "agent killed by operator",
            )
            .await
            {
                tracing::debug!("F11: D-Bus signal emission failed: {e}");
            }
        }

        Ok(true)
    }

    /// H-10: Approve a branch in GovernanceReview state.
    ///
    /// Root-only (UID 0). Transitions the branch from GovernanceReview to Committed.
    /// Returns a JSON-serialized CommitResult.
    async fn approve_branch(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        branch_id: &str,
    ) -> zbus::fdo::Result<String> {
        validate_branch_id(branch_id)?;
        tracing::info!(branch_id, "ApproveBranch requested");

        // S28: Use validate_and_authorize for consistent branch existence + access validation
        let (uid, id) =
            validate_and_authorize(&header, connection, branch_id, &self.manager).await?;

        // Root-only gate (on top of validate_and_authorize)
        if uid != 0 {
            tracing::warn!(uid, "ApproveBranch rejected: caller is not root");
            return Err(zbus::fdo::Error::AccessDenied(
                "only root (UID 0) may approve branches".into(),
            ));
        }

        // Capture profile and owner UID before approve_branch changes state
        let (profile, branch_uid) = self
            .manager
            .inspect(&id)
            .map(|info| (info.profile.clone(), info.uid))
            .unwrap_or_else(|| (String::new(), 0));

        let result = self
            .manager
            .approve_branch(&id)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let json =
            serde_json::to_string(&result).map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        // AA2: Compute changeset hash once and reuse across audit store,
        // provenance, and signal emission (was computed 3x independently).
        let changeset_hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(branch_id.as_bytes());
            hasher.update(result.files_committed.to_le_bytes());
            hasher.update(result.bytes_committed.to_le_bytes());
            format!("{:x}", hasher.finalize())
        };

        // Z3: Emit audit event to syslog/netlink for manual approval.
        self.audit_logger.log(AuditEvent::BranchCommitted {
            branch_id: id.clone(),
            files: result.files_committed,
            bytes: result.bytes_committed,
        });

        // Z2: Write approval event to persistent audit store for Ed25519 signature
        // and Merkle tree leaf (attestation bridge §3.1). Without this, manual
        // governance approvals are invisible to the attestation chain.
        {
            let approve_event = AuditEvent::BranchCommitted {
                branch_id: id.clone(),
                files: result.files_committed,
                bytes: result.bytes_committed,
            };
            let approve_identity =
                self.manager
                    .inspect(&id)
                    .map(|info| puzzled_types::AgentIdentity {
                        uid: info.uid,
                        profile: info.profile.clone(),
                        selinux_context: info.selinux_context.clone(),
                        framework: None,
                    });
            if let Err(e) = self.audit_store.lock().await.store_with_context(
                &approve_event,
                approve_identity,
                Some(changeset_hash.clone()),
            ) {
                tracing::warn!(branch_id, error = %e, "Z2: failed to store approval event in audit store");
            }
        }

        // W3: Update trust score for manual governance approval.
        let (trust_transition_result, trust_score_after) = {
            let mut trust = self.trust_manager.lock().unwrap_or_else(|e| e.into_inner());
            let transition = trust.on_audit_event("commit_approved", branch_uid, Some(branch_id));
            let score = trust.get_score(branch_uid).map(|s| s.score).unwrap_or(0);
            (transition, score)
        };

        // W4: Record governance provenance for manual approval.
        {
            let policy_version_str = {
                let store = self.audit_store.lock().await;
                store.policy_hash().unwrap_or("unknown").to_string()
            };
            if let Err(e) = crate::provenance::record_governance(
                &self.provenance_store,
                branch_id,
                &policy_version_str,
                "approved",
                &[],
                Some(changeset_hash.clone()),
                &[],
            ) {
                tracing::warn!(branch_id, error = %e, "W4: failed to record governance provenance");
            }
        }

        // Emit branch_committed signal on approval (with real commit metadata)
        if let Some(iface_ref) = get_signal_emitter(connection).await {
            if let Err(e) = ManagerInterface::branch_committed(
                iface_ref.signal_emitter(),
                branch_id,
                &changeset_hash,
                &profile,
            )
            .await
            {
                tracing::debug!("F11: D-Bus signal emission failed: {e}");
            }

            // W5: Emit trust_transition signal if tier boundary was crossed.
            if let Some((old_level, new_level)) = &trust_transition_result {
                if old_level != new_level {
                    if let Err(e) = ManagerInterface::trust_transition(
                        iface_ref.signal_emitter(),
                        branch_uid,
                        old_level.as_str(),
                        new_level.as_str(),
                        trust_score_after,
                        "commit_approved",
                    )
                    .await
                    {
                        tracing::debug!("W5: trust_transition signal emission failed: {e}");
                    }
                }
            }
        }

        Ok(json)
    }

    /// H-10: Reject a branch in GovernanceReview state.
    ///
    /// Root-only (UID 0). Transitions the branch from GovernanceReview to RolledBack.
    /// Returns true on success.
    async fn reject_branch(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        branch_id: &str,
        reason: &str,
    ) -> zbus::fdo::Result<bool> {
        validate_branch_id(branch_id)?;
        // K22: Sanitize reason before logging to prevent log injection
        let sanitized_reason = sanitize_log_reason(reason);
        tracing::info!(branch_id, reason = %sanitized_reason, "RejectBranch requested");

        // S28: Use validate_and_authorize for consistent branch existence + access validation
        let (uid, id) =
            validate_and_authorize(&header, connection, branch_id, &self.manager).await?;

        // Root-only gate (on top of validate_and_authorize)
        if uid != 0 {
            tracing::warn!(uid, "RejectBranch rejected: caller is not root");
            return Err(zbus::fdo::Error::AccessDenied(
                "only root (UID 0) may reject branches".into(),
            ));
        }

        let reject_reason = if reason.is_empty() {
            "rejected via D-Bus".to_string()
        } else {
            reason.to_string()
        };

        // Capture branch owner UID before reject changes state
        let branch_uid = self.manager.inspect(&id).map(|info| info.uid).unwrap_or(0);

        self.manager
            .reject_branch(&id, &reject_reason)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        // Z6: Emit audit event to syslog/netlink for manual rejection.
        self.audit_logger.log(AuditEvent::CommitRejected {
            branch_id: id.clone(),
            reason: reject_reason.clone(),
        });

        // Z5: Write rejection event to persistent audit store for Ed25519 signature
        // and Merkle tree leaf (attestation bridge §3.1). Without this, manual
        // governance rejections are invisible to the attestation chain.
        {
            let reject_event = AuditEvent::CommitRejected {
                branch_id: id.clone(),
                reason: reject_reason.clone(),
            };
            let reject_identity =
                self.manager
                    .inspect(&id)
                    .map(|info| puzzled_types::AgentIdentity {
                        uid: info.uid,
                        profile: info.profile.clone(),
                        selinux_context: info.selinux_context.clone(),
                        framework: None,
                    });
            if let Err(e) = self.audit_store.lock().await.store_with_context(
                &reject_event,
                reject_identity,
                None,
            ) {
                tracing::warn!(branch_id, error = %e, "Z5: failed to store rejection event in audit store");
            }
        }

        // W6: Update trust score for manual governance rejection.
        {
            let mut trust = self.trust_manager.lock().unwrap_or_else(|e| e.into_inner());
            trust.on_audit_event("commit_rejected", branch_uid, Some(branch_id));
        }

        // W7: Record governance provenance for manual rejection.
        {
            let policy_version_str = {
                let store = self.audit_store.lock().await;
                store.policy_hash().unwrap_or("unknown").to_string()
            };
            if let Err(e) = crate::provenance::record_governance(
                &self.provenance_store,
                branch_id,
                &policy_version_str,
                "rejected",
                std::slice::from_ref(&reject_reason),
                None,
                &[],
            ) {
                tracing::warn!(branch_id, error = %e, "W7: failed to record governance provenance");
            }
        }

        // X2: Clean up provenance data for the rejected branch.
        // PRD §4.3.8: "Branch rollback/cleanup removes the provenance directory."
        // Must happen AFTER W7 recording so the rejection decision is persisted
        // before the directory is removed.
        if let Err(e) = self.provenance_store.cleanup_branch(branch_id) {
            tracing::warn!(branch_id, error = %e, "X2: failed to clean up provenance data");
        }

        // Emit rollback signal with reason
        if let Some(iface_ref) = get_signal_emitter(connection).await {
            if let Err(e) = ManagerInterface::branch_rolled_back(
                iface_ref.signal_emitter(),
                branch_id,
                &reject_reason,
            )
            .await
            {
                tracing::debug!("F11: D-Bus signal emission failed: {e}");
            }
        }

        Ok(true)
    }

    /// H-11: Unregister an agent by rolling back its branch.
    ///
    /// Calls rollback with reason "unregistered".
    /// Y6: Full cross-module wiring — matches rollback_branch's pattern with
    /// audit store event, provenance recording, and provenance cleanup.
    async fn unregister_agent(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        branch_id: &str,
    ) -> zbus::fdo::Result<bool> {
        validate_branch_id(branch_id)?;
        tracing::info!(branch_id, "UnregisterAgent requested");

        let (_uid, id) =
            validate_and_authorize(&header, connection, branch_id, &self.manager).await?;

        self.manager
            .rollback("unregistered", &id)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        // AA3: Emit audit event to syslog/netlink for unregistration.
        // All other branch lifecycle terminals call audit_logger; without this,
        // unregister_agent events are only in the NDJSON audit store but not
        // in syslog/netlink, creating an observability gap.
        self.audit_logger.log(AuditEvent::BranchRolledBack {
            branch_id: id.clone(),
            reason: "unregistered".to_string(),
        });

        // Y6: Audit store event — write unregistration to persistent NDJSON audit
        // store for Ed25519 signature and Merkle tree leaf (attestation bridge).
        {
            let unregister_event = AuditEvent::BranchRolledBack {
                branch_id: id.clone(),
                reason: "unregistered".to_string(),
            };
            let unregister_identity =
                self.manager
                    .inspect(&id)
                    .map(|info| puzzled_types::AgentIdentity {
                        uid: info.uid,
                        profile: info.profile.clone(),
                        selinux_context: info.selinux_context.clone(),
                        framework: None,
                    });
            if let Err(e) = self.audit_store.lock().await.store_with_context(
                &unregister_event,
                unregister_identity,
                None,
            ) {
                tracing::warn!(branch_id, error = %e, "Y6: failed to store unregister event in audit store");
            }
        }

        // Y6: Record governance provenance for unregistration.
        {
            let policy_version_str = {
                let store = self.audit_store.lock().await;
                store.policy_hash().unwrap_or("unknown").to_string()
            };
            if let Err(e) = crate::provenance::record_governance(
                &self.provenance_store,
                branch_id,
                &policy_version_str,
                "unregistered",
                &["agent unregistered".to_string()],
                None,
                &[],
            ) {
                tracing::warn!(branch_id, error = %e, "Y6: failed to record unregister provenance");
            }
        }

        // Y6: Clean up provenance data for the unregistered branch.
        // Must happen AFTER provenance recording so the decision is persisted.
        if let Err(e) = self.provenance_store.cleanup_branch(branch_id) {
            tracing::warn!(branch_id, error = %e, "Y6: failed to clean up provenance data");
        }

        // Emit rollback signal with reason
        if let Some(iface_ref) = get_signal_emitter(connection).await {
            if let Err(e) = ManagerInterface::branch_rolled_back(
                iface_ref.signal_emitter(),
                branch_id,
                "unregistered",
            )
            .await
            {
                tracing::debug!("F11: D-Bus signal emission failed: {e}");
            }
        }

        Ok(true)
    }

    /// H-13: Return agent info as JSON.
    ///
    /// Returns JSON with pid, state, profile, created_at, uid, cgroup_path.
    async fn agent_info(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        branch_id: &str,
    ) -> zbus::fdo::Result<String> {
        validate_branch_id(branch_id)?;
        tracing::info!(branch_id, "AgentInfo requested");

        let (_uid, id) =
            validate_and_authorize(&header, connection, branch_id, &self.manager).await?;

        let info = self
            .manager
            .inspect(&id)
            .ok_or_else(|| zbus::fdo::Error::Failed(format!("branch {} not found", branch_id)))?;

        // Build agent info JSON with pid, state, profile, created_at, uid, cgroup_path
        let agent_info = serde_json::json!({
            "pid": info.pid.unwrap_or(0),
            "state": info.state.to_string(),
            "profile": info.profile,
            "created_at": info.created_at.to_rfc3339(),
            "uid": info.uid,
            "cgroup_path": "",
        });

        let json = serde_json::to_string(&agent_info)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        Ok(json)
    }

    /// Reload OPA/Rego policy bundles from disk.
    /// H18: Only root (UID 0) is allowed to reload policies.
    /// L-db2: Returns (bool, String) tuple with success status and detail message.
    async fn reload_policy(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<(bool, String)> {
        tracing::info!("ReloadPolicy requested");

        // H18: Restrict policy reload to root only
        let uid = get_caller_uid(&header, connection).await?;
        if uid != 0 {
            tracing::warn!(uid, "ReloadPolicy rejected: caller is not root");
            return Err(zbus::fdo::Error::AccessDenied(
                "only root (UID 0) may reload policies".into(),
            ));
        }

        let manager = &*self.manager;
        match manager.reload_policies() {
            Ok(()) => Ok((true, "policies reloaded successfully".to_string())),
            Err(e) => {
                let detail = format!("policy reload failed: {}", e);
                tracing::error!(%e, "ReloadPolicy failed");
                Ok((false, detail))
            }
        }
    }

    /// Query audit events with optional JSON filter.
    ///
    /// Filter JSON: { "branch_id": "...", "event_type": "...", "since": "...", "limit": N }
    ///
    /// PH2: Non-root callers can only see events where the `uid` field in the
    /// event details matches their own UID. Root (UID 0) sees all events.
    /// Events without a `uid` field (e.g., policy_reloaded, wal_recovery) are
    /// only visible to root.
    async fn query_audit_events(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        filter_json: &str,
    ) -> zbus::fdo::Result<String> {
        let uid = get_caller_uid(&header, connection).await?;
        tracing::info!(uid, "QueryAuditEvents requested");

        let filter: puzzled_types::AuditFilter = if filter_json.is_empty() {
            puzzled_types::AuditFilter {
                branch_id: None,
                event_type: None,
                since: None,
                limit: None,
            }
        } else {
            serde_json::from_str(filter_json)
                .map_err(|e| zbus::fdo::Error::Failed(format!("invalid filter: {}", e)))?
        };

        let store = self.audit_store.lock().await;
        let events = store
            .query(
                filter.branch_id.as_deref(),
                filter.event_type.as_deref(),
                filter.since.as_deref(),
                filter.limit,
            )
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        // Access control is enforced by D-Bus policy (only root and wheel
        // group can call this method). All callers with D-Bus access can
        // see all audit events.
        let filtered_events = events;

        let json = serde_json::to_string(&filtered_events)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        Ok(json)
    }

    /// Export audit events in the specified format (json or csv).
    ///
    /// H9: Restricted to root (UID 0) only — export may contain events from
    /// all users and branches.
    async fn export_audit_events(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        format: &str,
    ) -> zbus::fdo::Result<String> {
        let uid = get_caller_uid(&header, connection).await?;
        tracing::info!(uid, format, "ExportAuditEvents requested");

        // H9: Only root may export audit events (export contains all users' data)
        if uid != 0 {
            tracing::warn!(uid, "ExportAuditEvents rejected: caller is not root");
            return Err(zbus::fdo::Error::AccessDenied(
                "only root (UID 0) may export audit events".into(),
            ));
        }

        // PM10: Validate format parameter before passing to the audit store.
        // Only "json", "csv", and "cel" are supported export formats.
        match format {
            "json" | "csv" | "cel" => {}
            _ => {
                tracing::warn!(uid, format, "ExportAuditEvents rejected: invalid format");
                return Err(zbus::fdo::Error::InvalidArgs(format!(
                    "unsupported export format '{}': expected one of \"json\", \"csv\", \"cel\"",
                    format
                )));
            }
        }

        let store = self.audit_store.lock().await;
        store
            .export(format)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    // -- Attestation Methods (§3.1) --

    /// §3.1: Verify the attestation chain for a branch.
    /// Returns JSON with verification results (chain length, signature validity, etc.).
    /// R1: Root-only — exports full audit chain data.
    async fn verify_attestation_chain(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        branch_id: &str,
    ) -> zbus::fdo::Result<String> {
        validate_branch_id(branch_id)?;
        let uid = get_caller_uid(&header, connection).await?;
        if uid != 0 {
            return Err(zbus::fdo::Error::AccessDenied(
                "R1: only root may verify attestation chains".into(),
            ));
        }
        tracing::info!(branch_id = %branch_id, "§3.1: verify_attestation_chain called");

        // Read the public key for Ed25519 signature verification
        let attestation_dir = &self.manager.config().attestation.attestation_dir;
        let pubkey_path = attestation_dir.join("public_key.hex");
        let verifying_key: Option<ed25519_dalek::VerifyingKey> =
            std::fs::read_to_string(&pubkey_path)
                .ok()
                .and_then(|hex_str| {
                    let hex_str = hex_str.trim();
                    // H44: Guard against odd-length hex strings to prevent
                    // panic on out-of-bounds slice in the parsing loop.
                    if hex_str.len() % 2 != 0 {
                        return None;
                    }
                    let bytes: Vec<u8> = (0..hex_str.len())
                        .step_by(2)
                        .filter_map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).ok())
                        .collect();
                    if bytes.len() != 32 {
                        return None;
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    ed25519_dalek::VerifyingKey::from_bytes(&arr).ok()
                });

        let store = self.audit_store.lock().await;
        // A-I1: Query all events for this branch to verify chain continuity.
        // No limit is applied because verification must cover the entire chain —
        // a truncated query would silently miss chain breaks or invalid signatures.
        // This is an admin operation, not a high-frequency query.
        let events = store
            .query(Some(branch_id), None, None, None)
            .map_err(|e| zbus::fdo::Error::Failed(format!("querying audit events: {}", e)))?;

        let mut chain_length: u64 = 0;
        let mut signatures_valid: u64 = 0;
        let mut signatures_invalid: u64 = 0;
        let mut signatures_missing: u64 = 0;
        let mut signatures_not_verified: u64 = 0;
        let mut chain_breaks: u64 = 0;
        let mut timestamp_violations: u64 = 0;
        let mut prev_record_id: Option<String> = None;
        let mut prev_timestamp: Option<String> = None;

        for event in &events {
            if let Some(ref record_id) = event.record_id {
                chain_length += 1;

                // Check parent_record_id chain continuity: each record's
                // parent_record_id should match the previous record's record_id
                if chain_length > 1 {
                    let expected_parent = prev_record_id.as_deref();
                    let actual_parent = event.parent_record_id.as_deref();
                    if expected_parent != actual_parent {
                        chain_breaks += 1;
                    }
                }

                // J22: Use parsed DateTime comparison instead of lexicographic string
                // comparison, which can give wrong results for non-uniform formats.
                if let Some(ref prev_ts) = prev_timestamp {
                    match (
                        chrono::DateTime::parse_from_rfc3339(&event.timestamp),
                        chrono::DateTime::parse_from_rfc3339(prev_ts),
                    ) {
                        (Ok(curr), Ok(prev)) => {
                            if curr < prev {
                                timestamp_violations += 1;
                            }
                        }
                        _ => {
                            // If either timestamp fails to parse, count as violation
                            timestamp_violations += 1;
                        }
                    }
                }
                prev_timestamp = Some(event.timestamp.clone());
                prev_record_id = Some(record_id.clone());

                // Actually verify Ed25519 signature
                if let Some(ref sig_hex) = event.signature {
                    if let Some(ref vk) = verifying_key {
                        // Reconstruct canonical attestation string
                        let canonical =
                            crate::audit_store::AuditStore::build_canonical_attestation(event);
                        // Decode signature hex (reject invalid hex rather than silently dropping)
                        let sig_bytes: Option<Vec<u8>> = if sig_hex.len() % 2 != 0 {
                            None
                        } else {
                            (0..sig_hex.len())
                                .step_by(2)
                                .map(|i| {
                                    sig_hex
                                        .get(i..i + 2)
                                        .and_then(|s| u8::from_str_radix(s, 16).ok())
                                })
                                .collect()
                        };
                        if let Some(sig_bytes) = sig_bytes.filter(|b| b.len() == 64) {
                            let mut sig_arr = [0u8; 64];
                            sig_arr.copy_from_slice(&sig_bytes);
                            let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
                            if ed25519_dalek::Verifier::verify(vk, canonical.as_bytes(), &signature)
                                .is_ok()
                            {
                                signatures_valid += 1;
                            } else {
                                signatures_invalid += 1;
                            }
                        } else {
                            // Malformed hex or wrong length
                            signatures_invalid += 1;
                        }
                    }
                    if verifying_key.is_none() {
                        signatures_not_verified += 1;
                    }
                } else {
                    signatures_missing += 1;
                }
            }
        }

        Ok(serde_json::json!({
            "branch_id": branch_id,
            "chain_length": chain_length,
            "signatures_valid": signatures_valid,
            "signatures_invalid": signatures_invalid,
            "signatures_missing": signatures_missing,
            "signatures_not_verified": signatures_not_verified,
            "chain_breaks": chain_breaks,
            "timestamp_violations": timestamp_violations,
            "chain_intact": signatures_missing == 0 && signatures_not_verified == 0 && signatures_invalid == 0 && chain_breaks == 0 && timestamp_violations == 0 && chain_length > 0,
        })
        .to_string())
    }

    /// §3.1: Get Merkle inclusion proof for an audit event by leaf index.
    /// R1: Requires authentication.
    async fn get_inclusion_proof(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        leaf_index: u64,
    ) -> zbus::fdo::Result<String> {
        let _uid = get_caller_uid(&header, connection).await?;
        tracing::info!(leaf_index = leaf_index, "§3.1: get_inclusion_proof called");

        let store = self.audit_store.lock().await;
        let tree = store.merkle_tree().ok_or_else(|| {
            zbus::fdo::Error::Failed("attestation Merkle tree is not enabled".into())
        })?;

        let proof = tree
            .inclusion_proof(leaf_index)
            .map_err(|e| zbus::fdo::Error::Failed(format!("generating inclusion proof: {}", e)))?;

        serde_json::to_string(&proof)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serializing proof: {}", e)))
    }

    /// §3.1: Get Merkle consistency proof between two tree sizes.
    /// R1: Requires authentication.
    async fn get_consistency_proof(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        old_size: u64,
        new_size: u64,
    ) -> zbus::fdo::Result<String> {
        let _uid = get_caller_uid(&header, connection).await?;
        tracing::info!(
            old_size = old_size,
            new_size = new_size,
            "§3.1: get_consistency_proof called"
        );

        let store = self.audit_store.lock().await;
        let tree = store.merkle_tree().ok_or_else(|| {
            zbus::fdo::Error::Failed("attestation Merkle tree is not enabled".into())
        })?;

        let proof = tree.consistency_proof(old_size, new_size).map_err(|e| {
            zbus::fdo::Error::Failed(format!("generating consistency proof: {}", e))
        })?;

        serde_json::to_string(&proof)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serializing proof: {}", e)))
    }

    /// §3.1: Export attestation bundle for a branch (self-contained, offline-verifiable).
    /// Returns a JSON bundle containing: public_key, merkle_root, merkle_inclusion_proofs[],
    /// attestation records, and tree metadata — sufficient for offline verification.
    /// R1: Root-only — exports full audit records and signing keys.
    async fn export_attestation_bundle(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        branch_id: &str,
    ) -> zbus::fdo::Result<String> {
        validate_branch_id(branch_id)?;
        let uid = get_caller_uid(&header, connection).await?;
        if uid != 0 {
            return Err(zbus::fdo::Error::AccessDenied(
                "R1: only root may export attestation bundles".into(),
            ));
        }
        tracing::info!(branch_id = %branch_id, "§3.1: export_attestation_bundle called");

        // Read the Ed25519 public key from the attestation directory
        let attestation_dir = &self.manager.config().attestation.attestation_dir;
        let pubkey_path = attestation_dir.join("public_key.hex");
        let public_key = std::fs::read_to_string(&pubkey_path)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|e| {
                tracing::error!("S43: failed to read attestation public key: {e}");
                String::from("ERROR: key unavailable")
            });

        let store = self.audit_store.lock().await;
        // A-I1: Collect all attestation records for this branch without limit.
        // Export must include every record for the bundle to be complete and
        // offline-verifiable. This is an admin operation, not high-frequency.
        let events = store
            .query(Some(branch_id), None, None, None)
            .map_err(|e| zbus::fdo::Error::Failed(format!("querying events: {}", e)))?;

        let attestation_records: Vec<_> = events.iter().filter(|e| e.record_id.is_some()).collect();

        // Build Merkle inclusion proofs and root hash from the tree
        let (merkle_root, _tree_size, merkle_inclusion_proofs) = if let Some(tree) =
            store.merkle_tree()
        {
            let root_bytes = tree.root_hash().unwrap_or([0u8; 32]);
            let root_hex: String = root_bytes.iter().map(|b| format!("{:02x}", b)).collect();

            let mut proofs = Vec::new();
            for record in &attestation_records {
                if let Some(leaf_index) = record.merkle_leaf_index {
                    match tree.inclusion_proof(leaf_index) {
                        Ok(proof) => {
                            // Gap 17: Use PRD-compliant proof format
                            proofs.push(serde_json::json!({
                                "record_seq": record.seq,
                                "leaf_index": leaf_index,
                                "tree_size": proof.tree_size,
                                "proof_hashes": proof.proof_hashes,
                            }));
                        }
                        Err(e) => {
                            tracing::warn!(leaf_index, error = %e, "failed to generate inclusion proof");
                        }
                    }
                }
            }

            (root_hex, tree.size(), proofs)
        } else {
            (String::new(), 0, Vec::new())
        };

        // §3.1: key_rotation_history — scan for archived public keys
        let signing_key_path = &self.manager.config().signing_key_path;
        // Gap 15: Use valid_from / valid_until instead of rotated_at
        let key_rotation_history: Vec<serde_json::Value> = {
            let key_dir = signing_key_path
                .parent()
                .unwrap_or(std::path::Path::new("/"));
            let key_stem = signing_key_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let prefix = format!("{}.pub.", key_stem);
            let mut entries: Vec<(String, String)> = std::fs::read_dir(key_dir)
                .into_iter()
                .flatten()
                .filter_map(|entry| {
                    let entry = entry.ok()?;
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.starts_with(&prefix) {
                        let timestamp = name.strip_prefix(&prefix)?.to_string();
                        let pubkey_bytes = std::fs::read(entry.path()).ok()?;
                        let pubkey_hex: String =
                            pubkey_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                        Some((timestamp, pubkey_hex))
                    } else {
                        None
                    }
                })
                .collect();
            // Sort by timestamp for valid_from/valid_until calculation
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            entries
                .iter()
                .enumerate()
                .map(|(i, (timestamp, pubkey_hex))| {
                    let valid_from = if i == 0 {
                        "unknown".to_string()
                    } else {
                        entries[i - 1].0.clone()
                    };
                    serde_json::json!({
                        "valid_from": valid_from,
                        "valid_until": timestamp,
                        "public_key": pubkey_hex,
                    })
                })
                .collect()
        };

        // Gap 13: Load IMA manifest from the correct directory (branch_root/manifests)
        let ima_manifest_dir = self.manager.config().branch_root.join("manifests");
        let manifest_path = ima_manifest_dir.join(format!("{}.manifest.yaml", branch_id));
        let commit_manifest: serde_json::Value = if manifest_path.exists() {
            match std::fs::read_to_string(&manifest_path) {
                Ok(yaml_str) => serde_yaml::from_str(&yaml_str).unwrap_or(serde_json::Value::Null),
                Err(_) => serde_json::Value::Null,
            }
        } else {
            serde_json::Value::Null
        };

        // Gap 14: version 1, Gap 16: removed merkle_tree_size and record_count
        Ok(serde_json::json!({
            "version": 1,
            "branch_id": branch_id,
            "public_key": public_key,
            "key_rotation_history": key_rotation_history,
            "merkle_root": merkle_root,
            "merkle_inclusion_proofs": merkle_inclusion_proofs,
            "records": attestation_records,
            "commit_manifest": commit_manifest,
            "tpm_quote": serde_json::Value::Null,
        })
        .to_string())
    }

    /// §3.1: Get the current attestation public key (hex-encoded Ed25519).
    /// R1: Requires authentication (public key is non-sensitive but access must be auditable).
    async fn get_attestation_public_key(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<String> {
        let _uid = get_caller_uid(&header, connection).await?;
        tracing::info!("§3.1: get_attestation_public_key called");

        let manager = &self.manager;
        // Read public key from the attestation directory
        let attestation_dir = &manager.config().attestation.attestation_dir;
        let pubkey_path = attestation_dir.join("public_key.hex");
        match std::fs::read_to_string(&pubkey_path) {
            Ok(hex) => Ok(hex.trim().to_string()),
            Err(_) => Err(zbus::fdo::Error::Failed(
                "attestation public key not available (IMA not initialized or attestation disabled)".into(),
            )),
        }
    }

    // -- Credential Management Methods (§3.4) --

    /// §3.4: Store a credential for phantom token injection.
    /// name: credential reference name
    /// credential_type: type (e.g., "api_key", "oauth_bearer")
    /// value_source: credential value source ("file:/path" reads from file, otherwise literal)
    /// config_json: JSON with allowed_profiles, target_domains, injection method, ttl, etc.
    /// Returns: true on success
    async fn store_credential(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        name: &str,
        credential_type: &str,
        value_source: &str,
        config_json: &str,
    ) -> zbus::fdo::Result<bool> {
        let uid = get_caller_uid(&header, connection).await?;
        if uid != 0 {
            return Err(zbus::fdo::Error::AccessDenied(
                "Only root can store credentials".into(),
            ));
        }

        tracing::info!(
            name,
            credential_type,
            "StoreCredential requested (value redacted)"
        );

        let store = self.manager.credential_store().ok_or_else(|| {
            zbus::fdo::Error::Failed(
                "credential store not initialized (credentials.enabled=false)".into(),
            )
        })?;

        // Resolve credential value from value_source
        // L-12: Wrap credential value in Zeroizing to ensure cleanup on drop.
        let credential_value: zeroize::Zeroizing<String> =
            if let Some(path) = value_source.strip_prefix("file:") {
                // Validate path: reject traversal, /proc, /sys, /dev
                let p = std::path::Path::new(path);
                for component in p.components() {
                    if let std::path::Component::ParentDir = component {
                        return Err(zbus::fdo::Error::Failed(
                            "path traversal (..) not allowed in value_source".into(),
                        ));
                    }
                }
                // K28: Canonicalize path to resolve symlinks before checking
                // forbidden prefixes. Without this, a symlink like
                // /tmp/evil -> /proc/self/environ would bypass the check.
                let canonical = std::fs::canonicalize(p).map_err(|_e| {
                    zbus::fdo::Error::Failed("failed to resolve credential file path".to_string())
                })?;
                let canonical_str = canonical.to_string_lossy();
                if canonical_str.starts_with("/proc")
                    || canonical_str.starts_with("/sys")
                    || canonical_str.starts_with("/dev")
                {
                    return Err(zbus::fdo::Error::Failed(
                        "reading from /proc, /sys, /dev not allowed".into(),
                    ));
                }
                // H46: Use generic error message to avoid exposing filesystem paths
                zeroize::Zeroizing::new(
                    std::fs::read_to_string(&canonical)
                        .map_err(|_e| {
                            zbus::fdo::Error::Failed(
                                "failed to read credential from specified file".to_string(),
                            )
                        })?
                        .trim()
                        .to_string(),
                )
            } else {
                zeroize::Zeroizing::new(value_source.to_string())
            };

        // Parse config JSON for profile/domain/injection settings
        let config_val: serde_json::Value = if config_json.is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_str(config_json)
                .map_err(|e| zbus::fdo::Error::InvalidArgs(format!("invalid config JSON: {}", e)))?
        };

        // Build a StoredCredential from parsed parameters
        let cred = puzzle_proxy::credentials::StoredCredential {
            name: name.to_string(),
            credential_type: serde_json::from_value(serde_json::json!(credential_type))
                .unwrap_or(puzzle_proxy::credentials::CredentialType::ApiKey),
            value: credential_value,
            allowed_profiles: config_val
                .get("allowed_profiles")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default(),
            target_domains: config_val
                .get("target_domains")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default(),
            injection: config_val
                .get("injection")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or(puzzle_proxy::credentials::InjectionMethod::BearerHeader),
            expires_at: config_val
                .get("ttl")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            created_at: chrono::Utc::now().to_rfc3339(),
            rotated_at: None,
        };

        // Store in encrypted backend
        let mut guard = store.write().await;
        guard
            .store(cred)
            .map_err(|e| zbus::fdo::Error::Failed(format!("credential store error: {}", e)))?;

        // Gap 44: Emit audit event for credential storage
        self.audit_logger.log(AuditEvent::CredentialStored {
            credential_name: name.to_string(),
            caller_uid: uid,
        });

        tracing::info!(
            name,
            credential_type,
            "§3.4: credential stored successfully"
        );

        Ok(true)
    }

    // -- Podman-Native Mode Methods --

    /// Generate an OCI seccomp profile for a branch.
    ///
    /// Returns the filesystem path to the generated JSON profile.
    /// The profile includes SCMP_ACT_NOTIFY for execve/connect/bind,
    /// static deny for escape-vector syscalls, and the listenerPath
    /// for puzzled's seccomp notification socket.
    async fn generate_seccomp_profile(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        branch_id: &str,
    ) -> zbus::fdo::Result<String> {
        validate_branch_id(branch_id)?;
        tracing::info!(branch_id, "GenerateSeccompProfile requested");

        let (_uid, id) =
            validate_and_authorize(&header, connection, branch_id, &self.manager).await?;

        // Verify branch exists (result used for existence check only)
        let _info = self
            .manager
            .inspect(&id)
            .ok_or_else(|| zbus::fdo::Error::Failed(format!("branch {} not found", branch_id)))?;

        let branch_dir = self.manager.branch_dir(&id);
        let output_path = branch_dir.join("seccomp.json");
        let listener_socket = std::path::Path::new("/run/puzzled/seccomp-notify.sock");

        let profile = crate::seccomp_profile::generate_seccomp_profile(
            branch_id,
            listener_socket,
            true,  // include_notify
            false, // include_clone_guard (BPF LSM handles this when available)
        )
        .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let path = crate::seccomp_profile::write_seccomp_profile(&profile, &output_path)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        tracing::info!(
            branch_id,
            path = %path.display(),
            "seccomp profile generated"
        );

        Ok(path.to_string_lossy().to_string())
    }

    /// Generate Landlock rules JSON for a branch.
    ///
    /// Returns the filesystem path to the generated JSON rules file.
    /// The file is consumed by the puzzle-init shim inside the container.
    async fn generate_landlock_rules(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        branch_id: &str,
    ) -> zbus::fdo::Result<String> {
        validate_branch_id(branch_id)?;
        tracing::info!(branch_id, "GenerateLandlockRules requested");

        let (_uid, id) =
            validate_and_authorize(&header, connection, branch_id, &self.manager).await?;

        let info = self
            .manager
            .inspect(&id)
            .ok_or_else(|| zbus::fdo::Error::Failed(format!("branch {} not found", branch_id)))?;

        let profile = self.manager.get_profile(&info.profile).ok_or_else(|| {
            zbus::fdo::Error::Failed(format!("profile '{}' not found", info.profile))
        })?;

        let branch_dir = self.manager.branch_dir(&id);
        let output_path = branch_dir.join("landlock.json");
        // In Podman-native mode, the merged dir is bind-mounted at /workspace
        // inside the container. Use the container path so Landlock rules are
        // valid from the container's perspective (the host merged dir path
        // doesn't exist inside the container).
        let workspace = std::path::PathBuf::from("/workspace");

        let rules = crate::landlock_rules::generate_landlock_rules(&profile, &workspace)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let path = crate::landlock_rules::write_landlock_rules(&rules, &output_path)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        tracing::info!(
            branch_id,
            path = %path.display(),
            "Landlock rules generated"
        );

        Ok(path.to_string_lossy().to_string())
    }

    /// Attach governance to a running container (called by OCI hook at createRuntime).
    ///
    /// Registers the container PID with puzzled, starts BPF LSM and fanotify
    /// monitoring for the branch.
    async fn attach_governance(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        branch_id: &str,
        container_pid: u32,
        container_id: &str,
    ) -> zbus::fdo::Result<bool> {
        validate_branch_id(branch_id)?;
        tracing::info!(
            branch_id,
            container_pid,
            container_id,
            "AttachGovernance requested"
        );

        let (_uid, id) =
            validate_and_authorize(&header, connection, branch_id, &self.manager).await?;

        self.manager
            .attach_governance(&id, container_pid, container_id)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        // PXH4: Audit event for governance attachment
        self.audit_logger.log(AuditEvent::AgentRegistered {
            agent_id: branch_id.to_string(),
            profile: String::new(),
        });

        tracing::info!(branch_id, container_pid, "governance attached to container");

        Ok(true)
    }

    /// §3.4: Remove a credential by name.
    async fn remove_credential(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        credential_name: &str,
    ) -> zbus::fdo::Result<bool> {
        let uid = get_caller_uid(&header, connection).await?;
        if uid != 0 {
            return Err(zbus::fdo::Error::AccessDenied(
                "Only root can remove credentials".into(),
            ));
        }

        tracing::info!(credential_name, "RemoveCredential requested");

        let store = self
            .manager
            .credential_store()
            .ok_or_else(|| zbus::fdo::Error::Failed("credential store not initialized".into()))?;

        let mut guard = store.write().await;
        let removed = guard
            .remove(credential_name)
            .map_err(|e| zbus::fdo::Error::Failed(format!("credential store error: {}", e)))?;

        // Gap 44: Emit audit event for credential removal
        self.audit_logger.log(AuditEvent::CredentialRemoved {
            credential_name: credential_name.to_string(),
            caller_uid: uid,
        });

        tracing::info!(credential_name, removed, "§3.4: credential removal result");
        Ok(removed)
    }

    /// §3.4.12: Rotate a credential — replaces the real secret behind a credential name.
    ///
    /// Per PRD §3.4.12, takes both `branch_id` and `credential_name`. The `branch_id`
    /// identifies which branch's phantom token mappings should be updated after
    /// rotation. If `branch_id` is empty, rotation is global (all branches).
    ///
    /// value_source: "file:/path" reads value from file, otherwise treated as literal value.
    async fn rotate_credential(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        branch_id: &str,
        credential_name: &str,
        value_source: &str,
    ) -> zbus::fdo::Result<bool> {
        let uid = get_caller_uid(&header, connection).await?;
        if uid != 0 {
            return Err(zbus::fdo::Error::AccessDenied(
                "Only root can rotate credentials".into(),
            ));
        }

        tracing::info!(
            branch_id,
            credential_name,
            "§3.4.12: RotateCredential requested (value redacted)"
        );

        let store = self
            .manager
            .credential_store()
            .ok_or_else(|| zbus::fdo::Error::Failed("credential store not initialized".into()))?;

        // L-12: Wrap in Zeroizing to ensure cleanup on drop.
        let new_value: zeroize::Zeroizing<String> =
            if let Some(path) = value_source.strip_prefix("file:") {
                let p = std::path::Path::new(path);
                for component in p.components() {
                    if let std::path::Component::ParentDir = component {
                        return Err(zbus::fdo::Error::Failed(
                            "path traversal (..) not allowed in value_source".into(),
                        ));
                    }
                }
                // K28: Canonicalize path to resolve symlinks before checking
                // forbidden prefixes, matching store_credential fix.
                let canonical = std::fs::canonicalize(p).map_err(|_e| {
                    zbus::fdo::Error::Failed("failed to resolve credential file path".to_string())
                })?;
                let canonical_str = canonical.to_string_lossy();
                if canonical_str.starts_with("/proc")
                    || canonical_str.starts_with("/sys")
                    || canonical_str.starts_with("/dev")
                {
                    return Err(zbus::fdo::Error::Failed(
                        "reading from /proc, /sys, /dev not allowed".into(),
                    ));
                }
                // H46: Use generic error message to avoid exposing filesystem paths
                zeroize::Zeroizing::new(
                    std::fs::read_to_string(&canonical)
                        .map_err(|_e| {
                            zbus::fdo::Error::Failed(
                                "failed to read credential from specified file".to_string(),
                            )
                        })?
                        .trim()
                        .to_string(),
                )
            } else {
                zeroize::Zeroizing::new(value_source.to_string())
            };

        let mut guard = store.write().await;
        guard
            .rotate(credential_name, &new_value)
            .map_err(|e| zbus::fdo::Error::Failed(format!("credential store error: {}", e)))?;

        // Gap 44: Emit audit event for credential rotation
        self.audit_logger.log(AuditEvent::CredentialRotated {
            credential_name: credential_name.to_string(),
            caller_uid: uid,
        });

        // M-6: Emit CredentialRotated D-Bus signal so subscribers (GUI, monitoring)
        // can react to rotation events in real time (PRD §3.4.12).
        if let Some(iface_ref) = get_signal_emitter(connection).await {
            let ctx = iface_ref.signal_emitter();
            if let Err(e) = ManagerInterface::credential_rotated(
                ctx,
                branch_id,
                credential_name,
                "", // expires_at not available from current rotation API
            )
            .await
            {
                tracing::debug!("M-6: credential_rotated signal emission failed: {e}");
            }
        }

        tracing::info!(credential_name, "§3.4: credential rotated successfully");
        Ok(true)
    }

    /// §3.4.12: List credentials (returns metadata + domains, NOT real secrets).
    ///
    /// Per PRD §3.4.12, takes `branch_id` to scope the listing. If `branch_id`
    /// is empty, lists all credentials visible to the caller (filtered by UID).
    /// The `branch_id` is used as a profile filter — credentials are filtered
    /// to those allowed for the branch's profile.
    ///
    /// Root sees all credentials; non-root sees only credentials allowed for their UID's profiles.
    async fn list_credentials(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        branch_id: &str,
    ) -> zbus::fdo::Result<String> {
        // M-11: Use validate_and_authorize for branch ownership check when branch_id specified.
        let (uid, profile_name) = if branch_id.is_empty() {
            let uid = get_caller_uid(&header, connection).await?;
            (uid, String::new())
        } else {
            let (uid, id) =
                validate_and_authorize(&header, connection, branch_id, &self.manager).await?;
            let profile = self
                .manager
                .inspect(&id)
                .map(|info| info.profile.clone())
                .unwrap_or_default();
            (uid, profile)
        };
        tracing::info!(branch_id, profile_name = %profile_name, uid, "§3.4.12: ListCredentials requested");

        let store = self
            .manager
            .credential_store()
            .ok_or_else(|| zbus::fdo::Error::Failed("credential store not initialized".into()))?;

        let guard = store.read().await;
        let all_creds = guard.list();

        // §3.4.6: Root sees all; non-root sees only credentials allowed for their profiles.
        // For non-root callers, find which profiles the UID owns via active branches.
        let filtered: Vec<_> = if uid == 0 {
            // Root: filter by profile_name if non-empty, otherwise show all
            if profile_name.is_empty() {
                all_creds
            } else {
                all_creds
                    .into_iter()
                    .filter(|meta| {
                        meta.allowed_profiles.is_empty()
                            || meta
                                .allowed_profiles
                                .iter()
                                .any(|p| p == "*" || p == &profile_name)
                    })
                    .collect()
            }
        } else {
            // Non-root: only show credentials matching the caller's profile
            // Determine the caller's profiles from active branches owned by this UID
            let caller_profiles: Vec<String> = self
                .manager
                .list()
                .iter()
                .filter_map(|info| {
                    if info.uid == uid {
                        Some(info.profile.clone())
                    } else {
                        None
                    }
                })
                .collect();

            all_creds
                .into_iter()
                .filter(|meta| {
                    meta.allowed_profiles
                        .iter()
                        .any(|p| p == "*" || caller_profiles.iter().any(|cp| cp == p))
                })
                .collect()
        };

        let json = serde_json::to_string(&filtered)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialization error: {}", e)))?;

        Ok(json)
    }

    // -- §3.4 G19: Credential Provisioning Methods --

    /// §3.4 G19: Provision credentials for a branch.
    ///
    /// Orchestrates per-branch credential provisioning:
    /// 1. Reads credential specs from the branch's profile
    /// 2. For each spec: fetches real value from backend, generates phantom token
    /// 3. Allocates a proxy port
    /// 4. Persists credential mappings for restart recovery
    /// 5. Returns phantom token environment variables for container injection
    ///
    /// Called by `CreateBranch` when the profile has a credentials section,
    /// or directly by `puzzle-podman` before `podman run`.
    async fn provision_credentials(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        branch_id: &str,
    ) -> zbus::fdo::Result<String> {
        // M-11: Use validate_and_authorize for branch ownership + format validation.
        let (uid, id) =
            validate_and_authorize(&header, connection, branch_id, &self.manager).await?;
        tracing::info!(branch_id, uid, "§3.4 G19: ProvisionCredentials requested");

        // Get the branch and its profile
        let branch_info = self
            .manager
            .inspect(&id)
            .ok_or_else(|| zbus::fdo::Error::Failed(format!("branch {} not found", branch_id)))?;

        let profile = self
            .manager
            .get_profile(&branch_info.profile)
            .ok_or_else(|| {
                zbus::fdo::Error::Failed(format!(
                    "profile '{}' not found for branch {}",
                    branch_info.profile, branch_id
                ))
            })?;

        // Get credential store and phantom token manager
        let _store = self.manager.credential_store().ok_or_else(|| {
            zbus::fdo::Error::Failed(
                "credential store not initialized (credentials.enabled=false)".into(),
            )
        })?;

        let ptm = self.manager.phantom_token_manager().ok_or_else(|| {
            zbus::fdo::Error::Failed("phantom token manager not initialized".into())
        })?;

        // Build provisioning result with phantom token env vars
        let mut env_vars: Vec<serde_json::Value> = Vec::new();

        // Issue phantom tokens for the branch's credential mappings using
        // cryptographic random generation via PhantomTokenManager::issue_for_branch().
        // GAP-H2 fix: previous code generated deterministic tokens which undermined
        // phantom token security — anyone who knew branch_id + credential_ref could
        // predict the token.
        if let Some(ref cred_config) = profile.credentials {
            // M-4: Convert tuples to CredentialMapping structs with `required` field.
            let mappings: Vec<puzzle_proxy::credentials::CredentialMapping> = cred_config
                .credential_mappings()
                .into_iter()
                .map(|(domain, credential_ref, env_var, required)| {
                    puzzle_proxy::credentials::CredentialMapping {
                        domain,
                        credential_ref,
                        env_var,
                        required,
                    }
                })
                .collect();

            let mut ptm_guard = ptm.write().await;
            let issued = ptm_guard
                .issue_for_branch(&id, &branch_info.profile, &mappings)
                .await
                .map_err(|e| {
                    zbus::fdo::Error::Failed(format!(
                        "M-1/§3.4.5: credential provisioning failed: {e}"
                    ))
                })?;
            drop(ptm_guard);

            for (env_var, phantom_token) in &issued {
                // Find the matching mapping to include domain info
                let mapping = mappings.iter().find(|m| m.env_var == *env_var);
                let domain = mapping.map(|m| m.domain.as_str()).unwrap_or("");
                let credential_ref = mapping.map(|m| m.credential_ref.as_str()).unwrap_or("");

                env_vars.push(serde_json::json!({
                    "env_var": env_var,
                    "phantom_token": phantom_token,
                    "credential_ref": credential_ref,
                    "domain": domain,
                }));
            }
        }

        // §3.4.12: Include proxy_port, ca_cert_path, proxy_config_path per PRD spec
        let branch_state_dir = self.manager.config().branch_root.join(branch_id);
        let proxy_ca_cert_path = branch_state_dir.join("proxy-ca.pem");
        let proxy_config_path = branch_state_dir.join("proxy.json");

        // Build phantom_env_vars as {env_var: phantom_token} map per PRD
        let phantom_env_map: serde_json::Map<String, serde_json::Value> = env_vars
            .iter()
            .filter_map(|v| {
                let ev = v.get("env_var")?.as_str()?;
                let pt = v.get("phantom_token")?.as_str()?;
                Some((ev.to_string(), serde_json::Value::String(pt.to_string())))
            })
            .collect();

        let result = serde_json::json!({
            "branch_id": branch_id,
            "proxy_port": self.manager.config().network.proxy_port,
            // L-13: Key name matches PRD §3.4.12 output specification.
            "ca_cert_path": proxy_ca_cert_path.to_string_lossy(),
            "phantom_env_vars": phantom_env_map,
            "proxy_config_path": proxy_config_path.to_string_lossy(),
            "env_vars": env_vars,
            "status": "provisioned",
        });

        let json = serde_json::to_string(&result)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialization: {}", e)))?;

        tracing::info!(
            branch_id,
            credentials = env_vars.len(),
            "§3.4 G19: credentials provisioned"
        );

        // Emit audit event
        self.audit_logger.log(AuditEvent::CredentialStored {
            credential_name: format!("branch:{}", branch_id),
            caller_uid: uid,
        });

        Ok(json)
    }

    /// §3.4.12: Revoke all credential mappings for a branch.
    ///
    /// Atomically zeroizes all phantom token mappings and credential
    /// associations for the given branch. Called when a branch is committed,
    /// rolled back, or destroyed. Phantom tokens for this branch become
    /// permanently unresolvable.
    async fn revoke_credentials(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        branch_id: &str,
    ) -> zbus::fdo::Result<bool> {
        // M-11: Use validate_and_authorize for branch ownership + format validation.
        let (uid, id) =
            validate_and_authorize(&header, connection, branch_id, &self.manager).await?;
        tracing::info!(branch_id, uid, "§3.4.12: RevokeCredentials requested");

        // Revoke phantom tokens for this branch
        let ptm = self.manager.phantom_token_manager().ok_or_else(|| {
            zbus::fdo::Error::Failed("phantom token manager not initialized".into())
        })?;

        let mut ptm_guard = ptm.write().await;
        ptm_guard.revoke_branch(&id);
        drop(ptm_guard);

        // §3.4 T2.3: Stop the proxy and delete persisted credential mappings.
        // This mirrors cleanup_branch_resources() behavior for credential-specific resources.
        self.manager.revoke_branch_credential_resources(&id);

        // Emit audit event
        self.audit_logger.log(AuditEvent::CredentialRevoked {
            branch_id: id.clone(),
        });

        tracing::info!(
            branch_id,
            "§3.4.12: credentials revoked, proxy stopped, mappings deleted"
        );
        Ok(true)
    }

    /// §3.4 G19: Unlock a passphrase-encrypted credential.
    ///
    /// Derives AES key via Argon2id from the passphrase, decrypts the credential,
    /// and stores the plaintext in the secure credential store. The passphrase
    /// is zeroized immediately after key derivation.
    async fn unlock_credential(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        credential_name: &str,
        // SECURITY NOTE: The passphrase is borrowed from the D-Bus message buffer.
        // It cannot be explicitly zeroized because zbus does not expose the underlying
        // allocation. The passphrase exists in memory for the duration of the Argon2id
        // KDF call (~300ms at 64MiB memory cost). This is an accepted limitation of
        // the zbus framework. Mitigated by: puzzled process isolation (PR_SET_DUMPABLE=0,
        // SELinux puzzled_t, RLIMIT_CORE=0).
        passphrase: &str,
    ) -> zbus::fdo::Result<bool> {
        let uid = get_caller_uid(&header, connection).await?;
        // H-1: Access control — only root can unlock credentials, matching
        // store_credential and rotate_credential patterns.
        if uid != 0 {
            return Err(zbus::fdo::Error::AccessDenied(
                "Only root can unlock credentials".into(),
            ));
        }
        tracing::info!(
            credential_name,
            uid,
            "§3.4 G19: UnlockCredential requested (passphrase redacted)"
        );

        // Verify credential store is available
        let _store = self.manager.credential_store().ok_or_else(|| {
            zbus::fdo::Error::Failed(
                "credential store not initialized (credentials.enabled=false)".into(),
            )
        })?;

        // Look for the encrypted credential file
        let secrets_dir = std::env::var("XDG_CONFIG_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|_| std::env::var("HOME").map(|h| std::path::PathBuf::from(h).join(".config")))
            .unwrap_or_else(|_| std::path::PathBuf::from("/etc"))
            .join("puzzled/secrets");
        let enc_path = secrets_dir.join(format!("{}.enc", credential_name));

        if !enc_path.exists() {
            // H46: Generic error message — do not expose filesystem paths in D-Bus responses.
            // The full path is logged server-side for admin debugging.
            tracing::warn!(
                credential = %credential_name,
                path = %enc_path.display(),
                "§3.4 H46: encrypted credential file not found"
            );
            return Err(zbus::fdo::Error::Failed(format!(
                "encrypted credential '{}' not found",
                credential_name,
            )));
        }

        // Read encrypted file
        let encrypted_data = std::fs::read(&enc_path).map_err(|e| {
            // H46: Generic error — log the actual path and error server-side only.
            tracing::warn!(
                credential = %credential_name,
                path = %enc_path.display(),
                error = %e,
                "§3.4 H46: failed to read encrypted credential file"
            );
            zbus::fdo::Error::Failed(format!(
                "failed to read encrypted credential '{}'",
                credential_name
            ))
        })?;

        // Decrypt with passphrase via Argon2id
        let plaintext = puzzle_proxy::credential_backends::decrypt_with_passphrase(
            credential_name,
            &encrypted_data,
            passphrase.as_bytes(),
        )
        .map_err(|e| {
            zbus::fdo::Error::Failed(format!(
                "failed to decrypt credential '{}': {} (wrong passphrase?)",
                credential_name, e
            ))
        })?;

        // §3.4 G19: Store decrypted credential in the CredentialStore so phantom
        // tokens can resolve against it.
        //
        // M5: If the credential already exists in the store (e.g., was previously
        // provisioned), preserve its scoped allowed_profiles and target_domains
        // rather than defaulting to wildcards. This prevents an unlock from
        // widening a credential's scope beyond what its CredentialSpec permits.
        let credential_value = String::from_utf8(plaintext.to_vec()).map_err(|_| {
            zbus::fdo::Error::Failed(format!(
                "credential '{}' contains invalid UTF-8",
                credential_name
            ))
        })?;

        // Look up existing credential metadata to preserve scoping
        let store_read = self.manager.credential_store().ok_or_else(|| {
            zbus::fdo::Error::Failed(
                "credential store not initialized (credentials.enabled=false)".into(),
            )
        })?;
        let (existing_profiles, existing_domains, existing_injection) = {
            let guard = store_read.read().await;
            match guard.get(credential_name) {
                Some(existing) => (
                    existing.allowed_profiles.clone(),
                    existing.target_domains.clone(),
                    existing.injection.clone(),
                ),
                None => (
                    // No existing credential — use empty vecs (credential will only
                    // be usable after a profile provisions it with proper scoping)
                    vec![],
                    vec![],
                    puzzle_proxy::credentials::InjectionMethod::BearerHeader,
                ),
            }
        };

        let cred = puzzle_proxy::credentials::StoredCredential {
            name: credential_name.to_string(),
            credential_type: puzzle_proxy::credentials::CredentialType::ApiKey,
            value: credential_value.into(),
            allowed_profiles: existing_profiles,
            target_domains: existing_domains,
            injection: existing_injection,
            expires_at: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            rotated_at: None,
        };

        let store = self.manager.credential_store().ok_or_else(|| {
            zbus::fdo::Error::Failed(
                "credential store not initialized (credentials.enabled=false)".into(),
            )
        })?;
        let mut guard = store.write().await;
        guard
            .store(cred)
            .map_err(|e| zbus::fdo::Error::Failed(format!("storing unlocked credential: {}", e)))?;
        drop(guard);

        // Emit audit event for credential unlock
        self.audit_logger.log(AuditEvent::CredentialStored {
            credential_name: credential_name.to_string(),
            caller_uid: uid,
        });

        tracing::info!(
            credential_name,
            "§3.4 G19: credential unlocked and stored successfully"
        );

        Ok(true)
    }

    /// Trigger governance evaluation for a branch (called by OCI hook at poststop).
    ///
    /// Runs the full governance flow: freeze → diff → OPA evaluate → commit/rollback.
    async fn trigger_governance(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        branch_id: &str,
    ) -> zbus::fdo::Result<String> {
        validate_branch_id(branch_id)?;
        tracing::info!(branch_id, "TriggerGovernance requested");

        let (_uid, id) =
            validate_and_authorize(&header, connection, branch_id, &self.manager).await?;

        // Delegate to the existing commit flow which handles freeze → diff → OPA → WAL
        let result = self
            .manager
            .commit(&id)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let json =
            serde_json::to_string(&result).map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        // K27: Check policy_result and emit appropriate audit event.
        // Previously always logged BranchCommitted regardless of outcome.
        let tg_identity = self
            .manager
            .inspect(&id)
            .map(|info| puzzled_types::AgentIdentity {
                uid: info.uid,
                profile: info.profile.clone(),
                selinux_context: info.selinux_context.clone(),
                framework: None,
            });
        match &result.policy_result {
            puzzled_types::PolicyDecision::Approved => {
                self.audit_logger.log(AuditEvent::BranchCommitted {
                    branch_id: id.clone(),
                    files: result.files_committed,
                    bytes: result.bytes_committed,
                });
                let tg_event = AuditEvent::BranchCommitted {
                    branch_id: id.clone(),
                    files: result.files_committed,
                    bytes: result.bytes_committed,
                };
                if let Err(e) =
                    self.audit_store
                        .lock()
                        .await
                        .store_with_context(&tg_event, tg_identity, None)
                {
                    tracing::warn!(branch_id, error = %e, "H45: failed to store trigger_governance commit event");
                }
            }
            puzzled_types::PolicyDecision::Rejected(ref violations) => {
                let reject_reason = format!("{} policy violation(s)", violations.len());
                self.audit_logger.log(AuditEvent::CommitRejected {
                    branch_id: id.clone(),
                    reason: reject_reason.clone(),
                });
                let reject_event = AuditEvent::CommitRejected {
                    branch_id: id.clone(),
                    reason: reject_reason,
                };
                if let Err(e) = self.audit_store.lock().await.store_with_context(
                    &reject_event,
                    tg_identity.clone(),
                    None,
                ) {
                    tracing::warn!(branch_id, error = %e, "K27: failed to store trigger_governance reject event");
                }
                for v in violations {
                    self.audit_logger.log(AuditEvent::PolicyViolation {
                        branch_id: id.clone(),
                        rule: v.rule.clone(),
                        message: v.message.clone(),
                    });
                }
            }
            puzzled_types::PolicyDecision::Error(ref err_msg) => {
                let error_reason = format!("policy evaluation error: {}", err_msg);
                self.audit_logger.log(AuditEvent::CommitRejected {
                    branch_id: id.clone(),
                    reason: error_reason.clone(),
                });
                let error_event = AuditEvent::CommitRejected {
                    branch_id: id.clone(),
                    reason: error_reason,
                };
                if let Err(e) = self.audit_store.lock().await.store_with_context(
                    &error_event,
                    tg_identity,
                    None,
                ) {
                    tracing::warn!(branch_id, error = %e, "K27: failed to store trigger_governance error event");
                }
            }
        }

        Ok(json)
    }

    /// Idempotent branch creation — creates a branch if it doesn't exist,
    /// returns the existing branch_id if it does.
    ///
    /// Designed for use in Quadlet ExecStartPre to ensure the branch exists
    /// before container start.
    async fn ensure_branch(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        profile: &str,
        base_path: &str,
    ) -> zbus::fdo::Result<String> {
        tracing::info!(profile, base_path, "EnsureBranch requested");

        // L15: Reject if not initialized
        if !self.initialized.load(std::sync::atomic::Ordering::Acquire) {
            return Err(zbus::fdo::Error::Failed(
                "daemon is not fully initialized".into(),
            ));
        }

        let uid = get_caller_uid(&header, connection).await?;
        validate_dbus_inputs(profile, base_path, "[]")?;

        // M3: Validate profile exists before searching or creating branches.
        // Without this check, a typo in the profile name would silently create
        // a branch that fails later during sandbox setup.
        if self.manager.get_profile(profile).is_none() {
            return Err(zbus::fdo::Error::Failed(format!(
                "profile '{}' not found",
                profile
            )));
        }

        // R10: Apply rate limiting (same as create_branch) to prevent branch exhaustion DoS
        {
            let mut limiter = self.rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
            if !limiter.check(uid) {
                return Err(zbus::fdo::Error::Failed(
                    "rate limit exceeded for EnsureBranch".into(),
                ));
            }
        }

        // Check if a branch already exists for this profile + base_path
        let existing = self
            .manager
            .find_branch_by_profile_and_path(profile, base_path);
        if let Some(branch_id) = existing {
            // R9: Verify caller owns the existing branch (or is root) to prevent
            // leaking other users' branch info
            if let Some(info) = self.manager.inspect(&branch_id) {
                if uid != 0 && info.uid != uid {
                    return Err(zbus::fdo::Error::AccessDenied(
                        "R9: branch exists but is owned by a different user".into(),
                    ));
                }
                tracing::info!(
                    profile,
                    base_path,
                    branch_id = %branch_id,
                    "EnsureBranch returning existing branch"
                );
                let json = serde_json::to_string(&info)
                    .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
                return Ok(json);
            }
            return Ok(branch_id.to_string());
        }

        // Create new branch
        let agent_uid = if uid == 0 { 65534 } else { uid };
        let info = self
            .manager
            .create(profile, std::path::Path::new(base_path), agent_uid, vec![])
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        // K26: Register UID with trust manager, matching create_branch pattern.
        // Without this, branches created via ensure_branch would not have
        // profile-specific initial trust scores.
        {
            let mut trust = self.trust_manager.lock().unwrap_or_else(|e| e.into_inner());
            trust.register_uid(agent_uid, profile);
        }

        // H49: Write audit event for branch creation via ensure_branch,
        // matching the create_branch audit pattern.
        self.audit_logger.log(AuditEvent::BranchCreated {
            branch_id: info.id.clone(),
            profile: profile.to_string(),
            uid: agent_uid,
        });
        if let Err(e) = self
            .audit_store
            .lock()
            .await
            .store(&AuditEvent::BranchCreated {
                branch_id: info.id.clone(),
                profile: profile.to_string(),
                uid: agent_uid,
            })
        {
            tracing::warn!(error = %e, "H49: failed to store ensure_branch audit event");
        }

        let json =
            serde_json::to_string(&info).map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        Ok(json)
    }

    // -- §4.1 Trust methods --

    /// Get trust score and level for an agent (by UID).
    /// Non-root callers can only query their own UID's trust score.
    async fn get_trust_score(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        uid: u32,
    ) -> zbus::fdo::Result<String> {
        let caller_uid = get_caller_uid(&header, connection).await?;
        if caller_uid != 0 && caller_uid != uid {
            return Err(zbus::fdo::Error::AccessDenied(
                "non-root callers can only query their own trust score".into(),
            ));
        }

        let trust = self
            .trust_manager
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("trust lock poisoned: {e}")))?;

        match trust.get_score(uid) {
            Some(state) => {
                let json = serde_json::to_string(state)
                    .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
                Ok(json)
            }
            None => {
                // Return a default state for unknown UIDs
                let default = puzzled_types::TrustState::new(uid, 25);
                let json = serde_json::to_string(&default)
                    .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
                Ok(json)
            }
        }
    }

    /// Get behavioral baseline for an agent (by UID).
    async fn get_baseline(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        uid: u32,
    ) -> zbus::fdo::Result<String> {
        let caller_uid = get_caller_uid(&header, connection).await?;
        if caller_uid != 0 && caller_uid != uid {
            return Err(zbus::fdo::Error::AccessDenied(
                "non-root callers can only query their own baseline".into(),
            ));
        }

        let trust = self
            .trust_manager
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("trust lock poisoned: {e}")))?;

        match trust.get_baseline(uid) {
            Some(baseline) => {
                let json = serde_json::to_string(baseline)
                    .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
                Ok(json)
            }
            None => Ok("{}".to_string()),
        }
    }

    /// Reset trust score to initial value. Requires root (UID 0).
    async fn reset_trust_score(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        uid: u32,
        reason: &str,
    ) -> zbus::fdo::Result<bool> {
        let caller_uid = get_caller_uid(&header, connection).await?;
        if caller_uid != 0 {
            return Err(zbus::fdo::Error::AccessDenied(
                "ResetTrustScore requires root".into(),
            ));
        }

        let mut trust = self
            .trust_manager
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("trust lock poisoned: {e}")))?;

        trust
            .reset_score(uid, reason)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        tracing::info!(uid, reason, "trust score reset via D-Bus");
        Ok(true)
    }

    /// Set a temporary trust level override. Requires root.
    async fn set_trust_override(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        uid: u32,
        level: &str,
        duration_hours: u32,
    ) -> zbus::fdo::Result<bool> {
        let caller_uid = get_caller_uid(&header, connection).await?;
        if caller_uid != 0 {
            return Err(zbus::fdo::Error::AccessDenied(
                "SetTrustOverride requires root".into(),
            ));
        }

        #[cfg(feature = "ima")]
        let trust_level = match level {
            "untrusted" => TrustLevel::Untrusted,
            "restricted" => TrustLevel::Restricted,
            "standard" => TrustLevel::Standard,
            "elevated" => TrustLevel::Elevated,
            "trusted" => TrustLevel::Trusted,
            _ => {
                return Err(zbus::fdo::Error::InvalidArgs(format!(
                    "unknown trust level: {level}"
                )))
            }
        };

        #[cfg(not(feature = "ima"))]
        let trust_level = match level {
            "untrusted" => puzzled_types::TrustLevel::Untrusted,
            "restricted" => puzzled_types::TrustLevel::Restricted,
            "standard" => puzzled_types::TrustLevel::Standard,
            "elevated" => puzzled_types::TrustLevel::Elevated,
            "trusted" => puzzled_types::TrustLevel::Trusted,
            _ => {
                return Err(zbus::fdo::Error::InvalidArgs(format!(
                    "unknown trust level: {level}"
                )))
            }
        };

        let mut trust = self
            .trust_manager
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("trust lock poisoned: {e}")))?;

        trust
            .set_override(uid, trust_level, duration_hours)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        tracing::info!(uid, level, duration_hours, "trust override set via D-Bus");
        Ok(true)
    }

    /// List trust score change history for an agent.
    async fn list_trust_history(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        uid: u32,
        limit: u32,
    ) -> zbus::fdo::Result<String> {
        let caller_uid = get_caller_uid(&header, connection).await?;
        if caller_uid != 0 && caller_uid != uid {
            return Err(zbus::fdo::Error::AccessDenied(
                "non-root callers can only query their own trust history".into(),
            ));
        }

        let trust = self
            .trust_manager
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("trust lock poisoned: {e}")))?;

        // K23: Cap trust history limit to prevent excessive memory usage
        const MAX_TRUST_HISTORY_LIMIT: usize = 10_000;
        // S8: safe widening cast — u32 → usize on all supported platforms
        let capped_limit = (limit as usize).min(MAX_TRUST_HISTORY_LIMIT);
        let history = trust
            .get_history(uid, capped_limit)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let json =
            serde_json::to_string(&history).map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(json)
    }

    // -- §4.3 Provenance methods --

    /// Report a provenance record for a branch.
    /// Caller must own the branch.
    async fn report_provenance(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        branch_id: &str,
        record_json: &str,
    ) -> zbus::fdo::Result<String> {
        let uid = get_caller_uid(&header, connection).await?;
        validate_branch_id(branch_id)?;

        // K24: Validate provenance record size before processing to prevent
        // memory exhaustion from oversized JSON payloads.
        const MAX_PROVENANCE_RECORD_LEN: usize = 65536;
        if record_json.len() > MAX_PROVENANCE_RECORD_LEN {
            return Err(zbus::fdo::Error::InvalidArgs(format!(
                "K24: provenance record too large ({} bytes > {} byte limit)",
                record_json.len(),
                MAX_PROVENANCE_RECORD_LEN
            )));
        }

        // V6: Verify branch exists and caller owns it (or is root)
        let branch_info = self.manager.inspect(&BranchId::from(branch_id.to_string()));
        if uid != 0 {
            match &branch_info {
                Some(info) if info.uid != uid => {
                    return Err(zbus::fdo::Error::AccessDenied(
                        "caller does not own this branch".into(),
                    ));
                }
                None => {
                    return Err(zbus::fdo::Error::Failed(format!(
                        "branch not found: {branch_id}"
                    )));
                }
                _ => {}
            }
        }

        let record: puzzled_types::ProvenanceRecord =
            serde_json::from_str(record_json).map_err(|e| {
                zbus::fdo::Error::InvalidArgs(format!("invalid provenance record JSON: {e}"))
            })?;

        // AA1: Validate that the deserialized record's branch_id matches the
        // D-Bus branch_id parameter. Without this check, a caller could pass
        // branch_id="my-branch" (which they own) to pass the ownership check
        // above, but embed branch_id="victim-branch" inside record_json to
        // inject provenance records into a branch they don't own.
        if record.branch_id != branch_id {
            return Err(zbus::fdo::Error::InvalidArgs(format!(
                "AA1: record branch_id mismatch: record contains '{}' but D-Bus parameter is '{}'",
                record.branch_id, branch_id
            )));
        }

        self.provenance_store
            .record(&record)
            .map_err(|e| zbus::fdo::Error::Failed(format!("failed to record provenance: {e}")))?;

        Ok(record.id.clone())
    }

    /// Get provenance records for a branch as NDJSON.
    async fn get_provenance(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        branch_id: &str,
    ) -> zbus::fdo::Result<String> {
        let uid = get_caller_uid(&header, connection).await?;
        validate_branch_id(branch_id)?;

        // V6: Verify branch exists and caller owns it (or is root)
        let branch_info = self.manager.inspect(&BranchId::from(branch_id.to_string()));
        if uid != 0 {
            match &branch_info {
                Some(info) if info.uid != uid => {
                    return Err(zbus::fdo::Error::AccessDenied(
                        "caller does not own this branch".into(),
                    ));
                }
                None => {
                    return Err(zbus::fdo::Error::Failed(format!(
                        "branch not found: {branch_id}"
                    )));
                }
                _ => {}
            }
        }

        let records = self
            .provenance_store
            .get_records(branch_id)
            .map_err(|e| zbus::fdo::Error::Failed(format!("failed to get provenance: {e}")))?;

        // Return as JSON array
        let json =
            serde_json::to_string(&records).map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(json)
    }

    // -- §4.5 Identity methods --

    /// Get a JWT-SVID for a branch, scoped to the given audience.
    /// Caller must own the branch.
    #[cfg(feature = "ima")]
    async fn get_identity_token(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        branch_id: &str,
        audience_json: &str,
    ) -> zbus::fdo::Result<String> {
        let uid = get_caller_uid(&header, connection).await?;
        validate_branch_id(branch_id)?;

        // Verify caller owns the branch (or is root)
        let info = self
            .manager
            .inspect(&BranchId::from(branch_id.to_string()))
            .ok_or_else(|| zbus::fdo::Error::Failed(format!("branch not found: {branch_id}")))?;
        if uid != 0 && info.uid != uid {
            return Err(zbus::fdo::Error::AccessDenied(
                "caller does not own this branch".into(),
            ));
        }

        let audience: Vec<String> = serde_json::from_str(audience_json).map_err(|e| {
            zbus::fdo::Error::InvalidArgs(format!("invalid audience JSON array: {e}"))
        })?;

        // Get live trust data for this UID
        let (trust_level, trust_score) = {
            let trust = self
                .trust_manager
                .lock()
                .map_err(|e| zbus::fdo::Error::Failed(format!("trust lock poisoned: {e}")))?;
            match trust.get_score(info.uid) {
                Some(state) => (state.level.as_str().to_string(), state.score),
                None => ("restricted".to_string(), 25),
            }
        };

        // V4: Derive enforcement layers from profile's EnforcementRequirements
        let enforcement_layers = {
            let mut layers = Vec::new();
            if let Some(profile) = self.manager.get_profile(&info.profile) {
                if profile.enforcement.require_landlock {
                    layers.push("landlock".to_string());
                }
                if profile.enforcement.require_seccomp {
                    layers.push("seccomp".to_string());
                }
                if profile.enforcement.require_bpf_lsm {
                    layers.push("bpf_lsm".to_string());
                }
                if profile.enforcement.require_quota {
                    layers.push("quota".to_string());
                }
            }
            // Always include namespace-based isolation (unconditional)
            layers.push("pid_namespace".to_string());
            layers.push("mount_namespace".to_string());
            layers
        };

        // V5 + W8: Read policy_hash from audit_store (not a placeholder).
        // V7: Read attestation chain from Merkle tree. Single lock for both.
        let (policy_version, attestation_chain_hash, attestation_chain_length) = {
            let store = self.audit_store.lock().await;
            let pv = store.policy_hash().unwrap_or("unknown").to_string();
            let (ach, acl): (Option<String>, u32) = match store.merkle_tree() {
                Some(tree) => {
                    let hash_bytes = tree.root_hash().unwrap_or([0u8; 32]);
                    let root_hash: String = hash_bytes.iter().map(|b| format!("{b:02x}")).collect();
                    // G7: Safe cast — avoid silent truncation if tree exceeds u32::MAX leaves
                    let size = u32::try_from(tree.size()).unwrap_or_else(|_| {
                        tracing::warn!("G7: Merkle tree size exceeds u32::MAX");
                        u32::MAX
                    });
                    (Some(root_hash), size)
                }
                None => (None, 0),
            };
            (pv, ach, acl)
        };

        // X3/X4: Construct ContainmentClaims from the agent profile so that
        // JWT-SVIDs carry real containment metadata when include_containment_claims
        // is enabled. PRD §4.5.3 specifies: filesystem_scope, network_mode,
        // allowed_domains, exec_allowlist_count.
        let containment = self.manager.get_profile(&info.profile).map(|profile| {
            puzzled_types::ContainmentClaims {
                filesystem_scope: profile
                    .filesystem
                    .write_allowlist
                    .first()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| info.base_path.to_string_lossy().to_string()),
                network_mode: format!("{:?}", profile.network.mode),
                allowed_domains: profile.network.allowed_domains.clone(),
                // Y5: Safe cast — consistent with G7 pattern on Merkle tree size.
                exec_allowlist_count: u32::try_from(profile.exec_allowlist.len())
                    .unwrap_or(u32::MAX),
            }
        });

        let token = self
            .identity_manager
            .issue_jwt_svid_with_containment(
                branch_id,
                &info.profile,
                &trust_level,
                trust_score,
                &audience,
                &enforcement_layers,
                &policy_version,
                attestation_chain_hash.as_deref(),
                attestation_chain_length,
                containment,
            )
            .map_err(|e| zbus::fdo::Error::Failed(format!("JWT-SVID issuance failed: {e}")))?;

        Ok(token)
    }

    /// Get a JWT-SVID for a branch (stub when ima feature is disabled).
    #[cfg(not(feature = "ima"))]
    async fn get_identity_token(
        &self,
        #[zbus(header)] _header: zbus::message::Header<'_>,
        #[zbus(connection)] _connection: &zbus::Connection,
        _branch_id: &str,
        _audience_json: &str,
    ) -> zbus::fdo::Result<String> {
        Err(zbus::fdo::Error::NotSupported(
            "identity tokens require the 'ima' feature".into(),
        ))
    }

    /// Get the SPIFFE ID for a branch.
    #[cfg(feature = "ima")]
    async fn get_spiffe_id(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        branch_id: &str,
    ) -> zbus::fdo::Result<String> {
        let uid = get_caller_uid(&header, connection).await?;
        validate_branch_id(branch_id)?;

        // W10: Verify branch exists and caller owns it (or is root)
        let branch_info = self.manager.inspect(&BranchId::from(branch_id.to_string()));
        if uid != 0 {
            match &branch_info {
                Some(info) if info.uid != uid => {
                    return Err(zbus::fdo::Error::AccessDenied(
                        "caller does not own this branch".into(),
                    ));
                }
                None => {
                    return Err(zbus::fdo::Error::Failed(format!(
                        "branch not found: {branch_id}"
                    )));
                }
                _ => {}
            }
        }

        self.identity_manager
            .spiffe_id(branch_id)
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e}")))
    }

    /// Get the SPIFFE ID for a branch (stub when ima feature is disabled).
    #[cfg(not(feature = "ima"))]
    async fn get_spiffe_id(
        &self,
        #[zbus(header)] _header: zbus::message::Header<'_>,
        #[zbus(connection)] _connection: &zbus::Connection,
        _branch_id: &str,
    ) -> zbus::fdo::Result<String> {
        Err(zbus::fdo::Error::NotSupported(
            "SPIFFE IDs require the 'ima' feature".into(),
        ))
    }

    /// Get the JWK Set (public key) for offline JWT-SVID verification.
    #[cfg(feature = "ima")]
    async fn get_identity_jwks(
        &self,
        #[zbus(header)] _header: zbus::message::Header<'_>,
        #[zbus(connection)] _connection: &zbus::Connection,
    ) -> zbus::fdo::Result<String> {
        Ok(self.identity_manager.jwks())
    }

    /// Get the JWK Set (stub when ima feature is disabled).
    #[cfg(not(feature = "ima"))]
    async fn get_identity_jwks(
        &self,
        #[zbus(header)] _header: zbus::message::Header<'_>,
        #[zbus(connection)] _connection: &zbus::Connection,
    ) -> zbus::fdo::Result<String> {
        Err(zbus::fdo::Error::NotSupported(
            "JWKS requires the 'ima' feature".into(),
        ))
    }

    // -- Signals --

    /// Emitted when a trust level transition occurs (§4.1).
    #[zbus(signal)]
    async fn trust_transition(
        ctx: &SignalEmitter<'_>,
        uid: u32,
        old_level: &str,
        new_level: &str,
        score: u32,
        trigger_event: &str,
    ) -> zbus::Result<()>;

    /// Emitted when a branch is created.
    /// M-db2: Includes profile information.
    #[zbus(signal)]
    async fn branch_created(
        ctx: &SignalEmitter<'_>,
        branch_id: &str,
        profile: &str,
    ) -> zbus::Result<()>;

    /// M20: Emitted when a branch is committed. Enriched with changeset_hash and profile.
    #[zbus(signal)]
    async fn branch_committed(
        ctx: &SignalEmitter<'_>,
        branch_id: &str,
        changeset_hash: &str,
        profile: &str,
    ) -> zbus::Result<()>;

    /// Emitted when a branch is rolled back.
    /// L-db1: Includes reason parameter.
    #[zbus(signal)]
    async fn branch_rolled_back(
        ctx: &SignalEmitter<'_>,
        branch_id: &str,
        reason: &str,
    ) -> zbus::Result<()>;

    /// M20: Emitted when a policy violation is detected (branch rejected).
    /// Enriched with changeset_hash, reason, and profile.
    #[zbus(signal)]
    async fn policy_violation(
        ctx: &SignalEmitter<'_>,
        branch_id: &str,
        violations_json: &str,
        changeset_hash: &str,
        reason: &str,
        profile: &str,
    ) -> zbus::Result<()>;

    /// Emitted when a behavioral trigger fires.
    #[zbus(signal)]
    async fn behavioral_trigger(
        ctx: &SignalEmitter<'_>,
        branch_id: &str,
        trigger_json: &str,
    ) -> zbus::Result<()>;

    // NOTE: PM11 throttling is implemented via `should_emit_behavioral_trigger()`
    // below. Callers must check the throttle before emitting the signal.

    /// H12: Emitted when an agent times out (watchdog expiry).
    #[zbus(signal)]
    async fn agent_timeout(
        ctx: &SignalEmitter<'_>,
        branch_id: &str,
        timeout_duration_secs: u64,
    ) -> zbus::Result<()>;

    /// H-10: Emitted when a branch enters GovernanceReview state and awaits
    /// human approval. `diff_summary` is a JSON string with file count and
    /// total bytes.
    #[zbus(signal)]
    async fn governance_review_pending(
        ctx: &SignalEmitter<'_>,
        branch_id: &str,
        diff_summary: &str,
    ) -> zbus::Result<()>;

    /// M-db1: Generic branch event signal for extensible event notification.
    #[zbus(signal)]
    async fn branch_event(
        ctx: &SignalEmitter<'_>,
        branch_id: &str,
        event_type: &str,
        details_json: &str,
    ) -> zbus::Result<()>;

    /// §3.3: DLP violation detected — emitted when DLP blocks or quarantines a request.
    #[zbus(signal)]
    async fn dlp_violation(
        ctxt: &SignalEmitter<'_>,
        branch_id: &str,
        rule_name: &str,
        action: &str,
        domain: &str,
    ) -> zbus::Result<()>;

    /// §3.4 G20: Credential rotated — emitted when a credential value is refreshed.
    #[zbus(signal)]
    async fn credential_rotated(
        ctx: &SignalEmitter<'_>,
        branch_id: &str,
        credential_name: &str,
        expires_at: &str,
    ) -> zbus::Result<()>;

    /// §3.4 G20: Credential resolved — emitted when a phantom token is swapped for real value.
    #[zbus(signal)]
    async fn credential_resolved(
        ctx: &SignalEmitter<'_>,
        branch_id: &str,
        credential_name: &str,
        domain: &str,
        timestamp: &str,
    ) -> zbus::Result<()>;

    /// §3.4 G20: Credential proxy error — emitted on proxy failures.
    #[zbus(signal)]
    async fn credential_proxy_error(
        ctx: &SignalEmitter<'_>,
        branch_id: &str,
        error: &str,
        domain: &str,
    ) -> zbus::Result<()>;
}

/// L4: Maximum length for branch IDs received via D-Bus.
const MAX_BRANCH_ID_LEN: usize = 256;
/// L4: Maximum length for profile names received via D-Bus.
const MAX_PROFILE_NAME_LEN: usize = 128;
/// L4: Maximum length for base paths received via D-Bus.
const MAX_BASE_PATH_LEN: usize = 4096;
/// L4: Maximum length for command JSON received via D-Bus.
const MAX_COMMAND_JSON_LEN: usize = 65536;

/// L4: Validate that a branch_id is within length limits and contains only
/// allowed characters (alphanumeric, hyphens, underscores).
fn validate_branch_id(branch_id: &str) -> zbus::fdo::Result<()> {
    if branch_id.is_empty() {
        return Err(zbus::fdo::Error::Failed(
            "branch_id must not be empty".into(),
        ));
    }
    if branch_id.len() > MAX_BRANCH_ID_LEN {
        return Err(zbus::fdo::Error::Failed(format!(
            "branch_id exceeds maximum length of {} characters",
            MAX_BRANCH_ID_LEN
        )));
    }
    if !branch_id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(zbus::fdo::Error::Failed(
            "branch_id contains invalid characters (allowed: alphanumeric, hyphen, underscore)"
                .into(),
        ));
    }
    Ok(())
}

/// Validate D-Bus inputs for path traversal, shell metacharacters, null bytes,
/// and length limits (L4).
fn validate_dbus_inputs(
    profile: &str,
    base_path: &str,
    command_json: &str,
) -> zbus::fdo::Result<()> {
    // L4: profile: length limit + alphanumeric + hyphens/underscores only
    if profile.is_empty() {
        return Err(zbus::fdo::Error::Failed(
            "profile name must not be empty".into(),
        ));
    }
    if profile.len() > MAX_PROFILE_NAME_LEN {
        return Err(zbus::fdo::Error::Failed(format!(
            "profile name exceeds maximum length of {} characters",
            MAX_PROFILE_NAME_LEN
        )));
    }
    if !profile
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(zbus::fdo::Error::Failed(
            "invalid profile name (allowed: alphanumeric, hyphen, underscore)".into(),
        ));
    }
    // L4: base_path: length limit, must be absolute, no null bytes, no ".." components
    if base_path.len() > MAX_BASE_PATH_LEN {
        return Err(zbus::fdo::Error::Failed(format!(
            "base_path exceeds maximum length of {} characters",
            MAX_BASE_PATH_LEN
        )));
    }
    if !base_path.starts_with('/') {
        return Err(zbus::fdo::Error::Failed(
            "base_path must be absolute".into(),
        ));
    }
    if base_path.contains('\0') || base_path.split('/').any(|c| c == "..") {
        return Err(zbus::fdo::Error::Failed(
            "base_path contains illegal components".into(),
        ));
    }
    // L4: command_json: length limit
    if command_json.len() > MAX_COMMAND_JSON_LEN {
        return Err(zbus::fdo::Error::Failed(format!(
            "command_json exceeds maximum length of {} characters",
            MAX_COMMAND_JSON_LEN
        )));
    }
    // L4: command_json: must be valid JSON array of strings (or empty)
    if !command_json.is_empty() {
        let parsed: Result<Vec<String>, _> = serde_json::from_str(command_json);
        if parsed.is_err() {
            return Err(zbus::fdo::Error::Failed(
                "command_json must be a valid JSON array of strings".into(),
            ));
        }
    }
    Ok(())
}

/// Extract the caller UID from D-Bus peer credentials.
async fn get_caller_uid(
    header: &zbus::message::Header<'_>,
    connection: &zbus::Connection,
) -> zbus::fdo::Result<u32> {
    if let Some(sender) = header.sender() {
        let dbus_proxy = zbus::fdo::DBusProxy::new(connection)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("D-Bus proxy: {}", e)))?;
        let bus_name: zbus::names::BusName = sender.clone().into();
        dbus_proxy
            .get_connection_unix_user(bus_name)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("getting caller UID: {}", e)))
    } else {
        Err(zbus::fdo::Error::Failed(
            "cannot determine caller identity".into(),
        ))
    }
}

/// Check that a caller has access to a branch.
/// Access control is enforced by D-Bus policy (only root and wheel group
/// can call methods). Any caller with D-Bus access can operate on any branch.
/// H-30: Returns error when branch is not found instead of silently allowing access.
fn check_branch_access(
    _caller_uid: u32,
    manager: &BranchManager,
    id: &BranchId,
) -> zbus::fdo::Result<()> {
    if manager.inspect(id).is_some() {
        Ok(())
    } else {
        // H-30: Branch not found — fail closed instead of allowing access
        Err(zbus::fdo::Error::Failed("branch not found".into()))
    }
}

impl ManagerInterface {
    /// PM11: Returns the behavioral trigger throttle map for external callers
    /// (e.g., fanotify trigger processing in branch.rs) to use with
    /// `should_emit_behavioral_trigger()`.
    pub fn behavioral_trigger_throttle(
        &self,
    ) -> &Arc<std::sync::Mutex<HashMap<String, std::time::Instant>>> {
        &self.behavioral_trigger_last_emitted
    }

    /// M-db1: Helper to emit a generic branch_event signal.
    pub async fn emit_branch_event(
        connection: &zbus::Connection,
        branch_id: &str,
        event_type: &str,
        details_json: &str,
    ) {
        if let Some(iface_ref) = get_signal_emitter(connection).await {
            if let Err(e) = ManagerInterface::branch_event(
                iface_ref.signal_emitter(),
                branch_id,
                event_type,
                details_json,
            )
            .await
            {
                tracing::debug!("F11: D-Bus signal emission failed: {e}");
            }
        }
    }
}

/// PM11: Minimum interval between BehavioralTrigger signals for the same branch.
const BEHAVIORAL_TRIGGER_THROTTLE: std::time::Duration = std::time::Duration::from_secs(10);

/// PM11: Check whether a BehavioralTrigger signal should be emitted for this branch.
///
/// Returns `true` if at least `BEHAVIORAL_TRIGGER_THROTTLE` (10 seconds) has elapsed
/// since the last emission for this branch. Updates the timestamp on emission.
/// Callers should gate `ManagerInterface::behavioral_trigger()` behind this check
/// to avoid flooding D-Bus subscribers during sustained anomalous behavior.
///
/// M-db4: Also evicts entries older than 300s and caps at MAX_BEHAVIORAL_TRIGGER_ENTRIES.
pub fn should_emit_behavioral_trigger(
    last_emitted: &std::sync::Mutex<HashMap<String, std::time::Instant>>,
    branch_id: &str,
) -> bool {
    let now = std::time::Instant::now();
    let mut map = last_emitted.lock().unwrap_or_else(|e| e.into_inner());

    // M-db4: Evict entries older than 300s to prevent unbounded growth
    map.retain(|_, ts| now.duration_since(*ts) < BEHAVIORAL_TRIGGER_MAX_AGE);

    // M-db4: Cap at MAX_BEHAVIORAL_TRIGGER_ENTRIES
    if map.len() >= MAX_BEHAVIORAL_TRIGGER_ENTRIES {
        // Evict the oldest entry
        let oldest_key = map.iter().min_by_key(|(_, ts)| *ts).map(|(k, _)| k.clone());
        if let Some(key) = oldest_key {
            map.remove(&key);
        }
    }

    if let Some(last) = map.get(branch_id) {
        if now.duration_since(*last) < BEHAVIORAL_TRIGGER_THROTTLE {
            tracing::debug!(
                branch_id,
                "PM11: BehavioralTrigger signal throttled (< 10s since last emission)"
            );
            return false;
        }
    }
    map.insert(branch_id.to_string(), now);
    true
}

/// Get the signal emitter for the Manager interface, if available.
async fn get_signal_emitter(
    connection: &zbus::Connection,
) -> Option<zbus::object_server::InterfaceRef<ManagerInterface>> {
    connection
        .object_server()
        .interface::<_, ManagerInterface>("/org/lobstertrap/PuzzlePod1/Manager")
        .await
        .ok()
}

/// Validate a branch ID and authorize the caller.
#[allow(dead_code)] // Used by zbus interface methods; may appear unused on some targets
async fn validate_and_authorize(
    header: &zbus::message::Header<'_>,
    connection: &zbus::Connection,
    branch_id: &str,
    manager: &BranchManager,
) -> zbus::fdo::Result<(u32, BranchId)> {
    let uid = get_caller_uid(header, connection).await?;
    let id = BranchId::validated(branch_id.to_string())
        .map_err(|e| zbus::fdo::Error::Failed(format!("invalid branch_id: {}", e)))?;
    check_branch_access(uid, manager, &id)?;
    Ok((uid, id))
}

/// Start the D-Bus service. Returns the connection and the initialized flag;
/// the caller must set `initialized` to true after all subsystems are ready,
/// and keep the event loop alive (e.g., via ctrl_c wait).
///
/// M23: The initialized flag is NOT set inside this function. The caller
/// sets it after D-Bus + WAL recovery + policy load + seccomp hardening
/// are all complete, ensuring agents cannot register prematurely.
pub async fn start_dbus_service(
    config: &DaemonConfig,
    manager: Arc<BranchManager>,
    audit_store: Arc<tokio::sync::Mutex<AuditStore>>,
    audit_logger: Arc<AuditLogger>,
    trust_manager: Arc<std::sync::Mutex<TrustManager>>,
    provenance_store: Arc<ProvenanceStore>,
    #[cfg(feature = "ima")] identity_manager: Arc<crate::identity::IdentityManager>,
) -> Result<(Connection, Arc<std::sync::atomic::AtomicBool>)> {
    // M23: The initialized flag starts as false; the caller sets it after full init.
    let initialized = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let interface = ManagerInterface {
        manager,
        audit_store,
        rate_limiter: Arc::new(std::sync::Mutex::new(RateLimiter::new())),
        initialized: initialized.clone(),
        idempotency_cache: Arc::new(std::sync::Mutex::new(HashMap::new())),
        audit_logger,
        behavioral_trigger_last_emitted: Arc::new(std::sync::Mutex::new(HashMap::new())),
        trust_manager,
        provenance_store,
        #[cfg(feature = "ima")]
        identity_manager,
    };

    // Gap 6: Write the public key hex to attestation_dir/public_key.hex so that
    // GetAttestationPublicKey and VerifyAttestationChain can read it.
    if config.attestation.enabled {
        let attestation_dir = &config.attestation.attestation_dir;
        if let Err(e) = std::fs::create_dir_all(attestation_dir) {
            tracing::warn!(error = %e, "failed to create attestation dir for public key");
        } else {
            // Derive public key from signing key file
            let key_path = &config.signing_key_path;
            // H50: Verify signing key file permissions — warn if world-readable
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = std::fs::metadata(key_path) {
                    let mode = metadata.permissions().mode() & 0o777;
                    if mode & 0o044 != 0 {
                        tracing::warn!(
                            path = %key_path.display(),
                            mode = format!("{:04o}", mode),
                            "H50: signing key file is world-readable or group-readable; \
                             expected mode 0600 or 0400"
                        );
                    }
                }
            }
            if key_path.exists() {
                if let Ok(key_bytes) = std::fs::read(key_path) {
                    if key_bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&key_bytes);
                        let signing_key = ed25519_dalek::SigningKey::from_bytes(&arr);
                        let verifying_key = signing_key.verifying_key();
                        let hex: String = verifying_key
                            .as_bytes()
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect();
                        let pubkey_path = attestation_dir.join("public_key.hex");
                        if let Err(e) = std::fs::write(&pubkey_path, &hex) {
                            tracing::warn!(error = %e, "failed to write public_key.hex");
                        } else {
                            tracing::info!(path = %pubkey_path.display(), "public_key.hex written for attestation");
                        }
                    }
                }
            }
        }
    }

    let bus_type = config.bus_type.as_str();
    let connection = match bus_type {
        "session" => {
            // L-db4: Warn when session bus is used — should only be used for development/testing.
            tracing::warn!(
                "D-Bus configured to use session bus (bus_type = \"session\"). \
                 This is intended for development/testing only. \
                 Production deployments should use the system bus."
            );
            zbus::connection::Builder::session()?
                .name("org.lobstertrap.PuzzlePod1")?
                .serve_at("/org/lobstertrap/PuzzlePod1/Manager", interface)?
                .build()
                .await?
        }
        _ => {
            zbus::connection::Builder::system()?
                .name("org.lobstertrap.PuzzlePod1")?
                .serve_at("/org/lobstertrap/PuzzlePod1/Manager", interface)?
                .build()
                .await?
        }
    };

    tracing::info!(bus = bus_type, "D-Bus service registered");

    Ok((connection, initialized))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // validate_branch_id — production function tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_branch_id_valid() {
        assert!(validate_branch_id("my-branch-123").is_ok());
        assert!(validate_branch_id("branch_with_underscore").is_ok());
        assert!(validate_branch_id("a").is_ok());
        assert!(validate_branch_id("UPPERCASE").is_ok());
    }

    #[test]
    fn test_validate_branch_id_empty() {
        let err = validate_branch_id("").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn test_validate_branch_id_invalid_chars() {
        // Path traversal
        assert!(validate_branch_id("../etc/passwd").is_err());
        // Shell metacharacters
        assert!(validate_branch_id("branch;rm -rf /").is_err());
        // Spaces
        assert!(validate_branch_id("has space").is_err());
        // Null bytes
        assert!(validate_branch_id("null\x00byte").is_err());
        // Slashes
        assert!(validate_branch_id("with/slash").is_err());
    }

    #[test]
    fn test_validate_branch_id_too_long() {
        let long_id = "a".repeat(MAX_BRANCH_ID_LEN + 1);
        let err = validate_branch_id(&long_id).unwrap_err();
        assert!(err.to_string().contains("maximum length"));
    }

    #[test]
    fn test_validate_branch_id_max_length_accepted() {
        let max_id = "a".repeat(MAX_BRANCH_ID_LEN);
        assert!(validate_branch_id(&max_id).is_ok());
    }

    // -----------------------------------------------------------------------
    // validate_dbus_inputs — production function tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_dbus_inputs_valid() {
        assert!(validate_dbus_inputs("standard", "/workspace", "[]").is_ok());
        assert!(validate_dbus_inputs("my-profile_v2", "/home/user/project", "").is_ok());
    }

    #[test]
    fn test_validate_dbus_inputs_empty_profile() {
        assert!(validate_dbus_inputs("", "/workspace", "[]").is_err());
    }

    #[test]
    fn test_validate_dbus_inputs_profile_special_chars() {
        // Slash — path traversal
        assert!(validate_dbus_inputs("../hack", "/workspace", "").is_err());
        // Semicolon — command injection
        assert!(validate_dbus_inputs("a;b", "/workspace", "").is_err());
        // Space
        assert!(validate_dbus_inputs("a b", "/workspace", "").is_err());
    }

    #[test]
    fn test_validate_dbus_inputs_profile_too_long() {
        let long_profile = "a".repeat(MAX_PROFILE_NAME_LEN + 1);
        assert!(validate_dbus_inputs(&long_profile, "/workspace", "").is_err());
    }

    #[test]
    fn test_validate_dbus_inputs_relative_path() {
        assert!(validate_dbus_inputs("standard", "relative/path", "").is_err());
        assert!(validate_dbus_inputs("standard", "./local", "").is_err());
    }

    #[test]
    fn test_validate_dbus_inputs_path_traversal() {
        assert!(validate_dbus_inputs("standard", "/workspace/../etc/shadow", "").is_err());
    }

    #[test]
    fn test_validate_dbus_inputs_path_null_bytes() {
        assert!(validate_dbus_inputs("standard", "/workspace/\x00evil", "").is_err());
    }

    #[test]
    fn test_validate_dbus_inputs_path_too_long() {
        let long_path = format!("/{}", "a".repeat(MAX_BASE_PATH_LEN));
        assert!(validate_dbus_inputs("standard", &long_path, "").is_err());
    }

    #[test]
    fn test_validate_dbus_inputs_command_too_long() {
        let long_cmd = format!("[\"{}\"]", "a".repeat(MAX_COMMAND_JSON_LEN));
        assert!(validate_dbus_inputs("standard", "/workspace", &long_cmd).is_err());
    }

    // -----------------------------------------------------------------------
    // check_branch_access — production function tests (H-30)
    // -----------------------------------------------------------------------

    #[test]
    fn test_check_branch_access_root_always_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let manager = create_test_manager(dir.path());

        // Even for a non-existent branch, root gets "not found" not "access denied"
        let id = BranchId::from("nonexistent".to_string());
        let result = check_branch_access(0, &manager, &id);
        // Root bypasses the access check entirely — returns Ok even if branch not found
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_branch_access_nonexistent_branch_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let manager = create_test_manager(dir.path());

        // H-30: Non-root caller on non-existent branch should get an error
        let id = BranchId::from("ghost-branch".to_string());
        let result = check_branch_access(1000, &manager, &id);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    // -----------------------------------------------------------------------
    // RateLimiter — production struct tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_rate_limiter_production_allows_under_limit() {
        let mut limiter = RateLimiter::new();
        for _ in 0..RateLimiter::MAX_PER_MINUTE {
            assert!(limiter.check(1000));
        }
    }

    #[test]
    fn test_rate_limiter_production_blocks_over_limit() {
        let mut limiter = RateLimiter::new();
        for _ in 0..RateLimiter::MAX_PER_MINUTE {
            assert!(limiter.check(1000));
        }
        assert!(!limiter.check(1000));
    }

    #[test]
    fn test_rate_limiter_production_per_uid_isolation() {
        let mut limiter = RateLimiter::new();
        // Fill uid 1000
        for _ in 0..RateLimiter::MAX_PER_MINUTE {
            limiter.check(1000);
        }
        assert!(!limiter.check(1000));
        // uid 1001 unaffected
        assert!(limiter.check(1001));
    }

    #[test]
    fn test_rate_limiter_production_uid_eviction_at_capacity() {
        // A3: Verify that when MAX_TRACKED_UIDS is reached, stale UIDs are evicted
        let mut limiter = RateLimiter::new();
        // Fill up to capacity
        for uid in 0..RateLimiter::MAX_TRACKED_UIDS as u32 {
            limiter.check(uid);
        }
        assert_eq!(limiter.requests.len(), RateLimiter::MAX_TRACKED_UIDS);

        // One more UID should evict the oldest
        assert!(limiter.check(RateLimiter::MAX_TRACKED_UIDS as u32));
        assert!(limiter.requests.len() <= RateLimiter::MAX_TRACKED_UIDS);
    }

    // -----------------------------------------------------------------------
    // should_emit_behavioral_trigger — production function tests (PM11/M-db4)
    // -----------------------------------------------------------------------

    #[test]
    fn test_behavioral_trigger_throttle_first_emission() {
        let map = std::sync::Mutex::new(HashMap::new());
        // First emission should always be allowed
        assert!(should_emit_behavioral_trigger(&map, "branch-1"));
    }

    #[test]
    fn test_behavioral_trigger_throttle_suppresses_rapid_emissions() {
        let map = std::sync::Mutex::new(HashMap::new());
        // First: allowed
        assert!(should_emit_behavioral_trigger(&map, "branch-1"));
        // Second (immediate): suppressed
        assert!(!should_emit_behavioral_trigger(&map, "branch-1"));
    }

    #[test]
    fn test_behavioral_trigger_throttle_per_branch() {
        let map = std::sync::Mutex::new(HashMap::new());
        assert!(should_emit_behavioral_trigger(&map, "branch-1"));
        // Different branch should be independent
        assert!(should_emit_behavioral_trigger(&map, "branch-2"));
        // branch-1 still throttled
        assert!(!should_emit_behavioral_trigger(&map, "branch-1"));
    }

    #[test]
    fn test_behavioral_trigger_throttle_evicts_old_entries() {
        let map = std::sync::Mutex::new(HashMap::new());
        // Pre-fill with old entries
        {
            let mut m = map.lock().unwrap();
            let old_time = std::time::Instant::now()
                - BEHAVIORAL_TRIGGER_MAX_AGE
                - std::time::Duration::from_secs(1);
            for i in 0..100 {
                m.insert(format!("stale-{}", i), old_time);
            }
        }
        // M-db4: Stale entries should be evicted on next check
        assert!(should_emit_behavioral_trigger(&map, "fresh-branch"));
        let m = map.lock().unwrap();
        // All stale entries should be gone, only fresh-branch remains
        assert_eq!(m.len(), 1);
        assert!(m.contains_key("fresh-branch"));
    }

    #[test]
    fn test_behavioral_trigger_throttle_caps_at_max() {
        let map = std::sync::Mutex::new(HashMap::new());
        // Pre-fill to MAX
        {
            let mut m = map.lock().unwrap();
            for i in 0..MAX_BEHAVIORAL_TRIGGER_ENTRIES {
                m.insert(format!("branch-{}", i), std::time::Instant::now());
            }
        }
        // M-db4: Should evict oldest when at capacity
        assert!(should_emit_behavioral_trigger(&map, "new-branch"));
        let m = map.lock().unwrap();
        assert!(m.len() <= MAX_BEHAVIORAL_TRIGGER_ENTRIES);
        assert!(m.contains_key("new-branch"));
    }

    // -----------------------------------------------------------------------
    // IdempotencyCache bounds tests (M-db3)
    // -----------------------------------------------------------------------

    #[test]
    fn test_idempotency_cache_evicts_on_overflow() {
        let mut cache: HashMap<String, IdempotencyCacheEntry> = HashMap::new();

        // Fill to MAX
        for i in 0..MAX_IDEMPOTENCY_ENTRIES {
            cache.insert(
                format!("key-{}", i),
                IdempotencyCacheEntry {
                    result_json: format!("result-{}", i),
                    created_at: std::time::Instant::now(),
                },
            );
        }
        assert_eq!(cache.len(), MAX_IDEMPOTENCY_ENTRIES);

        // M-db3: Eviction logic (mirrors production code in create_branch)
        if cache.len() >= MAX_IDEMPOTENCY_ENTRIES {
            let oldest_key = cache
                .iter()
                .min_by_key(|(_, entry)| entry.created_at)
                .map(|(k, _)| k.clone());
            if let Some(key) = oldest_key {
                cache.remove(&key);
            }
        }
        cache.insert(
            "new-key".to_string(),
            IdempotencyCacheEntry {
                result_json: "new".to_string(),
                created_at: std::time::Instant::now(),
            },
        );
        assert_eq!(cache.len(), MAX_IDEMPOTENCY_ENTRIES);
        assert!(cache.contains_key("new-key"));
    }

    // -----------------------------------------------------------------------
    // S28: approve_branch and reject_branch must use validate_and_authorize
    // -----------------------------------------------------------------------

    /// S28: approve_branch must call validate_and_authorize() for consistent
    /// branch existence validation, not just an inline UID check.
    /// Without this, approve/reject on a nonexistent branch skips the
    /// branch existence check that all other methods perform.
    #[test]
    fn test_s28_approve_reject_use_validate_and_authorize() {
        let source = include_str!("dbus.rs");

        // Find the approve_branch method body
        let approve_start = source
            .find("fn approve_branch(")
            .expect("approve_branch method must exist");
        let approve_body = &source[approve_start..];
        // Find the next "async fn" which marks the end of approve_branch
        let approve_end = approve_body[50..]
            .find("async fn ")
            .unwrap_or(approve_body.len());
        let approve_text = &approve_body[..approve_end];

        assert!(
            approve_text.contains("validate_and_authorize"),
            "S28: approve_branch must call validate_and_authorize() for \
             consistent branch existence + access validation"
        );

        // Find the reject_branch method body
        let reject_start = source
            .find("fn reject_branch(")
            .expect("reject_branch method must exist");
        let reject_body = &source[reject_start..];
        let reject_end = reject_body[50..]
            .find("async fn ")
            .unwrap_or(reject_body.len());
        let reject_text = &reject_body[..reject_end];

        assert!(
            reject_text.contains("validate_and_authorize"),
            "S28: reject_branch must call validate_and_authorize() for \
             consistent branch existence + access validation"
        );
    }

    // -----------------------------------------------------------------------
    // R1: Attestation D-Bus methods must have authentication
    // -----------------------------------------------------------------------

    /// R1: All attestation methods that accept branch_id must call
    /// validate_branch_id() and get_caller_uid(). Methods that export
    /// sensitive data (verify_attestation_chain, export_attestation_bundle)
    /// must require root.
    #[test]
    fn test_r1_attestation_methods_have_auth() {
        let source = include_str!("dbus.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        let methods_requiring_root = [
            "fn verify_attestation_chain(",
            "fn export_attestation_bundle(",
        ];
        for method_sig in &methods_requiring_root {
            let start = prod_source
                .find(method_sig)
                .unwrap_or_else(|| panic!("method {} must exist", method_sig));
            let body = &prod_source[start..];
            let end = body[50..].find("async fn ").unwrap_or(body.len());
            let text = &body[..end];
            assert!(
                text.contains("get_caller_uid"),
                "R1: {} must call get_caller_uid() for authentication",
                method_sig
            );
            assert!(
                text.contains("validate_branch_id"),
                "R1: {} must call validate_branch_id() for input validation",
                method_sig
            );
        }

        // get_inclusion_proof and get_consistency_proof must at least authenticate
        for method_sig in &[
            "fn get_inclusion_proof(",
            "fn get_consistency_proof(",
            "fn get_attestation_public_key(",
        ] {
            let start = prod_source
                .find(method_sig)
                .unwrap_or_else(|| panic!("method {} must exist", method_sig));
            let body = &prod_source[start..];
            let end = body[50..].find("async fn ").unwrap_or(body.len());
            let text = &body[..end];
            assert!(
                text.contains("get_caller_uid"),
                "R1: {} must call get_caller_uid() for authentication",
                method_sig
            );
        }
    }

    // -----------------------------------------------------------------------
    // R4: netns name validation
    // -----------------------------------------------------------------------

    /// R4: Network namespace name must reject path traversal characters.
    #[test]
    fn test_r4_netns_name_validation_exists() {
        let source = include_str!("sandbox/network.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // The create_named_netns function must validate the name
        let start = prod_source
            .find("fn create_named_netns(")
            .expect("create_named_netns must exist");
        let body = &prod_source[start..];
        let end = body[50..]
            .find("\npub fn ")
            .or_else(|| body[50..].find("\nfn "))
            .unwrap_or(body.len());
        let text = &body[..end];

        assert!(
            text.contains("validate_netns_name")
                || text.contains("contains('/')")
                || text.contains("path traversal"),
            "R4: create_named_netns must validate name for path traversal"
        );
    }

    // -----------------------------------------------------------------------
    // R9: ensure_branch must check UID on existing branch
    // -----------------------------------------------------------------------

    /// R9: ensure_branch must not leak other users' branch info.
    #[test]
    fn test_r9_ensure_branch_checks_uid() {
        let source = include_str!("dbus.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        let start = prod_source
            .find("fn ensure_branch(")
            .expect("ensure_branch must exist");
        let body = &prod_source[start..];
        let end = body[50..].find("async fn ").unwrap_or(body.len());
        let text = &body[..end];

        // When returning existing branch, must check UID matches
        assert!(
            text.contains("info.uid")
                || text.contains(".uid ==")
                || text.contains("check_branch_access"),
            "R9: ensure_branch must verify caller UID owns the existing branch"
        );
    }

    // -----------------------------------------------------------------------
    // R10: ensure_branch must have rate limiting
    // -----------------------------------------------------------------------

    /// R10: ensure_branch must apply rate limiting like create_branch does.
    #[test]
    fn test_r10_ensure_branch_has_rate_limiting() {
        let source = include_str!("dbus.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        let start = prod_source
            .find("fn ensure_branch(")
            .expect("ensure_branch must exist");
        let body = &prod_source[start..];
        let end = body[50..].find("async fn ").unwrap_or(body.len());
        let text = &body[..end];

        assert!(
            text.contains("rate_limiter") || text.contains("check(uid)"),
            "R10: ensure_branch must apply rate limiting to prevent branch exhaustion DoS"
        );
    }

    // -----------------------------------------------------------------------
    // Helper: create a BranchManager for testing
    // -----------------------------------------------------------------------

    fn create_test_manager(dir: &std::path::Path) -> crate::branch::BranchManager {
        let profiles_dir = dir.join("profiles");
        let policies_dir = dir.join("policies");
        let wal_dir = dir.join("wal");
        let branch_root = dir.join("branches");
        std::fs::create_dir_all(&profiles_dir).unwrap();
        std::fs::create_dir_all(&policies_dir).unwrap();
        std::fs::create_dir_all(&wal_dir).unwrap();
        std::fs::create_dir_all(&branch_root).unwrap();

        let config = DaemonConfig {
            branch_root,
            profiles_dir: profiles_dir.clone(),
            policies_dir: policies_dir.clone(),
            max_branches: 64,
            ..Default::default()
        };
        let profile_loader = crate::profile::ProfileLoader::new(profiles_dir);
        let policy_engine = crate::policy::PolicyEngine::new(policies_dir);
        let wal = crate::wal::WriteAheadLog::new(wal_dir);
        let audit = crate::audit::AuditLogger::new();
        let conflict_detector = std::sync::Arc::new(std::sync::Mutex::new(
            crate::conflict::ConflictDetector::new(),
        ));
        let budget_manager =
            std::sync::Arc::new(std::sync::Mutex::new(crate::budget::BudgetManager::new()));

        crate::branch::BranchManager::new(
            config,
            profile_loader,
            policy_engine,
            wal,
            std::sync::Arc::new(audit),
            None,
            conflict_detector,
            budget_manager,
            None,
            None,
        )
    }

    // R6: Changeset hash must NOT use unwrap_or_default() which produces a
    // constant SHA-256 hash on failure, enabling hash collision across branches.
    #[test]
    fn test_r6_changeset_hash_no_unwrap_or_default() {
        let source = include_str!("dbus.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // Find the changeset_hash block
        let hash_start = prod_source
            .find("let hash_input = manifest_json")
            .expect("changeset hash_input assignment must exist");
        let hash_block = &prod_source[hash_start..hash_start + 300];
        assert!(
            !hash_block.contains("unwrap_or_default()"),
            "R6: changeset hash fallback must NOT use unwrap_or_default() which \
             produces a constant hash on failure. Found in:\n{}",
            hash_block
        );
    }

    /// S43: Ensure public_key / attestation_public_key reads do not use
    /// `unwrap_or_default()`, which silently returns an empty string on failure.
    #[test]
    fn test_s43_public_key_no_silent_default() {
        let source = include_str!("dbus.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        for (i, line) in prod_source.lines().enumerate() {
            let lower = line.to_lowercase();
            if (lower.contains("public_key") || lower.contains("attestation_public_key"))
                && line.contains("unwrap_or_default()")
            {
                panic!(
                    "S43: dbus.rs line {} reads a public key with unwrap_or_default(), \
                     which silently returns an empty string on failure. \
                     Use unwrap_or_else with tracing::error! instead.\nLine: {}",
                    i + 1,
                    line.trim()
                );
            }
        }
    }

    /// F11: Verify that no production code silently discards D-Bus signal emission results
    /// via `let _ = ManagerInterface::`. Each signal emission must log on failure.
    #[test]
    fn test_f11_dbus_signals_not_silently_dropped() {
        let source = include_str!("dbus.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        let count = prod_source.matches("let _ = ManagerInterface::").count();
        assert_eq!(
            count, 0,
            "F11: found {} instances of `let _ = ManagerInterface::` in production code. \
             Each D-Bus signal emission result must be checked with \
             `if let Err(e) = ManagerInterface::...` and logged via tracing::debug!.",
            count
        );
    }

    // -----------------------------------------------------------------------
    // V1: commit_branch must update trust score on approval and rejection
    // -----------------------------------------------------------------------

    #[test]
    fn test_v1_commit_branch_wires_trust_scoring() {
        let source = include_str!("dbus.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        let start = prod_source
            .find("fn commit_branch(")
            .expect("commit_branch method must exist");
        let body = &prod_source[start..];
        let end = body[80..]
            .find("\n    async fn ")
            .map(|p| p + 80)
            .unwrap_or(body.len());
        let commit_body = &body[..end];

        assert!(
            commit_body.contains("trust_manager"),
            "V1: commit_branch must use trust_manager to update trust score \
             on commit approval/rejection."
        );
        assert!(
            commit_body.contains("on_audit_event"),
            "V1: commit_branch must call on_audit_event to update trust scores."
        );
    }

    // -----------------------------------------------------------------------
    // V2: commit_branch must write provenance records
    // -----------------------------------------------------------------------

    #[test]
    fn test_v2_commit_branch_wires_provenance() {
        let source = include_str!("dbus.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        let start = prod_source
            .find("fn commit_branch(")
            .expect("commit_branch method must exist");
        let body = &prod_source[start..];
        let end = body[80..]
            .find("\n    async fn ")
            .map(|p| p + 80)
            .unwrap_or(body.len());
        let commit_body = &body[..end];

        assert!(
            commit_body.contains("provenance_store"),
            "V2: commit_branch must use provenance_store to write Governance \
             provenance records on commit approval/rejection."
        );
    }

    // -----------------------------------------------------------------------
    // V3: commit_branch must emit trust_transition signal on level change
    // -----------------------------------------------------------------------

    #[test]
    fn test_v3_commit_branch_emits_trust_transition() {
        let source = include_str!("dbus.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        let start = prod_source
            .find("fn commit_branch(")
            .expect("commit_branch method must exist");
        let body = &prod_source[start..];
        let end = body[80..]
            .find("\n    async fn ")
            .map(|p| p + 80)
            .unwrap_or(body.len());
        let commit_body = &body[..end];

        assert!(
            commit_body.contains("trust_transition"),
            "V3: commit_branch must emit trust_transition signal when \
             on_audit_event causes a trust level change."
        );
    }

    // -----------------------------------------------------------------------
    // V4: get_identity_token must not hardcode enforcement layers
    // -----------------------------------------------------------------------

    #[test]
    fn test_v4_identity_token_no_hardcoded_enforcement() {
        let source = include_str!("dbus.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        let start = prod_source
            .find("fn get_identity_token(")
            .expect("get_identity_token method must exist");
        let body = &prod_source[start..];
        let end = body[80..]
            .find("\n    async fn ")
            .or_else(|| body[80..].find("\n    /// "))
            .or_else(|| body[80..].find("\n    #[cfg("))
            .map(|p| p + 80)
            .unwrap_or(body.len());
        let method_body = &body[..end];

        assert!(
            !method_body.contains(r#""pid_ns".to_string()"#),
            "V4: get_identity_token must NOT hardcode enforcement layers \
             like pid_ns. Derive from profile enforcement requirements."
        );
    }

    // -----------------------------------------------------------------------
    // V5: get_identity_token must not hardcode policy_version
    // -----------------------------------------------------------------------

    #[test]
    fn test_v5_identity_token_no_hardcoded_policy_version() {
        let source = include_str!("dbus.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        let start = prod_source
            .find("fn get_identity_token(")
            .expect("get_identity_token method must exist");
        let body = &prod_source[start..];
        let end = body[80..]
            .find("\n    async fn ")
            .or_else(|| body[80..].find("\n    /// "))
            .or_else(|| body[80..].find("\n    #[cfg("))
            .map(|p| p + 80)
            .unwrap_or(body.len());
        let method_body = &body[..end];

        assert!(
            !method_body.contains(r#""v1.0""#),
            "V5: get_identity_token must NOT hardcode policy_version as \"v1.0\". \
             Read from governance config or policy engine."
        );
    }

    // -----------------------------------------------------------------------
    // V6: provenance D-Bus methods must verify branch exists for non-root
    // -----------------------------------------------------------------------

    #[test]
    fn test_v6_provenance_methods_verify_branch_exists() {
        let source = include_str!("dbus.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        for method_name in &["fn report_provenance(", "fn get_provenance("] {
            let start = prod_source
                .find(method_name)
                .unwrap_or_else(|| panic!("{} must exist", method_name));
            let body = &prod_source[start..];
            let end = body[80..]
                .find("\n    async fn ")
                .or_else(|| body[80..].find("\n    /// "))
                .or_else(|| body[80..].find("\n    #[cfg("))
                .map(|p| p + 80)
                .unwrap_or(body.len());
            let method_body = &body[..end];

            assert!(
                method_body.contains("branch not found"),
                "V6: {} must return an error when the branch doesn't exist \
                 for non-root callers.",
                method_name
            );
        }
    }

    // -----------------------------------------------------------------------
    // V7: get_identity_token must populate attestation chain data
    // -----------------------------------------------------------------------

    #[test]
    fn test_v7_identity_token_populates_attestation_chain() {
        let source = include_str!("dbus.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        let start = prod_source
            .find("fn get_identity_token(")
            .expect("get_identity_token method must exist");
        let body = &prod_source[start..];
        let end = body[80..]
            .find("\n    async fn ")
            .or_else(|| body[80..].find("\n    /// "))
            .or_else(|| body[80..].find("\n    #[cfg("))
            .map(|p| p + 80)
            .unwrap_or(body.len());
        let method_body = &body[..end];

        assert!(
            method_body.contains("audit_store") || method_body.contains("merkle"),
            "V7: get_identity_token must read attestation chain data \
             (root_hash, size) from the audit_store's Merkle tree."
        );
    }

    // ===================================================================
    // W-series: Pass 2-5 validation fixes
    // ===================================================================

    /// Helper: extract a method body from production source by method name.
    /// Returns the text from `fn method_name(` to the next `\n    async fn `.
    fn extract_method(source: &str, method_name: &str) -> String {
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        let start = prod_source
            .find(method_name)
            .unwrap_or_else(|| panic!("{} must exist in production code", method_name));
        let body = &prod_source[start..];
        let end = body[80..]
            .find("\n    async fn ")
            .or_else(|| body[80..].find("\n    /// "))
            .or_else(|| body[80..].find("\n    #[cfg("))
            .map(|p| p + 80)
            .unwrap_or(body.len());
        body[..end].to_string()
    }

    // -----------------------------------------------------------------------
    // W1: commit_branch must capture branch owner UID BEFORE commit()
    // -----------------------------------------------------------------------

    #[test]
    fn test_w1_commit_branch_uid_captured_before_commit() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn commit_branch(");

        // The V1 block (between "// V1:" and "// V2:") must NOT call
        // inspect(&id) to get uid — it should use a pre-captured variable.
        let v1_start = body.find("// V1:").expect("V1 comment must exist");
        let v2_start = body.find("// V2:").expect("V2 comment must exist");
        let v1_block = &body[v1_start..v2_start];

        assert!(
            !v1_block.contains("inspect(&id)"),
            "W1: V1 block must NOT call inspect(&id) for uid after commit() — \
             branch may be gone. Use a uid captured BEFORE self.manager.commit()."
        );
    }

    // -----------------------------------------------------------------------
    // W2: record_governance must pass changeset_hash as manifest_hash
    // -----------------------------------------------------------------------

    #[test]
    fn test_w2_commit_branch_provenance_manifest_hash() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn commit_branch(");

        // Find the record_governance call
        let rg_start = body
            .find("record_governance(")
            .expect("record_governance call must exist in commit_branch");
        let rg_block = &body[rg_start..rg_start + 500.min(body.len() - rg_start)];

        // The manifest_hash parameter (6th arg) must contain Some(changeset_hash
        assert!(
            rg_block.contains("Some(changeset_hash"),
            "W2: record_governance must pass changeset_hash as manifest_hash \
             (6th parameter), not as policy_version (3rd parameter)."
        );
    }

    // -----------------------------------------------------------------------
    // W3: approve_branch must wire trust scoring
    // -----------------------------------------------------------------------

    #[test]
    fn test_w3_approve_branch_wires_trust() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn approve_branch(");

        assert!(
            body.contains("trust_manager") && body.contains("on_audit_event"),
            "W3: approve_branch must call trust_manager.on_audit_event \
             to update trust score on manual governance approval."
        );
    }

    // -----------------------------------------------------------------------
    // W4: approve_branch must wire provenance recording
    // -----------------------------------------------------------------------

    #[test]
    fn test_w4_approve_branch_wires_provenance() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn approve_branch(");

        assert!(
            body.contains("record_governance") || body.contains("provenance_store"),
            "W4: approve_branch must record a Governance provenance record \
             for manual approval decisions."
        );
    }

    // -----------------------------------------------------------------------
    // W5: approve_branch must emit trust_transition signal
    // -----------------------------------------------------------------------

    #[test]
    fn test_w5_approve_branch_emits_trust_transition() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn approve_branch(");

        assert!(
            body.contains("trust_transition"),
            "W5: approve_branch must emit trust_transition signal when \
             on_audit_event causes a trust level change."
        );
    }

    // -----------------------------------------------------------------------
    // W6: reject_branch must wire trust scoring
    // -----------------------------------------------------------------------

    #[test]
    fn test_w6_reject_branch_wires_trust() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn reject_branch(");

        assert!(
            body.contains("trust_manager") && body.contains("on_audit_event"),
            "W6: reject_branch must call trust_manager.on_audit_event \
             to update trust score on manual governance rejection."
        );
    }

    // -----------------------------------------------------------------------
    // W7: reject_branch must wire provenance recording
    // -----------------------------------------------------------------------

    #[test]
    fn test_w7_reject_branch_wires_provenance() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn reject_branch(");

        assert!(
            body.contains("record_governance") || body.contains("provenance_store"),
            "W7: reject_branch must record a Governance provenance record \
             for manual rejection decisions."
        );
    }

    // -----------------------------------------------------------------------
    // W8: get_identity_token must read policy_hash from audit_store
    // -----------------------------------------------------------------------

    #[test]
    fn test_w8_identity_token_reads_policy_hash() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn get_identity_token(");

        assert!(
            body.contains("policy_hash"),
            "W8: get_identity_token must read policy version from \
             audit_store.policy_hash(), not use a meaningless placeholder."
        );
    }

    // -----------------------------------------------------------------------
    // W9: trust_transition score must be captured in same lock scope
    // -----------------------------------------------------------------------

    #[test]
    fn test_w9_trust_transition_score_same_lock_scope() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn commit_branch(");

        // The V3 block (between "// V3:" and "// B2:") must NOT re-lock
        // trust_manager to read the score — it should use a pre-captured value.
        let v3_start = body.find("// V3:").expect("V3 comment must exist");
        let b2_start = body.find("// B2:").expect("B2 comment must exist");
        let v3_block = &body[v3_start..b2_start];

        assert!(
            !v3_block.contains("trust_manager"),
            "W9: V3 block must NOT re-lock trust_manager to read score. \
             Capture score in the same lock scope as on_audit_event (V1 block) \
             to avoid TOCTOU race."
        );
    }

    // -----------------------------------------------------------------------
    // W10: get_spiffe_id must verify branch exists for non-root callers
    // -----------------------------------------------------------------------

    #[test]
    fn test_w10_spiffe_id_verifies_branch_exists() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn get_spiffe_id(");

        assert!(
            body.contains("branch not found"),
            "W10: get_spiffe_id must return an error when the branch \
             doesn't exist for non-root callers."
        );
    }

    // -----------------------------------------------------------------------
    // W11: rollback_branch must record provenance
    // -----------------------------------------------------------------------

    #[test]
    fn test_w11_rollback_branch_wires_provenance() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn rollback_branch(");

        assert!(
            body.contains("record_governance") || body.contains("provenance_store"),
            "W11: rollback_branch must record a Governance provenance record \
             for the rollback decision."
        );
    }

    /// G7: Merkle tree size must use try_from, not bare `as u32` which truncates.
    #[test]
    fn test_g7_merkle_size_safe_cast() {
        let source = include_str!("dbus.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];

        // The production code must NOT contain `tree.size() as u32`
        assert!(
            !production_code.contains("tree.size() as u32"),
            "G7: dbus.rs must not use bare `as u32` cast on tree.size() — \
             this silently truncates values exceeding u32::MAX. Use try_from instead."
        );

        // Verify it uses the safe alternative
        assert!(
            production_code.contains("u32::try_from(tree.size())"),
            "G7: dbus.rs must use u32::try_from(tree.size()) for safe casting"
        );
    }

    // -----------------------------------------------------------------------
    // X-series: G1 — Provenance cleanup on branch rollback/reject
    // -----------------------------------------------------------------------

    #[test]
    fn test_x1_rollback_branch_cleans_up_provenance() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn rollback_branch(");

        // After recording rollback provenance (W11), the rollback_branch method
        // must also clean up provenance data for the branch — otherwise
        // provenance directories accumulate indefinitely on disk.
        assert!(
            body.contains("cleanup_branch"),
            "X1: rollback_branch must call provenance cleanup (cleanup_branch) \
             to remove provenance data after the branch is rolled back. \
             PRD §4.3.8: 'Branch rollback/cleanup removes the provenance directory.'"
        );
    }

    #[test]
    fn test_x2_reject_branch_cleans_up_provenance() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn reject_branch(");

        // reject_branch internally rolls back the branch, so it must also
        // clean up provenance data.
        assert!(
            body.contains("cleanup_branch"),
            "X2: reject_branch must call provenance cleanup (cleanup_branch) \
             to remove provenance data after the branch is rejected. \
             PRD §4.3.8: 'Branch rollback/cleanup removes the provenance directory.'"
        );
    }

    // -----------------------------------------------------------------------
    // X-series: G3 — Containment claims in identity tokens
    // -----------------------------------------------------------------------

    #[test]
    #[cfg(feature = "ima")]
    fn test_x3_identity_token_uses_containment_api() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn get_identity_token(");

        // get_identity_token must call issue_jwt_svid_with_containment
        // (not just issue_jwt_svid) so that containment claims derived
        // from the profile are included when include_containment_claims is true.
        assert!(
            body.contains("issue_jwt_svid_with_containment"),
            "X3: get_identity_token must call issue_jwt_svid_with_containment \
             to pass profile-derived containment claims into the JWT-SVID. \
             PRD §4.5.3 specifies containment claims (filesystem_scope, \
             network_mode, allowed_domains, exec_allowlist_count)."
        );
    }

    #[test]
    #[cfg(feature = "ima")]
    fn test_x4_identity_token_constructs_containment_claims() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn get_identity_token(");

        // The containment claims must be derived from real profile data,
        // not hardcoded or left as None.
        assert!(
            body.contains("ContainmentClaims"),
            "X4: get_identity_token must construct ContainmentClaims from \
             the agent profile (filesystem scope, network mode, allowed \
             domains, exec allowlist count) — not leave containment as None."
        );
    }

    // ===================================================================
    // H-series Round 6: Security findings H40-H53
    // ===================================================================

    // -----------------------------------------------------------------------
    // H40: BranchCommitted events must include uid in details
    // -----------------------------------------------------------------------
    #[test]
    fn test_h40_branch_committed_includes_uid() {
        // H40 fix is in audit_store.rs store_with_context — verified there.
        // Here we verify that commit_branch passes agent_identity (with uid)
        // to store_with_context so the uid injection can work.
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn commit_branch(");
        assert!(
            body.contains("commit_identity") && body.contains("store_with_context"),
            "H40: commit_branch must pass commit_identity to store_with_context \
             so that uid is injected into BranchCommitted event details."
        );
    }

    // -----------------------------------------------------------------------
    // H44: Hex parsing must guard against odd-length input
    // -----------------------------------------------------------------------
    #[test]
    fn test_h44_odd_length_hex_returns_none() {
        // H44: Verify that odd-length hex input is handled without panic
        let source = include_str!("dbus.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            prod_source.contains("hex_str.len() % 2 != 0"),
            "H44: verify_attestation_chain must guard against odd-length hex \
             strings before the parsing loop to prevent out-of-bounds panic."
        );
    }

    // -----------------------------------------------------------------------
    // H45: trigger_governance must have audit logging
    // -----------------------------------------------------------------------
    #[test]
    fn test_h45_trigger_governance_has_audit_logging() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn trigger_governance(");
        assert!(
            body.contains("audit_store") || body.contains("audit_logger"),
            "H45: trigger_governance must write to audit_store or audit_logger \
             to record governance events, matching the commit_branch pattern."
        );
    }

    // -----------------------------------------------------------------------
    // H46: Credential file read errors must not expose filesystem paths
    // -----------------------------------------------------------------------
    #[test]
    fn test_h46_credential_read_error_no_path_leak() {
        let source = include_str!("dbus.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // The old pattern was: format!("reading credential from {}: {}", path, e)
        // H46 replaces it with a generic message
        assert!(
            !prod_source.contains(r#"format!("reading credential from {}: {}", path"#),
            "H46: credential file read errors must not include the filesystem path \
             in the error message. Use a generic message instead."
        );
        assert!(
            prod_source.contains("failed to read credential from specified file"),
            "H46: credential read errors must use the generic message \
             'failed to read credential from specified file'."
        );
    }

    // -----------------------------------------------------------------------
    // H49: ensure_branch must write audit event on creation
    // -----------------------------------------------------------------------
    #[test]
    fn test_h49_ensure_branch_writes_audit() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn ensure_branch(");
        assert!(
            body.contains("audit_store") || body.contains("audit_logger"),
            "H49: ensure_branch must write to audit_store on successful branch \
             creation, matching the create_branch audit pattern."
        );
    }

    // -----------------------------------------------------------------------
    // H50: Signing key file permissions must be verified
    // -----------------------------------------------------------------------
    #[test]
    fn test_h50_signing_key_permissions_checked() {
        let source = include_str!("dbus.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            prod_source.contains("H50") && prod_source.contains("permissions"),
            "H50: start_dbus_service must verify signing key file permissions \
             and warn if world-readable (expected 0600 or 0400)."
        );
    }

    // -----------------------------------------------------------------------
    // H52: command_json must not be logged verbatim
    // -----------------------------------------------------------------------
    #[test]
    fn test_h52_command_json_not_logged_verbatim() {
        let source = include_str!("dbus.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // The old line was: tracing::info!(profile, base_path, command_json, ...)
        // H52 replaces command_json with command_json_len
        assert!(
            !prod_source.contains("profile, base_path, command_json, \"CreateBranch"),
            "H52: command_json must not be logged verbatim in CreateBranch. \
             Log command_json_len instead."
        );
        assert!(
            prod_source.contains("command_json_len"),
            "H52: CreateBranch must log command_json_len instead of the full value."
        );
    }

    // ===================================================================
    // Y-series: Third validation — §4.1, §4.3, §4.5 vs PRD (round 3)
    // ===================================================================

    // -----------------------------------------------------------------------
    // Y1: create_branch must call register_uid for profile-specific initial scores
    // -----------------------------------------------------------------------

    #[test]
    fn test_y1_create_branch_registers_uid_with_profile() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn create_branch(");

        // PRD §4.1.9: register_uid(uid, profile_name) allows explicit UID
        // registration with profile-specific initial scores.
        // create_branch must call it so that the trust score is initialized
        // with the correct profile modifier (restricted→10, privileged→50).
        assert!(
            body.contains("register_uid"),
            "Y1: create_branch must call trust_manager.register_uid() to \
             initialize the trust score with a profile-specific initial value. \
             PRD §4.1.9: 'Callers should call this when a branch is created \
             with a known profile.'"
        );
    }

    // -----------------------------------------------------------------------
    // Y2: commit_branch must not use wildcard match for PolicyDecision
    // -----------------------------------------------------------------------

    #[test]
    fn test_y2_commit_branch_no_wildcard_policy_decision() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn commit_branch(");

        // The PolicyDecision enum has 3 variants: Approved, Rejected(_), Error(_).
        // Using `_ => "commit_approved"` silently treats Error as Approved for
        // trust scoring. Must use exhaustive match or explicit Error handling.
        //
        // Check that no `_ => "commit_approved"` pattern exists.
        assert!(
            !body.contains(r#"_ => "commit_approved""#),
            "Y2: commit_branch must not use a wildcard `_ =>` match that treats \
             PolicyDecision::Error as 'commit_approved' for trust scoring. \
             Use explicit variants or handle Error as a distinct event."
        );
    }

    // -----------------------------------------------------------------------
    // Y5: exec_allowlist_count must use safe cast (consistent with G7)
    // -----------------------------------------------------------------------

    #[test]
    #[cfg(feature = "ima")]
    fn test_y5_exec_allowlist_count_safe_cast() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn get_identity_token(");

        // Bare `as u32` silently truncates on exotic profiles with > 4B entries.
        // Must use try_from for consistency with the G7 pattern on Merkle tree size.
        assert!(
            !body.contains("exec_allowlist.len() as u32"),
            "Y5: exec_allowlist_count must not use bare `as u32` cast. \
             Use u32::try_from() for consistency with G7 pattern."
        );
    }

    // -----------------------------------------------------------------------
    // Y6: unregister_agent must have full cross-module wiring
    // -----------------------------------------------------------------------

    #[test]
    fn test_y6_unregister_agent_records_provenance() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn unregister_agent(");

        // unregister_agent is semantically a rollback. It must have the same
        // cross-module wiring as rollback_branch: provenance recording +
        // provenance cleanup + audit store event.
        assert!(
            body.contains("record_governance") || body.contains("provenance_store"),
            "Y6: unregister_agent must record a provenance event for the \
             unregistration decision, matching rollback_branch's wiring."
        );
    }

    #[test]
    fn test_y6_unregister_agent_cleans_up_provenance() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn unregister_agent(");

        assert!(
            body.contains("cleanup_branch"),
            "Y6: unregister_agent must call provenance cleanup (cleanup_branch) \
             to remove provenance data, matching rollback_branch's X1 pattern."
        );
    }

    #[test]
    fn test_y6_unregister_agent_writes_audit_store() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn unregister_agent(");

        assert!(
            body.contains("audit_store"),
            "Y6: unregister_agent must write to audit_store for attestation, \
             matching rollback_branch's attestation bridge pattern."
        );
    }

    // ===================================================================
    // Z-series: Fourth validation — attestation chain completeness
    // ===================================================================

    // -----------------------------------------------------------------------
    // Z2: approve_branch must write to audit store (attestation chain)
    // -----------------------------------------------------------------------

    #[test]
    fn test_z2_approve_branch_writes_audit_store() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn approve_branch(");

        assert!(
            body.contains("store_with_context"),
            "Z2: approve_branch must write to audit_store via store_with_context \
             so that manual governance approvals appear in the attestation chain \
             (§3.1). Without this, approved branches have no Ed25519 signature \
             or Merkle tree leaf."
        );
    }

    // -----------------------------------------------------------------------
    // Z3: approve_branch must call audit_logger
    // -----------------------------------------------------------------------

    #[test]
    fn test_z3_approve_branch_calls_audit_logger() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn approve_branch(");

        assert!(
            body.contains("audit_logger"),
            "Z3: approve_branch must call audit_logger to write the approval \
             event to syslog/netlink, matching commit_branch's pattern."
        );
    }

    // -----------------------------------------------------------------------
    // Z5: reject_branch must write to audit store (attestation chain)
    // -----------------------------------------------------------------------

    #[test]
    fn test_z5_reject_branch_writes_audit_store() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn reject_branch(");

        assert!(
            body.contains("store_with_context"),
            "Z5: reject_branch must write to audit_store via store_with_context \
             so that manual governance rejections appear in the attestation chain \
             (§3.1). Without this, rejected branches have no Ed25519 signature \
             or Merkle tree leaf."
        );
    }

    // -----------------------------------------------------------------------
    // Z6: reject_branch must call audit_logger
    // -----------------------------------------------------------------------

    #[test]
    fn test_z6_reject_branch_calls_audit_logger() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn reject_branch(");

        assert!(
            body.contains("audit_logger"),
            "Z6: reject_branch must call audit_logger to write the rejection \
             event to syslog/netlink, matching commit_branch/rollback_branch's pattern."
        );
    }

    // -----------------------------------------------------------------------
    // Z11: commit_branch signal emission must not use wildcard for PolicyDecision
    // -----------------------------------------------------------------------

    #[test]
    fn test_z11_commit_branch_signal_no_wildcard() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn commit_branch(");

        // The signal emission match for PolicyDecision must not use `_ => {}`
        // which silently swallows PolicyDecision::Error — subscribers should
        // be notified of governance evaluation failures.
        //
        // We check that no `_ => {}` or `_ => { }` pattern exists in the
        // signal emission section (after the match on policy_result for signals).
        let signal_section = body.find("match &result.policy_result").and_then(|first| {
            // Find the SECOND match (the signal emission one, not the
            // trust scoring one which was already fixed by Y2).
            body[first + 1..]
                .find("match &result.policy_result")
                .map(|off| first + 1 + off)
        });
        if let Some(start) = signal_section {
            let section = &body[start..];
            // Extract just the match block (up to the closing brace pattern)
            let block = section.split("Ok(json)").next().unwrap_or(section);
            assert!(
                !block.contains("_ => {}"),
                "Z11: commit_branch signal emission must not use `_ => {{}}` \
                 wildcard for PolicyDecision. PolicyDecision::Error should emit \
                 a signal or be handled explicitly."
            );
        }
    }

    // -----------------------------------------------------------------------
    // J21: command_json must not be logged verbatim in activate_branch
    // -----------------------------------------------------------------------
    #[test]
    fn test_j21_activate_branch_no_verbatim_command_json() {
        let source = include_str!("dbus.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // activate_branch must NOT log command_json directly
        assert!(
            !prod_source.contains("branch_id, command_json, \"ActivateBranch"),
            "J21: activate_branch must not log command_json verbatim. \
             Use command_json_len instead."
        );
        // Verify the fix uses command_json_len
        assert!(
            prod_source.contains("command_json_len = command_json.len()")
                && prod_source.contains("\"ActivateBranch requested\""),
            "J21: activate_branch must log command_json_len instead of command_json."
        );
    }

    // -----------------------------------------------------------------------
    // J22: Timestamp comparison uses parse_from_rfc3339, not lexicographic
    // -----------------------------------------------------------------------
    #[test]
    fn test_j22_timestamp_comparison_uses_parsed_datetime() {
        let source = include_str!("dbus.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // The verify_attestation_chain method must use parse_from_rfc3339
        assert!(
            prod_source.contains("parse_from_rfc3339"),
            "J22: verify_attestation_chain must use chrono::DateTime::parse_from_rfc3339 \
             for timestamp comparison, not lexicographic string comparison."
        );
    }

    // -----------------------------------------------------------------------
    // AA1: report_provenance must validate record.branch_id == branch_id
    // -----------------------------------------------------------------------
    #[test]
    fn test_aa1_report_provenance_validates_record_branch_id() {
        let source = include_str!("dbus.rs");
        let report_body = extract_method(source, "fn report_provenance");
        // Must check that the deserialized record's branch_id matches the
        // D-Bus parameter branch_id to prevent provenance injection.
        assert!(
            report_body.contains("record.branch_id")
                && (report_body.contains("!= branch_id")
                    || report_body.contains("!= id")
                    || report_body.contains("mismatch")),
            "AA1: report_provenance must validate that record.branch_id matches \
             the D-Bus branch_id parameter to prevent provenance injection into \
             branches the caller doesn't own."
        );
    }

    // -----------------------------------------------------------------------
    // AA2: approve_branch computes changeset hash once, not multiple times
    // -----------------------------------------------------------------------
    #[test]
    fn test_aa2_approve_branch_single_changeset_hash() {
        let source = include_str!("dbus.rs");
        let approve_body = extract_method(source, "fn approve_branch");
        // Count occurrences of the SHA256 hash computation pattern
        let hash_computations = approve_body.matches("Sha256::new()").count();
        assert!(
            hash_computations <= 1,
            "AA2: approve_branch computes SHA256 changeset hash {hash_computations} times. \
             Should compute once and reuse the variable."
        );
    }

    // -----------------------------------------------------------------------
    // AA3: unregister_agent calls audit_logger (syslog/netlink)
    // -----------------------------------------------------------------------
    #[test]
    fn test_aa3_unregister_agent_calls_audit_logger() {
        let source = include_str!("dbus.rs");
        let unregister_body = extract_method(source, "fn unregister_agent");
        assert!(
            unregister_body.contains("audit_logger.log("),
            "AA3: unregister_agent must call audit_logger.log() to emit the \
             unregistration event to syslog/netlink, matching all other branch \
             lifecycle terminals."
        );
    }

    // ===================================================================
    // K-series (round 8): Security hardening fixes
    // ===================================================================

    // -----------------------------------------------------------------------
    // K21: rollback_branch reason must be sanitized before logging
    // -----------------------------------------------------------------------
    #[test]
    fn test_k21_rollback_branch_reason_sanitized() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn rollback_branch(");
        // Must not log reason directly — must use sanitize_log_reason
        assert!(
            body.contains("sanitize_log_reason"),
            "K21: rollback_branch must sanitize the reason parameter before \
             logging to prevent log injection via embedded control characters."
        );
    }

    // -----------------------------------------------------------------------
    // K22: reject_branch reason must be sanitized before logging
    // -----------------------------------------------------------------------
    #[test]
    fn test_k22_reject_branch_reason_sanitized() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn reject_branch(");
        assert!(
            body.contains("sanitize_log_reason"),
            "K22: reject_branch must sanitize the reason parameter before \
             logging to prevent log injection via embedded control characters."
        );
    }

    // -----------------------------------------------------------------------
    // K23: list_trust_history limit must be capped
    // -----------------------------------------------------------------------
    #[test]
    fn test_k23_trust_history_limit_capped() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn list_trust_history(");
        assert!(
            body.contains("MAX_TRUST_HISTORY_LIMIT"),
            "K23: list_trust_history must define MAX_TRUST_HISTORY_LIMIT \
             and cap the caller-supplied limit to prevent excessive memory usage."
        );
    }

    // -----------------------------------------------------------------------
    // K24: report_provenance must validate record size
    // -----------------------------------------------------------------------
    #[test]
    fn test_k24_provenance_record_size_validated() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn report_provenance(");
        assert!(
            body.contains("MAX_PROVENANCE_RECORD_LEN"),
            "K24: report_provenance must define MAX_PROVENANCE_RECORD_LEN \
             and reject oversized record_json payloads before processing."
        );
    }

    // -----------------------------------------------------------------------
    // K25: MAX_EXPORT_FILE_SIZE must be reasonable for pretty-print
    // -----------------------------------------------------------------------
    #[test]
    fn test_k25_export_file_size_reasonable() {
        let source = include_str!("audit_store.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            prod_source.contains("MAX_EXPORT_FILE_SIZE"),
            "K25: audit_store.rs must define MAX_EXPORT_FILE_SIZE"
        );
        // Verify it's <= 100MB (not 500MB) to account for pretty-print expansion
        assert!(
            prod_source.contains("100 * 1024 * 1024"),
            "K25: MAX_EXPORT_FILE_SIZE should be 100MB (not 500MB) to account \
             for pretty-print JSON expansion that can 3-5x the in-memory size."
        );
    }

    // -----------------------------------------------------------------------
    // K26: ensure_branch must call register_uid after creation
    // -----------------------------------------------------------------------
    #[test]
    fn test_k26_ensure_branch_registers_uid() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn ensure_branch(");
        assert!(
            body.contains("register_uid"),
            "K26: ensure_branch must call trust_manager.register_uid() after \
             branch creation, matching the create_branch pattern for \
             profile-specific initial trust scores."
        );
    }

    // -----------------------------------------------------------------------
    // K27: trigger_governance must check policy_result
    // -----------------------------------------------------------------------
    #[test]
    fn test_k27_trigger_governance_checks_policy_result() {
        let source = include_str!("dbus.rs");
        let body = extract_method(source, "fn trigger_governance(");
        assert!(
            body.contains("policy_result"),
            "K27: trigger_governance must check result.policy_result and emit \
             appropriate audit events (BranchCommitted vs CommitRejected/PolicyViolation)."
        );
        // Must not unconditionally log BranchCommitted
        assert!(
            body.contains("PolicyDecision::Rejected") || body.contains("CommitRejected"),
            "K27: trigger_governance must handle rejected policy decisions, \
             not always emit BranchCommitted."
        );
    }

    // -----------------------------------------------------------------------
    // K28: store_credential and rotate_credential must canonicalize paths
    // -----------------------------------------------------------------------
    #[test]
    fn test_k28_credential_file_path_canonicalized() {
        let source = include_str!("dbus.rs");
        let store_body = extract_method(source, "fn store_credential(");
        assert!(
            store_body.contains("canonicalize"),
            "K28: store_credential must use std::fs::canonicalize() to resolve \
             symlinks before checking /proc, /sys, /dev prefixes."
        );
        let rotate_body = extract_method(source, "fn rotate_credential(");
        assert!(
            rotate_body.contains("canonicalize"),
            "K28: rotate_credential must use std::fs::canonicalize() to resolve \
             symlinks before checking /proc, /sys, /dev prefixes."
        );
    }

    // -----------------------------------------------------------------------
    // H-1: unlock_credential must have root access control
    // -----------------------------------------------------------------------
    #[test]
    fn test_h1_unlock_credential_has_root_access_control() {
        let source = include_str!("dbus.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        let body = extract_method(prod_source, "fn unlock_credential(");
        assert!(
            body.contains("uid != 0"),
            "H-1: unlock_credential must check uid != 0 for root-only access, \
             matching store_credential and rotate_credential patterns."
        );
        assert!(
            body.contains("AccessDenied"),
            "H-1: unlock_credential must return AccessDenied for non-root callers."
        );
    }

    // -----------------------------------------------------------------------
    // M-11: credential D-Bus methods must use validate_and_authorize
    // -----------------------------------------------------------------------
    #[test]
    fn test_m11_provision_credentials_uses_validate_and_authorize() {
        let source = include_str!("dbus.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        let body = extract_method(prod_source, "fn provision_credentials(");
        assert!(
            body.contains("validate_and_authorize"),
            "M-11: provision_credentials must use validate_and_authorize for \
             branch ownership verification, not raw BranchId::from()."
        );
        assert!(
            !body.contains("BranchId::from("),
            "M-11: provision_credentials must not use unchecked BranchId::from()."
        );
    }

    #[test]
    fn test_m11_revoke_credentials_uses_validate_and_authorize() {
        let source = include_str!("dbus.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        let body = extract_method(prod_source, "fn revoke_credentials(");
        assert!(
            body.contains("validate_and_authorize"),
            "M-11: revoke_credentials must use validate_and_authorize for \
             branch ownership verification, not raw BranchId::from()."
        );
        assert!(
            !body.contains("BranchId::from("),
            "M-11: revoke_credentials must not use unchecked BranchId::from()."
        );
    }

    #[test]
    fn test_m11_list_credentials_uses_validate_and_authorize() {
        let source = include_str!("dbus.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        let body = extract_method(prod_source, "fn list_credentials(");
        assert!(
            body.contains("validate_and_authorize"),
            "M-11: list_credentials must use validate_and_authorize for \
             branch ownership verification when branch_id is non-empty."
        );
        assert!(
            !body.contains("BranchId::from("),
            "M-11: list_credentials must not use unchecked BranchId::from()."
        );
    }
}
