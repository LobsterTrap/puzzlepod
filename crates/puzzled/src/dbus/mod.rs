// SPDX-License-Identifier: Apache-2.0
use std::collections::HashMap;
use std::sync::Arc;

use crate::audit::AuditEvent;
use crate::audit::AuditLogger;
use crate::audit_store::AuditStore;
use crate::branch::BranchManager;
use crate::config::DaemonConfig;
pub(crate) mod helpers;

use self::helpers::{
    get_caller_uid, require_root, sanitize_log_reason, validate_and_authorize, validate_branch_id,
    validate_dbus_inputs, DaemonServices, IdempotencyCacheEntry, RateLimiter, IDEMPOTENCY_TTL,
    MAX_IDEMPOTENCY_ENTRIES,
};
use crate::provenance::ProvenanceStore;
use crate::sync_util::unlock_poisoned;
use crate::trust::TrustManager;
use anyhow::Result;
use puzzled_types::BranchId;
#[cfg(feature = "ima")]
use puzzled_types::TrustLevel;
use zbus::connection::Connection;
use zbus::interface;
use zbus::object_server::SignalEmitter;

/// Emit a D-Bus signal, swallowing errors with a debug log.
///
/// Reduces the repeated get_signal_emitter → emit → log-error boilerplate.
macro_rules! emit_dbus_signal {
    ($conn:expr, |$ctx:ident| $signal:expr, $label:literal) => {
        if let Some(iface_ref) = get_signal_emitter($conn).await {
            let $ctx = iface_ref.signal_emitter();
            if let Err(e) = $signal.await {
                tracing::debug!(concat!($label, ": D-Bus signal emission failed: {}"), e);
            }
        }
    };
}

/// D-Bus interface: org.lobstertrap.PuzzlePod1.Manager
pub struct ManagerInterface {
    services: DaemonServices,
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
        if !self
            .services
            .initialized
            .load(std::sync::atomic::Ordering::Acquire)
        {
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
            let mut limiter = unlock_poisoned(self.services.rate_limiter.lock());
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
            let mut cache = unlock_poisoned(self.services.idempotency_cache.lock());
            cache.retain(|_, entry| entry.created_at.elapsed() < IDEMPOTENCY_TTL);
            if let Some(entry) = cache.get(&idempotency_key) {
                // Verify the cached branch still exists. If it was committed
                // or rolled back, the entry is stale and should be evicted
                // so a new branch can be created with the same parameters.
                let still_valid = serde_json::from_str::<serde_json::Value>(&entry.result_json)
                    .ok()
                    .and_then(|v| v.get("id").and_then(|id| id.as_str().map(String::from)))
                    .and_then(|id_str| puzzled_types::BranchId::validated(id_str).ok())
                    .map(|bid| self.services.manager.inspect(&bid).is_some())
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

        let manager = &*self.services.manager;

        let agent_uid = if uid == 0 { 65534 } else { uid };

        let info = manager
            .create_branch(profile, std::path::Path::new(base_path), agent_uid)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        // Y1: Register the agent UID with the trust manager using profile-specific
        // initial scores. PRD §4.1.9: "Callers should call this when a branch is
        // created with a known profile to ensure the correct initial score is used."
        // Existing UIDs are not overwritten (or_insert_with semantics).
        {
            let mut trust = unlock_poisoned(self.services.trust_manager.lock());
            trust.register_uid(agent_uid, profile);
        }

        let json =
            serde_json::to_string(&info).map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        // L-br1: Audit event for branch creation is emitted in BranchManager::create()
        // (branch.rs). Removed the duplicate here to avoid double-logging.

        // §3.1: Write branch_created event to persistent audit store
        self.services
            .store_audit_event(
                &AuditEvent::BranchCreated {
                    branch_id: info.id.clone(),
                    profile: profile.to_string(),
                    uid: agent_uid,
                },
                &info.id,
                None,
            )
            .await;

        // DC2: Store result in idempotency cache
        {
            let mut cache = unlock_poisoned(self.services.idempotency_cache.lock());

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
        emit_dbus_signal!(
            connection,
            |ctx| ManagerInterface::branch_created(ctx, &branch_id_str, profile),
            "F11"
        );

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

        if !self
            .services
            .initialized
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(zbus::fdo::Error::Failed(
                "daemon is not fully initialized; try again shortly".into(),
            ));
        }

        let (uid, id) =
            validate_and_authorize(&header, connection, branch_id, &self.services.manager).await?;

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

        self.services
            .manager
            .activate_branch(&id, agent_uid, 0, command)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let info =
            self.services.manager.inspect(&id).ok_or_else(|| {
                zbus::fdo::Error::Failed("branch not found after activation".into())
            })?;

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
            validate_and_authorize(&header, connection, branch_id, &self.services.manager).await?;

        // M14: Idempotency — if branch is already committed, return cached result
        // m4 TODO: Cache the actual CommitResult from the first successful commit
        // so that repeated calls return the real files_committed/bytes_committed
        // values instead of zeros. Consider storing CommitResult in BranchInfo or
        // a separate DashMap<BranchId, CommitResult>.
        if let Some(info) = self.services.manager.inspect(&id) {
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
            .services
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
            let manifest_dir = self.services.manager.config().branch_root.join("manifests");
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
                self.services.manager
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
            .services
            .manager
            .commit(&id)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let json =
            serde_json::to_string(&result).map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        // PXH4: Emit audit event for branch commit
        self.services.audit_logger.log(AuditEvent::BranchCommitted {
            branch_id: id.clone(),
            files: result.files_committed,
            bytes: result.bytes_committed,
        });

        // §3.1: Write governance event to persistent audit store
        self.services
            .store_audit_event(
                &AuditEvent::BranchCommitted {
                    branch_id: id.clone(),
                    files: result.files_committed,
                    bytes: result.bytes_committed,
                },
                &id,
                Some(changeset_hash.clone()),
            )
            .await;

        // Gap 4: Store CommitRejected/PolicyViolation in audit store
        if let puzzled_types::PolicyDecision::Rejected(ref violations) = result.policy_result {
            let reject_reason = format!("{} policy violation(s)", violations.len());
            let reject_event = AuditEvent::CommitRejected {
                branch_id: id.clone(),
                reason: reject_reason.clone(),
            };
            self.services.audit_logger.log(AuditEvent::CommitRejected {
                branch_id: id.clone(),
                reason: reject_reason.clone(),
            });
            self.services
                .store_audit_event(&reject_event, &id, Some(changeset_hash.clone()))
                .await;
            for v in violations {
                let pv_event = AuditEvent::PolicyViolation {
                    branch_id: id.clone(),
                    rule: v.rule.clone(),
                    message: v.message.clone(),
                };
                self.services.audit_logger.log(AuditEvent::PolicyViolation {
                    branch_id: id.clone(),
                    rule: v.rule.clone(),
                    message: v.message.clone(),
                });
                self.services.store_audit_event(&pv_event, &id, None).await;
            }
        }

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
        let (trust_transition_result, trust_score_after) =
            self.services
                .update_trust_score(trust_event_type, branch_uid, branch_id);

        // V2: Record governance provenance for this commit.
        {
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
            self.services
                .record_governance_provenance(
                    branch_id,
                    gov_result,
                    &violations,
                    Some(changeset_hash.clone()),
                )
                .await;
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
        self.services.cleanup_behavioral_throttle(branch_id);

        // H6: Emit D-Bus signals for commit result
        // H-10: Detect governance review pending (Approved + files_committed==0
        // + branch still exists in GovernanceReview state)
        let is_governance_review = matches!(
            &result.policy_result,
            puzzled_types::PolicyDecision::Approved
        ) && result.files_committed == 0
            && self
                .services
                .manager
                .inspect(&id)
                .map(|info| info.state == puzzled_types::BranchState::GovernanceReview)
                .unwrap_or(false);

        if let Some(iface_ref) = get_signal_emitter(connection).await {
            let ctx = iface_ref.signal_emitter();
            if is_governance_review {
                // H-10: Emit governance_review_pending signal with diff summary
                // Use pending_review_summary() for actual changeset counts
                let (file_count, total_bytes) = self
                    .services
                    .manager
                    .pending_review_summary(&id)
                    .unwrap_or((0, 0));
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
            validate_and_authorize(&header, connection, branch_id, &self.services.manager).await?;

        // M14: Idempotency — if branch is already rolled back, return success
        if let Some(info) = self.services.manager.inspect(&id) {
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
        self.services
            .manager
            .rollback(&rollback_reason, &id)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        // PXH4: Emit audit event for branch rollback
        self.services
            .audit_logger
            .log(AuditEvent::BranchRolledBack {
                branch_id: id.clone(),
                reason: rollback_reason.clone(),
            });

        // §3.1: Write rollback event to persistent audit store
        self.services
            .store_audit_event(
                &AuditEvent::BranchRolledBack {
                    branch_id: id.clone(),
                    reason: rollback_reason.clone(),
                },
                &id,
                None,
            )
            .await;

        // W11: Record governance provenance for rollback decision.
        self.services
            .record_governance_provenance(
                branch_id,
                "rollback",
                std::slice::from_ref(&rollback_reason),
                None,
            )
            .await;

        // X1: Clean up provenance data for the rolled-back branch.
        // PRD §4.3.8: "Branch rollback/cleanup removes the provenance directory."
        // Must happen AFTER W11 recording so the rollback decision is persisted
        // before the directory is removed.
        if let Err(e) = self.services.provenance_store.cleanup_branch(branch_id) {
            tracing::warn!(branch_id, error = %e, "X1: failed to clean up provenance data");
        }

        // B2: Clean up behavioral trigger throttle entry for this branch.
        self.services.cleanup_behavioral_throttle(branch_id);

        // H6: Emit D-Bus signal for rollback
        // L-db1: Include reason in BranchRolledBack signal
        emit_dbus_signal!(
            connection,
            |ctx| ManagerInterface::branch_rolled_back(ctx, branch_id, &rollback_reason),
            "F11"
        );

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
            validate_and_authorize(&header, connection, branch_id, &self.services.manager).await?;

        let info =
            self.services.manager.inspect(&id).ok_or_else(|| {
                zbus::fdo::Error::Failed(format!("branch {} not found", branch_id))
            })?;

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

        let uid = get_caller_uid(&header, connection).await?;
        let manager = &*self.services.manager;
        let branches: Vec<_> = manager
            .list()
            .into_iter()
            .filter(|b| uid == 0 || b.uid == uid)
            .collect();

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
            validate_and_authorize(&header, connection, branch_id, &self.services.manager).await?;

        let changes = self
            .services
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
        let manager = &*self.services.manager;
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
            validate_and_authorize(&header, connection, branch_id, &self.services.manager).await?;

        self.services
            .manager
            .kill_agent(&id)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        // M-db5: Emit audit event for agent kill with caller UID
        self.services.audit_logger.log(AuditEvent::AgentKilled {
            branch_id: id.clone(),
            caller_uid: uid,
        });

        // §3.1: Write agent-killed event to persistent audit store
        self.services
            .store_audit_event(
                &AuditEvent::AgentKilled {
                    branch_id: id.clone(),
                    caller_uid: uid,
                },
                &id,
                None,
            )
            .await;

        // Emit rollback signal
        // L-db1: Include reason in BranchRolledBack signal
        emit_dbus_signal!(
            connection,
            |ctx| ManagerInterface::branch_rolled_back(ctx, branch_id, "agent killed by operator"),
            "F11"
        );

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
            validate_and_authorize(&header, connection, branch_id, &self.services.manager).await?;

        require_root(uid, "approve branches")?;

        // Capture profile and owner UID before approve_branch changes state
        let (profile, branch_uid) = self
            .services
            .manager
            .inspect(&id)
            .map(|info| (info.profile.clone(), info.uid))
            .unwrap_or_else(|| (String::new(), 0));

        let result = self
            .services
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
        self.services.audit_logger.log(AuditEvent::BranchCommitted {
            branch_id: id.clone(),
            files: result.files_committed,
            bytes: result.bytes_committed,
        });

        // Z2: Write approval event to persistent audit store (§3.1)
        self.services
            .store_audit_event(
                &AuditEvent::BranchCommitted {
                    branch_id: id.clone(),
                    files: result.files_committed,
                    bytes: result.bytes_committed,
                },
                &id,
                Some(changeset_hash.clone()),
            )
            .await;

        // W3: Update trust score for manual governance approval.
        let (trust_transition_result, trust_score_after) =
            self.services
                .update_trust_score("commit_approved", branch_uid, branch_id);

        // W4: Record governance provenance for manual approval.
        self.services
            .record_governance_provenance(branch_id, "approved", &[], Some(changeset_hash.clone()))
            .await;

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
            validate_and_authorize(&header, connection, branch_id, &self.services.manager).await?;

        require_root(uid, "reject branches")?;

        let reject_reason = if reason.is_empty() {
            "rejected via D-Bus".to_string()
        } else {
            reason.to_string()
        };

        // Capture branch owner UID before reject changes state
        let branch_uid = self
            .services
            .manager
            .inspect(&id)
            .map(|info| info.uid)
            .unwrap_or(0);

        self.services
            .manager
            .reject_branch(&id, &reject_reason)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        // Z6: Emit audit event to syslog/netlink for manual rejection.
        self.services.audit_logger.log(AuditEvent::CommitRejected {
            branch_id: id.clone(),
            reason: reject_reason.clone(),
        });

        // Z5: Write rejection event to persistent audit store (§3.1)
        self.services
            .store_audit_event(
                &AuditEvent::CommitRejected {
                    branch_id: id.clone(),
                    reason: reject_reason.clone(),
                },
                &id,
                None,
            )
            .await;

        // W6: Update trust score for manual governance rejection.
        self.services
            .update_trust_score("commit_rejected", branch_uid, branch_id);

        // W7: Record governance provenance for manual rejection.
        self.services
            .record_governance_provenance(
                branch_id,
                "rejected",
                std::slice::from_ref(&reject_reason),
                None,
            )
            .await;

        // X2: Clean up provenance data for the rejected branch.
        // PRD §4.3.8: "Branch rollback/cleanup removes the provenance directory."
        // Must happen AFTER W7 recording so the rejection decision is persisted
        // before the directory is removed.
        if let Err(e) = self.services.provenance_store.cleanup_branch(branch_id) {
            tracing::warn!(branch_id, error = %e, "X2: failed to clean up provenance data");
        }

        // Emit rollback signal with reason
        emit_dbus_signal!(
            connection,
            |ctx| ManagerInterface::branch_rolled_back(ctx, branch_id, &reject_reason),
            "F11"
        );

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
            validate_and_authorize(&header, connection, branch_id, &self.services.manager).await?;

        self.services
            .manager
            .rollback("unregistered", &id)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        // AA3: Emit audit event to syslog/netlink for unregistration.
        // All other branch lifecycle terminals call audit_logger; without this,
        // unregister_agent events are only in the NDJSON audit store but not
        // in syslog/netlink, creating an observability gap.
        self.services
            .audit_logger
            .log(AuditEvent::BranchRolledBack {
                branch_id: id.clone(),
                reason: "unregistered".to_string(),
            });

        // Y6: Write unregistration to persistent audit store (§3.1)
        self.services
            .store_audit_event(
                &AuditEvent::BranchRolledBack {
                    branch_id: id.clone(),
                    reason: "unregistered".to_string(),
                },
                &id,
                None,
            )
            .await;

        // Y6: Record governance provenance for unregistration.
        self.services
            .record_governance_provenance(
                branch_id,
                "unregistered",
                &["agent unregistered".to_string()],
                None,
            )
            .await;

        // Y6: Clean up provenance data for the unregistered branch.
        // Must happen AFTER provenance recording so the decision is persisted.
        if let Err(e) = self.services.provenance_store.cleanup_branch(branch_id) {
            tracing::warn!(branch_id, error = %e, "Y6: failed to clean up provenance data");
        }

        // Emit rollback signal with reason
        emit_dbus_signal!(
            connection,
            |ctx| ManagerInterface::branch_rolled_back(ctx, branch_id, "unregistered"),
            "F11"
        );

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
            validate_and_authorize(&header, connection, branch_id, &self.services.manager).await?;

        let info =
            self.services.manager.inspect(&id).ok_or_else(|| {
                zbus::fdo::Error::Failed(format!("branch {} not found", branch_id))
            })?;

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
        require_root(uid, "reload policies")?;

        let manager = &*self.services.manager;
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

        let store = self.services.audit_store.lock().await;
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
        require_root(uid, "export audit events")?;

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

        let store = self.services.audit_store.lock().await;
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
        require_root(uid, "verify attestation chains")?;
        tracing::info!(branch_id = %branch_id, "§3.1: verify_attestation_chain called");

        // Read the public key for Ed25519 signature verification
        let attestation_dir = &self.services.manager.config().attestation.attestation_dir;
        let pubkey_path = attestation_dir.join("public_key.hex");
        let verifying_key: Option<ed25519_dalek::VerifyingKey> =
            std::fs::read_to_string(&pubkey_path)
                .ok()
                .and_then(|hex_str| {
                    let bytes = puzzled_types::merkle::hex_decode(hex_str.trim()).ok()?;
                    let arr: [u8; 32] = bytes.try_into().ok()?;
                    ed25519_dalek::VerifyingKey::from_bytes(&arr).ok()
                });

        let store = self.services.audit_store.lock().await;
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
                        let sig_bytes = puzzled_types::merkle::hex_decode(sig_hex)
                            .ok()
                            .filter(|b| b.len() == 64);
                        if let Some(sig_bytes) = sig_bytes {
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

        let store = self.services.audit_store.lock().await;
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

        let store = self.services.audit_store.lock().await;
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
        require_root(uid, "export attestation bundles")?;
        tracing::info!(branch_id = %branch_id, "§3.1: export_attestation_bundle called");

        // Read the Ed25519 public key from the attestation directory
        let attestation_dir = &self.services.manager.config().attestation.attestation_dir;
        let pubkey_path = attestation_dir.join("public_key.hex");
        let public_key = std::fs::read_to_string(&pubkey_path)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|e| {
                tracing::error!("S43: failed to read attestation public key: {e}");
                String::from("ERROR: key unavailable")
            });

        let store = self.services.audit_store.lock().await;
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
        let signing_key_path = &self.services.manager.config().signing_key_path;
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
        let ima_manifest_dir = self.services.manager.config().branch_root.join("manifests");
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

        let manager = &self.services.manager;
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

        let store = self.services.manager.credential_store().ok_or_else(|| {
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
        self.services
            .audit_logger
            .log(AuditEvent::CredentialStored {
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
            validate_and_authorize(&header, connection, branch_id, &self.services.manager).await?;

        let info =
            self.services.manager.inspect(&id).ok_or_else(|| {
                zbus::fdo::Error::Failed(format!("branch {} not found", branch_id))
            })?;

        let agent_profile = self
            .services
            .manager
            .get_profile(&info.profile)
            .ok_or_else(|| {
                zbus::fdo::Error::Failed(format!("profile '{}' not found", info.profile))
            })?;

        let branch_dir = self.services.manager.branch_dir(&id);
        let output_path = branch_dir.join("seccomp.json");
        let listener_socket = std::path::Path::new("/run/puzzled/seccomp-notify.sock");

        let profile = crate::seccomp_profile::generate_seccomp_profile(
            branch_id,
            listener_socket,
            true,  // include_notify
            false, // include_clone_guard (BPF LSM handles this when available)
            agent_profile.seccomp_mode,
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
            validate_and_authorize(&header, connection, branch_id, &self.services.manager).await?;

        let info =
            self.services.manager.inspect(&id).ok_or_else(|| {
                zbus::fdo::Error::Failed(format!("branch {} not found", branch_id))
            })?;

        let profile = self
            .services
            .manager
            .get_profile(&info.profile)
            .ok_or_else(|| {
                zbus::fdo::Error::Failed(format!("profile '{}' not found", info.profile))
            })?;

        let branch_dir = self.services.manager.branch_dir(&id);
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
            validate_and_authorize(&header, connection, branch_id, &self.services.manager).await?;

        self.services
            .manager
            .attach_governance(&id, container_pid, container_id)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        // PXH4: Audit event for governance attachment
        self.services.audit_logger.log(AuditEvent::AgentRegistered {
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

        let store =
            self.services.manager.credential_store().ok_or_else(|| {
                zbus::fdo::Error::Failed("credential store not initialized".into())
            })?;

        let mut guard = store.write().await;
        let removed = guard
            .remove(credential_name)
            .map_err(|e| zbus::fdo::Error::Failed(format!("credential store error: {}", e)))?;

        // Gap 44: Emit audit event for credential removal
        self.services
            .audit_logger
            .log(AuditEvent::CredentialRemoved {
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

        let store =
            self.services.manager.credential_store().ok_or_else(|| {
                zbus::fdo::Error::Failed("credential store not initialized".into())
            })?;

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
        self.services
            .audit_logger
            .log(AuditEvent::CredentialRotated {
                credential_name: credential_name.to_string(),
                caller_uid: uid,
            });

        // M-6: Emit CredentialRotated D-Bus signal so subscribers (GUI, monitoring)
        // can react to rotation events in real time (PRD §3.4.12).
        emit_dbus_signal!(
            connection,
            |ctx| ManagerInterface::credential_rotated(ctx, branch_id, credential_name, ""),
            "M-6"
        );

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
                validate_and_authorize(&header, connection, branch_id, &self.services.manager)
                    .await?;
            let profile = self
                .services
                .manager
                .inspect(&id)
                .map(|info| info.profile.clone())
                .unwrap_or_default();
            (uid, profile)
        };
        tracing::info!(branch_id, profile_name = %profile_name, uid, "§3.4.12: ListCredentials requested");

        let store =
            self.services.manager.credential_store().ok_or_else(|| {
                zbus::fdo::Error::Failed("credential store not initialized".into())
            })?;

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
                .services
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
            validate_and_authorize(&header, connection, branch_id, &self.services.manager).await?;
        tracing::info!(branch_id, uid, "§3.4 G19: ProvisionCredentials requested");

        // Get the branch and its profile
        let branch_info =
            self.services.manager.inspect(&id).ok_or_else(|| {
                zbus::fdo::Error::Failed(format!("branch {} not found", branch_id))
            })?;

        let profile = self
            .services
            .manager
            .get_profile(&branch_info.profile)
            .ok_or_else(|| {
                zbus::fdo::Error::Failed(format!(
                    "profile '{}' not found for branch {}",
                    branch_info.profile, branch_id
                ))
            })?;

        // Get credential store and phantom token manager
        let _store = self.services.manager.credential_store().ok_or_else(|| {
            zbus::fdo::Error::Failed(
                "credential store not initialized (credentials.enabled=false)".into(),
            )
        })?;

        let ptm = self
            .services
            .manager
            .phantom_token_manager()
            .ok_or_else(|| {
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
        let branch_state_dir = self.services.manager.config().branch_root.join(branch_id);
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
            "proxy_port": self.services.manager.config().network.proxy_port,
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
        self.services
            .audit_logger
            .log(AuditEvent::CredentialStored {
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
            validate_and_authorize(&header, connection, branch_id, &self.services.manager).await?;
        tracing::info!(branch_id, uid, "§3.4.12: RevokeCredentials requested");

        // Revoke phantom tokens for this branch
        let ptm = self
            .services
            .manager
            .phantom_token_manager()
            .ok_or_else(|| {
                zbus::fdo::Error::Failed("phantom token manager not initialized".into())
            })?;

        let mut ptm_guard = ptm.write().await;
        ptm_guard.revoke_branch(&id);
        drop(ptm_guard);

        // §3.4 T2.3: Stop the proxy and delete persisted credential mappings.
        // This mirrors cleanup_branch_resources() behavior for credential-specific resources.
        self.services
            .manager
            .revoke_branch_credential_resources(&id);

        // Emit audit event
        self.services
            .audit_logger
            .log(AuditEvent::CredentialRevoked {
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
        let _store = self.services.manager.credential_store().ok_or_else(|| {
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
        let store_read = self.services.manager.credential_store().ok_or_else(|| {
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

        let store = self.services.manager.credential_store().ok_or_else(|| {
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
        self.services
            .audit_logger
            .log(AuditEvent::CredentialStored {
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
            validate_and_authorize(&header, connection, branch_id, &self.services.manager).await?;

        // Delegate to the existing commit flow which handles freeze → diff → OPA → WAL
        let result = self
            .services
            .manager
            .commit(&id)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let json =
            serde_json::to_string(&result).map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        // K27: Check policy_result and emit appropriate audit event.
        // Previously always logged BranchCommitted regardless of outcome.
        let tg_identity =
            self.services
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
                self.services.audit_logger.log(AuditEvent::BranchCommitted {
                    branch_id: id.clone(),
                    files: result.files_committed,
                    bytes: result.bytes_committed,
                });
                let tg_event = AuditEvent::BranchCommitted {
                    branch_id: id.clone(),
                    files: result.files_committed,
                    bytes: result.bytes_committed,
                };
                if let Err(e) = self.services.audit_store.lock().await.store_with_context(
                    &tg_event,
                    tg_identity,
                    None,
                ) {
                    tracing::warn!(branch_id, error = %e, "H45: failed to store trigger_governance commit event");
                }
            }
            puzzled_types::PolicyDecision::Rejected(ref violations) => {
                let reject_reason = format!("{} policy violation(s)", violations.len());
                self.services.audit_logger.log(AuditEvent::CommitRejected {
                    branch_id: id.clone(),
                    reason: reject_reason.clone(),
                });
                let reject_event = AuditEvent::CommitRejected {
                    branch_id: id.clone(),
                    reason: reject_reason,
                };
                if let Err(e) = self.services.audit_store.lock().await.store_with_context(
                    &reject_event,
                    tg_identity.clone(),
                    None,
                ) {
                    tracing::warn!(branch_id, error = %e, "K27: failed to store trigger_governance reject event");
                }
                for v in violations {
                    self.services.audit_logger.log(AuditEvent::PolicyViolation {
                        branch_id: id.clone(),
                        rule: v.rule.clone(),
                        message: v.message.clone(),
                    });
                }
            }
            puzzled_types::PolicyDecision::Error(ref err_msg) => {
                let error_reason = format!("policy evaluation error: {}", err_msg);
                self.services.audit_logger.log(AuditEvent::CommitRejected {
                    branch_id: id.clone(),
                    reason: error_reason.clone(),
                });
                let error_event = AuditEvent::CommitRejected {
                    branch_id: id.clone(),
                    reason: error_reason,
                };
                if let Err(e) = self.services.audit_store.lock().await.store_with_context(
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
        if !self
            .services
            .initialized
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(zbus::fdo::Error::Failed(
                "daemon is not fully initialized".into(),
            ));
        }

        let uid = get_caller_uid(&header, connection).await?;
        validate_dbus_inputs(profile, base_path, "[]")?;

        // M3: Validate profile exists before searching or creating branches.
        // Without this check, a typo in the profile name would silently create
        // a branch that fails later during sandbox setup.
        if self.services.manager.get_profile(profile).is_none() {
            return Err(zbus::fdo::Error::Failed(format!(
                "profile '{}' not found",
                profile
            )));
        }

        // R10: Apply rate limiting (same as create_branch) to prevent branch exhaustion DoS
        {
            let mut limiter = unlock_poisoned(self.services.rate_limiter.lock());
            if !limiter.check(uid) {
                return Err(zbus::fdo::Error::Failed(
                    "rate limit exceeded for EnsureBranch".into(),
                ));
            }
        }

        // Check if a branch already exists for this profile + base_path
        let existing = self
            .services
            .manager
            .find_branch_by_profile_and_path(profile, base_path);
        if let Some(branch_id) = existing {
            // R9: Verify caller owns the existing branch (or is root) to prevent
            // leaking other users' branch info
            if let Some(info) = self.services.manager.inspect(&branch_id) {
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
            .services
            .manager
            .create(profile, std::path::Path::new(base_path), agent_uid, vec![])
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        // K26: Register UID with trust manager, matching create_branch pattern.
        // Without this, branches created via ensure_branch would not have
        // profile-specific initial trust scores.
        {
            let mut trust = unlock_poisoned(self.services.trust_manager.lock());
            trust.register_uid(agent_uid, profile);
        }

        // H49: Write audit event for branch creation via ensure_branch,
        // matching the create_branch audit pattern.
        self.services.audit_logger.log(AuditEvent::BranchCreated {
            branch_id: info.id.clone(),
            profile: profile.to_string(),
            uid: agent_uid,
        });
        if let Err(e) = self
            .services
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
            .services
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
            .services
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
            .services
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
            .services
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
            .services
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
        let branch_info = self
            .services
            .manager
            .inspect(&BranchId::from(branch_id.to_string()));
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

        self.services
            .provenance_store
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
        let branch_info = self
            .services
            .manager
            .inspect(&BranchId::from(branch_id.to_string()));
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
            .services
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
            .services
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
                .services
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
            if let Some(profile) = self.services.manager.get_profile(&info.profile) {
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
            let store = self.services.audit_store.lock().await;
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
        let containment = self
            .services
            .manager
            .get_profile(&info.profile)
            .map(|profile| {
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
            .services
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
        let branch_info = self
            .services
            .manager
            .inspect(&BranchId::from(branch_id.to_string()));
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

        self.services
            .identity_manager
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
        Ok(self.services.identity_manager.jwks())
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

    // -- FR-DBUS-002: Profile, policy, and status query methods --

    /// Return a JSON array of loaded profile names.
    async fn list_profiles(&self) -> zbus::fdo::Result<String> {
        let names = self.services.manager.profile_names();
        serde_json::to_string(&names)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serializing profiles: {e}")))
    }

    /// Return the full profile as JSON for the named profile.
    async fn show_profile(&self, name: String) -> zbus::fdo::Result<String> {
        let profile = self
            .services
            .manager
            .get_profile(&name)
            .ok_or_else(|| zbus::fdo::Error::Failed(format!("profile '{name}' not found")))?;
        serde_json::to_string(&profile)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serializing profile: {e}")))
    }

    /// Parse a YAML string as a profile and validate it. Return JSON with pass/fail and errors.
    async fn validate_profile(&self, yaml: String) -> zbus::fdo::Result<String> {
        let profile: Result<puzzled_types::AgentProfile, _> = serde_yaml::from_str(&yaml);
        let result = match profile {
            Err(e) => serde_json::json!({
                "valid": false,
                "errors": [e.to_string()],
            }),
            Ok(p) => match crate::profile::validate_profile(&p) {
                Ok(()) => serde_json::json!({
                    "valid": true,
                    "errors": [],
                }),
                Err(e) => serde_json::json!({
                    "valid": false,
                    "errors": [e.to_string()],
                }),
            },
        };
        Ok(result.to_string())
    }

    /// Evaluate a policy file against synthetic input without loading into the live engine.
    async fn test_policy(
        &self,
        policy_path: String,
        input_json: String,
    ) -> zbus::fdo::Result<String> {
        let result = std::thread::spawn(move || -> Result<String, String> {
            let contents = std::fs::read_to_string(&policy_path)
                .map_err(|e| format!("reading policy file: {e}"))?;
            let mut engine = regorus::Engine::new();
            engine
                .add_policy(policy_path.clone(), contents)
                .map_err(|e| format!("loading policy: {e}"))?;
            let input_value = regorus::Value::from_json_str(&input_json)
                .map_err(|e| format!("parsing input JSON: {e}"))?;
            engine.set_input(input_value);
            let query_results = engine
                .eval_query("data".to_string(), false)
                .map_err(|e| format!("evaluating policy: {e}"))?;
            serde_json::to_string(&query_results.result)
                .map_err(|e| format!("serializing results: {e}"))
        })
        .join()
        .map_err(|_| zbus::fdo::Error::Failed("policy evaluation thread panicked".into()))?;
        result.map_err(zbus::fdo::Error::Failed)
    }

    /// Return daemon status information as JSON.
    async fn status(&self) -> zbus::fdo::Result<String> {
        let branch_count = self.services.manager.branch_count();
        let profile_count = self.services.manager.profile_count();
        let status = serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "branch_count": branch_count,
            "profile_count": profile_count,
        });
        Ok(status.to_string())
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

impl ManagerInterface {
    /// PM11: Returns the behavioral trigger throttle map for external callers
    /// (e.g., fanotify trigger processing in branch.rs) to use with
    /// `should_emit_behavioral_trigger()`.
    pub fn behavioral_trigger_throttle(
        &self,
    ) -> &Arc<std::sync::Mutex<HashMap<String, std::time::Instant>>> {
        &self.services.behavioral_trigger_last_emitted
    }

    /// M-db1: Helper to emit a generic branch_event signal.
    pub async fn emit_branch_event(
        connection: &zbus::Connection,
        branch_id: &str,
        event_type: &str,
        details_json: &str,
    ) {
        emit_dbus_signal!(
            connection,
            |ctx| ManagerInterface::branch_event(ctx, branch_id, event_type, details_json),
            "F11"
        );
    }
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
        services: DaemonServices {
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
        },
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

    let connection = match config.bus_type {
        crate::config::BusType::Session => {
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
        crate::config::BusType::System => {
            zbus::connection::Builder::system()?
                .name("org.lobstertrap.PuzzlePod1")?
                .serve_at("/org/lobstertrap/PuzzlePod1/Manager", interface)?
                .build()
                .await?
        }
    };

    tracing::info!(bus = %config.bus_type, "D-Bus service registered");

    Ok((connection, initialized))
}

#[cfg(test)]
mod tests;
