// SPDX-License-Identifier: Apache-2.0
//! D-Bus helper types and utility functions extracted from `dbus.rs`.
//!
//! This module contains shared types (`DaemonServices`, `RateLimiter`,
//! `IdempotencyCacheEntry`), validation helpers, and constants used by the
//! `ManagerInterface` D-Bus implementation. Extracted to reduce the size of
//! `dbus.rs` while keeping the `#[interface]` impl block and all
//! source-inspection tests in the original file.

use std::collections::HashMap;
use std::sync::Arc;

use crate::audit::AuditEvent;
use crate::audit::AuditLogger;
use crate::audit_store::AuditStore;
use crate::branch::BranchManager;
use crate::provenance::ProvenanceStore;
use crate::sync_util::unlock_poisoned;
use crate::trust::TrustManager;
use puzzled_types::BranchId;
#[cfg(feature = "ima")]
use puzzled_types::TrustLevel;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// DC2: TTL for idempotency cache entries. Requests with the same key
/// (agent_name + profile) within this window return the cached result.
pub(crate) const IDEMPOTENCY_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// M-db3: Maximum number of entries in the idempotency cache.
/// When exceeded, the oldest (or a random) entry is evicted to prevent unbounded growth.
pub(crate) const MAX_IDEMPOTENCY_ENTRIES: usize = 1024;

/// M-db4: Maximum number of entries in the behavioral trigger throttle map.
#[allow(dead_code)] // Used by should_emit_behavioral_trigger and tests in dbus.rs
pub(crate) const MAX_BEHAVIORAL_TRIGGER_ENTRIES: usize = 1024;

/// M-db4: Maximum age for behavioral trigger throttle entries (seconds).
#[allow(dead_code)] // Used by should_emit_behavioral_trigger and tests in dbus.rs
pub(crate) const BEHAVIORAL_TRIGGER_MAX_AGE: std::time::Duration =
    std::time::Duration::from_secs(300);

/// PM11: Minimum interval between BehavioralTrigger signals for the same branch.
#[allow(dead_code)] // Used by should_emit_behavioral_trigger and tests in dbus.rs
pub(crate) const BEHAVIORAL_TRIGGER_THROTTLE: std::time::Duration =
    std::time::Duration::from_secs(10);

/// L4: Maximum length for branch IDs received via D-Bus.
pub(crate) const MAX_BRANCH_ID_LEN: usize = 256;
/// L4: Maximum length for profile names received via D-Bus.
pub(crate) const MAX_PROFILE_NAME_LEN: usize = 128;
/// L4: Maximum length for base paths received via D-Bus.
pub(crate) const MAX_BASE_PATH_LEN: usize = 4096;
/// L4: Maximum length for command JSON received via D-Bus.
pub(crate) const MAX_COMMAND_JSON_LEN: usize = 65536;

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

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
pub(crate) fn sanitize_log_reason(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '_' } else { c })
        .collect()
}

/// Reject the D-Bus call if the caller is not root (UID 0).
pub(crate) fn require_root(uid: u32, operation: &str) -> zbus::fdo::Result<()> {
    if uid != 0 {
        tracing::warn!(uid, "{operation} rejected: caller is not root");
        Err(zbus::fdo::Error::AccessDenied(format!(
            "only root (UID 0) may {operation}"
        )))
    } else {
        Ok(())
    }
}

/// L4: Validate that a branch_id is within length limits and contains only
/// allowed characters (alphanumeric, hyphens, underscores).
pub(crate) fn validate_branch_id(branch_id: &str) -> zbus::fdo::Result<()> {
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
pub(crate) fn validate_dbus_inputs(
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
pub(crate) async fn get_caller_uid(
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

/// Check that a caller has access to a branch (must be owner or root).
/// H-30: Returns error when branch is not found instead of silently allowing access.
pub(crate) fn check_branch_access(
    caller_uid: u32,
    manager: &BranchManager,
    id: &BranchId,
) -> zbus::fdo::Result<()> {
    if caller_uid == 0 {
        return Ok(());
    }
    if let Some(info) = manager.inspect(id) {
        if info.uid == caller_uid {
            return Ok(());
        }
        Err(zbus::fdo::Error::AccessDenied(
            "you do not own this branch".into(),
        ))
    } else {
        // H-30: Branch not found — fail closed instead of allowing access
        Err(zbus::fdo::Error::Failed("branch not found".into()))
    }
}

/// Validate a branch ID and authorize the caller.
#[allow(dead_code)] // Used by zbus interface methods; may appear unused on some targets
pub(crate) async fn validate_and_authorize(
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

/// PM11: Check whether a BehavioralTrigger signal should be emitted for this branch.
///
/// Returns `true` if at least `BEHAVIORAL_TRIGGER_THROTTLE` (10 seconds) has elapsed
/// since the last emission for this branch. Updates the timestamp on emission.
/// Callers should gate `ManagerInterface::behavioral_trigger()` behind this check
/// to avoid flooding D-Bus subscribers during sustained anomalous behavior.
///
/// M-db4: Also evicts entries older than 300s and caps at MAX_BEHAVIORAL_TRIGGER_ENTRIES.
#[allow(dead_code)] // Public API for behavioral trigger throttling; used by tests in dbus.rs
pub fn should_emit_behavioral_trigger(
    last_emitted: &std::sync::Mutex<HashMap<String, std::time::Instant>>,
    branch_id: &str,
) -> bool {
    let now = std::time::Instant::now();
    let mut map = unlock_poisoned(last_emitted.lock());

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

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

/// M10: Simple per-UID rate limiter for branch creation.
/// Tracks timestamps of recent requests per UID; rejects if > MAX_PER_MINUTE.
/// A3: Bounded to MAX_TRACKED_UIDS to prevent memory exhaustion from UID cycling.
pub(crate) struct RateLimiter {
    /// Recent request timestamps per caller UID.
    pub(crate) requests: HashMap<u32, Vec<std::time::Instant>>,
}

impl RateLimiter {
    pub(crate) const MAX_PER_MINUTE: usize = 10;
    /// A3: Maximum number of UIDs tracked. Prevents memory exhaustion if an attacker
    /// cycles through many UIDs. When the limit is reached, stale UIDs (no requests
    /// in the last 60s) are evicted first; if still full, the oldest UID is evicted.
    pub(crate) const MAX_TRACKED_UIDS: usize = 4096;

    pub(crate) fn new() -> Self {
        Self {
            requests: HashMap::new(),
        }
    }

    /// Check if a request from this UID is allowed. Returns false if rate-limited.
    pub(crate) fn check(&mut self, uid: u32) -> bool {
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
pub(crate) struct IdempotencyCacheEntry {
    pub(crate) result_json: String,
    pub(crate) created_at: std::time::Instant,
}

/// Shared daemon state grouped into a single context struct.
/// All fields are `Arc`-wrapped, so `Clone` is cheap (reference-count bumps only).
#[derive(Clone)]
pub(crate) struct DaemonServices {
    pub(crate) manager: Arc<BranchManager>,
    pub(crate) audit_store: Arc<tokio::sync::Mutex<AuditStore>>,
    pub(crate) rate_limiter: Arc<std::sync::Mutex<RateLimiter>>,
    /// L15: Tracks whether the daemon is fully initialized.
    /// Set to true after all subsystems are ready.
    pub(crate) initialized: Arc<std::sync::atomic::AtomicBool>,
    /// DC2: Idempotency cache for CreateBranch. Key is "{profile}:{base_path}:{command_json}"
    /// from the same caller UID. Prevents duplicate branch creation on D-Bus retries.
    pub(crate) idempotency_cache: Arc<std::sync::Mutex<HashMap<String, IdempotencyCacheEntry>>>,
    /// PXH4: Audit logger for emitting audit events on D-Bus operations.
    pub(crate) audit_logger: Arc<AuditLogger>,
    /// PM11: Tracks last BehavioralTrigger signal emission time per branch.
    /// Rate-limited to at most 1 signal per branch per 10 seconds to prevent
    /// flooding D-Bus subscribers during sustained anomalous behavior.
    pub(crate) behavioral_trigger_last_emitted:
        Arc<std::sync::Mutex<HashMap<String, std::time::Instant>>>,
    /// §4.1: Trust manager for per-UID trust scoring and behavioral baselines.
    pub(crate) trust_manager: Arc<std::sync::Mutex<TrustManager>>,
    /// §4.3: Provenance store for per-branch causal chain records.
    pub(crate) provenance_store: Arc<ProvenanceStore>,
    /// §4.5: Identity manager for JWT-SVID issuance (requires ima feature).
    #[cfg(feature = "ima")]
    pub(crate) identity_manager: Arc<crate::identity::IdentityManager>,
}

impl DaemonServices {
    /// Store an audit event in the persistent NDJSON audit store (attestation bridge §3.1).
    ///
    /// Resolves agent identity from the branch manager and writes the event with
    /// optional changeset hash for Ed25519 signature and Merkle tree leaf.
    pub(crate) async fn store_audit_event(
        &self,
        event: &AuditEvent,
        branch_id: &BranchId,
        changeset_hash: Option<String>,
    ) {
        let identity = self
            .manager
            .inspect(branch_id)
            .map(|info| info.agent_identity());
        if let Err(e) =
            self.audit_store
                .lock()
                .await
                .store_with_context(event, identity, changeset_hash)
        {
            tracing::warn!(
                branch_id = %branch_id,
                error = %e,
                "failed to store event in audit store"
            );
        }
    }

    /// Record a governance provenance entry, fetching policy_hash from the audit store.
    pub(crate) async fn record_governance_provenance(
        &self,
        branch_id: &str,
        result: &str,
        violations: &[String],
        manifest_hash: Option<String>,
    ) {
        let policy_version_str = {
            let store = self.audit_store.lock().await;
            store.policy_hash().unwrap_or("unknown").to_string()
        };
        if let Err(e) = crate::provenance::record_governance(
            &self.provenance_store,
            branch_id,
            &policy_version_str,
            result,
            violations,
            manifest_hash,
            &[],
        ) {
            tracing::warn!(
                branch_id,
                error = %e,
                "failed to record governance provenance"
            );
        }
    }

    /// Remove the behavioral trigger throttle entry for a terminated branch.
    pub(crate) fn cleanup_behavioral_throttle(&self, branch_id: &str) {
        unlock_poisoned(self.behavioral_trigger_last_emitted.lock()).remove(branch_id);
    }

    /// Update trust score and return transition info for optional signal emission.
    pub(crate) fn update_trust_score(
        &self,
        event_type: &str,
        branch_uid: u32,
        branch_id: &str,
    ) -> (Option<(TrustLevel, TrustLevel)>, u32) {
        let mut trust = unlock_poisoned(self.trust_manager.lock());
        let transition = trust.on_audit_event(event_type, branch_uid, Some(branch_id));
        let score = trust.get_score(branch_uid).map(|s| s.score).unwrap_or(0);
        (transition, score)
    }
}
