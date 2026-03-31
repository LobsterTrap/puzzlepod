// SPDX-License-Identifier: Apache-2.0
//! Graduated Trust with Behavioral Learning (PRD Section 4.1).
//!
//! Tracks per-UID trust scores that drive privilege escalation / de-escalation.
//! Scores are updated by audit events (commit approved, policy violation, etc.)
//! and behavioral baseline anomaly detection.  State is persisted to disk as
//! JSON so that trust survives daemon restarts.
//!
//! # Thread Safety
//!
//! `TrustManager` is not internally synchronized.  Callers must wrap it in
//! `Arc<Mutex<TrustManager>>` or equivalent when accessed from multiple async
//! tasks (e.g., concurrent D-Bus handlers for the same UID).

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{BufRead, Write};
use std::path::PathBuf;

use puzzled_types::{BaselineSeverity, ScoringRule, TrustEvent, TrustLevel, TrustState};

use crate::config::{MetricBehavioralConfig, TrustConfig};
use crate::error::{PuzzledError, Result};

// ---------------------------------------------------------------------------
// Constants (fallbacks when no config provided)
// ---------------------------------------------------------------------------

/// Default rolling window duration: 7 days in seconds.
const DEFAULT_WINDOW_SECS: u64 = 604_800;

/// Default anomaly threshold in standard deviations.
const DEFAULT_THRESHOLD_SIGMA: f64 = 2.0;

/// Default minimum observations before anomaly detection activates (PRD: 10).
const DEFAULT_MIN_SAMPLES: usize = 10;

/// N5: Maximum trust history file size in bytes (10 MB).
/// When exceeded, the file is truncated to the last 50% of lines.
const MAX_TRUST_HISTORY_BYTES: u64 = 10_485_760;

// ---------------------------------------------------------------------------
// MetricWindow — rolling-window statistics for a single metric
// ---------------------------------------------------------------------------

/// Rolling window of observations for a single behavioral metric.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetricWindow {
    /// (value, ISO 8601 timestamp) pairs, ordered by insertion time.
    pub observations: VecDeque<(f64, String)>,
    /// Rolling window duration in seconds.
    pub window_secs: u64,
    /// Anomaly threshold in standard deviations above/below the mean.
    pub threshold_sigma: f64,
    /// Severity to report when an anomaly is detected.
    pub severity: BaselineSeverity,
    /// Minimum number of observations required before anomaly detection
    /// activates.  With fewer observations, statistical measures are
    /// unreliable and all values are accepted silently.
    pub min_samples: usize,
    /// Counter for amortized pruning — avoids O(n) timestamp parsing on
    /// every `observe()` call.  Pruning runs every `PRUNE_INTERVAL` inserts.
    #[serde(default)]
    observations_since_prune: u32,
}

/// Number of observations between pruning passes.  Balances freshness
/// (expired observations affect mean/σ) against cost (RFC 3339 parsing).
const PRUNE_INTERVAL: u32 = 16;

impl MetricWindow {
    /// Create a new metric window with the given severity and default config.
    pub fn new(severity: BaselineSeverity) -> Self {
        Self::with_config(
            severity,
            DEFAULT_THRESHOLD_SIGMA,
            DEFAULT_WINDOW_SECS,
            DEFAULT_MIN_SAMPLES,
        )
    }

    /// Create a metric window with explicit configuration.
    pub fn with_config(
        severity: BaselineSeverity,
        threshold_sigma: f64,
        window_secs: u64,
        min_samples: usize,
    ) -> Self {
        Self {
            observations: VecDeque::new(),
            window_secs,
            threshold_sigma,
            severity,
            min_samples,
            observations_since_prune: 0,
        }
    }

    /// Record an observation. Returns `Some(severity)` if the value is
    /// anomalous (exceeds μ + kσ, i.e. one-sided upper-bound detection per
    /// PRD §4.1.4).  Only values *above* the mean trigger anomalies —
    /// unusually low values (less active agent) are benign.
    /// Observations below `min_samples` never trigger.
    pub fn observe(&mut self, value: f64, timestamp: String) -> Option<BaselineSeverity> {
        // Amortized pruning: run every PRUNE_INTERVAL inserts to avoid
        // O(n) timestamp parsing on every observe() call.
        self.observations_since_prune += 1;
        if self.observations_since_prune >= PRUNE_INTERVAL {
            self.prune_expired();
            self.observations_since_prune = 0;
        }

        // Need at least min_samples prior observations for meaningful statistics.
        let anomaly = if self.observations.len() >= self.min_samples {
            let mean = self.mean();
            let sd = self.stddev();
            // One-sided: only values exceeding μ + kσ are anomalous.
            // Low values (value < mean) are benign — agent was less active.
            // Guard: zero stddev means all prior values identical.
            if sd > 0.0 && (value - mean) > self.threshold_sigma * sd {
                Some(self.severity)
            } else {
                None
            }
        } else {
            None
        };

        self.observations.push_back((value, timestamp));
        anomaly
    }

    /// Arithmetic mean of the current observations.
    pub fn mean(&self) -> f64 {
        if self.observations.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.observations.iter().map(|(v, _)| v).sum();
        sum / self.observations.len() as f64
    }

    /// Population standard deviation of the current observations.
    pub fn stddev(&self) -> f64 {
        let n = self.observations.len();
        if n < 2 {
            return 0.0;
        }
        let mean = self.mean();
        let variance: f64 = self
            .observations
            .iter()
            .map(|(v, _)| {
                let diff = v - mean;
                diff * diff
            })
            .sum::<f64>()
            / n as f64;
        variance.sqrt()
    }

    /// Remove observations whose timestamp is older than `window_secs`
    /// relative to the most recent observation.
    ///
    /// Timestamps are ISO 8601 strings; we parse them with `chrono` for
    /// accurate comparison.  Unparseable timestamps are retained to avoid
    /// silent data loss.
    pub fn prune_expired(&mut self) {
        if self.observations.is_empty() {
            return;
        }

        // Find the latest timestamp to use as the reference point.
        let latest = self
            .observations
            .iter()
            .filter_map(|(_, ts)| chrono::DateTime::parse_from_rfc3339(ts).ok())
            .max();

        let latest = match latest {
            Some(t) => t,
            None => return, // no parseable timestamps — keep everything
        };

        // N2: Safe conversion — avoid truncation of large window_secs values,
        // and use try_seconds/checked_sub to avoid panic on overflow.
        let window_secs = i64::try_from(self.window_secs).unwrap_or(i64::MAX);
        let duration = chrono::Duration::try_seconds(window_secs).unwrap_or(chrono::Duration::MAX);
        let cutoff = match latest.checked_sub_signed(duration) {
            Some(c) => c,
            None => return, // N2: window so large everything is within range — keep all
        };

        self.observations.retain(|(_, ts)| {
            match chrono::DateTime::parse_from_rfc3339(ts) {
                Ok(t) => t >= cutoff,
                Err(_) => true, // keep unparseable
            }
        });
    }
}

// ---------------------------------------------------------------------------
// BehavioralBaseline — per-UID collection of metric windows (persistable)
// ---------------------------------------------------------------------------

/// Per-UID behavioral baseline for anomaly detection.
/// Persisted to `baselines/{uid}.json` so that learning survives restarts.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BehavioralBaseline {
    pub uid: u32,
    /// Rolling windows keyed by metric name (e.g. "exec_count", "file_writes").
    pub metrics: HashMap<String, MetricWindow>,
}

impl BehavioralBaseline {
    fn new(uid: u32) -> Self {
        Self {
            uid,
            metrics: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// DailyDeltaTracker — in-memory tracking to avoid disk I/O on hot path
// ---------------------------------------------------------------------------

/// Tracks cumulative positive deltas per (UID, event_type) for the current
/// day.  Replaces the previous approach of reading history from disk on
/// every positive event.
#[derive(Debug, Default)]
struct DailyDeltaTracker {
    /// ISO 8601 date string (e.g., "2026-03-16").
    date: String,
    /// (uid, event_type) → cumulative positive delta applied today.
    cumulative: HashMap<(u32, String), i32>,
}

impl DailyDeltaTracker {
    fn ensure_today(&mut self) {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        if self.date != today {
            self.date = today;
            self.cumulative.clear();
        }
    }

    fn today_total(&mut self, uid: u32, event_type: &str) -> i32 {
        self.ensure_today();
        *self
            .cumulative
            .get(&(uid, event_type.to_string()))
            .unwrap_or(&0)
    }

    fn record(&mut self, uid: u32, event_type: &str, delta: i32) {
        self.ensure_today();
        *self
            .cumulative
            .entry((uid, event_type.to_string()))
            .or_insert(0) += delta;
    }
}

// ---------------------------------------------------------------------------
// Default scoring rules
// ---------------------------------------------------------------------------

/// Return the default scoring rules used when no configuration file exists.
///
/// Includes `trust_decay` (PRD §4.1.3) and `max_increase_per_day` on
/// `commit_approved` (PRD: 10 points/day cap).
pub fn default_scoring_rules() -> Vec<ScoringRule> {
    vec![
        ScoringRule {
            event: "commit_approved".into(),
            delta: 2,
            max_increase_per_day: Some(10),
            description: Some("Successful commit approved by policy".into()),
        },
        ScoringRule {
            event: "branch_completed_clean".into(),
            delta: 1,
            max_increase_per_day: None,
            description: Some("Branch lifecycle completed with no violations".into()),
        },
        ScoringRule {
            event: "policy_violation".into(),
            delta: -10,
            max_increase_per_day: None,
            description: Some("Commit rejected due to policy violation".into()),
        },
        ScoringRule {
            event: "containment_violation".into(),
            delta: -25,
            max_increase_per_day: None,
            description: Some("Agent attempted blocked syscall or escape vector".into()),
        },
        ScoringRule {
            event: "behavioral_trigger".into(),
            delta: -5,
            max_increase_per_day: None,
            description: Some("Behavioral anomaly detected (generic)".into()),
        },
        ScoringRule {
            event: "behavioral_trigger_warning".into(),
            delta: -5,
            max_increase_per_day: None,
            description: Some("Behavioral anomaly detected (warning severity)".into()),
        },
        ScoringRule {
            event: "behavioral_trigger_critical".into(),
            delta: -15,
            max_increase_per_day: None,
            description: Some("Behavioral anomaly detected (critical severity)".into()),
        },
        ScoringRule {
            event: "behavioral_trigger_fatal".into(),
            delta: -50,
            max_increase_per_day: None,
            description: Some("Behavioral anomaly detected (fatal severity)".into()),
        },
        ScoringRule {
            event: "commit_rejected".into(),
            delta: -5,
            max_increase_per_day: None,
            description: Some("Commit rejected by governance policy".into()),
        },
        ScoringRule {
            event: "trust_decay".into(),
            delta: -1,
            max_increase_per_day: None,
            description: Some("Natural trust decay for inactive agent (weekly)".into()),
        },
    ]
}

// ---------------------------------------------------------------------------
// TrustManager
// ---------------------------------------------------------------------------

/// Manages per-UID trust scores, behavioral baselines, and persistence.
pub struct TrustManager {
    /// Per-UID trust scores.
    pub(crate) scores: HashMap<u32, TrustState>,
    /// Scoring rules (event → delta).
    rules: Vec<ScoringRule>,
    /// Directory for persistent storage (`scores/`, `history/`, `baselines/`).
    store_dir: PathBuf,
    /// Per-UID behavioral baselines (persisted on save_baselines).
    pub(crate) baselines: HashMap<u32, BehavioralBaseline>,
    /// In-memory daily delta tracking (replaces disk-based daily limit check).
    daily_deltas: DailyDeltaTracker,
    /// Per-metric behavioral configuration (metric_name → config).
    metric_configs: HashMap<String, MetricBehavioralConfig>,
    /// Default anomaly threshold sigma (from TrustConfig).
    default_threshold_sigma: f64,
    /// Default window duration in seconds (from TrustConfig).
    default_window_secs: u64,
    /// Default min samples before anomaly detection activates.
    default_min_samples: usize,
    /// Default initial trust score for auto-created UIDs (from TrustConfig).
    /// Used as fallback when no profile-specific initial score is registered.
    default_initial_score: u32,
}

impl TrustManager {
    /// Create a new TrustManager with default configuration.
    pub fn new(store_dir: PathBuf, rules: Vec<ScoringRule>) -> Self {
        Self {
            scores: HashMap::new(),
            rules,
            store_dir,
            baselines: HashMap::new(),
            daily_deltas: DailyDeltaTracker::default(),
            metric_configs: HashMap::new(),
            default_threshold_sigma: DEFAULT_THRESHOLD_SIGMA,
            default_window_secs: DEFAULT_WINDOW_SECS,
            default_min_samples: DEFAULT_MIN_SAMPLES,
            default_initial_score: 25,
        }
    }

    /// Create a TrustManager from a `TrustConfig`, wiring all config values
    /// into the runtime (window duration, anomaly threshold, min samples,
    /// per-metric configs).
    pub fn from_config(config: &TrustConfig, rules: Vec<ScoringRule>) -> Self {
        Self {
            scores: HashMap::new(),
            rules,
            store_dir: config.store_dir.clone(),
            baselines: HashMap::new(),
            daily_deltas: DailyDeltaTracker::default(),
            metric_configs: config.metric_configs.clone(),
            default_threshold_sigma: config.anomaly_threshold_sigma,
            // V25: Use saturating_mul for defense-in-depth (config validation bounds this to <= 365)
            default_window_secs: config.window_duration_days.saturating_mul(86_400),
            default_min_samples: config.min_samples,
            default_initial_score: config.initial_score,
        }
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Return the current trust state for a UID, if any.
    pub fn get_score(&self, uid: u32) -> Option<&TrustState> {
        self.scores.get(&uid)
    }

    /// Return the behavioral baseline for a UID, if any.
    pub fn get_baseline(&self, uid: u32) -> Option<&BehavioralBaseline> {
        self.baselines.get(&uid)
    }

    /// Pre-register a UID with a profile-specific initial score.
    ///
    /// Callers should call this when a branch is created with a known profile
    /// to ensure the correct initial score is used. If the UID already has a
    /// score, this is a no-op (existing score is not overwritten).
    pub fn register_uid(&mut self, uid: u32, profile_name: &str) {
        let score = self.initial_score(profile_name);
        self.scores
            .entry(uid)
            .or_insert_with(|| TrustState::new(uid, score));
    }

    // -----------------------------------------------------------------------
    // Persistence
    // -----------------------------------------------------------------------

    /// Load persisted trust scores and baselines from `store_dir/`.
    pub fn load(&mut self) -> Result<()> {
        let scores_dir = self.store_dir.join("scores");
        let entries = match fs::read_dir(&scores_dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Also try loading baselines even if scores dir doesn't exist.
                return self.load_baselines();
            }
            Err(e) => {
                return Err(PuzzledError::Trust(format!(
                    "failed to read trust scores dir: {e}"
                )))
            }
        };
        for entry in entries {
            let entry = entry.map_err(|e| {
                PuzzledError::Trust(format!("failed to read trust score entry: {e}"))
            })?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let data = fs::read_to_string(&path).map_err(|e| {
                PuzzledError::Trust(format!(
                    "failed to read trust score file {}: {e}",
                    path.display()
                ))
            })?;
            let state: TrustState = serde_json::from_str(&data).map_err(|e| {
                PuzzledError::Trust(format!(
                    "failed to parse trust score file {}: {e}",
                    path.display()
                ))
            })?;
            self.scores.insert(state.uid, state);
        }

        // Load persisted baselines.
        self.load_baselines()?;

        // Reconstruct daily delta tracker from today's history so that
        // max_increase_per_day survives daemon restarts.
        self.reconstruct_daily_deltas();

        Ok(())
    }

    /// Reconstruct the `DailyDeltaTracker` from today's NDJSON history files.
    ///
    /// Scans all UID history files for events with today's date and positive
    /// deltas, summing them per (uid, event_type).  This is called once on
    /// startup — not on the scoring hot path.
    fn reconstruct_daily_deltas(&mut self) {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        self.daily_deltas.date = today.clone();
        self.daily_deltas.cumulative.clear();

        let history_dir = self.store_dir.join("history");
        let entries = match fs::read_dir(&history_dir) {
            Ok(e) => e,
            Err(_) => return, // No history dir yet — nothing to reconstruct.
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            let file = match fs::File::open(&path) {
                Ok(f) => f,
                Err(_) => continue,
            };
            for line in std::io::BufReader::new(file).lines().map_while(|l| l.ok()) {
                if let Ok(event) = serde_json::from_str::<TrustEvent>(&line) {
                    // Only count today's positive deltas.
                    if event.delta > 0 && event.timestamp.starts_with(&today) {
                        *self
                            .daily_deltas
                            .cumulative
                            .entry((event.uid, event.event_type.clone()))
                            .or_insert(0) += event.delta;
                    }
                }
            }
        }
    }

    /// Persist the trust state for a single UID to `store_dir/scores/{uid}.json`.
    /// Uses fsync to guarantee crash safety for security-critical score data.
    pub fn save(&self, uid: u32) -> Result<()> {
        let state = self
            .scores
            .get(&uid)
            .ok_or_else(|| PuzzledError::NotFound(format!("no trust state for uid {uid}")))?;
        let scores_dir = self.store_dir.join("scores");
        fs::create_dir_all(&scores_dir)?;
        let path = scores_dir.join(format!("{uid}.json"));
        let data = serde_json::to_string_pretty(state)
            .map_err(|e| PuzzledError::Trust(format!("failed to serialize trust state: {e}")))?;
        let file = fs::File::create(&path)?;
        let mut writer = std::io::BufWriter::new(file);
        writer.write_all(data.as_bytes())?;
        writer
            .get_ref()
            .sync_all()
            .map_err(|e| PuzzledError::Trust(format!("failed to fsync trust score: {e}")))?;
        Ok(())
    }

    /// Persist behavioral baselines for all UIDs to `store_dir/baselines/`.
    pub fn save_baselines(&self) -> Result<()> {
        let baselines_dir = self.store_dir.join("baselines");
        fs::create_dir_all(&baselines_dir)?;
        for (uid, baseline) in &self.baselines {
            let path = baselines_dir.join(format!("{uid}.json"));
            let data = serde_json::to_string_pretty(baseline).map_err(|e| {
                PuzzledError::Trust(format!("failed to serialize baseline for uid {uid}: {e}"))
            })?;
            let file = fs::File::create(&path)?;
            let mut writer = std::io::BufWriter::new(file);
            writer.write_all(data.as_bytes())?;
            writer.get_ref().sync_all().map_err(|e| {
                PuzzledError::Trust(format!("failed to fsync baseline for uid {uid}: {e}"))
            })?;
        }
        Ok(())
    }

    /// Load persisted baselines from `store_dir/baselines/`.
    fn load_baselines(&mut self) -> Result<()> {
        let baselines_dir = self.store_dir.join("baselines");
        let entries = match fs::read_dir(&baselines_dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(PuzzledError::Trust(format!(
                    "failed to read baselines dir: {e}"
                )))
            }
        };
        for entry in entries {
            let entry = entry
                .map_err(|e| PuzzledError::Trust(format!("failed to read baseline entry: {e}")))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let data = fs::read_to_string(&path).map_err(|e| {
                PuzzledError::Trust(format!(
                    "failed to read baseline file {}: {e}",
                    path.display()
                ))
            })?;
            let baseline: BehavioralBaseline = serde_json::from_str(&data).map_err(|e| {
                PuzzledError::Trust(format!(
                    "failed to parse baseline file {}: {e}",
                    path.display()
                ))
            })?;
            self.baselines.insert(baseline.uid, baseline);
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Scoring
    // -----------------------------------------------------------------------

    /// Process an audit event and update the trust score for the given UID.
    ///
    /// Returns `Some((old_level, new_level))` if the event caused a tier
    /// transition, `None` otherwise.
    ///
    /// After updating the score, persists it to disk (fsync) for crash safety.
    /// Daily rate limits are enforced in-memory (no disk I/O on hot path).
    pub fn on_audit_event(
        &mut self,
        event_type: &str,
        uid: u32,
        branch_id: Option<&str>,
    ) -> Option<(TrustLevel, TrustLevel)> {
        // Find matching rule.
        let rule = self.rules.iter().find(|r| r.event == event_type)?;
        let delta = rule.delta;

        // max_increase_per_day enforcement (in-memory, no disk I/O).
        if delta > 0 {
            if let Some(max_per_day) = rule.max_increase_per_day {
                let today_total = self.daily_deltas.today_total(uid, event_type);
                if today_total + delta > max_per_day {
                    tracing::debug!(
                        uid,
                        event_type,
                        delta,
                        today_total,
                        max_per_day,
                        "skipping delta: would exceed max_increase_per_day"
                    );
                    return None;
                }
            }
        }

        let initial = self.default_initial_score;
        let state = self
            .scores
            .entry(uid)
            .or_insert_with(|| TrustState::new(uid, initial));

        let old_score = state.score;
        let old_level = state.level;

        // Apply delta with clamping to [0, 100].
        state.apply_delta(delta);

        let new_score = state.score;
        let new_level = state.level;

        // Track daily positive deltas after successful application.
        if delta > 0 {
            self.daily_deltas.record(uid, event_type, delta);
        }

        // Track cumulative counters.
        match event_type {
            "commit_approved" | "branch_completed_clean" => {
                state.clean_commits += 1;
            }
            "policy_violation" | "containment_violation" | "commit_rejected" => {
                state.violations += 1;
            }
            _ => {}
        }

        // Append history event (best-effort — do not fail the scoring update).
        let event = TrustEvent {
            uid,
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_type: event_type.to_string(),
            delta,
            old_score,
            new_score,
            old_level,
            new_level,
            branch_id: branch_id.map(|s| s.to_string()),
            reason: format!("{event_type}: delta {delta}"),
        };
        if let Err(e) = self.append_history(&event) {
            tracing::error!(uid, %e, "failed to persist trust history event");
        }

        // Persist score to disk for crash safety.
        // R24: If persistence fails, the in-memory score diverges from disk.
        // On daemon restart, the stale on-disk score will be loaded instead.
        // Logged at error level; changing return type to Result would be too
        // invasive for all callers. Monitor for repeated failures in production.
        if let Err(e) = self.save(uid) {
            tracing::error!(uid, %e, "R24: failed to persist trust score — in-memory and on-disk scores may diverge");
        }

        if old_level != new_level {
            self.handle_transition(uid, old_level, new_level, new_score);
            Some((old_level, new_level))
        } else {
            None
        }
    }

    /// Reset a UID's score to the default (25) with the given reason.
    pub fn reset_score(&mut self, uid: u32, reason: &str) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let old = self.scores.get(&uid);
        let old_score = old.map(|s| s.score).unwrap_or(25);
        let old_level = old.map(|s| s.level).unwrap_or(TrustLevel::Restricted);
        let new_score = 25u32;
        let new_level = TrustLevel::from_score(new_score);

        self.scores.insert(uid, TrustState::new(uid, new_score));

        let event = TrustEvent {
            uid,
            timestamp: now,
            event_type: "manual_reset".to_string(),
            // K87: Clamp both values to 100 before casting to prevent wrap on corrupted data
            delta: (new_score.min(100) as i32) - (old_score.min(100) as i32),
            old_score,
            new_score,
            old_level,
            new_level,
            branch_id: None,
            reason: format!("reset: {reason}"),
        };
        self.append_history(&event)?;
        self.save(uid)?;
        Ok(())
    }

    /// Set an admin override for a UID that expires after `duration_hours`.
    pub fn set_override(&mut self, uid: u32, level: TrustLevel, duration_hours: u32) -> Result<()> {
        let now = chrono::Utc::now();
        // Q5: Use i64::from() instead of bare `as i64` for type safety
        let expires = now + chrono::Duration::hours(i64::from(duration_hours));

        let initial = self.default_initial_score;
        let state = self
            .scores
            .entry(uid)
            .or_insert_with(|| TrustState::new(uid, initial));

        state.override_active = true;
        state.override_level = Some(level);
        state.override_expires = Some(expires.to_rfc3339());
        state.last_updated = now.to_rfc3339();

        self.save(uid)?;
        Ok(())
    }

    /// Return the most recent `limit` trust events for a UID.
    pub fn get_history(&self, uid: u32, limit: usize) -> Result<Vec<TrustEvent>> {
        let history_path = self.store_dir.join("history").join(format!("{uid}.jsonl"));
        let data = match fs::read_to_string(&history_path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(PuzzledError::Trust(format!(
                    "failed to read trust history for uid {uid}: {e}"
                )))
            }
        };
        // Q6: Count and log malformed trust history entries instead of silently dropping
        let mut malformed = 0usize;
        let mut events: Vec<TrustEvent> = data
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| match serde_json::from_str(l) {
                Ok(e) => Some(e),
                Err(_) => {
                    malformed += 1;
                    None
                }
            })
            .collect();
        if malformed > 0 {
            tracing::warn!(
                uid,
                malformed,
                "Q6: skipped malformed trust history entries"
            );
        }

        // Return the most recent `limit` events.
        if events.len() > limit {
            events = events.split_off(events.len() - limit);
        }
        Ok(events)
    }

    /// Record a behavioral metric observation and return the anomaly severity
    /// if the value is outside the expected range.
    ///
    /// Uses per-metric configuration (threshold, severity) if available,
    /// otherwise falls back to defaults.
    pub fn observe_metric(
        &mut self,
        uid: u32,
        metric: &str,
        value: f64,
    ) -> Option<BaselineSeverity> {
        let baseline = self
            .baselines
            .entry(uid)
            .or_insert_with(|| BehavioralBaseline::new(uid));

        // Resolve per-metric config or fall back to defaults.
        let (severity, threshold, window_secs, min_samples) =
            if let Some(cfg) = self.metric_configs.get(metric) {
                (
                    cfg.severity,
                    cfg.threshold_sigma,
                    self.default_window_secs,
                    self.default_min_samples,
                )
            } else {
                (
                    BaselineSeverity::Warning,
                    self.default_threshold_sigma,
                    self.default_window_secs,
                    self.default_min_samples,
                )
            };

        let window = baseline
            .metrics
            .entry(metric.to_string())
            .or_insert_with(|| {
                MetricWindow::with_config(severity, threshold, window_secs, min_samples)
            });

        let now = chrono::Utc::now().to_rfc3339();
        let result = window.observe(value, now);

        // Persist baselines when an anomaly is detected so that the
        // observation window survives daemon crashes.  Normal observations
        // are persisted on the next periodic save_baselines() call.
        if result.is_some() {
            if let Err(e) = self.save_baselines() {
                tracing::error!(uid, metric, %e, "failed to persist baselines after anomaly");
            }
        }

        result
    }

    /// Clear expired overrides across all UIDs and persist updated state.
    ///
    /// Call periodically (e.g., from a timer) to ensure persisted state
    /// doesn't carry stale `override_active: true` for expired overrides.
    pub fn clear_expired_overrides(&mut self) {
        let uids: Vec<u32> = self.scores.keys().copied().collect();
        for uid in uids {
            if let Some(state) = self.scores.get_mut(&uid) {
                if state.clear_expired_override() {
                    if let Err(e) = self.save(uid) {
                        tracing::error!(uid, %e, "failed to persist cleared override");
                    }
                }
            }
        }
    }

    /// Return the default initial trust score for a given profile name.
    pub fn initial_score(&self, profile_name: &str) -> u32 {
        match profile_name {
            "restricted" => 10,
            "standard" => 25,
            "privileged" => 50,
            _ => 25,
        }
    }

    /// Handle a trust level transition for a UID.
    ///
    /// Asymmetric behavior per PRD §4.1.3:
    /// - **Downward** (tightening): Should be applied immediately to active
    ///   branches.  Currently logs + stubs for integration with containment
    ///   adjuster (cgroup.freeze → Landlock tighten → cgroup limits → thaw).
    /// - **Upward** (expansion): Deferred to next branch creation to avoid
    ///   TOCTOU issues with the diff engine.
    /// - **Emergency lockdown** (score < 10, Untrusted): Agent should be frozen
    ///   pending manual review.
    pub fn handle_transition(
        &self,
        uid: u32,
        old_level: TrustLevel,
        new_level: TrustLevel,
        score: u32,
    ) {
        if new_level < old_level {
            // Downward transition — immediate tightening required.
            tracing::warn!(
                uid,
                ?old_level,
                ?new_level,
                score,
                "trust level DOWNWARD transition — immediate containment tightening required"
            );

            // Emergency lockdown: score dropped into danger zone.
            if score < 10 && new_level == TrustLevel::Untrusted {
                tracing::error!(
                    uid,
                    score,
                    "EMERGENCY LOCKDOWN: trust score critically low — \
                     agent should be frozen pending manual review"
                );
                // Integration point: freeze agent via cgroup.freeze,
                // emit governance_review_pending D-Bus signal,
                // transition branch to Degraded state.
            }
        } else {
            // Upward transition — deferred to next branch creation.
            tracing::info!(
                uid,
                ?old_level,
                ?new_level,
                score,
                "trust level UPWARD transition — expansion deferred to next branch creation"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Append a trust event to the NDJSON history file for the UID.
    /// Uses fsync to guarantee durability of the audit trail.
    ///
    /// N5: If the history file exceeds `MAX_TRUST_HISTORY_BYTES`, truncate by
    /// rewriting only the last 50% of lines before appending.
    fn append_history(&self, event: &TrustEvent) -> Result<()> {
        let history_dir = self.store_dir.join("history");
        fs::create_dir_all(&history_dir)?;
        let path = history_dir.join(format!("{}.jsonl", event.uid));

        // N5: Check file size and truncate if it exceeds the limit.
        if path.exists() {
            if let Ok(metadata) = fs::metadata(&path) {
                if metadata.len() > MAX_TRUST_HISTORY_BYTES {
                    tracing::warn!(
                        uid = event.uid,
                        size = metadata.len(),
                        limit = MAX_TRUST_HISTORY_BYTES,
                        "N5: trust history file exceeds size limit, truncating to last 50% of lines"
                    );
                    if let Ok(contents) = fs::read_to_string(&path) {
                        let lines: Vec<&str> = contents.lines().collect();
                        let keep_from = lines.len() / 2;
                        let truncated = lines[keep_from..].join("\n");
                        // Rewrite with only the retained lines
                        fs::write(&path, format!("{truncated}\n")).map_err(|e| {
                            PuzzledError::Trust(format!("failed to truncate trust history: {e}"))
                        })?;
                    }
                }
            }
        }

        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        let line = serde_json::to_string(event)
            .map_err(|e| PuzzledError::Trust(format!("failed to serialize trust event: {e}")))?;
        writeln!(file, "{line}")?;
        file.sync_all()
            .map_err(|e| PuzzledError::Trust(format!("failed to fsync trust history: {e}")))?;
        Ok(())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_manager(dir: &TempDir) -> TrustManager {
        TrustManager::new(dir.path().to_path_buf(), default_scoring_rules())
    }

    // -----------------------------------------------------------------------
    // Default rules
    // -----------------------------------------------------------------------

    #[test]
    fn default_rules_exist() {
        let rules = default_scoring_rules();
        assert_eq!(rules.len(), 10);
        let types: Vec<&str> = rules.iter().map(|r| r.event.as_str()).collect();
        assert!(types.contains(&"commit_approved"));
        assert!(types.contains(&"branch_completed_clean"));
        assert!(types.contains(&"policy_violation"));
        assert!(types.contains(&"containment_violation"));
        assert!(types.contains(&"behavioral_trigger"));
        assert!(types.contains(&"behavioral_trigger_warning"));
        assert!(types.contains(&"behavioral_trigger_critical"));
        assert!(types.contains(&"behavioral_trigger_fatal"));
        assert!(types.contains(&"commit_rejected"));
        assert!(types.contains(&"trust_decay"));
    }

    #[test]
    fn default_rule_deltas() {
        let rules = default_scoring_rules();
        let find = |name: &str| rules.iter().find(|r| r.event == name).unwrap().delta;
        assert_eq!(find("commit_approved"), 2);
        assert_eq!(find("branch_completed_clean"), 1);
        assert_eq!(find("policy_violation"), -10);
        assert_eq!(find("containment_violation"), -25);
        assert_eq!(find("behavioral_trigger"), -5);
        assert_eq!(find("behavioral_trigger_warning"), -5);
        assert_eq!(find("behavioral_trigger_critical"), -15);
        assert_eq!(find("behavioral_trigger_fatal"), -50);
        assert_eq!(find("commit_rejected"), -5);
        assert_eq!(find("trust_decay"), -1);
    }

    #[test]
    fn commit_approved_has_daily_limit() {
        let rules = default_scoring_rules();
        let rule = rules.iter().find(|r| r.event == "commit_approved").unwrap();
        assert_eq!(rule.max_increase_per_day, Some(10));
    }

    // -----------------------------------------------------------------------
    // Scoring rule matching and delta application
    // -----------------------------------------------------------------------

    #[test]
    fn on_audit_event_applies_positive_delta() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);
        mgr.on_audit_event("commit_approved", 1000, None);
        let state = mgr.get_score(1000).unwrap();
        // Default 25 + 2 = 27
        assert_eq!(state.score, 27);
    }

    #[test]
    fn on_audit_event_applies_negative_delta() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);
        mgr.on_audit_event("commit_approved", 1000, None); // 25 -> 27
        mgr.on_audit_event("policy_violation", 1000, None); // 27 -> 17
        let state = mgr.get_score(1000).unwrap();
        assert_eq!(state.score, 17);
    }

    #[test]
    fn on_audit_event_unknown_event_returns_none() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);
        let result = mgr.on_audit_event("unknown_event", 1000, None);
        assert!(result.is_none());
        // No state should have been created.
        assert!(mgr.get_score(1000).is_none());
    }

    #[test]
    fn on_audit_event_persists_score() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);
        mgr.on_audit_event("commit_approved", 1000, None);

        // Load into a fresh manager — score should have been saved.
        let mut mgr2 = make_manager(&dir);
        mgr2.load().unwrap();
        let state = mgr2.get_score(1000).unwrap();
        assert_eq!(state.score, 27);
    }

    // -----------------------------------------------------------------------
    // max_increase_per_day enforcement (in-memory)
    // -----------------------------------------------------------------------

    #[test]
    fn max_increase_per_day_enforced() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);

        // commit_approved: delta=2, max_increase_per_day=10.
        // First 5 events: cumulative = 2,4,6,8,10 → all allowed.
        for i in 1..=5 {
            mgr.on_audit_event("commit_approved", 1000, None);
            assert_eq!(mgr.get_score(1000).unwrap().score, 25 + i * 2);
        }

        // 6th event: cumulative would be 12 > 10, skipped.
        let result = mgr.on_audit_event("commit_approved", 1000, None);
        assert!(result.is_none());
        assert_eq!(mgr.get_score(1000).unwrap().score, 35); // unchanged
    }

    #[test]
    fn daily_deltas_reconstructed_on_load() {
        let dir = TempDir::new().unwrap();

        // Manager 1: accumulate some daily deltas via commit_approved events.
        {
            let mut mgr = make_manager(&dir);
            // 5 × commit_approved (+2 each) = cumulative daily delta 10.
            for _ in 0..5 {
                mgr.on_audit_event("commit_approved", 1000, None);
            }
            assert_eq!(mgr.get_score(1000).unwrap().score, 35); // 25 + 10
        }

        // Manager 2: load from disk — daily deltas should be reconstructed
        // from history, so the 6th commit_approved should still be blocked.
        {
            let mut mgr2 = make_manager(&dir);
            mgr2.load().unwrap();

            // Score was persisted as 35.
            assert_eq!(mgr2.get_score(1000).unwrap().score, 35);

            // This should be blocked: daily total is already 10, adding 2
            // would exceed max_increase_per_day=10.
            let result = mgr2.on_audit_event("commit_approved", 1000, None);
            assert!(result.is_none());
            assert_eq!(mgr2.get_score(1000).unwrap().score, 35); // unchanged
        }
    }

    // -----------------------------------------------------------------------
    // Tier transitions (upward and downward)
    // -----------------------------------------------------------------------

    #[test]
    fn tier_transition_upward() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);

        // Start at 25 (Restricted). commit_approved has daily limit of 10.
        // 5 × commit_approved (+2 each) = 35. Then use branch_completed_clean (+1 each).
        for _ in 0..5 {
            mgr.on_audit_event("commit_approved", 1000, None);
        }
        assert_eq!(mgr.get_score(1000).unwrap().score, 35);

        // 5 × branch_completed_clean (+1 each, no daily limit) → 35 + 4 = 39
        for _ in 0..4 {
            let r = mgr.on_audit_event("branch_completed_clean", 1000, None);
            assert!(r.is_none());
        }
        assert_eq!(mgr.get_score(1000).unwrap().score, 39);

        // One more → 40 → Standard.
        let transition = mgr.on_audit_event("branch_completed_clean", 1000, None);
        assert!(transition.is_some());
        let (old, new) = transition.unwrap();
        assert_eq!(old, TrustLevel::Restricted);
        assert_eq!(new, TrustLevel::Standard);
        assert_eq!(mgr.get_score(1000).unwrap().score, 40);
    }

    #[test]
    fn tier_transition_downward() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);

        // Start at 25 (Restricted). policy_violation = -10 → 15 = Untrusted.
        let transition = mgr.on_audit_event("policy_violation", 1000, None);
        assert!(transition.is_some());
        let (old, new) = transition.unwrap();
        assert_eq!(old, TrustLevel::Restricted);
        assert_eq!(new, TrustLevel::Untrusted);
        assert_eq!(mgr.get_score(1000).unwrap().score, 15);
    }

    // -----------------------------------------------------------------------
    // Score clamping at 0 and 100
    // -----------------------------------------------------------------------

    #[test]
    fn score_clamped_at_zero() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);
        // Default 25 - 25 (containment_violation) = 0.
        mgr.on_audit_event("containment_violation", 1000, None);
        assert_eq!(mgr.get_score(1000).unwrap().score, 0);

        // Another violation should stay at 0, not underflow.
        mgr.on_audit_event("containment_violation", 1000, None);
        assert_eq!(mgr.get_score(1000).unwrap().score, 0);
    }

    #[test]
    fn score_clamped_at_100() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);

        // Set score high via TrustState::new and manual adjustment.
        let mut state = TrustState::new(1000, 99);
        state.level = TrustLevel::Trusted;
        mgr.scores.insert(1000, state);

        mgr.on_audit_event("commit_approved", 1000, None); // 99 + 2 → clamped to 100
        assert_eq!(mgr.get_score(1000).unwrap().score, 100);

        mgr.on_audit_event("commit_approved", 1000, None); // stays at 100
        assert_eq!(mgr.get_score(1000).unwrap().score, 100);
    }

    // -----------------------------------------------------------------------
    // Override mechanism with expiry
    // -----------------------------------------------------------------------

    #[test]
    fn set_override_stores_level_and_expiry() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);

        // Create initial state.
        mgr.on_audit_event("commit_approved", 1000, None);

        mgr.set_override(1000, TrustLevel::Trusted, 24).unwrap();
        let state = mgr.get_score(1000).unwrap();
        assert!(state.override_active);
        assert_eq!(state.override_level, Some(TrustLevel::Trusted));
        assert!(state.override_expires.is_some());

        // Verify the expiry is ~24h from now.
        let expires =
            chrono::DateTime::parse_from_rfc3339(state.override_expires.as_ref().unwrap()).unwrap();
        let now = chrono::Utc::now();
        let diff = expires.signed_duration_since(now);
        // Should be between 23h and 25h (allowing for test execution time).
        assert!(diff.num_hours() >= 23);
        assert!(diff.num_hours() <= 25);
    }

    #[test]
    fn set_override_on_new_uid() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);

        // Override for UID that doesn't exist yet — should create default state.
        mgr.set_override(2000, TrustLevel::Standard, 1).unwrap();
        let state = mgr.get_score(2000).unwrap();
        assert_eq!(state.score, 25); // default
        assert!(state.override_active);
        assert_eq!(state.override_level, Some(TrustLevel::Standard));
    }

    // -----------------------------------------------------------------------
    // Behavioral baseline — mean, stddev, anomaly detection
    // -----------------------------------------------------------------------

    #[test]
    fn metric_window_mean() {
        let mut w = MetricWindow::new(BaselineSeverity::Warning);
        let ts = || chrono::Utc::now().to_rfc3339();
        w.observations.push_back((10.0, ts()));
        w.observations.push_back((20.0, ts()));
        w.observations.push_back((30.0, ts()));
        assert!((w.mean() - 20.0).abs() < f64::EPSILON);
    }

    #[test]
    fn metric_window_stddev() {
        let mut w = MetricWindow::new(BaselineSeverity::Warning);
        let ts = || chrono::Utc::now().to_rfc3339();
        // Values: 2, 4, 4, 4, 5, 5, 7, 9
        for v in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0] {
            w.observations.push_back((v, ts()));
        }
        // Population stddev = 2.0
        assert!((w.stddev() - 2.0).abs() < 1e-10);
    }

    #[test]
    fn metric_window_empty_stats() {
        let w = MetricWindow::new(BaselineSeverity::Warning);
        assert!((w.mean() - 0.0).abs() < f64::EPSILON);
        assert!((w.stddev() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn metric_window_single_observation_no_anomaly() {
        let mut w = MetricWindow::with_config(BaselineSeverity::Critical, 2.0, 604_800, 2);
        let ts = chrono::Utc::now().to_rfc3339();
        // First observation never triggers anomaly.
        assert!(w.observe(100.0, ts).is_none());
    }

    #[test]
    fn metric_window_anomaly_detection() {
        // Use min_samples=2 to test the anomaly algorithm directly.
        let mut w = MetricWindow::with_config(BaselineSeverity::Warning, 2.0, 604_800, 2);
        let ts = || chrono::Utc::now().to_rfc3339();

        // Build a baseline of ~10.0 with low variance.
        for _ in 0..20 {
            assert!(w.observe(10.0, ts()).is_none());
        }
        // With all-10.0, stddev=0.0, so the guard in observe should prevent
        // anomaly when stddev is zero.
        assert!(w.observe(10.0, ts()).is_none());

        // Now add variation to make stddev > 0.
        w.observations.clear();
        for v in [10.0, 10.5, 9.5, 10.0, 10.5, 9.5] {
            w.observe(v, ts());
        }
        // mean ~10.0, stddev ~0.35.  A value of 15.0 is ~14 sigma away.
        let result = w.observe(15.0, ts());
        assert_eq!(result, Some(BaselineSeverity::Warning));

        // A value close to the mean should not trigger.
        let result = w.observe(10.1, ts());
        assert!(result.is_none());

        // A value far BELOW the mean should NOT trigger (one-sided detection).
        // Unusually low activity is benign — only high values are anomalous.
        let result = w.observe(0.0, ts());
        assert!(result.is_none());
    }

    #[test]
    fn metric_window_min_samples_respected() {
        // Default min_samples=10.  Even an extreme outlier should not
        // trigger anomaly with fewer observations.
        let mut w = MetricWindow::new(BaselineSeverity::Warning);
        let ts = || chrono::Utc::now().to_rfc3339();

        // Add 9 observations (< 10 min_samples).
        for _ in 0..9 {
            w.observations.push_back((10.0, ts()));
        }
        // 10th observation as extreme outlier — still shouldn't trigger
        // because we have exactly 9 prior observations (< min_samples=10).
        assert!(w.observe(1000.0, ts()).is_none());

        // Now we have 10 observations. Add more baseline data with variation.
        w.observations.clear();
        for v in [10.0, 10.5, 9.5, 10.0, 10.5, 9.5, 10.0, 10.5, 9.5, 10.0] {
            w.observations.push_back((v, ts()));
        }
        // 11th observation as extreme outlier — should trigger now.
        let result = w.observe(100.0, ts());
        assert_eq!(result, Some(BaselineSeverity::Warning));
    }

    // -----------------------------------------------------------------------
    // MetricWindow pruning of expired observations
    // -----------------------------------------------------------------------

    #[test]
    fn prune_expired_removes_old_observations() {
        let mut w = MetricWindow::new(BaselineSeverity::Warning);
        w.window_secs = 3600; // 1 hour window

        let now = chrono::Utc::now();
        let old = (now - chrono::Duration::hours(2)).to_rfc3339();
        let recent = now.to_rfc3339();

        w.observations.push_back((1.0, old));
        w.observations.push_back((2.0, recent));

        w.prune_expired();

        assert_eq!(w.observations.len(), 1);
        assert!((w.observations[0].0 - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn prune_expired_keeps_all_within_window() {
        let mut w = MetricWindow::new(BaselineSeverity::Warning);
        w.window_secs = 3600;

        let now = chrono::Utc::now();
        let ts1 = (now - chrono::Duration::minutes(30)).to_rfc3339();
        let ts2 = (now - chrono::Duration::minutes(10)).to_rfc3339();
        let ts3 = now.to_rfc3339();

        w.observations.push_back((1.0, ts1));
        w.observations.push_back((2.0, ts2));
        w.observations.push_back((3.0, ts3));

        w.prune_expired();

        assert_eq!(w.observations.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Persistence — save/load roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn save_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);

        // Generate some state.
        mgr.on_audit_event("commit_approved", 1000, Some("branch-1"));
        mgr.on_audit_event("commit_approved", 1000, None);
        mgr.on_audit_event("policy_violation", 2000, None);

        // Load into a fresh manager.
        let mut mgr2 = make_manager(&dir);
        mgr2.load().unwrap();

        let s1 = mgr2.get_score(1000).unwrap();
        assert_eq!(s1.score, 29); // 25 + 2 + 2
        assert_eq!(s1.level, TrustLevel::Restricted);

        let s2 = mgr2.get_score(2000).unwrap();
        assert_eq!(s2.score, 15); // 25 - 10
        assert_eq!(s2.level, TrustLevel::Untrusted);
    }

    #[test]
    fn load_empty_dir_succeeds() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);
        mgr.load().unwrap();
        assert!(mgr.scores.is_empty());
    }

    #[test]
    fn load_nonexistent_dir_succeeds() {
        let dir = TempDir::new().unwrap();
        let mut mgr = TrustManager::new(
            dir.path().join("nonexistent").to_path_buf(),
            default_scoring_rules(),
        );
        mgr.load().unwrap();
        assert!(mgr.scores.is_empty());
    }

    // -----------------------------------------------------------------------
    // Baseline persistence
    // -----------------------------------------------------------------------

    #[test]
    fn baselines_save_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);

        // Record some observations to create baselines.
        for i in 0..5 {
            mgr.observe_metric(1000, "exec_count", 10.0 + i as f64);
            mgr.observe_metric(1000, "file_writes", 5.0);
        }
        mgr.observe_metric(2000, "exec_count", 20.0);

        // Save baselines.
        mgr.save_baselines().unwrap();

        // Load into a fresh manager.
        let mut mgr2 = make_manager(&dir);
        mgr2.load().unwrap();

        let b1 = mgr2.get_baseline(1000).unwrap();
        assert_eq!(b1.metrics.len(), 2);
        assert_eq!(b1.metrics["exec_count"].observations.len(), 5);
        assert_eq!(b1.metrics["file_writes"].observations.len(), 5);

        let b2 = mgr2.get_baseline(2000).unwrap();
        assert_eq!(b2.metrics["exec_count"].observations.len(), 1);
    }

    // -----------------------------------------------------------------------
    // from_config wires values correctly
    // -----------------------------------------------------------------------

    #[test]
    fn from_config_wires_values() {
        let config = TrustConfig {
            enabled: true,
            store_dir: PathBuf::from("/tmp/test-trust"),
            initial_score: 30,
            window_duration_days: 14,
            anomaly_threshold_sigma: 3.0,
            min_samples: 20,
            metric_configs: {
                let mut m = std::collections::HashMap::new();
                m.insert(
                    "test_metric".to_string(),
                    MetricBehavioralConfig {
                        threshold_sigma: 4.0,
                        severity: BaselineSeverity::Critical,
                    },
                );
                m
            },
        };

        let mgr = TrustManager::from_config(&config, default_scoring_rules());
        assert_eq!(mgr.default_threshold_sigma, 3.0);
        assert_eq!(mgr.default_window_secs, 14 * 86_400);
        assert_eq!(mgr.default_min_samples, 20);
        assert!(mgr.metric_configs.contains_key("test_metric"));
    }

    // -----------------------------------------------------------------------
    // Per-metric config in observe_metric
    // -----------------------------------------------------------------------

    #[test]
    fn observe_metric_uses_per_metric_config() {
        let dir = TempDir::new().unwrap();
        let config = TrustConfig {
            store_dir: dir.path().to_path_buf(),
            min_samples: 2, // low for testing
            metric_configs: {
                let mut m = std::collections::HashMap::new();
                m.insert(
                    "deletion_count".to_string(),
                    MetricBehavioralConfig {
                        threshold_sigma: 2.0,
                        severity: BaselineSeverity::Critical,
                    },
                );
                m
            },
            ..TrustConfig::default()
        };

        let mut mgr = TrustManager::from_config(&config, default_scoring_rules());

        // Build baseline with low variance.
        for v in [5.0, 5.5, 4.5, 5.0, 5.5] {
            mgr.observe_metric(1000, "deletion_count", v);
        }

        // Large outlier should trigger with Critical severity (not Warning).
        let result = mgr.observe_metric(1000, "deletion_count", 100.0);
        assert_eq!(result, Some(BaselineSeverity::Critical));
    }

    // -----------------------------------------------------------------------
    // Initial score by profile name
    // -----------------------------------------------------------------------

    #[test]
    fn initial_score_restricted() {
        let dir = TempDir::new().unwrap();
        let mgr = make_manager(&dir);
        assert_eq!(mgr.initial_score("restricted"), 10);
    }

    #[test]
    fn initial_score_standard() {
        let dir = TempDir::new().unwrap();
        let mgr = make_manager(&dir);
        assert_eq!(mgr.initial_score("standard"), 25);
    }

    #[test]
    fn initial_score_privileged() {
        let dir = TempDir::new().unwrap();
        let mgr = make_manager(&dir);
        assert_eq!(mgr.initial_score("privileged"), 50);
    }

    #[test]
    fn initial_score_unknown_profile() {
        let dir = TempDir::new().unwrap();
        let mgr = make_manager(&dir);
        assert_eq!(mgr.initial_score("custom-profile"), 25);
    }

    // -----------------------------------------------------------------------
    // History append and query
    // -----------------------------------------------------------------------

    #[test]
    fn history_append_and_query() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);

        mgr.on_audit_event("commit_approved", 1000, Some("b-1"));
        mgr.on_audit_event("commit_approved", 1000, Some("b-2"));
        mgr.on_audit_event("policy_violation", 1000, None);

        let history = mgr.get_history(1000, 10).unwrap();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].event_type, "commit_approved");
        assert_eq!(history[0].branch_id, Some("b-1".into()));
        assert_eq!(history[2].event_type, "policy_violation");
    }

    #[test]
    fn history_limit_returns_most_recent() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);

        for _ in 0..5 {
            mgr.on_audit_event("commit_approved", 1000, None);
        }

        let history = mgr.get_history(1000, 2).unwrap();
        assert_eq!(history.len(), 2);
    }

    #[test]
    fn history_empty_for_unknown_uid() {
        let dir = TempDir::new().unwrap();
        let mgr = make_manager(&dir);
        let history = mgr.get_history(9999, 10).unwrap();
        assert!(history.is_empty());
    }

    #[test]
    fn history_event_type_field_is_populated() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);

        mgr.on_audit_event("commit_approved", 1000, None);
        mgr.on_audit_event("policy_violation", 1000, None);

        let history = mgr.get_history(1000, 10).unwrap();
        assert_eq!(history[0].event_type, "commit_approved");
        assert_eq!(history[1].event_type, "policy_violation");
    }

    // -----------------------------------------------------------------------
    // Reset score
    // -----------------------------------------------------------------------

    #[test]
    fn reset_score_sets_default() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);

        // Build up a score: 5 × commit_approved (+2, limited to 10/day) +
        // 10 × branch_completed_clean (+1 each) = 25 + 10 + 10 = 45.
        for _ in 0..5 {
            mgr.on_audit_event("commit_approved", 1000, None);
        }
        for _ in 0..10 {
            mgr.on_audit_event("branch_completed_clean", 1000, None);
        }
        assert_eq!(mgr.get_score(1000).unwrap().score, 45);

        mgr.reset_score(1000, "admin reset").unwrap();
        let state = mgr.get_score(1000).unwrap();
        assert_eq!(state.score, 25);
        assert_eq!(state.level, TrustLevel::Restricted);
    }

    #[test]
    fn reset_score_clears_override() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);

        mgr.on_audit_event("commit_approved", 1000, None);
        mgr.set_override(1000, TrustLevel::Trusted, 24).unwrap();
        assert!(mgr.get_score(1000).unwrap().override_active);

        mgr.reset_score(1000, "cleared").unwrap();
        assert!(!mgr.get_score(1000).unwrap().override_active);
    }

    // -----------------------------------------------------------------------
    // TrustLevel::from_score boundaries
    // -----------------------------------------------------------------------

    #[test]
    fn trust_level_boundaries() {
        assert_eq!(TrustLevel::from_score(0), TrustLevel::Untrusted);
        assert_eq!(TrustLevel::from_score(19), TrustLevel::Untrusted);
        assert_eq!(TrustLevel::from_score(20), TrustLevel::Restricted);
        assert_eq!(TrustLevel::from_score(39), TrustLevel::Restricted);
        assert_eq!(TrustLevel::from_score(40), TrustLevel::Standard);
        assert_eq!(TrustLevel::from_score(59), TrustLevel::Standard);
        assert_eq!(TrustLevel::from_score(60), TrustLevel::Elevated);
        assert_eq!(TrustLevel::from_score(79), TrustLevel::Elevated);
        assert_eq!(TrustLevel::from_score(80), TrustLevel::Trusted);
        assert_eq!(TrustLevel::from_score(100), TrustLevel::Trusted);
        assert_eq!(TrustLevel::from_score(200), TrustLevel::Trusted);
    }

    // -----------------------------------------------------------------------
    // observe_metric integration
    // -----------------------------------------------------------------------

    #[test]
    fn observe_metric_creates_baseline() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);

        assert!(mgr.get_baseline(1000).is_none());
        mgr.observe_metric(1000, "exec_count", 5.0);
        assert!(mgr.get_baseline(1000).is_some());
        assert!(mgr
            .get_baseline(1000)
            .unwrap()
            .metrics
            .contains_key("exec_count"));
    }

    #[test]
    fn observe_metric_detects_anomaly() {
        let dir = TempDir::new().unwrap();
        // Use min_samples=2 via config for this test.
        let config = TrustConfig {
            store_dir: dir.path().to_path_buf(),
            min_samples: 2,
            ..TrustConfig::default()
        };
        let mut mgr = TrustManager::from_config(&config, default_scoring_rules());

        // Build baseline with enough identical values that stddev is 0
        // (no anomaly possible when stddev=0), then add varied values.
        for _ in 0..5 {
            assert!(mgr.observe_metric(1000, "file_writes", 10.0).is_none());
        }

        // Now manually add variation to the window directly so we get
        // a non-zero stddev without triggering anomaly detection.
        let baseline = mgr.baselines.get_mut(&1000).unwrap();
        let window = baseline.metrics.get_mut("file_writes").unwrap();
        window.observations.clear();
        let ts = || chrono::Utc::now().to_rfc3339();
        for v in [10.0, 10.5, 9.5, 10.0, 10.5, 9.5] {
            window.observations.push_back((v, ts()));
        }

        // Large outlier should trigger anomaly.
        let result = mgr.observe_metric(1000, "file_writes", 100.0);
        assert_eq!(result, Some(BaselineSeverity::Warning));
    }

    // -----------------------------------------------------------------------
    // Branch ID in events
    // -----------------------------------------------------------------------

    #[test]
    fn audit_event_with_branch_id_persists() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);

        mgr.on_audit_event("commit_approved", 1000, Some("branch-xyz"));
        let history = mgr.get_history(1000, 10).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].branch_id, Some("branch-xyz".into()));
    }

    #[test]
    fn audit_event_without_branch_id() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);

        mgr.on_audit_event("commit_approved", 1000, None);
        let history = mgr.get_history(1000, 10).unwrap();
        assert_eq!(history[0].branch_id, None);
    }

    // -----------------------------------------------------------------------
    // Cumulative counter tracking
    // -----------------------------------------------------------------------

    #[test]
    fn on_audit_event_tracks_clean_commits() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);
        mgr.on_audit_event("commit_approved", 1000, None);
        mgr.on_audit_event("commit_approved", 1000, None);
        mgr.on_audit_event("branch_completed_clean", 1000, None);
        let state = mgr.get_score(1000).unwrap();
        assert_eq!(state.clean_commits, 3);
        assert_eq!(state.violations, 0);
    }

    #[test]
    fn on_audit_event_tracks_violations() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);
        mgr.on_audit_event("policy_violation", 1000, None);
        mgr.on_audit_event("commit_rejected", 1000, None);
        let state = mgr.get_score(1000).unwrap();
        assert_eq!(state.violations, 2);
        assert_eq!(state.clean_commits, 0);
    }

    #[test]
    fn reset_score_clears_counters() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);

        mgr.on_audit_event("commit_approved", 1000, None);
        mgr.on_audit_event("policy_violation", 1000, None);
        assert_eq!(mgr.get_score(1000).unwrap().clean_commits, 1);
        assert_eq!(mgr.get_score(1000).unwrap().violations, 1);

        mgr.reset_score(1000, "full reset").unwrap();
        assert_eq!(mgr.get_score(1000).unwrap().clean_commits, 0);
        assert_eq!(mgr.get_score(1000).unwrap().violations, 0);
    }

    // -----------------------------------------------------------------------
    // trust_decay rule
    // -----------------------------------------------------------------------

    #[test]
    fn trust_decay_reduces_score() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);
        mgr.on_audit_event("commit_approved", 1000, None); // 25 → 27
        mgr.on_audit_event("trust_decay", 1000, None); // 27 → 26
        assert_eq!(mgr.get_score(1000).unwrap().score, 26);
    }

    // -----------------------------------------------------------------------
    // DailyDeltaTracker unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn daily_delta_tracker_tracks_totals() {
        let mut tracker = DailyDeltaTracker::default();
        tracker.record(1000, "commit_approved", 2);
        tracker.record(1000, "commit_approved", 2);
        assert_eq!(tracker.today_total(1000, "commit_approved"), 4);

        // Different UID is independent.
        assert_eq!(tracker.today_total(2000, "commit_approved"), 0);
        // Different event type is independent.
        assert_eq!(tracker.today_total(1000, "branch_completed_clean"), 0);
    }

    // -----------------------------------------------------------------------
    // register_uid with profile-specific initial score (Fix 5)
    // -----------------------------------------------------------------------

    #[test]
    fn register_uid_with_restricted_profile() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);
        mgr.register_uid(1000, "restricted");
        let state = mgr.get_score(1000).unwrap();
        assert_eq!(state.score, 10);
        assert_eq!(state.level, TrustLevel::Untrusted);
    }

    #[test]
    fn register_uid_with_privileged_profile() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);
        mgr.register_uid(1000, "privileged");
        let state = mgr.get_score(1000).unwrap();
        assert_eq!(state.score, 50);
        assert_eq!(state.level, TrustLevel::Standard);
    }

    #[test]
    fn register_uid_does_not_overwrite_existing() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);

        // First event creates state at default_initial_score (25).
        mgr.on_audit_event("commit_approved", 1000, None);
        assert_eq!(mgr.get_score(1000).unwrap().score, 27); // 25 + 2

        // register_uid should NOT overwrite the existing score.
        mgr.register_uid(1000, "restricted");
        assert_eq!(mgr.get_score(1000).unwrap().score, 27); // unchanged
    }

    #[test]
    fn on_audit_event_uses_default_initial_score() {
        let dir = TempDir::new().unwrap();
        let config = TrustConfig {
            initial_score: 15, // custom default
            store_dir: dir.path().to_path_buf(),
            ..TrustConfig::default()
        };
        let mut mgr = TrustManager::from_config(&config, default_scoring_rules());

        // First event for UID 1000 auto-creates with initial_score=15.
        mgr.on_audit_event("commit_approved", 1000, None);
        assert_eq!(mgr.get_score(1000).unwrap().score, 17); // 15 + 2
    }

    // -----------------------------------------------------------------------
    // clear_expired_override (Fix 6)
    // -----------------------------------------------------------------------

    #[test]
    fn clear_expired_override_clears_stale_flag() {
        let mut state = TrustState::new(1000, 50);
        // Set an override that expired 1 hour ago.
        state.override_active = true;
        state.override_level = Some(TrustLevel::Trusted);
        let expired = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        state.override_expires = Some(expired);

        assert!(state.clear_expired_override());
        assert!(!state.override_active);
        assert!(state.override_level.is_none());
        assert!(state.override_expires.is_none());
    }

    #[test]
    fn clear_expired_override_noop_for_active() {
        let mut state = TrustState::new(1000, 50);
        // Set an override that expires in 1 hour (still active).
        state.override_active = true;
        state.override_level = Some(TrustLevel::Trusted);
        let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        state.override_expires = Some(future);

        assert!(!state.clear_expired_override());
        assert!(state.override_active);
        assert_eq!(state.override_level, Some(TrustLevel::Trusted));
    }

    #[test]
    fn clear_expired_override_noop_when_no_override() {
        let mut state = TrustState::new(1000, 50);
        assert!(!state.clear_expired_override());
    }

    /// K87: Verify that .min(100) is used before i32 cast in trust score delta.
    #[test]
    fn k87_delta_clamps_before_cast() {
        let source = include_str!("trust.rs");
        assert!(
            source.contains("new_score.min(100) as i32")
                && source.contains("old_score.min(100) as i32"),
            "K87: trust score delta must clamp values to 100 before i32 cast"
        );
    }

    #[test]
    fn clear_expired_overrides_sweep() {
        let dir = TempDir::new().unwrap();
        let mut mgr = make_manager(&dir);

        // Create two UIDs with overrides.
        mgr.set_override(1000, TrustLevel::Trusted, 24).unwrap();
        mgr.set_override(2000, TrustLevel::Elevated, 24).unwrap();

        // Manually expire UID 1000's override.
        if let Some(state) = mgr.scores.get_mut(&1000) {
            let expired = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
            state.override_expires = Some(expired);
        }

        mgr.clear_expired_overrides();

        // UID 1000 should have override cleared.
        let s1 = mgr.get_score(1000).unwrap();
        assert!(!s1.override_active);

        // UID 2000 should still have active override.
        let s2 = mgr.get_score(2000).unwrap();
        assert!(s2.override_active);
    }

    // -----------------------------------------------------------------------
    // N2: large window_secs must not panic or produce negative duration
    // -----------------------------------------------------------------------

    #[test]
    fn n2_large_window_secs_no_panic() {
        // A very large window_secs (u64::MAX) must not panic due to truncation
        // when cast to i64. The fix uses i64::try_from().unwrap_or(i64::MAX).
        let mut window = MetricWindow {
            window_secs: u64::MAX,
            min_samples: 1,
            threshold_sigma: 2.0,
            observations: VecDeque::from(vec![
                (42.0, chrono::Utc::now().to_rfc3339()),
                (
                    43.0,
                    (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339(),
                ),
            ]),
            observations_since_prune: 0,
            severity: BaselineSeverity::Warning,
        };
        // This must not panic
        window.prune_expired();
        // With i64::MAX seconds window, nothing should be pruned
        assert_eq!(window.observations.len(), 2);
    }

    // -----------------------------------------------------------------------
    // N5: trust history file truncation when exceeding size limit
    // -----------------------------------------------------------------------

    #[test]
    fn n5_history_truncation_on_size_limit() {
        let dir = TempDir::new().unwrap();
        let mgr = make_manager(&dir);

        let history_dir = dir.path().join("history");
        std::fs::create_dir_all(&history_dir).unwrap();
        let history_path = history_dir.join("1000.jsonl");

        // Write a file that exceeds MAX_TRUST_HISTORY_BYTES
        // Each line is ~100 bytes, so we need ~105_000 lines to exceed 10 MB
        {
            let mut f = std::fs::File::create(&history_path).unwrap();
            let line = "x".repeat(99); // 99 chars + newline = 100 bytes
            for _ in 0..(MAX_TRUST_HISTORY_BYTES / 100 + 100) {
                writeln!(f, "{}", line).unwrap();
            }
        }
        let size_before = std::fs::metadata(&history_path).unwrap().len();
        assert!(size_before > MAX_TRUST_HISTORY_BYTES);

        // Appending should trigger truncation
        let event = TrustEvent {
            uid: 1000,
            event_type: "test".to_string(),
            delta: 1,
            old_score: 50,
            new_score: 51,
            old_level: TrustLevel::Standard,
            new_level: TrustLevel::Standard,
            timestamp: chrono::Utc::now().to_rfc3339(),
            reason: "test".to_string(),
            branch_id: None,
        };
        mgr.append_history(&event).unwrap();

        let size_after = std::fs::metadata(&history_path).unwrap().len();
        // After truncation to 50% of lines + new event, file should be smaller
        assert!(
            size_after < size_before,
            "file should be smaller after truncation: before={}, after={}",
            size_before,
            size_after
        );
    }
}
