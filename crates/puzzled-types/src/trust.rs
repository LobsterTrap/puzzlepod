// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Trust (§4.1 -- Graduated Trust with Behavioral Learning)
// ---------------------------------------------------------------------------

/// Trust level derived from numeric score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Score 0-19.
    Untrusted,
    /// Score 20-39.
    Restricted,
    /// Score 40-59.
    Standard,
    /// Score 60-79.
    Elevated,
    /// Score 80-100.
    Trusted,
}

impl TrustLevel {
    /// Return the trust level corresponding to a numeric score (0-100).
    pub fn from_score(score: u32) -> Self {
        match score {
            0..=19 => TrustLevel::Untrusted,
            20..=39 => TrustLevel::Restricted,
            40..=59 => TrustLevel::Standard,
            60..=79 => TrustLevel::Elevated,
            _ => TrustLevel::Trusted,
        }
    }

    /// Return the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustLevel::Untrusted => "untrusted",
            TrustLevel::Restricted => "restricted",
            TrustLevel::Standard => "standard",
            TrustLevel::Elevated => "elevated",
            TrustLevel::Trusted => "trusted",
        }
    }
}

impl std::fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Persistent trust state for an agent identity (keyed by UID).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustState {
    pub uid: u32,
    pub score: u32,
    pub level: TrustLevel,
    pub clean_commits: u32,
    pub violations: u32,
    pub last_updated: String,
    pub override_active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_expires: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_level: Option<TrustLevel>,
}

impl TrustState {
    /// Create a new trust state with the given initial score.
    pub fn new(uid: u32, initial_score: u32) -> Self {
        let score = initial_score.min(100);
        Self {
            uid,
            score,
            level: TrustLevel::from_score(score),
            clean_commits: 0,
            violations: 0,
            last_updated: chrono::Utc::now().to_rfc3339(),
            override_active: false,
            override_expires: None,
            override_level: None,
        }
    }

    /// Return the effective trust level (accounting for overrides).
    pub fn effective_level(&self) -> TrustLevel {
        if self.override_active {
            if let Some(ref expires) = self.override_expires {
                if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(expires) {
                    if chrono::Utc::now() < exp {
                        return self.override_level.unwrap_or(self.level);
                    }
                }
            }
        }
        self.level
    }

    /// Clear the override if it has expired, returning true if cleared.
    ///
    /// Call this before persisting state or exposing it via D-Bus to avoid
    /// stale `override_active: true` in serialized output.
    pub fn clear_expired_override(&mut self) -> bool {
        if !self.override_active {
            return false;
        }
        if let Some(ref expires) = self.override_expires {
            if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(expires) {
                if chrono::Utc::now() >= exp {
                    self.override_active = false;
                    self.override_level = None;
                    self.override_expires = None;
                    return true;
                }
            }
        }
        false
    }

    /// Apply a score delta, clamping to [0, 100].
    /// S48: Uses saturating_add to prevent wrapping on extreme delta values.
    pub fn apply_delta(&mut self, delta: i32) {
        // F26: Guard against future changes that might allow score > 100,
        // which would cause the `as i32` cast to produce unexpected values
        // if score ever exceeded i32::MAX.
        debug_assert!(self.score <= 100, "F26: trust score out of expected range");
        let new_score = (self.score as i32).saturating_add(delta).clamp(0, 100) as u32;
        self.score = new_score;
        self.level = TrustLevel::from_score(new_score);
        self.last_updated = chrono::Utc::now().to_rfc3339();
    }
}

/// A trust score change event (appended to history).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustEvent {
    pub timestamp: String,
    pub uid: u32,
    /// Machine-readable event type (e.g., "commit_approved", "policy_violation").
    /// Used for structured querying — separate from human-readable `reason`.
    #[serde(default)]
    pub event_type: String,
    pub old_score: u32,
    pub new_score: u32,
    pub old_level: TrustLevel,
    pub new_level: TrustLevel,
    pub delta: i32,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch_id: Option<String>,
}

/// Scoring rule loaded from configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoringRule {
    pub event: String,
    pub delta: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_increase_per_day: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Behavioral baseline severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BaselineSeverity {
    /// Warning-level deviation.
    Warning,
    /// Critical deviation.
    Critical,
    /// Fatal deviation (reserved for future use).
    Fatal,
}
