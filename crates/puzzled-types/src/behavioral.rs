// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};
use zbus::zvariant::Type;

use crate::branch::BranchId;

// ---------------------------------------------------------------------------
// Budget / adaptive escalation
// ---------------------------------------------------------------------------

/// Budget tier for adaptive resource allocation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Type)]
pub enum BudgetTier {
    /// Minimal resources, strict limits.
    #[default]
    Restricted,
    /// Standard allocation after proven clean commits.
    Standard,
    /// Extended allocation for established agents.
    Extended,
}

/// Budget status for a branch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BudgetStatus {
    pub branch_id: BranchId,
    pub tier: BudgetTier,
    pub clean_commits: u32,
    pub violations: u32,
}

// ---------------------------------------------------------------------------
// Behavioral triggers (fanotify)
// ---------------------------------------------------------------------------

/// A behavioral trigger fired by the fanotify monitor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BehavioralTrigger {
    MassDeletion {
        count: u32,
        threshold: u32,
    },
    ExcessiveReads {
        rate: u32,
        threshold: u32,
    },
    CredentialAccess {
        path: String,
    },
    /// Fanotify event queue overflowed — incremental tracking is incomplete.
    /// The diff engine must fall back to a full upper-dir walk for this branch.
    QueueOverflow,
    /// §3.4 G28: Phantom token detected in file write — potential credential leak.
    /// Fired when fanotify detects a write containing `pt_puzzled_*` patterns.
    PhantomTokenLeakage {
        /// File path where the phantom token was written.
        file_path: String,
        /// The phantom token prefix detected (first 16 chars max).
        token_prefix: String,
    },
}
