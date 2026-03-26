// SPDX-License-Identifier: Apache-2.0
//! Adaptive budget engine for agent resource allocation.
//!
//! Agents start in the Restricted tier. After a configurable number of
//! clean commits, they escalate to Standard, then Extended. Any policy
//! violation drops them one tier.
//!
//! Tier changes adjust cgroup resource limits (memory, CPU) and storage
//! quotas dynamically. This implements the "trust through behavior"
//! principle — agents earn more resources by demonstrating safe behavior.

use std::collections::HashMap;

use puzzled_types::{BranchId, BudgetStatus, BudgetTier, ResourceLimits};

/// J1: Safely convert a non-negative f64 to u32, clamping to u32::MAX
/// instead of silently truncating values above 2^32.
fn saturating_f64_to_u32(v: f64) -> u32 {
    if v.is_nan() || v <= 0.0 {
        0
    } else if v >= u32::MAX as f64 {
        u32::MAX
    } else {
        v as u32
    }
}

/// S5: Safely convert a non-negative f64 to u64, clamping to u64::MAX.
/// Handles NaN, infinity, and the imprecision of u64::MAX as f64.
fn saturating_f64_to_u64(v: f64) -> u64 {
    if v.is_nan() || v <= 0.0 {
        0
    } else if v >= u64::MAX as f64 {
        u64::MAX
    } else {
        v as u64
    }
}

/// Thresholds for tier escalation.
const ESCALATE_TO_STANDARD: u32 = 3;
const ESCALATE_TO_EXTENDED: u32 = 10;

/// F13: Maximum number of tracked agent identities to prevent unbounded HashMap growth.
const MAX_TRACKED_AGENTS: usize = 10_000;

/// Manages adaptive budgets for agent branches.
pub struct BudgetManager {
    /// Budget status per agent identity (keyed by profile + UID, not branch).
    agents: HashMap<String, AgentBudget>,
}

/// Budget tracking for a single agent identity.
struct AgentBudget {
    tier: BudgetTier,
    clean_commits: u32,
    violations: u32,
    /// Resource multipliers for each tier.
    tier_multipliers: TierMultipliers,
}

/// Resource multipliers applied per tier.
#[derive(Debug, Clone)]
struct TierMultipliers {
    restricted: f64,
    standard: f64,
    extended: f64,
}

impl Default for TierMultipliers {
    fn default() -> Self {
        Self {
            restricted: 0.5,
            standard: 1.0,
            extended: 2.0,
        }
    }
}

impl Default for BudgetManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BudgetManager {
    /// Create a new budget manager.
    pub fn new() -> Self {
        Self {
            agents: HashMap::new(),
        }
    }

    /// Get or create the budget for an agent identity.
    fn get_or_create(&mut self, agent_key: &str) -> &mut AgentBudget {
        // F13: Bound the agents HashMap to prevent unbounded growth
        if self.agents.len() >= MAX_TRACKED_AGENTS && !self.agents.contains_key(agent_key) {
            tracing::warn!(
                capacity = MAX_TRACKED_AGENTS,
                agent = %agent_key,
                "F13: agent budget tracker at capacity, evicting oldest entries"
            );
            // Evict the first entry to make room
            if let Some(first_key) = self.agents.keys().next().cloned() {
                self.agents.remove(&first_key);
            }
        }
        self.agents
            .entry(agent_key.to_string())
            .or_insert_with(|| AgentBudget {
                tier: BudgetTier::Restricted,
                clean_commits: 0,
                violations: 0,
                tier_multipliers: TierMultipliers::default(),
            })
    }

    /// Apply effective resource limits to the cgroup for a branch.
    ///
    /// Called after tier changes to ensure running cgroups reflect the new tier.
    ///
    /// # Errors
    /// H8: Returns `Err` if any cgroup file write fails — callers must handle
    /// the failure rather than silently proceeding with unenforced limits.
    pub fn apply_tier_limits(
        &self,
        agent_key: &str,
        base_limits: &ResourceLimits,
        cgroup_path: &std::path::Path,
    ) -> Result<(), std::io::Error> {
        let limits = self.effective_limits(agent_key, base_limits);
        let write = |file: &str, value: String| -> Result<(), std::io::Error> {
            let path = cgroup_path.join(file);
            std::fs::write(&path, &value).map_err(|e| {
                // R12: Use error! not warn! — failed cgroup writes mean resource
                // limits are NOT enforced, which is security-relevant.
                tracing::error!(
                    path = %path.display(),
                    value = %value,
                    error = %e,
                    "R12: failed to apply budget tier limit to cgroup — resource limits unenforced"
                );
                e
            })
        };
        write("memory.max", format!("{}", limits.memory_bytes))?;
        write("cpu.weight", format!("{}", limits.cpu_shares.max(1)))?;
        write("pids.max", format!("{}", limits.max_pids.max(4)))?;
        tracing::debug!(
            agent = %agent_key,
            memory = limits.memory_bytes,
            cpu = limits.cpu_shares,
            pids = limits.max_pids,
            "applied budget tier limits to cgroup"
        );
        Ok(())
    }

    /// Record a successful (clean) commit for an agent.
    ///
    /// May trigger tier escalation.
    pub fn record_clean_commit(&mut self, agent_key: &str) -> BudgetTier {
        let budget = self.get_or_create(agent_key);
        budget.clean_commits = budget.clean_commits.saturating_add(1);

        let old_tier = budget.tier;

        // Check for escalation — check Standard first to prevent skipping tiers.
        // An agent at Restricted must escalate to Standard before reaching Extended.
        if budget.clean_commits >= ESCALATE_TO_STANDARD && budget.tier == BudgetTier::Restricted {
            budget.tier = BudgetTier::Standard;
        } else if budget.clean_commits >= ESCALATE_TO_EXTENDED
            && budget.tier == BudgetTier::Standard
        {
            budget.tier = BudgetTier::Extended;
        }

        if budget.tier != old_tier {
            tracing::info!(
                agent = %agent_key,
                from = ?old_tier,
                to = ?budget.tier,
                clean_commits = budget.clean_commits,
                "budget tier escalated"
            );
        }

        budget.tier
    }

    /// Record a policy violation for an agent.
    ///
    /// Drops the agent one tier.
    pub fn record_violation(&mut self, agent_key: &str) -> BudgetTier {
        let budget = self.get_or_create(agent_key);
        budget.violations = budget.violations.saturating_add(1);

        let old_tier = budget.tier;

        // De-escalate one tier
        budget.tier = match budget.tier {
            BudgetTier::Extended => BudgetTier::Standard,
            BudgetTier::Standard => BudgetTier::Restricted,
            BudgetTier::Restricted => BudgetTier::Restricted,
        };

        // M2: Reset clean commit counter to zero on violation.
        // The agent must earn trust from scratch after any de-escalation.
        // Previously this set clean_commits to the threshold for the new tier,
        // which meant a single clean commit could re-escalate immediately.
        budget.clean_commits = 0;

        if budget.tier != old_tier {
            tracing::warn!(
                agent = %agent_key,
                from = ?old_tier,
                to = ?budget.tier,
                violations = budget.violations,
                "budget tier de-escalated due to violation"
            );
        }

        budget.tier
    }

    /// Get the current budget status for an agent.
    pub fn get_status(&self, agent_key: &str, branch_id: &BranchId) -> BudgetStatus {
        if let Some(budget) = self.agents.get(agent_key) {
            BudgetStatus {
                branch_id: branch_id.clone(),
                tier: budget.tier,
                clean_commits: budget.clean_commits,
                violations: budget.violations,
            }
        } else {
            BudgetStatus {
                branch_id: branch_id.clone(),
                tier: BudgetTier::Restricted,
                clean_commits: 0,
                violations: 0,
            }
        }
    }

    /// Compute effective resource limits based on the agent's budget tier.
    ///
    /// Takes the profile's base limits and multiplies by the tier factor.
    pub fn effective_limits(
        &self,
        agent_key: &str,
        base_limits: &ResourceLimits,
    ) -> ResourceLimits {
        let multiplier = if let Some(budget) = self.agents.get(agent_key) {
            match budget.tier {
                BudgetTier::Restricted => budget.tier_multipliers.restricted,
                BudgetTier::Standard => budget.tier_multipliers.standard,
                BudgetTier::Extended => budget.tier_multipliers.extended,
            }
        } else {
            0.5 // Default restricted
        };

        ResourceLimits {
            // S42: Use .max(1) on all float-to-int casts to prevent zero limits
            // that could mean "unlimited" in some kernel contexts (e.g., cgroup).
            // Q7/S5: Clamp float-to-u64 using safe upper bound (2^53 is max exact f64 integer)
            memory_bytes: saturating_f64_to_u64(
                (base_limits.memory_bytes as f64 * multiplier).max(1.0),
            ),
            // J1: Use saturating_f64_to_u32 to clamp to u32::MAX instead of truncating
            cpu_shares: saturating_f64_to_u32(
                (base_limits.cpu_shares as f64 * multiplier).max(1.0),
            ),
            io_weight: saturating_f64_to_u32((base_limits.io_weight as f64 * multiplier).max(1.0)),
            max_pids: saturating_f64_to_u32((base_limits.max_pids as f64 * multiplier).max(4.0)),
            // Q7/S5: Clamp float-to-u64 using safe upper bound
            storage_quota_mb: saturating_f64_to_u64(
                (base_limits.storage_quota_mb as f64 * multiplier).max(1.0),
            ),
            inode_quota: saturating_f64_to_u64(
                (base_limits.inode_quota as f64 * multiplier).max(1.0),
            ),
            max_threads: base_limits.max_threads,
            no_new_privileges: base_limits.no_new_privileges,
            max_files_read: base_limits.max_files_read,
            max_files_written: base_limits.max_files_written,
            max_single_file_size_mb: base_limits.max_single_file_size_mb,
            cpu_quota_us: base_limits.cpu_quota_us,
            memory_high: base_limits.memory_high,
            io_max: base_limits.io_max.clone(),
            max_exec_calls: base_limits.max_exec_calls,
            max_open_fds: base_limits.max_open_fds,
            max_files_deleted: base_limits.max_files_deleted,
            max_total_write_mb: base_limits.max_total_write_mb,
            lifetime_minutes: base_limits.lifetime_minutes,
        }
    }

    /// Generate the agent key from profile name and UID.
    pub fn agent_key(profile: &str, uid: u32) -> String {
        format!("{}:{}", profile, uid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escalation() {
        let mut mgr = BudgetManager::new();
        let key = "test:1000";

        // Initial: Restricted
        let status = mgr.get_status(key, &BranchId::from("b1".to_string()));
        assert_eq!(status.tier, BudgetTier::Restricted);

        // 3 clean commits -> Standard
        for _ in 0..3 {
            mgr.record_clean_commit(key);
        }
        let status = mgr.get_status(key, &BranchId::from("b1".to_string()));
        assert_eq!(status.tier, BudgetTier::Standard);

        // 10 total -> Extended
        for _ in 0..7 {
            mgr.record_clean_commit(key);
        }
        let status = mgr.get_status(key, &BranchId::from("b1".to_string()));
        assert_eq!(status.tier, BudgetTier::Extended);
    }

    #[test]
    fn test_deescalation() {
        let mut mgr = BudgetManager::new();
        let key = "test:1000";

        // Escalate to Extended
        for _ in 0..10 {
            mgr.record_clean_commit(key);
        }
        assert_eq!(
            mgr.get_status(key, &BranchId::from("b1".to_string())).tier,
            BudgetTier::Extended
        );

        // Violation -> Standard
        mgr.record_violation(key);
        assert_eq!(
            mgr.get_status(key, &BranchId::from("b1".to_string())).tier,
            BudgetTier::Standard
        );

        // Another violation -> Restricted
        mgr.record_violation(key);
        assert_eq!(
            mgr.get_status(key, &BranchId::from("b1".to_string())).tier,
            BudgetTier::Restricted
        );
    }

    #[test]
    fn test_effective_limits() {
        let mut mgr = BudgetManager::new();
        let key = "test:1000";

        let base = ResourceLimits {
            memory_bytes: 512 * 1024 * 1024,
            cpu_shares: 100,
            io_weight: 100,
            max_pids: 64,
            storage_quota_mb: 1024,
            inode_quota: 10_000,
            max_threads: None,
            no_new_privileges: None,
            max_files_read: None,
            max_files_written: None,
            max_single_file_size_mb: None,
            cpu_quota_us: None,
            memory_high: None,
            io_max: None,
            max_exec_calls: None,
            max_open_fds: None,
            max_files_deleted: None,
            max_total_write_mb: None,
            lifetime_minutes: None,
        };

        // Restricted: 0.5x
        let limits = mgr.effective_limits(key, &base);
        assert_eq!(limits.memory_bytes, 256 * 1024 * 1024);

        // Escalate to Standard: 1.0x
        for _ in 0..3 {
            mgr.record_clean_commit(key);
        }
        let limits = mgr.effective_limits(key, &base);
        assert_eq!(limits.memory_bytes, 512 * 1024 * 1024);

        // Escalate to Extended: 2.0x
        for _ in 0..7 {
            mgr.record_clean_commit(key);
        }
        let limits = mgr.effective_limits(key, &base);
        assert_eq!(limits.memory_bytes, 1024 * 1024 * 1024);
    }

    #[test]
    fn test_m2_deescalation_resets_clean_commits_to_zero() {
        let mut mgr = BudgetManager::new();
        let key = "test:1000";

        // Escalate to Extended (10 clean commits)
        for _ in 0..10 {
            mgr.record_clean_commit(key);
        }
        assert_eq!(
            mgr.get_status(key, &BranchId::from("b1".to_string())).tier,
            BudgetTier::Extended
        );

        // Violation: Extended -> Standard, clean_commits must be 0
        mgr.record_violation(key);
        let status = mgr.get_status(key, &BranchId::from("b1".to_string()));
        assert_eq!(status.tier, BudgetTier::Standard);
        assert_eq!(
            status.clean_commits, 0,
            "M2: clean_commits must be 0 after de-escalation, not the escalation threshold"
        );

        // Agent needs ESCALATE_TO_EXTENDED (10) more clean commits to get back to Extended
        for _ in 0..9 {
            mgr.record_clean_commit(key);
        }
        assert_eq!(
            mgr.get_status(key, &BranchId::from("b1".to_string())).tier,
            BudgetTier::Standard,
            "should still be Standard after 9 commits (need 10 for Extended)"
        );
        mgr.record_clean_commit(key);
        assert_eq!(
            mgr.get_status(key, &BranchId::from("b1".to_string())).tier,
            BudgetTier::Extended,
            "should escalate to Extended after 10 clean commits from zero"
        );

        // Violation: Extended -> Standard -> Restricted (two violations)
        mgr.record_violation(key);
        assert_eq!(
            mgr.get_status(key, &BranchId::from("b1".to_string()))
                .clean_commits,
            0
        );
        mgr.record_violation(key);
        let status = mgr.get_status(key, &BranchId::from("b1".to_string()));
        assert_eq!(status.tier, BudgetTier::Restricted);
        assert_eq!(
            status.clean_commits, 0,
            "M2: clean_commits must be 0 after de-escalation to Restricted"
        );
    }

    /// S42: Verify float-to-int casts in effective_limits use .max(1)
    /// to prevent zero limits that could mean "unlimited" in kernel contexts.
    #[test]
    fn test_s42_budget_no_zero_limits() {
        let source = include_str!("budget.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // Find the effective_limits method
        let func_start = prod_source
            .find("fn effective_limits(")
            .expect("effective_limits method must exist");
        let body = &prod_source[func_start..];
        let end = body.find("\n    }").unwrap_or(body.len()) + 6;
        let func_body = &body[..end];
        // Every `as u64` and `as u32` cast from float must have .max(1)
        // to prevent zero limits (memory_bytes, storage_quota_mb, inode_quota).
        for line in func_body.lines() {
            let trimmed = line.trim();
            if (trimmed.contains("as u64") || trimmed.contains("as u32"))
                && trimmed.contains("multiplier")
                && !trimmed.starts_with("//")
            {
                assert!(
                    trimmed.contains(".max(") || trimmed.contains(".clamp("),
                    "S42: float-to-int cast must use .max(1) or .clamp() to prevent zero/NaN limits: {}",
                    trimmed
                );
            }
        }
    }

    // ---------------------------------------------------------------
    // agent_key
    // ---------------------------------------------------------------

    #[test]
    fn test_agent_key_format() {
        assert_eq!(
            BudgetManager::agent_key("restricted", 1000),
            "restricted:1000"
        );
        assert_eq!(BudgetManager::agent_key("standard", 0), "standard:0");
        assert_eq!(BudgetManager::agent_key("", 42), ":42");
        assert_eq!(
            BudgetManager::agent_key("my-profile", u32::MAX),
            format!("my-profile:{}", u32::MAX)
        );
    }

    // ---------------------------------------------------------------
    // Default trait
    // ---------------------------------------------------------------

    #[test]
    fn test_default_creates_empty_manager() {
        let mgr = BudgetManager::default();
        // Unknown agent should return default Restricted status
        let status = mgr.get_status("nonexistent:0", &BranchId::from("b1".to_string()));
        assert_eq!(status.tier, BudgetTier::Restricted);
        assert_eq!(status.clean_commits, 0);
        assert_eq!(status.violations, 0);
    }

    // ---------------------------------------------------------------
    // get_status edge cases
    // ---------------------------------------------------------------

    #[test]
    fn test_get_status_unknown_agent_returns_default() {
        let mgr = BudgetManager::new();
        let bid = BranchId::from("branch-abc".to_string());
        let status = mgr.get_status("no-such-agent:999", &bid);
        assert_eq!(status.tier, BudgetTier::Restricted);
        assert_eq!(status.clean_commits, 0);
        assert_eq!(status.violations, 0);
        // branch_id should be propagated
        assert_eq!(format!("{}", status.branch_id), "branch-abc");
    }

    #[test]
    fn test_get_status_reflects_violation_count() {
        let mut mgr = BudgetManager::new();
        let key = "test:1000";
        let bid = BranchId::from("b1".to_string());

        mgr.record_violation(key);
        mgr.record_violation(key);
        mgr.record_violation(key);

        let status = mgr.get_status(key, &bid);
        assert_eq!(status.violations, 3);
        // Already at Restricted, violations should still be counted
        assert_eq!(status.tier, BudgetTier::Restricted);
    }

    // ---------------------------------------------------------------
    // effective_limits edge cases
    // ---------------------------------------------------------------

    #[test]
    fn test_effective_limits_unknown_agent_uses_restricted_multiplier() {
        let mgr = BudgetManager::new();
        let base = make_base_limits();
        let limits = mgr.effective_limits("unknown:0", &base);
        // 0.5x multiplier for unknown agent
        assert_eq!(limits.memory_bytes, base.memory_bytes / 2);
        assert_eq!(limits.storage_quota_mb, base.storage_quota_mb / 2);
        assert_eq!(limits.inode_quota, base.inode_quota / 2);
    }

    #[test]
    fn test_effective_limits_preserves_non_scaled_fields() {
        let mgr = BudgetManager::new();
        let mut base = make_base_limits();
        base.max_threads = Some(16);
        base.no_new_privileges = Some(true);
        base.max_files_read = Some(500);
        base.max_files_written = Some(200);
        base.max_single_file_size_mb = Some(50);
        base.cpu_quota_us = Some(100_000);

        let limits = mgr.effective_limits("any:1", &base);
        // These fields should be passed through unchanged
        assert_eq!(limits.max_threads, Some(16));
        assert_eq!(limits.no_new_privileges, Some(true));
        assert_eq!(limits.max_files_read, Some(500));
        assert_eq!(limits.max_files_written, Some(200));
        assert_eq!(limits.max_single_file_size_mb, Some(50));
        assert_eq!(limits.cpu_quota_us, Some(100_000));
    }

    #[test]
    fn test_effective_limits_cpu_shares_floor_at_one() {
        let mgr = BudgetManager::new();
        let mut base = make_base_limits();
        base.cpu_shares = 1; // 1 * 0.5 = 0.5, should clamp to 1
        let limits = mgr.effective_limits("any:1", &base);
        assert!(limits.cpu_shares >= 1, "cpu_shares must be at least 1");
    }

    #[test]
    fn test_effective_limits_io_weight_floor_at_one() {
        let mgr = BudgetManager::new();
        let mut base = make_base_limits();
        base.io_weight = 1; // 1 * 0.5 = 0.5, should clamp to 1
        let limits = mgr.effective_limits("any:1", &base);
        assert!(limits.io_weight >= 1, "io_weight must be at least 1");
    }

    #[test]
    fn test_effective_limits_max_pids_floor_at_four() {
        let mgr = BudgetManager::new();
        let mut base = make_base_limits();
        base.max_pids = 1; // 1 * 0.5 = 0.5, should clamp to 4
        let limits = mgr.effective_limits("any:1", &base);
        assert!(limits.max_pids >= 4, "max_pids must be at least 4");
    }

    #[test]
    fn test_effective_limits_all_tiers() {
        let mut mgr = BudgetManager::new();
        let key = "test:1000";
        let base = make_base_limits();

        // Restricted (0.5x)
        let r = mgr.effective_limits(key, &base);
        assert_eq!(r.memory_bytes, 256 * 1024 * 1024);
        assert_eq!(r.cpu_shares, 50);
        assert_eq!(r.io_weight, 50);
        assert_eq!(r.max_pids, 32);
        assert_eq!(r.storage_quota_mb, 512);
        assert_eq!(r.inode_quota, 5_000);

        // Standard (1.0x)
        for _ in 0..3 {
            mgr.record_clean_commit(key);
        }
        let s = mgr.effective_limits(key, &base);
        assert_eq!(s.memory_bytes, 512 * 1024 * 1024);
        assert_eq!(s.cpu_shares, 100);
        assert_eq!(s.io_weight, 100);
        assert_eq!(s.max_pids, 64);
        assert_eq!(s.storage_quota_mb, 1024);
        assert_eq!(s.inode_quota, 10_000);

        // Extended (2.0x)
        for _ in 0..7 {
            mgr.record_clean_commit(key);
        }
        let e = mgr.effective_limits(key, &base);
        assert_eq!(e.memory_bytes, 1024 * 1024 * 1024);
        assert_eq!(e.cpu_shares, 200);
        assert_eq!(e.io_weight, 200);
        assert_eq!(e.max_pids, 128);
        assert_eq!(e.storage_quota_mb, 2048);
        assert_eq!(e.inode_quota, 20_000);
    }

    // ---------------------------------------------------------------
    // apply_tier_limits
    // ---------------------------------------------------------------

    #[test]
    fn test_apply_tier_limits_writes_cgroup_files() {
        let mgr = BudgetManager::new();
        let key = "test:1000";
        let base = make_base_limits();

        let dir = std::env::temp_dir().join(format!("budget_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // Pre-create the files so write succeeds
        std::fs::write(dir.join("memory.max"), "").unwrap();
        std::fs::write(dir.join("cpu.weight"), "").unwrap();
        std::fs::write(dir.join("pids.max"), "").unwrap();

        mgr.apply_tier_limits(key, &base, &dir).unwrap();

        // Restricted tier: 0.5x
        let mem: u64 = std::fs::read_to_string(dir.join("memory.max"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(mem, 256 * 1024 * 1024);

        let cpu: u32 = std::fs::read_to_string(dir.join("cpu.weight"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(cpu, 50);

        let pids: u32 = std::fs::read_to_string(dir.join("pids.max"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(pids, 32);

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_apply_tier_limits_nonexistent_dir_returns_error() {
        // H8: apply_tier_limits must return Err on write failure, not silently proceed
        let mgr = BudgetManager::new();
        let key = "test:1000";
        let base = make_base_limits();
        let bad_path = std::path::Path::new("/tmp/nonexistent_budget_test_dir_12345");
        let result = mgr.apply_tier_limits(key, &base, bad_path);
        assert!(
            result.is_err(),
            "H8: apply_tier_limits must return Err on write failure"
        );
    }

    #[test]
    fn test_apply_tier_limits_enforces_min_cpu_and_pids() {
        let mut mgr = BudgetManager::new();
        let key = "test:1000";

        // Create agent so it exists
        mgr.record_clean_commit(key);
        mgr.record_violation(key); // back to Restricted, clean_commits=0

        let mut base = make_base_limits();
        base.cpu_shares = 1; // 1 * 0.5 = 0.5 -> max(1) = 1
        base.max_pids = 2; // 2 * 0.5 = 1.0 -> max(4) = 4

        let dir = std::env::temp_dir().join(format!("budget_test_min_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("memory.max"), "").unwrap();
        std::fs::write(dir.join("cpu.weight"), "").unwrap();
        std::fs::write(dir.join("pids.max"), "").unwrap();

        mgr.apply_tier_limits(key, &base, &dir).unwrap();

        let cpu: u32 = std::fs::read_to_string(dir.join("cpu.weight"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(cpu >= 1, "cpu.weight must be at least 1, got {}", cpu);

        let pids: u32 = std::fs::read_to_string(dir.join("pids.max"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(pids >= 4, "pids.max must be at least 4, got {}", pids);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------------------------------------------------------------
    // Escalation boundary conditions
    // ---------------------------------------------------------------

    #[test]
    fn test_escalation_exact_boundaries() {
        let mut mgr = BudgetManager::new();
        let key = "test:1000";
        let bid = BranchId::from("b1".to_string());

        // 2 commits: still Restricted
        for _ in 0..2 {
            mgr.record_clean_commit(key);
        }
        assert_eq!(mgr.get_status(key, &bid).tier, BudgetTier::Restricted);

        // 3rd commit: escalate to Standard
        let tier = mgr.record_clean_commit(key);
        assert_eq!(tier, BudgetTier::Standard);

        // 9 commits total: still Standard
        for _ in 0..6 {
            mgr.record_clean_commit(key);
        }
        assert_eq!(mgr.get_status(key, &bid).tier, BudgetTier::Standard);

        // 10th commit: escalate to Extended
        let tier = mgr.record_clean_commit(key);
        assert_eq!(tier, BudgetTier::Extended);
    }

    #[test]
    fn test_extended_stays_extended_on_more_commits() {
        let mut mgr = BudgetManager::new();
        let key = "test:1000";

        for _ in 0..10 {
            mgr.record_clean_commit(key);
        }
        assert_eq!(
            mgr.get_status(key, &BranchId::from("b1".to_string())).tier,
            BudgetTier::Extended
        );

        // Additional commits should stay at Extended
        for _ in 0..20 {
            let tier = mgr.record_clean_commit(key);
            assert_eq!(tier, BudgetTier::Extended);
        }
    }

    #[test]
    fn test_record_clean_commit_returns_current_tier() {
        let mut mgr = BudgetManager::new();
        let key = "test:1000";

        // First commit returns Restricted (threshold is 3)
        let tier = mgr.record_clean_commit(key);
        assert_eq!(tier, BudgetTier::Restricted);

        let tier = mgr.record_clean_commit(key);
        assert_eq!(tier, BudgetTier::Restricted);

        // 3rd commit returns Standard
        let tier = mgr.record_clean_commit(key);
        assert_eq!(tier, BudgetTier::Standard);
    }

    #[test]
    fn test_record_violation_returns_current_tier() {
        let mut mgr = BudgetManager::new();
        let key = "test:1000";

        // Violation on fresh agent stays Restricted
        let tier = mgr.record_violation(key);
        assert_eq!(tier, BudgetTier::Restricted);
    }

    #[test]
    fn test_violation_at_restricted_stays_restricted() {
        let mut mgr = BudgetManager::new();
        let key = "test:1000";

        // Multiple violations at Restricted should not go below Restricted
        for _ in 0..5 {
            let tier = mgr.record_violation(key);
            assert_eq!(tier, BudgetTier::Restricted);
        }
        let status = mgr.get_status(key, &BranchId::from("b1".to_string()));
        assert_eq!(status.violations, 5);
        assert_eq!(status.tier, BudgetTier::Restricted);
        assert_eq!(status.clean_commits, 0);
    }

    // ---------------------------------------------------------------
    // Multiple independent agents
    // ---------------------------------------------------------------

    #[test]
    fn test_multiple_agents_independent() {
        let mut mgr = BudgetManager::new();
        let key_a = "profile_a:1000";
        let key_b = "profile_b:2000";
        let bid = BranchId::from("b1".to_string());

        // Escalate agent A to Standard
        for _ in 0..3 {
            mgr.record_clean_commit(key_a);
        }
        assert_eq!(mgr.get_status(key_a, &bid).tier, BudgetTier::Standard);

        // Agent B should still be Restricted
        assert_eq!(mgr.get_status(key_b, &bid).tier, BudgetTier::Restricted);

        // Violate agent A
        mgr.record_violation(key_a);
        assert_eq!(mgr.get_status(key_a, &bid).tier, BudgetTier::Restricted);

        // Agent B unaffected, escalate it
        for _ in 0..3 {
            mgr.record_clean_commit(key_b);
        }
        assert_eq!(mgr.get_status(key_b, &bid).tier, BudgetTier::Standard);
        assert_eq!(mgr.get_status(key_a, &bid).tier, BudgetTier::Restricted);
    }

    // ---------------------------------------------------------------
    // Zero base limits
    // ---------------------------------------------------------------

    #[test]
    fn test_effective_limits_zero_base() {
        let mgr = BudgetManager::new();
        let base = ResourceLimits {
            memory_bytes: 0,
            cpu_shares: 0,
            io_weight: 0,
            max_pids: 0,
            storage_quota_mb: 0,
            inode_quota: 0,
            max_threads: None,
            no_new_privileges: None,
            max_files_read: None,
            max_files_written: None,
            max_single_file_size_mb: None,
            cpu_quota_us: None,
            memory_high: None,
            io_max: None,
            max_exec_calls: None,
            max_open_fds: None,
            max_files_deleted: None,
            max_total_write_mb: None,
            lifetime_minutes: None,
        };
        let limits = mgr.effective_limits("any:1", &base);
        // S42: Floor enforcement — zero base * multiplier must still produce >= 1
        assert!(limits.memory_bytes >= 1, "S42: memory_bytes must be >= 1");
        assert!(limits.cpu_shares >= 1);
        assert!(limits.io_weight >= 1);
        assert!(limits.max_pids >= 4);
        assert!(
            limits.storage_quota_mb >= 1,
            "S42: storage_quota_mb must be >= 1"
        );
        assert!(limits.inode_quota >= 1, "S42: inode_quota must be >= 1");
    }

    // ---------------------------------------------------------------
    // Phase 1.8: Additional budget management tests
    // ---------------------------------------------------------------

    #[test]
    fn test_initial_budget_set_correctly() {
        // A freshly created agent should start at Restricted tier with
        // zero clean commits and zero violations.
        let mut mgr = BudgetManager::new();
        let key = "new-agent:5000";
        let bid = BranchId::from("b1".to_string());

        // Trigger agent creation via get_or_create (called internally by record_clean_commit)
        mgr.record_clean_commit(key);

        // Reset: create a fresh manager and check status for unknown key
        let mgr2 = BudgetManager::new();
        let status = mgr2.get_status("fresh:1000", &bid);
        assert_eq!(
            status.tier,
            BudgetTier::Restricted,
            "initial tier should be Restricted"
        );
        assert_eq!(status.clean_commits, 0, "initial clean_commits should be 0");
        assert_eq!(status.violations, 0, "initial violations should be 0");

        // Also verify that a single commit puts us at 1 clean commit
        let status_after = mgr.get_status(key, &bid);
        assert_eq!(status_after.clean_commits, 1);
        assert_eq!(
            status_after.tier,
            BudgetTier::Restricted,
            "1 commit is below the 3-commit threshold"
        );
    }

    #[test]
    fn test_clean_commit_count_increments() {
        // Verify that each call to record_clean_commit increments the counter.
        let mut mgr = BudgetManager::new();
        let key = "counter-test:1000";
        let bid = BranchId::from("b1".to_string());

        for expected in 1..=5 {
            mgr.record_clean_commit(key);
            let status = mgr.get_status(key, &bid);
            assert_eq!(
                status.clean_commits, expected,
                "clean_commits should be {} after {} calls",
                expected, expected
            );
        }
    }

    #[test]
    fn test_budget_exhaustion_detection_via_effective_limits() {
        // "Budget exhaustion" manifests as the Restricted tier applying the
        // lowest multiplier (0.5x). After a violation resets to Restricted,
        // effective limits should be at the minimum (0.5x base).
        let mut mgr = BudgetManager::new();
        let key = "exhaust-test:1000";
        let base = make_base_limits();

        // Escalate to Extended
        for _ in 0..10 {
            mgr.record_clean_commit(key);
        }
        assert_eq!(
            mgr.get_status(key, &BranchId::from("b".to_string())).tier,
            BudgetTier::Extended
        );
        let extended_limits = mgr.effective_limits(key, &base);
        assert_eq!(extended_limits.memory_bytes, 1024 * 1024 * 1024); // 2x

        // Two violations: Extended -> Standard -> Restricted
        mgr.record_violation(key);
        mgr.record_violation(key);
        let status = mgr.get_status(key, &BranchId::from("b".to_string()));
        assert_eq!(status.tier, BudgetTier::Restricted);
        assert_eq!(
            status.clean_commits, 0,
            "violations should reset clean_commits"
        );

        // Effective limits should now be at the restricted (0.5x) level
        let restricted_limits = mgr.effective_limits(key, &base);
        assert_eq!(
            restricted_limits.memory_bytes,
            256 * 1024 * 1024,
            "restricted tier should halve memory"
        );
        assert_eq!(restricted_limits.cpu_shares, 50);
        assert_eq!(restricted_limits.storage_quota_mb, 512);

        // Verify the budget is "exhausted" — cannot get more than 0.5x
        // without earning trust back through clean commits
        mgr.record_violation(key); // additional violation at Restricted
        let still_restricted = mgr.effective_limits(key, &base);
        assert_eq!(
            still_restricted.memory_bytes,
            256 * 1024 * 1024,
            "cannot go below Restricted tier"
        );
    }

    #[test]
    fn test_budget_escalation_after_successful_commit() {
        // Verify the full escalation path: Restricted -> Standard -> Extended
        // and that the tier changes are reflected in effective_limits.
        let mut mgr = BudgetManager::new();
        let key = "escalation-test:2000";
        let bid = BranchId::from("b1".to_string());
        let base = make_base_limits();

        // Phase 1: Restricted (0.5x)
        let limits_r = mgr.effective_limits(key, &base);
        assert_eq!(limits_r.memory_bytes, base.memory_bytes / 2);

        // Phase 2: 3 clean commits -> Standard (1.0x)
        for i in 1..=3 {
            let tier = mgr.record_clean_commit(key);
            if i < 3 {
                assert_eq!(tier, BudgetTier::Restricted);
            } else {
                assert_eq!(tier, BudgetTier::Standard);
            }
        }
        let status = mgr.get_status(key, &bid);
        assert_eq!(status.tier, BudgetTier::Standard);
        assert_eq!(status.clean_commits, 3);
        let limits_s = mgr.effective_limits(key, &base);
        assert_eq!(limits_s.memory_bytes, base.memory_bytes); // 1.0x

        // Phase 3: 7 more clean commits (10 total) -> Extended (2.0x)
        for i in 4..=10 {
            let tier = mgr.record_clean_commit(key);
            if i < 10 {
                assert_eq!(tier, BudgetTier::Standard);
            } else {
                assert_eq!(tier, BudgetTier::Extended);
            }
        }
        let status = mgr.get_status(key, &bid);
        assert_eq!(status.tier, BudgetTier::Extended);
        assert_eq!(status.clean_commits, 10);
        let limits_e = mgr.effective_limits(key, &base);
        assert_eq!(limits_e.memory_bytes, base.memory_bytes * 2); // 2.0x
    }

    // ---------------------------------------------------------------
    // Helper
    // ---------------------------------------------------------------

    // R12: Cgroup budget tier write failures must use tracing::error!, not warn!.
    // A failed cgroup write means resource limits are NOT enforced, which is a
    // security-relevant failure that should be logged at error level.
    #[test]
    fn test_r12_cgroup_write_failures_use_error_not_warn() {
        let source = include_str!("budget.rs");
        // Find the apply_tier_limits function body
        let func_start = source
            .find("fn apply_tier_limits(")
            .expect("apply_tier_limits function must exist");
        // Get the function body (up to the next pub fn or end of impl)
        let body = &source[func_start..];
        let end = body[50..].find("\n    pub fn ").unwrap_or(body.len());
        let func_body = &body[..end];
        // The write closure's error handling must use error!, not warn!
        assert!(
            !func_body.contains("tracing::warn!("),
            "R12: apply_tier_limits cgroup write failures must use tracing::error!, \
             not tracing::warn! — failed cgroup writes mean resource limits are unenforced"
        );
    }

    // ---------------------------------------------------------------
    // F2: budget counters must use saturating arithmetic
    // ---------------------------------------------------------------

    #[test]
    fn test_f2_budget_counters_use_saturating_add() {
        let source = include_str!("budget.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        // Both clean_commits and violations increments must use saturating_add
        assert!(
            production_code.contains("clean_commits = budget.clean_commits.saturating_add(1)")
                || production_code
                    .contains("clean_commits = budget.clean_commits.saturating_add( 1 )"),
            "F2: clean_commits increment must use saturating_add(1) to prevent u32 wrap"
        );
        assert!(
            production_code.contains("violations = budget.violations.saturating_add(1)")
                || production_code.contains("violations = budget.violations.saturating_add( 1 )"),
            "F2: violations increment must use saturating_add(1) to prevent u32 wrap"
        );
    }

    // ---------------------------------------------------------------
    // F13: agent budget tracker must be bounded
    // ---------------------------------------------------------------

    #[test]
    fn test_f13_budget_agents_bounded() {
        let source = include_str!("budget.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        assert!(
            production_code.contains("MAX_TRACKED_AGENTS"),
            "F13: BudgetManager must define MAX_TRACKED_AGENTS to bound the agents HashMap"
        );
    }

    // ---------------------------------------------------------------
    // H8: apply_tier_limits must return Result
    // ---------------------------------------------------------------

    #[test]
    fn test_h8_apply_tier_limits_returns_result() {
        let source = include_str!("budget.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        assert!(
            production_code.contains("fn apply_tier_limits(")
                && production_code.contains("-> Result<(), std::io::Error>"),
            "H8: apply_tier_limits must return Result<(), std::io::Error> — \
             must not fail open by silently ignoring cgroup write errors"
        );
    }

    // ---------------------------------------------------------------
    // J1: saturating_f64_to_u32 must clamp large values
    // ---------------------------------------------------------------

    #[test]
    fn test_j1_saturating_f64_to_u32_clamps_large_values() {
        // Values above u32::MAX must clamp to u32::MAX, not truncate
        assert_eq!(saturating_f64_to_u32(5_000_000_000.0), u32::MAX);
        assert_eq!(saturating_f64_to_u32(u32::MAX as f64 + 1.0), u32::MAX);
        assert_eq!(saturating_f64_to_u32(f64::MAX), u32::MAX);
        assert_eq!(saturating_f64_to_u32(f64::INFINITY), u32::MAX);
        // Normal values pass through
        assert_eq!(saturating_f64_to_u32(100.0), 100);
        assert_eq!(saturating_f64_to_u32(1.0), 1);
        assert_eq!(saturating_f64_to_u32(0.5), 0);
        // Negative and zero
        assert_eq!(saturating_f64_to_u32(0.0), 0);
        assert_eq!(saturating_f64_to_u32(-1.0), 0);
        assert_eq!(saturating_f64_to_u32(f64::NEG_INFINITY), 0);
    }

    #[test]
    fn test_j1_effective_limits_no_bare_as_u32_float_cast() {
        let source = include_str!("budget.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        let func_start = production_code
            .find("fn effective_limits(")
            .expect("effective_limits must exist");
        let body = &production_code[func_start..];
        let end = body.find("\n    }").unwrap_or(body.len()) + 6;
        let func_body = &body[..end];
        // No bare `as u32` after a float expression with multiplier
        for line in func_body.lines() {
            let trimmed = line.trim();
            if trimmed.contains("multiplier")
                && trimmed.contains("as u32")
                && !trimmed.starts_with("//")
            {
                assert!(
                    trimmed.contains("saturating_f64_to_u32"),
                    "J1: float-to-u32 cast must use saturating_f64_to_u32, found: {}",
                    trimmed
                );
            }
        }
    }

    fn make_base_limits() -> ResourceLimits {
        ResourceLimits {
            memory_bytes: 512 * 1024 * 1024,
            cpu_shares: 100,
            io_weight: 100,
            max_pids: 64,
            storage_quota_mb: 1024,
            inode_quota: 10_000,
            max_threads: None,
            no_new_privileges: None,
            max_files_read: None,
            max_files_written: None,
            max_single_file_size_mb: None,
            cpu_quota_us: None,
            memory_high: None,
            io_max: None,
            max_exec_calls: None,
            max_open_fds: None,
            max_files_deleted: None,
            max_total_write_mb: None,
            lifetime_minutes: None,
        }
    }
}
