// SPDX-License-Identifier: Apache-2.0
use puzzled_types::{BranchId, BranchState, CommitResult, FileChange, PolicyDecision};
use std::path::PathBuf;
use std::sync::Arc;

use crate::audit::AuditEvent;
use crate::error::{PuzzledError, Result};
use crate::sync_util::unlock_poisoned;

use super::{BranchManager, CommitGuard};

impl BranchManager {
    /// Freeze agent, generate diff, evaluate policy, WAL commit or rollback.
    ///
    /// This is the core "Commit" operation in the Fork-Explore-Commit model.
    pub fn commit(&self, id: &BranchId) -> Result<CommitResult> {
        // M-br6: Wrap entire commit in a timeout
        let timeout_secs = self.config.commit_timeout_seconds;
        let commit_deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

        // H-1: Mark this branch as mid-commit FIRST. If insert() returns false,
        // a commit is already in progress for this branch — reject immediately.
        {
            let mut committing = unlock_poisoned(self.committing_branches.lock());
            if !committing.insert(id.clone()) {
                return Err(PuzzledError::Branch(format!(
                    "commit already in progress for branch {}",
                    id
                )));
            }
        }

        // BC2: RAII guard ensures committing_branches is cleaned up on all exit paths.
        // Uses Arc clone so the guard doesn't hold a borrow on `self`.
        let _commit_guard = CommitGuard {
            committing_branches: Arc::clone(&self.committing_branches),
            branch_id: id.clone(),
        };

        // H-2: Validate branch exists and is Active, and atomically transition to Frozen
        // using a single get_mut() call. This prevents a race where the state could change
        // between reading and writing.
        let (base_path, upper_dir, branch_created_at, branch_pid) = {
            let mut info = self
                .branches
                .get_mut(id)
                .ok_or_else(|| PuzzledError::NotFound(format!("branch {}", id)))?;

            if !matches!(info.state, BranchState::Active | BranchState::Ready) {
                return Err(PuzzledError::Branch(format!(
                    "branch {} is in state {}, expected Active or Ready",
                    id, info.state
                )));
            }

            // H-2: Atomically transition to Frozen while still holding the mutable ref
            let old_state = info.state;
            info.state = BranchState::Frozen;
            tracing::debug!(
                branch = %id,
                from = %old_state,
                to = %info.state,
                "state transition"
            );

            (
                info.base_path.clone(),
                info.upper_dir.clone(),
                info.created_at,
                info.pid,
            )
        };

        // Step 2: Freeze the cgroup (TOCTOU protection — mandatory when a process may still run)
        #[cfg(target_os = "linux")]
        let cgroup_path_for_diff: Option<PathBuf> = {
            if let Some(handle) = self.sandboxes.get(id) {
                if let Err(e) = crate::sandbox::cgroup::CgroupManager::freeze(&handle.cgroup_path) {
                    tracing::error!(error = %e, "failed to freeze cgroup — cannot proceed with commit");
                    self.rollback_internal("cgroup freeze failed during commit", id)?;
                    return Err(PuzzledError::Sandbox(format!(
                        "cgroup freeze failed, commit aborted: {}",
                        e
                    )));
                }
                Some(handle.cgroup_path.clone())
            } else if let Some(pid) = branch_pid {
                match freeze_cgroup_by_pid(pid) {
                    Ok(path) => {
                        tracing::warn!(
                            branch = %id,
                            pid,
                            cgroup = %path.display(),
                            "cgroup freeze via PID discovery (no sandbox handle; Podman-native)"
                        );
                        Some(path)
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "failed to freeze cgroup via PID — cannot proceed with commit");
                        self.rollback_internal("cgroup freeze failed during commit", id)?;
                        return Err(PuzzledError::Sandbox(format!(
                            "cgroup freeze failed, commit aborted: {}",
                            e
                        )));
                    }
                }
            } else {
                // No process running — TOCTOU protection not needed (no concurrent writes possible)
                None
            }
        };
        #[cfg(not(target_os = "linux"))]
        let cgroup_path_for_diff: Option<PathBuf> = None;

        // Emit audit event for freeze
        self.audit.log(AuditEvent::BranchFrozen {
            branch_id: id.clone(),
        });

        // Step 3: Generate diff
        // M3: Pass cgroup path for freeze verification during commit.
        // On non-Linux, cgroup_path is None (no cgroup support).
        let diff_start = std::time::Instant::now();
        let changes =
            self.diff_engine
                .generate(&upper_dir, &base_path, cgroup_path_for_diff.as_deref())?;
        if let Some(m) = self.get_metrics() {
            m.record_diff(diff_start.elapsed().as_secs_f64());
        }

        // M-br6: Check commit timeout after diff generation
        if std::time::Instant::now() > commit_deadline {
            tracing::error!(branch = %id, timeout_secs, "M-br6: commit timeout exceeded during diff generation");
            self.thaw_cgroup(id);
            self.rollback_internal("commit timeout exceeded", id)?;
            return Err(PuzzledError::Branch(format!(
                "commit timeout ({}s) exceeded for branch {}",
                timeout_secs, id
            )));
        }

        if changes.is_empty() {
            // No changes to commit — clean up resources before returning
            self.transition(id, BranchState::Committed)?;
            #[cfg(target_os = "linux")]
            self.cleanup_sandbox_resources(id);
            unlock_poisoned(self.conflict_detector.lock()).unregister_branch(id);
            self.branches.remove(id);
            return Ok(CommitResult {
                branch_id: id.clone(),
                files_committed: 0,
                bytes_committed: 0,
                policy_result: PolicyDecision::Approved,
            });
        }

        // Step 3b: Evaluate governance policy (per PRD: policy evaluation before conflict detection)
        // Pass profile name for profile-aware policy rules (e.g., per-profile storage quotas)
        // H-14: Pass workspace_root (base_path) so the Rego rule `deny_outside_workspace` fires.
        // U30: Symlink escape within workspace is mitigated by Landlock (kernel-enforced, path-based)
        let profile_name = self.branches.get(id).map(|r| r.profile.clone());
        let workspace_root = base_path.to_string_lossy().to_string();
        // K67: Look up profile to pass storage_quota_bytes and allow_symlinks to OPA.
        // Converts storage_quota_mb to bytes so the Rego dynamic_storage_quota rule
        // uses the actual profile limit instead of hard-coded fallbacks.
        // V40: Pass allow_symlinks so deny_symlink uses the profile setting.
        let loaded_profile = profile_name
            .as_deref()
            .and_then(|name| self.profile_loader.get(name));
        let storage_quota_bytes =
            loaded_profile.map(|p| p.resource_limits.storage_quota_mb * 1024 * 1024);
        let allow_symlinks = loaded_profile.map(|p| p.allow_symlinks);
        let decision = self.policy_engine.evaluate_full(
            &changes,
            profile_name.as_deref(),
            Some(&workspace_root),
            storage_quota_bytes,
            allow_symlinks,
        )?;

        // Wire metrics: policy evaluation outcome
        if let Some(m) = self.get_metrics() {
            match &decision {
                PolicyDecision::Approved => {
                    m.policy_approved.inc();
                }
                PolicyDecision::Rejected(_) => {
                    m.policy_rejected.inc();
                }
                PolicyDecision::Error(_) => {
                    m.policy_errors.inc();
                }
            }
        }

        // Step 3c: Check for cross-branch conflicts (after policy evaluation per PRD)
        {
            let mut detector = unlock_poisoned(self.conflict_detector.lock());
            detector.register_changes(id, &base_path, &changes);
            let conflicts = detector.check_conflicts_with_time(
                id,
                &base_path,
                &changes,
                Some(branch_created_at),
            );
            if !conflicts.is_empty() {
                if let Some(m) = self.get_metrics() {
                    // Q9: Use try_from instead of bare `as u64` for len-to-u64 conversion
                    m.conflicts_total
                        .inc_by(u64::try_from(conflicts.len()).unwrap_or(u64::MAX));
                }
            }
            if let Err(e) = detector.resolve(&conflicts) {
                tracing::warn!(branch = %id, error = %e, "cross-branch conflict detected");
                // Unregister and rollback
                detector.unregister_branch(id);
                drop(detector);
                // Thaw cgroup before rollback
                self.thaw_cgroup(id);
                self.rollback_internal("conflict: cross-branch conflict detected", id)?;
                return Ok(CommitResult {
                    branch_id: id.clone(),
                    files_committed: 0,
                    bytes_committed: 0,
                    policy_result: PolicyDecision::Rejected(vec![puzzled_types::Violation {
                        rule: "conflict_detection".to_string(),
                        message: e.to_string(),
                        severity: puzzled_types::ViolationSeverity::Error,
                    }]),
                });
            }

            // C8: Two-phase conflict protocol — reserve paths after conflict check
            // passes but before WAL commit, preventing TOCTOU between check and commit.
            let reservation_paths: Vec<PathBuf> = changes.iter().map(|c| c.path.clone()).collect();
            if let Err(e) = detector.reserve_paths(id, reservation_paths) {
                tracing::warn!(branch = %id, error = %e, "C8: path reservation failed");
                detector.unregister_branch(id);
                drop(detector);
                self.thaw_cgroup(id);
                self.rollback_internal("C8: path reservation conflict", id)?;
                return Ok(CommitResult {
                    branch_id: id.clone(),
                    files_committed: 0,
                    bytes_committed: 0,
                    policy_result: PolicyDecision::Rejected(vec![puzzled_types::Violation {
                        rule: "conflict_reservation".to_string(),
                        message: e,
                        severity: puzzled_types::ViolationSeverity::Error,
                    }]),
                });
            }
        }

        // M-br6: Check commit timeout before proceeding to WAL commit
        if std::time::Instant::now() > commit_deadline {
            tracing::error!(branch = %id, timeout_secs, "M-br6: commit timeout exceeded during policy/conflict evaluation");
            unlock_poisoned(self.conflict_detector.lock()).cancel_reservation(id);
            self.thaw_cgroup(id);
            self.rollback_internal("commit timeout exceeded", id)?;
            return Err(PuzzledError::Branch(format!(
                "commit timeout ({}s) exceeded for branch {}",
                timeout_secs, id
            )));
        }

        match decision {
            PolicyDecision::Approved if self.config.require_human_approval => {
                // H-10: Policy approved but human review is required.
                // Transition to GovernanceReview, store the changeset for later
                // approval/rejection, and return early with files_committed=0.
                self.transition(id, BranchState::Committing)?;
                self.transition(id, BranchState::GovernanceReview)?;

                // Store the changeset and base_path for approve_branch() to use later
                self.pending_reviews
                    .insert(id.clone(), (changes.clone(), base_path.clone()));

                self.audit.log(AuditEvent::BranchFrozen {
                    branch_id: id.clone(),
                });

                tracing::info!(
                    branch = %id,
                    files = changes.len(),
                    "H-10: branch awaiting governance review (require_human_approval=true)"
                );

                Ok(CommitResult {
                    branch_id: id.clone(),
                    files_committed: 0,
                    bytes_committed: 0,
                    policy_result: PolicyDecision::Approved,
                })
            }
            PolicyDecision::Approved => {
                self.finalize_approved_commit(id, &changes, &base_path, PolicyDecision::Approved)
            }
            PolicyDecision::Rejected(violations) => {
                let decision = PolicyDecision::Rejected(violations.clone());
                self.handle_rejected_commit(id, &changes, &base_path, &violations, decision)
            }
            PolicyDecision::Error(ref msg) => {
                tracing::error!(branch = %id, error = %msg, "policy evaluation error");
                // M9: Wire metrics: include error context in outcome label
                if let Some(m) = self.get_metrics() {
                    m.commit_outcomes
                        .get_or_create(&crate::metrics::OutcomeLabels {
                            outcome: "error".to_string(), // T1: fixed label to prevent unbounded metric cardinality
                        })
                        .inc();
                }
                self.apply_fail_mode(id);
                Ok(CommitResult {
                    branch_id: id.clone(),
                    files_committed: 0,
                    bytes_committed: 0,
                    policy_result: decision,
                })
            }
        }
    }

    /// Execute the approved commit path: WAL write, IMA signing, journal replay,
    /// budget update, resource cleanup, and conflict finalization.
    pub(super) fn finalize_approved_commit(
        &self,
        id: &BranchId,
        changes: &[FileChange],
        base_path: &std::path::Path,
        decision: PolicyDecision,
    ) -> Result<CommitResult> {
        let commit_start = std::time::Instant::now();
        let (commit_profile, commit_created_at) = self
            .branches
            .get(id)
            .map(|r| (Some(r.profile.clone()), Some(r.created_at)))
            .unwrap_or((None, None));
        // m-3 audit fix: Re-verify cgroup is still frozen before WAL commit.
        // The human-approval path re-freezes; the auto-approve path should at
        // least verify the freeze is still active to guard against external
        // interference (e.g., another process writing to cgroup.freeze).
        #[cfg(target_os = "linux")]
        {
            let cgroup_for_verify = if let Some(handle) = self.sandboxes.get(id) {
                Some(Ok(handle.cgroup_path.clone()))
            } else {
                self.branches
                    .get(id)
                    .and_then(|r| r.pid)
                    .map(crate::sandbox::cgroup::cgroup_v2_fs_path_for_pid)
            };
            if let Some(resolved) = cgroup_for_verify {
                let cgroup_path = match resolved {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::error!(
                            branch = %id,
                            error = %e,
                            "cannot resolve cgroup for pre-WAL freeze verification"
                        );
                        self.rollback_internal(
                            "cgroup path resolution failed before WAL commit",
                            id,
                        )?;
                        return Err(PuzzledError::Sandbox(e.to_string()));
                    }
                };
                let events_path = cgroup_path.join("cgroup.events");
                if let Ok(contents) = std::fs::read_to_string(&events_path) {
                    if !contents.lines().any(|l| l.trim() == "frozen 1") {
                        tracing::error!(branch = %id, "cgroup no longer frozen before WAL commit — aborting");
                        self.rollback_internal("cgroup unfrozen before WAL commit (TOCTOU)", id)?;
                        return Err(PuzzledError::Sandbox(
                            "cgroup was unfrozen between governance and WAL commit".to_string(),
                        ));
                    }
                }
            }
        }

        // WAL commit
        self.transition(id, BranchState::Committing)?;
        // M7: If wal_commit fails, thaw the cgroup and recover to Active state.
        // B1: Log thaw failures explicitly — if both WAL and thaw fail, the branch
        // is in an unrecoverable state and should transition to Failed.
        if let Err(e) = self.wal_commit(id, changes, base_path) {
            tracing::error!(branch = %id, error = %e, "WAL commit failed, recovering");
            // C8: Cancel path reservation on WAL failure
            unlock_poisoned(self.conflict_detector.lock()).cancel_reservation(id);
            self.thaw_cgroup(id);
            if let Err(te) = self.transition(id, BranchState::Active) {
                tracing::error!(
                    branch = %id,
                    wal_error = %e,
                    transition_error = %te,
                    "double failure: WAL commit failed AND recovery transition failed, marking Failed"
                );
                // S7: Log transition-to-Failed failure explicitly instead of discarding
                if let Err(fe) = self.transition(id, BranchState::Failed) {
                    tracing::error!(
                        branch = %id,
                        error = %fe,
                        "S7: triple failure — transition to Failed also failed. \
                         Branch state is inconsistent. WAL recovery on restart will handle rollback."
                    );
                }
            }
            return Err(e);
        }

        // C8: Confirm path reservation after successful WAL commit
        unlock_poisoned(self.conflict_detector.lock()).confirm_commit(id);

        // S12: Sign the commit manifest (IMA).
        // When IMA is configured, signing failures should be treated as errors
        // (the commit was approved but cannot be attested). Log at error level
        // so operators are alerted. The commit still proceeds because the WAL
        // has already been executed, but the integrity chain is broken.
        if let Some(ima) = &self.ima {
            let ima = ima.lock().unwrap_or_else(|e| {
                tracing::warn!(
                    branch = %id,
                    "S10: IMA mutex poison recovered — previous IMA thread panicked"
                );
                e.into_inner()
            });
            if let Err(e) = ima.sign_commit(id, changes) {
                tracing::error!(
                    branch = %id,
                    error = %e,
                    "S12: IMA manifest signing failed — commit integrity chain is broken. \
                     The commit has been applied but cannot be attested."
                );
            }
        }

        // Replay network journal (side-effect requests)
        self.replay_network_journal(id);

        // Thaw the cgroup before transitioning
        self.thaw_cgroup(id);

        self.transition(id, BranchState::Committed)?;

        // Q9: Use try_from instead of bare `as u64` for len-to-u64 conversion
        let files = u64::try_from(changes.len()).unwrap_or(u64::MAX);
        let bytes: u64 = changes.iter().map(|c| c.size).sum();

        // Record clean commit for budget escalation
        self.update_budget_after_commit(id, true);

        // Clean up sandbox resources
        #[cfg(target_os = "linux")]
        self.cleanup_sandbox_resources(id);

        // Mark committed in conflict detector
        self.finalize_conflict_tracking(id, changes);

        self.audit.log(AuditEvent::BranchCommitted {
            branch_id: id.clone(),
            files,
            bytes,
        });

        self.branches.remove(id);

        // Wire metrics: commit duration, files, bytes, outcome
        if let Some(m) = self.get_metrics() {
            let profile_name = commit_profile.as_deref().unwrap_or("unknown");
            m.record_commit(profile_name, commit_start.elapsed().as_secs_f64());
            m.commit_files_total.inc_by(files);
            m.commit_bytes_total.inc_by(bytes);
            m.commit_outcomes
                .get_or_create(&crate::metrics::OutcomeLabels {
                    outcome: "approved".to_string(),
                })
                .inc();
            // Record branch lifetime duration
            if let Some(created) = commit_created_at {
                let lifetime =
                    // S9: precision loss irrelevant for metrics (>285M years)
                (chrono::Utc::now() - created).num_milliseconds().max(0) as f64 / 1000.0;
                m.branch_duration_seconds.observe(lifetime);
            }
        }

        tracing::info!(branch = %id, files, bytes, "branch committed");

        Ok(CommitResult {
            branch_id: id.clone(),
            files_committed: files,
            bytes_committed: bytes,
            policy_result: decision,
        })
    }

    /// Handle a rejected commit: log violations, check fail mode for warning-only
    /// pass-through, update budget, and apply fail mode.
    pub(super) fn handle_rejected_commit(
        &self,
        id: &BranchId,
        changes: &[FileChange],
        base_path: &std::path::Path,
        violations: &[puzzled_types::Violation],
        decision: PolicyDecision,
    ) -> Result<CommitResult> {
        // Log violations
        for v in violations {
            self.audit.log(AuditEvent::PolicyViolation {
                branch_id: id.clone(),
                rule: v.rule.clone(),
                message: v.message.clone(),
            });
        }

        // PH3: FailOperational + warning-only violations → allow commit to proceed
        let fail_mode = self
            .branches
            .get(id)
            .and_then(|r| self.profile_loader.get(&r.profile).map(|p| p.fail_mode))
            .unwrap_or(puzzled_types::FailMode::FailClosed);

        let all_warnings_only = violations
            .iter()
            .all(|v| v.severity == puzzled_types::ViolationSeverity::Warning);

        if fail_mode == puzzled_types::FailMode::FailOperational && all_warnings_only {
            tracing::warn!(
                branch = %id,
                warning_count = violations.len(),
                "PH3: FailOperational — warning-only violations, allowing commit to proceed"
            );

            self.transition(id, BranchState::Committing)?;
            // M-br1: If WAL commit fails in FailOperational+warnings path,
            // cancel reservation and thaw cgroup (matching main commit error handling).
            if let Err(e) = self.wal_commit(id, changes, base_path) {
                tracing::error!(branch = %id, error = %e, "M-br1: WAL commit failed in FailOperational warning path");
                unlock_poisoned(self.conflict_detector.lock()).cancel_reservation(id);
                self.thaw_cgroup(id);
                if let Err(te) = self.transition(id, BranchState::Active) {
                    tracing::error!(
                        branch = %id,
                        wal_error = %e,
                        transition_error = %te,
                        "M-br1: double failure in FailOperational path"
                    );
                    if let Err(e2) = self.transition(id, BranchState::Failed) {
                        tracing::error!(
                            branch = %id,
                            error = %e2,
                            "F16: fallback transition to Failed also failed"
                        );
                    }
                }
                return Err(e);
            }
            // C8: Confirm path reservation after successful WAL commit
            unlock_poisoned(self.conflict_detector.lock()).confirm_commit(id);
            self.thaw_cgroup(id);
            self.transition(id, BranchState::Committed)?;

            // Q9: Use try_from instead of bare `as u64` for len-to-u64 conversion
            let files = u64::try_from(changes.len()).unwrap_or(u64::MAX);
            let bytes: u64 = changes.iter().map(|c| c.size).sum();

            #[cfg(target_os = "linux")]
            self.cleanup_sandbox_resources(id);
            self.finalize_conflict_tracking(id, changes);
            self.branches.remove(id);

            self.audit.log(AuditEvent::BranchCommitted {
                branch_id: id.clone(),
                files,
                bytes,
            });

            return Ok(CommitResult {
                branch_id: id.clone(),
                files_committed: files,
                bytes_committed: bytes,
                policy_result: PolicyDecision::Approved,
            });
        }

        // FailClosed or Error+/Critical violations: reject and apply fail mode
        // C8: Cancel path reservation on rejection
        unlock_poisoned(self.conflict_detector.lock()).cancel_reservation(id);
        // Wire metrics: rejected outcome
        if let Some(m) = self.get_metrics() {
            m.commit_outcomes
                .get_or_create(&crate::metrics::OutcomeLabels {
                    outcome: "rejected".to_string(),
                })
                .inc();
        }
        self.update_budget_after_commit(id, false);
        self.apply_fail_mode(id);

        Ok(CommitResult {
            branch_id: id.clone(),
            files_committed: 0,
            bytes_committed: 0,
            policy_result: decision,
        })
    }

    /// Update budget after a commit attempt (clean commit escalates, violation de-escalates).
    pub(super) fn update_budget_after_commit(&self, id: &BranchId, clean: bool) {
        if let Some(info) = self.branches.get(id) {
            let agent_key = crate::budget::BudgetManager::agent_key(&info.profile, info.uid);
            let _profile = self.profile_loader.get(&info.profile).cloned();
            let mut budget = unlock_poisoned(self.budget_manager.lock());
            let old_tier = budget.get_status(&agent_key, id).tier;
            let new_tier = if clean {
                budget.record_clean_commit(&agent_key)
            } else {
                budget.record_violation(&agent_key)
            };
            if new_tier != old_tier {
                #[cfg(target_os = "linux")]
                if let (Some(handle), Some(prof)) = (self.sandboxes.get(id), &_profile) {
                    if let Err(e) = budget.apply_tier_limits(
                        &agent_key,
                        &prof.resource_limits,
                        &handle.cgroup_path,
                    ) {
                        tracing::error!(
                            branch = %id,
                            error = %e,
                            "H8: failed to apply budget tier limits — resource limits may be unenforced"
                        );
                    }
                }
            }
            let action = if clean { "clean commit" } else { "violation" };
            tracing::debug!(branch = %id, tier = ?new_tier, "budget updated after {action}");
        }
    }

    /// Mark branch as committed in conflict detector and unregister it.
    pub(super) fn finalize_conflict_tracking(&self, id: &BranchId, changes: &[FileChange]) {
        let committed_paths: Vec<PathBuf> = changes.iter().map(|c| c.path.clone()).collect();
        let mut detector = unlock_poisoned(self.conflict_detector.lock());
        detector.mark_committed(id, committed_paths, chrono::Utc::now());
        detector.unregister_branch(id);
    }

    /// Apply the fail mode from the branch's profile on commit rejection or error.
    ///
    /// - FailClosed (default): thaw + rollback
    /// - FailSilent: keep frozen (hold last safe state)
    /// - FailOperational: thaw but don't rollback (reduced capability)
    /// - FailSafeState: thaw + rollback + kill agent via cgroup
    pub(super) fn apply_fail_mode(&self, id: &BranchId) {
        let fail_mode = self
            .branches
            .get(id)
            .and_then(|r| self.profile_loader.get(&r.profile).map(|p| p.fail_mode))
            .unwrap_or(puzzled_types::FailMode::FailClosed);

        match fail_mode {
            puzzled_types::FailMode::FailClosed => {
                // Thaw + rollback (default behavior)
                #[cfg(target_os = "linux")]
                self.thaw_cgroup(id);
                if let Err(e) = self.rollback_internal("FailClosed: policy rejection or error", id)
                {
                    tracing::error!(branch = %id, error = %e, "rollback failed in FailClosed mode");
                }
            }
            puzzled_types::FailMode::FailSilent => {
                // H-26: Keep frozen — hold last safe state. Transition to Degraded
                // instead of removing from DashMap so the branch remains trackable.
                // Clean up puzzled-side resources but the cgroup remains (keeping agent frozen).
                self.cleanup_branch_resources(id);
                if let Some(mut info) = self.branches.get_mut(id) {
                    info.state = BranchState::Degraded;
                }
                tracing::warn!(
                    branch = %id,
                    "FailSilent: keeping agent frozen (holding last safe state), resources cleaned up, state=Degraded"
                );
            }
            puzzled_types::FailMode::FailOperational => {
                // H-26: Thaw but don't rollback — reduced capability. Transition to Degraded
                // instead of removing from DashMap so the branch remains trackable.
                #[cfg(target_os = "linux")]
                self.thaw_cgroup(id);
                // Clean up puzzled-side resources. The agent process continues running
                // in reduced capability mode, but puzzled releases its handles.
                self.cleanup_branch_resources(id);
                if let Some(mut info) = self.branches.get_mut(id) {
                    info.state = BranchState::Degraded;
                }
                tracing::warn!(
                    branch = %id,
                    "FailOperational: agent thawed, changes preserved (reduced capability), resources cleaned up, state=Degraded"
                );
            }
            puzzled_types::FailMode::FailSafeState => {
                // Thaw + rollback + kill agent + verify termination
                #[cfg(target_os = "linux")]
                let cgroup_path = self
                    .sandboxes
                    .get(id)
                    .map(|h| h.cgroup_path.clone())
                    .or_else(|| {
                        self.branches.get(id).and_then(|r| r.pid).and_then(|pid| {
                            crate::sandbox::cgroup::cgroup_v2_fs_path_for_pid(pid).ok()
                        })
                    });
                #[cfg(target_os = "linux")]
                self.thaw_cgroup(id);
                if let Err(e) =
                    self.rollback_internal("FailSafeState: controlled stop after rejection", id)
                {
                    tracing::error!(
                        branch = %id,
                        error = %e,
                        "rollback failed in FailSafeState mode"
                    );
                }
                // H3: Verify agent processes are actually dead (belt-and-suspenders for safety)
                // M3: Use non-blocking tokio::time::sleep instead of blocking thread::sleep
                // to avoid holding any locks during the wait.
                #[cfg(target_os = "linux")]
                if let Some(cg_path) = cgroup_path {
                    let branch_id_clone = id.clone();
                    let procs_path = cg_path.join("cgroup.procs");
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
                    loop {
                        match std::fs::read_to_string(&procs_path) {
                            Ok(contents) if contents.trim().is_empty() => break,
                            Err(_) => break, // cgroup already removed
                            _ => {}
                        }
                        if std::time::Instant::now() > deadline {
                            tracing::error!(
                                branch = %branch_id_clone,
                                "FailSafeState: processes still alive after 3s kill timeout"
                            );
                            break;
                        }
                        // Sleep briefly to avoid burning CPU in a spin loop.
                        // A full async sleep is not feasible here since apply_fail_mode
                        // is synchronous.
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                }
                tracing::warn!(branch = %id, "FailSafeState: agent killed after rollback");
            }
        }
    }
}

/// Freeze the cgroup containing `pid` by resolving `/proc/<pid>/cgroup` (cgroup v2 `0::` line)
/// and delegating to [`crate::sandbox::cgroup::CgroupManager::freeze`].
#[cfg(target_os = "linux")]
fn freeze_cgroup_by_pid(pid: u32) -> Result<PathBuf> {
    let path = crate::sandbox::cgroup::cgroup_v2_fs_path_for_pid(pid)?;
    crate::sandbox::cgroup::CgroupManager::freeze(&path)?;
    Ok(path)
}
