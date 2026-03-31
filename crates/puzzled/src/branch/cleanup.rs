// SPDX-License-Identifier: Apache-2.0
#[cfg(target_os = "linux")]
use nix::mount::MntFlags;
use puzzled_types::{BranchId, BranchState};

use crate::sync_util::unlock_poisoned;

use super::BranchManager;

impl BranchManager {
    /// Cleanly shut down all active branches during daemon shutdown.
    ///
    /// Iterates all active/frozen branches and cleans up their resources:
    /// kills cgroup processes, unmounts OverlayFS, removes cgroup scopes,
    /// and cleans up network resources. Transitions branches to Terminated
    /// and emits audit events. Does NOT remove upper directories (state is
    /// preserved for recovery on restart).
    pub fn shutdown_all(&self) {
        let branch_ids: Vec<BranchId> = self.branches.iter().map(|r| r.key().clone()).collect();
        if branch_ids.is_empty() {
            return;
        }

        tracing::info!(count = branch_ids.len(), "shutting down active branches");

        for id in &branch_ids {
            let state = match self.branches.get(id) {
                Some(info) => info.state,
                None => continue,
            };

            // Only shut down branches that are still alive (including Degraded/Ready)
            if !matches!(
                state,
                BranchState::Active
                    | BranchState::Ready
                    | BranchState::Frozen
                    | BranchState::Creating
                    | BranchState::Degraded
            ) {
                continue;
            }

            // H-26: Thaw frozen or degraded-frozen branches before cleanup so cgroup.kill works
            // S6: Log thaw failures — if thaw fails, subsequent cgroup.kill will also fail
            #[cfg(target_os = "linux")]
            if state == BranchState::Frozen || state == BranchState::Degraded {
                self.thaw_cgroup(id);
            }

            self.cleanup_branch_resources(id);

            // Transition state to Terminated
            if let Some(mut info) = self.branches.get_mut(id) {
                info.state = BranchState::Terminated;
            }

            self.audit.log(crate::audit::AuditEvent::BranchRolledBack {
                branch_id: id.clone(),
                reason: "daemon shutdown".to_string(),
            });

            tracing::info!(branch = %id, "branch terminated during shutdown");
        }
    }

    /// Clean up all branch resources: sandbox (cgroup, overlay, pidfd, seccomp, BPF LSM,
    /// fanotify), network setup, network journal, and conflict tracking.
    ///
    /// This is the single cleanup path used by FailSilent, FailOperational, and rollback
    /// to ensure no resource leaks. Does NOT remove the upper directory or transition
    /// branch state — those are caller responsibilities.
    pub(super) fn cleanup_branch_resources(&self, id: &BranchId) {
        // §3.4: Revoke phantom tokens for this branch
        if let Some(ref ptm) = self.phantom_token_manager {
            // Must guarantee revocation — use blocking write to avoid silently skipping
            let mut ptm_guard = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(ptm.write())
            });
            ptm_guard.revoke_branch(id);
            tracing::debug!(branch = %id, "§3.4: phantom tokens revoked for branch");
        }

        // Clean up sandbox resources (cgroup, overlay, pidfd, seccomp, BPF LSM, fanotify, network)
        #[cfg(target_os = "linux")]
        self.cleanup_sandbox_resources(id);

        // Abort the proxy server task if running
        if let Some((_, task)) = self.proxy_tasks.remove(id) {
            task.abort();
            tracing::debug!(branch = %id, "HTTP proxy task aborted");
        }

        // Discard network journal if present
        if let Some((_, journal)) = self.network_journals.remove(id) {
            journal.discard();
        }

        // C8: Cancel any active path reservation for this branch
        // Clean up conflict tracking
        {
            let mut detector = unlock_poisoned(self.conflict_detector.lock());
            detector.cancel_reservation(id);
            detector.unregister_branch(id);
        }
    }

    /// Clean up sandbox resources (seccomp, network, fanotify, BPF LSM, cgroup, overlay, pidfd).
    ///
    /// Called from both commit (after success) and rollback. Does NOT remove the
    /// upper directory or transition branch state — those are caller responsibilities.
    #[cfg(target_os = "linux")]
    pub(super) fn cleanup_sandbox_resources(&self, id: &BranchId) {
        if let Some((_, mut handle)) = self.sandboxes.remove(id) {
            // Unregister seccomp notify fd
            if handle.seccomp_notify_fd.is_some() {
                if let Some(ref handler) = self.seccomp_handler {
                    handler.unregister(id.clone());
                }
            }

            // Clean up network resources
            if let Some((_, net_setup)) = self.network_setups.remove(id) {
                net_setup.cleanup();
            }

            // Remove fanotify trigger receiver
            self.fanotify_triggers.remove(id);

            // S17: Clean up BPF LSM rate limits — log error to detect map entry leaks
            if let Some(ref bpf_lsm) = self.bpf_lsm {
                if let Ok(meta) = std::fs::metadata(&handle.cgroup_path) {
                    use std::os::unix::fs::MetadataExt;
                    if let Err(e) = bpf_lsm.remove_cgroup(meta.ino()) {
                        tracing::warn!(
                            branch = %id,
                            cgroup_ino = meta.ino(),
                            error = %e,
                            "S17: BPF LSM cgroup removal failed — map entry may leak"
                        );
                    }
                }
            }

            // S4: Kill processes via cgroup — log error instead of silently discarding
            if let Err(e) = crate::sandbox::cgroup::CgroupManager::remove_scope(&handle.cgroup_path)
            {
                tracing::error!(
                    branch = %id,
                    cgroup = %handle.cgroup_path.display(),
                    error = %e,
                    "S4: cgroup remove_scope failed — orphaned agent processes may persist"
                );
            }

            // S5: Unmount OverlayFS — log error instead of silently discarding.
            // A failed unmount leaves the branch filesystem visible and accessible.
            if let Err(e) = nix::mount::umount2(&handle.merged_dir, MntFlags::MNT_DETACH) {
                tracing::error!(
                    branch = %id,
                    merged = %handle.merged_dir.display(),
                    error = %e,
                    "S5: OverlayFS unmount failed — branch filesystem may remain accessible"
                );
            } else {
                tracing::debug!(merged = %handle.merged_dir.display(), "OverlayFS unmounted");
            }

            // Close pidfd and mark it closed so Drop doesn't double-close.
            // Double-close causes fd reuse races in parallel tests (SIGABRT).
            if handle.pidfd >= 0 {
                unsafe { libc::close(handle.pidfd) };
                handle.pidfd = -1;
            }

            tracing::info!(branch = %id, "sandbox resources cleaned up");
        }
    }

    /// Thaw the cgroup for a branch (best-effort, logs on failure).
    pub(super) fn thaw_cgroup(&self, id: &BranchId) {
        #[cfg(target_os = "linux")]
        {
            if let Some(handle) = self.sandboxes.get(id) {
                if let Err(e) = crate::sandbox::cgroup::CgroupManager::thaw(&handle.cgroup_path) {
                    tracing::warn!(branch = %id, error = %e, "failed to thaw cgroup");
                }
            } else if let Some(pid) = self.branches.get(id).and_then(|r| r.pid) {
                match crate::sandbox::cgroup::cgroup_v2_fs_path_for_pid(pid) {
                    Ok(path) => {
                        if let Err(e) = crate::sandbox::cgroup::CgroupManager::thaw(&path) {
                            tracing::warn!(
                                branch = %id,
                                pid,
                                error = %e,
                                "failed to thaw cgroup (resolved via PID; no sandbox handle)"
                            );
                        }
                    }
                    Err(e) => tracing::warn!(
                        branch = %id,
                        pid,
                        error = %e,
                        "failed to resolve cgroup path for thaw via PID"
                    ),
                }
            }
        }
        let _ = id; // suppress unused warning on non-Linux
    }

    /// Replay the network journal for a committed branch (async, best-effort).
    ///
    /// Aborts the proxy server first so no new entries are written during replay.
    pub(super) fn replay_network_journal(&self, id: &BranchId) {
        // Stop the proxy before replaying — no new entries should arrive during replay
        if let Some((_, task)) = self.proxy_tasks.remove(id) {
            task.abort();
            tracing::debug!(branch = %id, "HTTP proxy task aborted before journal replay");
        }

        if let Some((_, journal)) = self.network_journals.remove(id) {
            let branch_id_clone = id.clone();
            // Guard against missing Tokio runtime (e.g., in synchronous tests).
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    match journal.replay(&[]).await {
                        Ok(count) if count > 0 => {
                            tracing::info!(
                                branch = %branch_id_clone,
                                replayed = count,
                                "network journal replayed"
                            );
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(
                                branch = %branch_id_clone,
                                error = %e,
                                "network journal replay failed (continuing)"
                            );
                        }
                    }
                });
            } else {
                tracing::debug!(
                    branch = %branch_id_clone,
                    "skipping network journal replay (no Tokio runtime)"
                );
            }
        }
    }
}
