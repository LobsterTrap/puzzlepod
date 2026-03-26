// SPDX-License-Identifier: Apache-2.0
use anyhow::{bail, Context, Result};
use std::path::PathBuf;

use crate::client::PuzzledClient;

use super::scenario::{ActionType, Scenario};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Outcome {
    Committed,
    Denied,
    RolledBack,
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Outcome::Committed => write!(f, "committed"),
            Outcome::Denied => write!(f, "denied"),
            Outcome::RolledBack => write!(f, "rolled_back"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StepResult {
    pub index: usize,
    pub total: usize,
    pub action_type: ActionType,
    pub target: String,
    pub description: Option<String>,
    pub skipped: bool,
}

#[derive(Debug, Clone)]
pub struct InspectResult {
    pub added: usize,
    pub modified: usize,
    pub deleted: usize,
    pub total_files: usize,
    pub total_bytes: u64,
    pub files: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct ApproveResult {
    pub outcome: Outcome,
    pub deny_reason: Option<String>,
}

#[derive(Debug)]
pub struct HistoryEntry {
    pub index: usize,
    pub action_type: ActionType,
    pub target: String,
    pub skipped: bool,
}

/// Controls whether the simulator writes directly to the overlay upper dir
/// (legacy, no sandbox) or spawns `puzzle-sim-worker` inside a full sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimMode {
    /// Write directly to `upper_dir` — no sandbox, no process isolation.
    Direct,
    /// Use `activate_branch()` to spawn `puzzle-sim-worker` inside the full
    /// sandbox (namespaces, seccomp, Landlock, cgroup).
    Sandbox,
}

pub struct SimEngine {
    scenario: Option<Scenario>,
    profile_override: Option<String>,
    cursor: usize,
    branch_id: Option<String>,
    merge_path: Option<PathBuf>,
    storage_base: String,
    history: Vec<HistoryEntry>,
    mode: SimMode,
}

impl SimEngine {
    pub fn new(storage_base: &str) -> Self {
        Self {
            scenario: None,
            profile_override: None,
            cursor: 0,
            branch_id: None,
            merge_path: None,
            storage_base: storage_base.to_string(),
            history: Vec::new(),
            mode: SimMode::Direct,
        }
    }

    pub fn with_mode(mut self, mode: SimMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn mode(&self) -> SimMode {
        self.mode
    }

    pub fn storage_base(&self) -> &str {
        &self.storage_base
    }

    pub fn load(&mut self, scenario: Scenario) {
        self.scenario = Some(scenario);
        self.profile_override = None;
        self.cursor = 0;
        self.branch_id = None;
        self.merge_path = None;
        self.history.clear();
    }

    pub fn scenario(&self) -> Option<&Scenario> {
        self.scenario.as_ref()
    }

    pub fn active_profile(&self) -> Option<&str> {
        if let Some(ov) = &self.profile_override {
            Some(ov.as_str())
        } else {
            self.scenario.as_ref().map(|s| s.profile.as_str())
        }
    }

    pub fn set_profile(&mut self, profile: String) {
        self.profile_override = Some(profile);
    }

    #[allow(dead_code)]
    pub fn branch_id(&self) -> Option<&str> {
        self.branch_id.as_deref()
    }

    #[allow(dead_code)]
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn total_actions(&self) -> usize {
        self.scenario.as_ref().map_or(0, |s| s.actions.len())
    }

    pub fn has_remaining_actions(&self) -> bool {
        self.cursor < self.total_actions()
    }

    pub fn is_started(&self) -> bool {
        self.branch_id.is_some()
    }

    pub fn history(&self) -> &[HistoryEntry] {
        &self.history
    }

    /// Create a branch via D-Bus and prepare for action execution.
    ///
    /// In `Direct` mode, uses `upper_dir` for direct writes (no sandbox).
    /// In `Sandbox` mode, writes the scenario YAML to `upper_dir`, then calls
    /// `activate_branch()` with `puzzle-sim-worker` as the command. The worker
    /// executes all actions inside the full sandbox.
    pub async fn start(&mut self, client: &PuzzledClient) -> Result<String> {
        let scenario = self.scenario.as_ref().context("no scenario loaded")?;

        let profile = self.active_profile().context("no profile")?.to_string();

        let base_path = scenario.base_path.to_string_lossy().to_string();

        let response = client
            .create_branch(&profile, &base_path, "[]")
            .await
            .context("failed to create branch")?;

        let parsed: serde_json::Value =
            serde_json::from_str(&response).context("invalid CreateBranch response")?;

        let bid = parsed
            .get("branch_id")
            .or_else(|| parsed.get("id"))
            .and_then(|v| v.as_str())
            .context("response missing branch_id")?
            .to_string();

        let upper = parsed
            .get("upper_dir")
            .and_then(|v| v.as_str())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(format!("{}/{}/upper", self.storage_base, bid)));

        self.branch_id = Some(bid.clone());
        self.cursor = 0;
        self.history.clear();

        if self.mode == SimMode::Sandbox {
            let scenario_yaml =
                serde_yaml::to_string(scenario).context("serializing scenario to YAML")?;
            let scenario_file = upper.join(".puzzle-sim-scenario.yaml");
            std::fs::create_dir_all(&upper).context("creating upper_dir for scenario")?;
            std::fs::write(&scenario_file, &scenario_yaml)
                .context("writing scenario YAML to upper_dir")?;

            let merged_scenario = "/.puzzle-sim-scenario.yaml".to_string();
            let command = serde_json::to_string(&vec![
                "puzzle-sim-worker".to_string(),
                "--scenario".to_string(),
                merged_scenario,
                "--root".to_string(),
                "/".to_string(),
            ])
            .context("serializing worker command")?;

            client
                .activate_branch(&bid, &command)
                .await
                .context("failed to activate branch with sandbox")?;

            self.merge_path = None;
        } else {
            self.merge_path = Some(upper);
        }

        Ok(bid)
    }

    /// Wait for the sandboxed worker process to complete.
    ///
    /// Polls `agent_info` until the branch state transitions away from `Active`
    /// (i.e., the worker exited and the branch moved to `Exited` or `Terminated`).
    /// Returns the final branch state string.
    ///
    /// N3: Times out after WORKER_TIMEOUT_SECS to prevent infinite polling.
    pub async fn wait_for_worker(&self, client: &PuzzledClient) -> Result<String> {
        // N3: Maximum time to wait for a worker process to complete
        const WORKER_TIMEOUT_SECS: u64 = 300;

        let bid = self.branch_id.as_ref().context("no active branch")?;
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(WORKER_TIMEOUT_SECS);
        loop {
            if std::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "N3: worker timeout after {}s waiting for branch {} to exit",
                    WORKER_TIMEOUT_SECS,
                    bid
                );
            }

            let info_json = client.agent_info(bid).await?;
            let parsed: serde_json::Value =
                serde_json::from_str(&info_json).unwrap_or(serde_json::Value::Null);
            let state = parsed
                .get("state")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            match state.as_str() {
                "active" | "ready" => {
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
                _ => return Ok(state),
            }
        }
    }

    /// Execute the next action.
    pub async fn step(&mut self) -> Result<StepResult> {
        self.step_inner(false, &[], &[]).await
    }

    async fn step_inner(
        &mut self,
        skip_by_index: bool,
        skip_indices: &[usize],
        skip_tags: &[String],
    ) -> Result<StepResult> {
        let merge_path = self
            .merge_path
            .as_ref()
            .context("no active branch -- call 'start' first")?
            .clone();

        let scenario = self.scenario.as_ref().context("no scenario loaded")?;
        let idx = self.cursor;
        if idx >= scenario.actions.len() {
            bail!("no more actions to execute");
        }

        let action = &scenario.actions[idx];
        let total = scenario.actions.len();
        let target = action.display_target().to_string();
        let description = action.description.clone();
        let action_type = action.action_type;

        let should_skip = (skip_by_index && skip_indices.contains(&idx))
            || (!skip_tags.is_empty() && action.tags.iter().any(|t| skip_tags.contains(t)));

        if !should_skip {
            action.execute(&merge_path)?;
        }

        self.history.push(HistoryEntry {
            index: idx,
            action_type,
            target: target.clone(),
            skipped: should_skip,
        });
        self.cursor = idx + 1;

        Ok(StepResult {
            index: idx,
            total,
            action_type,
            target,
            description,
            skipped: should_skip,
        })
    }

    /// Execute all remaining actions.
    pub async fn run(
        &mut self,
        skip_indices: &[usize],
        skip_tags: &[String],
    ) -> Result<Vec<StepResult>> {
        let mut results = Vec::new();
        while self.has_remaining_actions() {
            let r = self
                .step_inner(!skip_indices.is_empty(), skip_indices, skip_tags)
                .await?;
            results.push(r);
        }
        Ok(results)
    }

    /// Inspect the branch changeset via D-Bus.
    pub async fn inspect(&self, client: &PuzzledClient) -> Result<InspectResult> {
        let bid = self.branch_id.as_ref().context("no active branch")?;
        let response = client
            .inspect_branch(bid)
            .await
            .context("branch inspect failed")?;

        let parsed: serde_json::Value =
            serde_json::from_str(&response).context("invalid InspectBranch response")?;

        let changeset = parsed.get("changeset").or(Some(&parsed));

        let summary = changeset
            .and_then(|c| c.get("summary"))
            .unwrap_or(&serde_json::Value::Null);

        let changes = changeset
            .and_then(|c| c.get("changes"))
            .and_then(|c| c.as_array());

        let files: Vec<(String, String)> = changes
            .map(|arr| {
                arr.iter()
                    .map(|c| {
                        let path = c
                            .get("path")
                            .and_then(|v| v.as_str())
                            .unwrap_or("<unknown>")
                            .to_string();
                        let kind = c
                            .get("kind")
                            .or_else(|| c.get("change_type"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                            .to_string();
                        (path, kind)
                    })
                    .collect()
            })
            .unwrap_or_default();

        // R2: Use usize::try_from instead of bare `as usize` casts from D-Bus JSON
        Ok(InspectResult {
            added: usize::try_from(summary.get("added").and_then(|v| v.as_u64()).unwrap_or(0))
                .unwrap_or(usize::MAX),
            modified: usize::try_from(
                summary
                    .get("modified")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            )
            .unwrap_or(usize::MAX),
            deleted: usize::try_from(summary.get("deleted").and_then(|v| v.as_u64()).unwrap_or(0))
                .unwrap_or(usize::MAX),
            total_files: usize::try_from(
                summary
                    .get("total_files_changed")
                    .or_else(|| summary.get("total_files"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(u64::try_from(files.len()).unwrap_or(0)),
            )
            .unwrap_or(usize::MAX),
            total_bytes: summary
                .get("total_bytes_changed")
                .or_else(|| summary.get("total_bytes"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            files,
        })
    }

    /// Submit the branch for governance review (commit) via D-Bus.
    pub async fn approve(&mut self, client: &PuzzledClient) -> Result<ApproveResult> {
        // U29: Clone branch_id instead of consuming it, so it survives D-Bus errors.
        // Only clear it after a successful response is received.
        let bid = self.branch_id.as_ref().context("no active branch")?.clone();
        let response = client
            .commit_branch(&bid)
            .await
            .context("branch commit failed")?;

        // U29: Now that the call succeeded, clear the branch_id.
        self.branch_id = None;
        self.merge_path = None;

        let parsed: serde_json::Value =
            serde_json::from_str(&response).unwrap_or(serde_json::Value::Null);

        let is_rejected = match parsed.get("policy_result") {
            Some(serde_json::Value::Object(obj)) => {
                obj.contains_key("Rejected") || obj.contains_key("Error")
            }
            Some(serde_json::Value::String(s)) => s == "Rejected" || s == "Error",
            _ => {
                let status = parsed.get("status").and_then(|v| v.as_str()).unwrap_or("");
                status == "denied" || status == "rejected"
            }
        };

        if is_rejected {
            let reason = parsed
                .get("policy_result")
                .and_then(|pr| {
                    pr.get("Rejected")
                        .or_else(|| pr.get("Error"))
                        .map(|v| v.to_string())
                })
                .or_else(|| {
                    parsed
                        .get("reason")
                        .or_else(|| parsed.get("deny_reason"))
                        .or_else(|| parsed.get("error"))
                        .and_then(|v| v.as_str())
                        .map(String::from)
                })
                .unwrap_or_else(|| "denied by policy".to_string());
            Ok(ApproveResult {
                outcome: Outcome::Denied,
                deny_reason: Some(reason),
            })
        } else {
            Ok(ApproveResult {
                outcome: Outcome::Committed,
                deny_reason: None,
            })
        }
    }

    /// Reject (rollback) the branch via D-Bus.
    pub async fn reject(&mut self, client: &PuzzledClient) -> Result<()> {
        // U29: Clone branch_id instead of consuming it, so it survives D-Bus errors.
        let bid = self.branch_id.as_ref().context("no active branch")?.clone();
        client
            .rollback_branch(&bid, "rejected by puzzle-sim")
            .await
            .context("branch rollback failed")?;
        // U29: Clear only after successful rollback.
        self.branch_id = None;
        self.merge_path = None;
        Ok(())
    }

    pub fn reset(&mut self) {
        self.cursor = 0;
        self.branch_id = None;
        self.merge_path = None;
        self.history.clear();
    }
}
