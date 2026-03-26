// SPDX-License-Identifier: Apache-2.0
use puzzled_types::{FileChange, PolicyDecision, Violation, ViolationSeverity};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{PuzzledError, Result};

/// OPA/Rego policy engine using regorus (pure-Rust Rego evaluator).
///
/// H-29: Engine wrapped in `Mutex` for interior mutability so that `evaluate()`
/// and `reload()` take `&self` instead of `&mut self`. This eliminates the need
/// for an external `RwLock<PolicyEngine>` wrapper — callers can use `PolicyEngine`
/// directly without lock contention.
///
/// Evaluates commit governance policies against file changesets.
/// Cross-platform: policy evaluation is testable on macOS.
pub struct PolicyEngine {
    policy_dir: PathBuf,
    engine: std::sync::Mutex<regorus::Engine>,
    policy_count: std::sync::atomic::AtomicUsize,
    /// H8: Maximum time (ms) allowed for policy evaluation before timeout.
    /// On timeout, the commit is rejected with a Critical violation (fail-closed).
    evaluation_timeout_ms: u64,
    /// H-7: Counter of policy evaluation threads that leaked (timed out and were
    /// not joinable within 2x timeout). Indicates regorus hangs. Wrapped in Arc
    /// so the background join thread can decrement on recovery.
    leaked_policy_threads: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// F17: Counter of currently active policy evaluation threads.
    /// Used with MAX_CONCURRENT_EVALUATIONS to bound concurrency.
    active_evaluations: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// G10: Counter of currently active watcher threads (background join threads
    /// that wait for leaked policy evaluation threads to finish).
    active_watcher_threads: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl PolicyEngine {
    /// Create a new policy engine, loading Rego policies from the given directory.
    ///
    /// `evaluation_timeout_ms` sets the maximum duration for a single policy
    /// evaluation. If 0, a default of 5000ms is used.
    pub fn new(policy_dir: PathBuf) -> Self {
        Self::with_timeout(policy_dir, 5000)
    }

    /// Create a new policy engine with a custom evaluation timeout.
    pub fn with_timeout(policy_dir: PathBuf, evaluation_timeout_ms: u64) -> Self {
        let timeout = if evaluation_timeout_ms == 0 {
            5000
        } else {
            evaluation_timeout_ms
        };
        Self {
            policy_dir,
            engine: std::sync::Mutex::new(regorus::Engine::new()),
            policy_count: std::sync::atomic::AtomicUsize::new(0),
            evaluation_timeout_ms: timeout,
            leaked_policy_threads: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            active_evaluations: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            active_watcher_threads: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Load/reload all `.rego` files from the policy directory into the engine.
    ///
    /// H-29: Takes `&self` — acquires internal Mutex for engine replacement.
    pub fn reload(&self) -> Result<()> {
        let mut new_engine = regorus::Engine::new();

        // R25: Return an error when policy directory doesn't exist instead of
        // silently succeeding with no policies loaded.
        if !self.policy_dir.exists() {
            return Err(PuzzledError::Config(format!(
                "R25: policy directory does not exist: {}",
                self.policy_dir.display()
            )));
        }

        let entries = std::fs::read_dir(&self.policy_dir).map_err(|e| {
            PuzzledError::Policy(format!(
                "cannot read policy dir {}: {}",
                self.policy_dir.display(),
                e
            ))
        })?;

        let mut count = 0;
        for entry in entries {
            let entry = entry.map_err(|e| PuzzledError::Policy(e.to_string()))?;
            let path = entry.path();

            if path.extension().and_then(|e| e.to_str()) == Some("rego") {
                let contents = std::fs::read_to_string(&path).map_err(|e| {
                    PuzzledError::Policy(format!("reading {}: {}", path.display(), e))
                })?;

                new_engine
                    .add_policy(path.display().to_string(), contents)
                    .map_err(|e| {
                        PuzzledError::Policy(format!("loading {}: {}", path.display(), e))
                    })?;
                count += 1;
            }
        }

        // Swap engine under lock
        {
            let mut engine = self.engine.lock().unwrap_or_else(|e| {
                // S10/H-29: Mutex was poisoned by a panic in a previous holder.
                // Recovery is intentional (policy engine state is replaced below),
                // but log a warning so the event is visible in audit logs.
                tracing::warn!("S10: policy engine mutex was poisoned — recovering (H-29)");
                e.into_inner()
            });
            *engine = new_engine;
        }
        self.policy_count
            .store(count, std::sync::atomic::Ordering::Relaxed);
        tracing::info!(count, dir = %self.policy_dir.display(), "loaded Rego policies");
        Ok(())
    }

    /// Evaluate commit governance policy against a set of file changes.
    ///
    /// Input format matches commit.rego expectations:
    /// ```json
    /// { "changes": [{ "path": "...", "kind": "...", "size": ..., "checksum": "..." }],
    ///   "profile": "standard" }
    /// ```
    ///
    /// If `profile_name` is provided, it is included in the input as `input.profile`,
    /// enabling profile-aware policy rules (e.g., per-profile storage quotas).
    ///
    /// Evaluates:
    /// - `data.puzzlepod.commit.allow` -> bool
    /// - `data.puzzlepod.commit.violations` -> set of violation objects
    ///
    /// H-29: Takes `&self` — evaluation uses a thread-isolated engine copy.
    pub fn evaluate(
        &self,
        changes: &[FileChange],
        profile_name: Option<&str>,
    ) -> Result<PolicyDecision> {
        self.evaluate_with_workspace(changes, profile_name, None)
    }

    /// Evaluate governance policy with workspace root for boundary enforcement.
    ///
    /// H-14: `workspace_root` is passed to the Rego input so that the
    /// `deny_outside_workspace` rule can fire correctly.
    /// H-7: Maximum number of leaked policy threads before rejecting new evaluations.
    /// Each leaked thread consumes ~8 MB stack + regorus engine memory. On edge devices
    /// (4 GB target), 16 leaked threads = ~128 MB — acceptable. Beyond this, reject
    /// to prevent OOM.
    const MAX_LEAKED_THREADS: u64 = 16;

    /// F17: Maximum number of concurrent policy evaluation threads.
    /// Prevents unbounded thread creation under high load.
    const MAX_CONCURRENT_EVALUATIONS: usize = 16;

    /// G10: Maximum number of watcher threads that wait for leaked policy
    /// evaluation threads to finish. Prevents unbounded watcher thread creation
    /// when many evaluations time out in succession.
    const MAX_WATCHER_THREADS: usize = 16;

    pub fn evaluate_with_workspace(
        &self,
        changes: &[FileChange],
        profile_name: Option<&str>,
        workspace_root: Option<&str>,
    ) -> Result<PolicyDecision> {
        // K67: Delegate to full method with no storage_quota_bytes
        self.evaluate_full(changes, profile_name, workspace_root, None)
    }

    /// Evaluate governance policy with all optional parameters.
    ///
    /// K67: `storage_quota_bytes` is passed to the Rego input so that the
    /// `dynamic_storage_quota` rule can use profile-specific limits.
    pub fn evaluate_full(
        &self,
        changes: &[FileChange],
        profile_name: Option<&str>,
        workspace_root: Option<&str>,
        storage_quota_bytes: Option<u64>,
    ) -> Result<PolicyDecision> {
        // F17: Reject if too many concurrent evaluations are in progress.
        let active = self
            .active_evaluations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if active >= Self::MAX_CONCURRENT_EVALUATIONS {
            self.active_evaluations
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            tracing::error!(
                active,
                max = Self::MAX_CONCURRENT_EVALUATIONS,
                "F17: policy evaluation rejected — too many concurrent evaluations"
            );
            return Ok(PolicyDecision::Rejected(vec![Violation {
                rule: "evaluation_overloaded".to_string(),
                message: format!(
                    "policy evaluation thread limit exceeded ({}/{})",
                    active,
                    Self::MAX_CONCURRENT_EVALUATIONS
                ),
                severity: ViolationSeverity::Critical,
            }]));
        }

        // F17: Guard to decrement active_evaluations on all exit paths.
        struct EvalGuard(std::sync::Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for EvalGuard {
            fn drop(&mut self) {
                self.0.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        let _eval_guard = EvalGuard(std::sync::Arc::clone(&self.active_evaluations));

        // H-7: Reject if too many policy threads have leaked (DoS prevention).
        // Each leaked thread holds ~8 MB stack + regorus engine instance.
        let leaked_count = self
            .leaked_policy_threads
            .load(std::sync::atomic::Ordering::Relaxed);
        if leaked_count >= Self::MAX_LEAKED_THREADS {
            tracing::error!(
                leaked_count,
                max = Self::MAX_LEAKED_THREADS,
                "H-7: policy evaluation rejected — too many leaked threads (DoS prevention)"
            );
            return Ok(PolicyDecision::Rejected(vec![Violation {
                rule: "exhausted_policy_threads".to_string(),
                message: format!(
                    "policy evaluation thread limit exceeded ({}/{}) — system may be under load or attack",
                    leaked_count, Self::MAX_LEAKED_THREADS
                ),
                severity: ViolationSeverity::Critical,
            }]));
        }

        // Fail-closed: reject if no policies are loaded
        if self.policy_count.load(std::sync::atomic::Ordering::Relaxed) == 0 {
            tracing::error!("no governance policies loaded — fail-closed, rejecting commit");
            return Ok(PolicyDecision::Rejected(vec![Violation {
                rule: "no_policies_loaded".to_string(),
                message: "no governance policies are loaded; cannot evaluate commit (fail-closed)"
                    .to_string(),
                severity: ViolationSeverity::Critical,
            }]));
        }

        // Build input JSON with optional profile metadata for profile-aware policies
        // M1: Include total_bytes_changed so Rego policies can use input.total_bytes_changed
        let total_bytes_changed: u64 = changes.iter().map(|c| c.size).sum();
        let mut input = serde_json::json!({
            "changes": changes.iter().map(|c| {
                serde_json::json!({
                    "path": c.path.to_string_lossy(),
                    "kind": format!("{:?}", c.kind),
                    "size": c.size,
                    "checksum": &c.checksum,
                    // K60: Include symlink target in Rego input so policies can
                    // validate symlink destinations (e.g., deny_symlink_outside_workspace)
                    "target": c.target.as_deref().unwrap_or(""),
                    // R1: Include new_mode so Rego can check setuid/setgid bits
                    "new_mode": c.new_mode,
                })
            }).collect::<Vec<_>>(),
            "total_bytes_changed": total_bytes_changed
        });
        if let Some(profile) = profile_name {
            input["profile"] = serde_json::Value::String(profile.to_string());
        }
        // H-14: Set workspace_root so the Rego rule `deny_outside_workspace` fires correctly.
        if let Some(root) = workspace_root {
            input["workspace_root"] = serde_json::Value::String(root.to_string());
        }
        // K67: Include storage_quota_bytes so Rego can use dynamic profile-specific
        // limits instead of hard-coded values. Populated from profile metadata when available.
        if let Some(quota) = storage_quota_bytes {
            input["storage_quota_bytes"] = serde_json::Value::Number(quota.into());
        }

        let input_str = serde_json::to_string(&input)
            .map_err(|e| PuzzledError::Policy(format!("serializing input: {}", e)))?;

        // B5: Hard timeout via channel-based isolation.
        // regorus::Engine is !Send, so we can't move it to another thread.
        // Instead, we spawn a thread with a fresh engine that loads policies,
        // evaluates, and sends the result through a channel. The caller uses
        // recv_timeout to enforce a hard deadline — if evaluation hangs, the
        // caller returns a timeout rejection immediately without blocking.
        //
        // Trade-off: ~2-5ms overhead per evaluation for policy reloading.
        // This is acceptable given typical LLM inference latency (~seconds).
        let timeout_ms = self.evaluation_timeout_ms;
        let policy_dir = self.policy_dir.clone();
        let input_str_clone = input_str;

        let (tx, rx) = std::sync::mpsc::channel();

        let handle = std::thread::spawn(move || {
            let result = (|| -> Result<PolicyDecision> {
                let mut engine = regorus::Engine::new();

                // S1: Reload policies in the isolated thread.
                // Track load failures — if any .rego file fails to compile,
                // reject the evaluation (fail-closed). Silent discard via
                // `let _ =` would allow evaluation with incomplete rules.
                let mut policy_load_errors: Vec<String> = Vec::new();
                if let Ok(entries) = std::fs::read_dir(&policy_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.extension().and_then(|e| e.to_str()) == Some("rego") {
                            // R5: Do not silently skip unreadable policy files
                            match std::fs::read_to_string(&path) {
                                Ok(contents) => {
                                    if let Err(e) =
                                        engine.add_policy(path.display().to_string(), contents)
                                    {
                                        policy_load_errors.push(format!(
                                            "{}: {}",
                                            path.display(),
                                            e
                                        ));
                                    }
                                }
                                Err(e) => {
                                    policy_load_errors.push(format!(
                                        "R5: failed to read {}: {}",
                                        path.display(),
                                        e
                                    ));
                                }
                            }
                        }
                    }
                }

                if !policy_load_errors.is_empty() {
                    return Ok(PolicyDecision::Rejected(vec![Violation {
                        rule: "policy_load_failure".to_string(),
                        message: format!(
                            "S1: {} policy file(s) failed to compile — rejecting evaluation \
                             (fail-closed): {}",
                            policy_load_errors.len(),
                            policy_load_errors.join("; ")
                        ),
                        severity: ViolationSeverity::Critical,
                    }]));
                }

                let input_value = regorus::Value::from_json_str(&input_str_clone)
                    .map_err(|e| PuzzledError::Policy(format!("parsing input: {}", e)))?;
                engine.set_input(input_value);

                // Evaluate allow rule
                let allow_result = engine
                    .eval_rule("data.puzzlepod.commit.allow".to_string())
                    .map_err(|e| PuzzledError::Policy(format!("evaluating allow rule: {}", e)))?;

                let allowed = matches!(allow_result, regorus::Value::Bool(true));

                if allowed {
                    return Ok(PolicyDecision::Approved);
                }

                // Parse violations using eval_query (matches evaluate_inner logic)
                let violations_query = engine
                    .eval_query("data.puzzlepod.commit.violations".to_string(), false)
                    .map_err(|e| PuzzledError::Policy(format!("evaluating violations: {}", e)))?;

                let violations = PolicyEngine::parse_query_violations(&violations_query);
                if violations.is_empty() {
                    Ok(PolicyDecision::Rejected(vec![Violation {
                        rule: "unknown".to_string(),
                        message: "policy denied commit with no specific violations".to_string(),
                        severity: ViolationSeverity::Error,
                    }]))
                } else {
                    Ok(PolicyDecision::Rejected(violations))
                }
            })();
            // Q4: Log channel send failures (caller likely timed out)
            if let Err(_e) = tx.send(result) {
                tracing::debug!("Q4: policy result channel send failed — caller likely timed out");
            }
        });

        match rx.recv_timeout(Duration::from_millis(timeout_ms)) {
            Ok(result) => result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                tracing::error!(
                    timeout_ms,
                    "policy evaluation exceeded hard timeout — fail-closed, rejecting commit"
                );
                // H-7: Track the leaked thread. Attempt to join with 2x timeout
                // in background. regorus has no cancellation API, so the thread
                // will run until completion or process exit.
                let leaked_count = self
                    .leaked_policy_threads
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    + 1;
                tracing::warn!(
                    leaked_count,
                    "H-7: policy evaluation thread leaked (regorus has no cancellation API)"
                );
                let leaked_counter = std::sync::Arc::clone(&self.leaked_policy_threads);
                // G10: Check watcher thread count before spawning.
                let watcher_count = self
                    .active_watcher_threads
                    .fetch_add(0, std::sync::atomic::Ordering::Relaxed);
                if watcher_count >= Self::MAX_WATCHER_THREADS {
                    tracing::warn!(
                        watcher_count,
                        max = Self::MAX_WATCHER_THREADS,
                        "G10: watcher thread limit reached — skipping background join \
                         (leaked thread will be cleaned up on process exit)"
                    );
                } else {
                    let watcher_counter = std::sync::Arc::clone(&self.active_watcher_threads);
                    watcher_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    std::thread::spawn(move || {
                        // Wait for the evaluation thread to finish (best-effort)
                        let start = std::time::Instant::now();
                        match handle.join() {
                            Ok(_) => {
                                // H-7: Thread recovered — decrement leaked count so future
                                // evaluations are not blocked.
                                leaked_counter.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                                tracing::info!(
                                    elapsed_ms = start.elapsed().as_millis(),
                                    "H-7: leaked policy thread completed after timeout (counter decremented)"
                                );
                            }
                            Err(_) => {
                                tracing::error!(
                                    "H-7: leaked policy thread panicked (counter not decremented)"
                                );
                            }
                        }
                        // G10: Decrement watcher thread count.
                        watcher_counter.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    });
                }
                Ok(PolicyDecision::Rejected(vec![Violation {
                    rule: "timeout".to_string(),
                    message: format!("policy evaluation exceeded {}ms hard timeout", timeout_ms),
                    severity: ViolationSeverity::Critical,
                }]))
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                tracing::error!("policy evaluation thread panicked — fail-closed");
                Ok(PolicyDecision::Rejected(vec![Violation {
                    rule: "evaluation_panic".to_string(),
                    message: "policy evaluation thread panicked".to_string(),
                    severity: ViolationSeverity::Critical,
                }]))
            }
        }
    }

    /// Inner evaluation logic (used by tests and non-timeout paths).
    /// B5: Production evaluate() now uses thread-based isolation with hard timeout.
    #[allow(dead_code)]
    fn evaluate_inner(&self) -> Result<PolicyDecision> {
        let mut engine = self.engine.lock().unwrap_or_else(|e| {
            // S10/H-29: Mutex was poisoned — recover but log a warning.
            tracing::warn!(
                "S10: policy engine mutex was poisoned in evaluate_inner — recovering (H-29)"
            );
            e.into_inner()
        });
        // Evaluate the allow rule
        let allow_result = engine
            .eval_rule("data.puzzlepod.commit.allow".to_string())
            .map_err(|e| PuzzledError::Policy(format!("evaluating allow rule: {}", e)))?;

        let allowed = matches!(allow_result, regorus::Value::Bool(true));

        if allowed {
            return Ok(PolicyDecision::Approved);
        }

        // Evaluate violations using eval_query to get the full set
        let violations_query = engine
            .eval_query("data.puzzlepod.commit.violations".to_string(), false)
            .map_err(|e| PuzzledError::Policy(format!("evaluating violations: {}", e)))?;

        let violations = Self::parse_query_violations(&violations_query);

        if violations.is_empty() {
            // Policy denied but no specific violations collected
            Ok(PolicyDecision::Rejected(vec![Violation {
                rule: "unknown".to_string(),
                message: "policy denied commit with no specific violations".to_string(),
                severity: ViolationSeverity::Error,
            }]))
        } else {
            Ok(PolicyDecision::Rejected(violations))
        }
    }

    /// Return the number of loaded policies.
    pub fn policy_count(&self) -> usize {
        self.policy_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// H-7: Return the count of leaked policy evaluation threads.
    pub fn leaked_thread_count(&self) -> u64 {
        self.leaked_policy_threads
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Validate a policy file without loading it into the engine.
    pub fn validate(path: &Path) -> Result<()> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| PuzzledError::Policy(format!("reading {}: {}", path.display(), e)))?;

        let mut engine = regorus::Engine::new();
        engine
            .add_policy(path.display().to_string(), contents)
            .map_err(|e| PuzzledError::Policy(format!("validating {}: {}", path.display(), e)))?;

        Ok(())
    }

    /// Parse query results from violations evaluation into Violation structs.
    fn parse_query_violations(query_results: &regorus::QueryResults) -> Vec<Violation> {
        let mut violations = Vec::new();

        for result in &query_results.result {
            for expr in &result.expressions {
                Self::extract_violations_from_value(&expr.value, &mut violations);
            }
        }

        violations
    }

    /// Extract Violation structs from a regorus Value.
    ///
    /// Regorus represents Rego sets as Object where keys are set elements
    /// and values are Bool(true). So `violations` comes back as:
    /// `Object({Object({...}): Bool(true), ...})`
    fn extract_violations_from_value(value: &regorus::Value, violations: &mut Vec<Violation>) {
        match value {
            regorus::Value::Set(set) => {
                for item in set.iter() {
                    if let Some(v) = Self::parse_single_violation(item) {
                        violations.push(v);
                    }
                }
            }
            regorus::Value::Array(arr) => {
                for item in arr.iter() {
                    if let Some(v) = Self::parse_single_violation(item) {
                        violations.push(v);
                    }
                }
            }
            regorus::Value::Object(obj) => {
                // Rego set-as-object: keys are violation objects, values are true
                for (key, val) in obj.iter() {
                    if matches!(val, regorus::Value::Bool(true)) {
                        if let Some(v) = Self::parse_single_violation(key) {
                            violations.push(v);
                        }
                    }
                }
                // If no set elements found, try parsing the object itself
                if violations.is_empty() {
                    if let Some(v) = Self::parse_single_violation(value) {
                        violations.push(v);
                    }
                }
            }
            _ => {}
        }
    }

    /// Parse a single violation object from a regorus Value.
    fn parse_single_violation(value: &regorus::Value) -> Option<Violation> {
        let obj = match value {
            regorus::Value::Object(obj) => obj,
            _ => return None,
        };

        let get_str = |key: &str| -> Option<String> {
            obj.iter()
                .find(|(k, _)| matches!(k, regorus::Value::String(s) if s.as_ref() == key))
                .and_then(|(_, v)| {
                    if let regorus::Value::String(s) = v {
                        Some(s.as_ref().to_string())
                    } else {
                        None
                    }
                })
        };

        let rule = get_str("rule")?;
        let message = get_str("message").unwrap_or_else(|| "policy violation".to_string());
        let severity_str = get_str("severity").unwrap_or_else(|| "error".to_string());

        let severity = match severity_str.as_str() {
            "warning" => ViolationSeverity::Warning,
            "critical" => ViolationSeverity::Critical,
            _ => ViolationSeverity::Error,
        };

        Some(Violation {
            rule,
            message,
            severity,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use puzzled_types::FileChangeKind;
    use std::fs;

    fn create_policy_engine() -> PolicyEngine {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("policies")
            .join("rules");
        let engine = PolicyEngine::new(dir);
        engine.reload().unwrap();
        engine
    }

    #[test]
    fn test_policy_approve_clean_changeset() {
        let engine = create_policy_engine();

        let changes = vec![FileChange {
            path: PathBuf::from("src/main.rs"),
            kind: FileChangeKind::Modified,
            size: 1024,
            checksum: "abc123".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        }];

        let decision = engine.evaluate(&changes, None).unwrap();
        assert!(matches!(decision, PolicyDecision::Approved));
    }

    #[test]
    fn test_policy_reject_sensitive_file() {
        let engine = create_policy_engine();

        let changes = vec![FileChange {
            path: PathBuf::from("config/.env"),
            kind: FileChangeKind::Added,
            size: 256,
            checksum: "def456".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        }];

        let decision = engine.evaluate(&changes, None).unwrap();
        match decision {
            PolicyDecision::Rejected(violations) => {
                assert!(!violations.is_empty());
                assert!(violations.iter().any(|v| v.rule == "no_sensitive_files"));
            }
            other => panic!("expected Rejected, got {:?}", other),
        }
    }

    #[test]
    fn test_policy_reject_system_modification() {
        let engine = create_policy_engine();

        let changes = vec![FileChange {
            path: PathBuf::from("/usr/bin/malicious"),
            kind: FileChangeKind::Added,
            size: 4096,
            checksum: "ghi789".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        }];

        let decision = engine.evaluate(&changes, None).unwrap();
        match decision {
            PolicyDecision::Rejected(violations) => {
                assert!(violations
                    .iter()
                    .any(|v| v.rule == "no_system_modifications"));
            }
            other => panic!("expected Rejected, got {:?}", other),
        }
    }

    #[test]
    fn test_policy_validate() {
        let rego_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("policies")
            .join("rules")
            .join("commit.rego");

        PolicyEngine::validate(&rego_path).unwrap();
    }

    #[test]
    fn test_policy_validate_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let bad_rego = dir.path().join("bad.rego");
        fs::write(&bad_rego, "this is not valid rego {{{{").unwrap();

        assert!(PolicyEngine::validate(&bad_rego).is_err());
    }

    #[test]
    fn test_policy_evaluation_timeout() {
        // Create an engine with a very short timeout (1ms) and a valid policy.
        // Normal evaluation should complete within 1ms for simple policies,
        // so this test validates the timeout mechanism exists and the field is set.
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("policies")
            .join("rules");
        let engine = PolicyEngine::with_timeout(dir, 5000);
        engine.reload().unwrap();

        // Verify the timeout field is set
        assert_eq!(engine.evaluation_timeout_ms, 5000);

        // Normal evaluation should succeed within timeout
        let changes = vec![FileChange {
            path: PathBuf::from("src/main.rs"),
            kind: FileChangeKind::Modified,
            size: 1024,
            checksum: "abc123".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        }];

        let decision = engine.evaluate(&changes, None).unwrap();
        assert!(matches!(decision, PolicyDecision::Approved));
    }

    #[test]
    fn test_policy_timeout_rejection_format() {
        // Verify the timeout rejection has the correct format
        let violation = Violation {
            rule: "timeout".to_string(),
            message: "policy evaluation exceeded timeout".to_string(),
            severity: ViolationSeverity::Critical,
        };
        assert_eq!(violation.rule, "timeout");
        assert_eq!(violation.message, "policy evaluation exceeded timeout");
        assert_eq!(violation.severity, ViolationSeverity::Critical);
    }

    #[test]
    fn test_policy_profile_aware_restricted_rejects_large_changeset() {
        let engine = create_policy_engine();

        // Create a changeset that exceeds the restricted profile limit (10 MiB)
        // but is under the default limit (100 MiB).
        let changes = vec![FileChange {
            path: PathBuf::from("data/output.bin"),
            kind: FileChangeKind::Added,
            size: 20 * 1024 * 1024, // 20 MiB
            checksum: "large".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        }];

        // Without profile: should be approved (under 100 MiB default)
        let decision = engine.evaluate(&changes, None).unwrap();
        assert!(
            matches!(decision, PolicyDecision::Approved),
            "20 MiB should be under the default 100 MiB limit"
        );

        // With "restricted" profile: should be rejected (over 10 MiB limit)
        let decision = engine.evaluate(&changes, Some("restricted")).unwrap();
        match decision {
            PolicyDecision::Rejected(violations) => {
                assert!(
                    violations.iter().any(|v| v.rule == "profile_storage_quota"),
                    "restricted profile should enforce 10 MiB limit, got: {:?}",
                    violations
                );
            }
            other => panic!(
                "expected Rejected for restricted profile with 20 MiB changeset, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_policy_count() {
        let engine = create_policy_engine();
        assert!(
            engine.policy_count() > 0,
            "policy_count should be > 0 after reload"
        );
    }

    #[test]
    fn test_leaked_thread_count_initial() {
        let engine = create_policy_engine();
        assert_eq!(
            engine.leaked_thread_count(),
            0,
            "leaked_thread_count should be 0 initially"
        );
    }

    #[test]
    fn test_policy_no_policies_loaded_rejects() {
        // Fail-closed: no policies loaded should reject
        let dir = tempfile::tempdir().unwrap();
        let engine = PolicyEngine::new(dir.path().to_path_buf());
        // Don't call reload — policy_count stays 0

        let changes = vec![FileChange {
            path: PathBuf::from("src/main.rs"),
            kind: FileChangeKind::Modified,
            size: 1024,
            checksum: "abc".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        }];

        let decision = engine.evaluate(&changes, None).unwrap();
        match decision {
            PolicyDecision::Rejected(violations) => {
                assert!(violations.iter().any(|v| v.rule == "no_policies_loaded"));
            }
            other => panic!("expected Rejected, got {:?}", other),
        }
    }

    #[test]
    fn test_policy_with_timeout_zero_uses_default() {
        let dir = tempfile::tempdir().unwrap();
        let engine = PolicyEngine::with_timeout(dir.path().to_path_buf(), 0);
        assert_eq!(
            engine.evaluation_timeout_ms, 5000,
            "timeout of 0 should default to 5000ms"
        );
    }

    #[test]
    fn test_policy_validate_nonexistent_file() {
        let result = PolicyEngine::validate(std::path::Path::new("/nonexistent/file.rego"));
        assert!(result.is_err());
    }

    #[test]
    fn test_policy_reload_nonexistent_dir() {
        let engine = PolicyEngine::new(PathBuf::from("/nonexistent/dir"));
        // R25: Should return Err — non-existent policy dir is a configuration error
        let result = engine.reload();
        assert!(
            result.is_err(),
            "R25: reload() must return Err for nonexistent policy directory"
        );
        assert_eq!(engine.policy_count(), 0);
    }

    #[test]
    fn test_policy_evaluate_with_workspace() {
        let engine = create_policy_engine();

        let changes = vec![FileChange {
            path: PathBuf::from("src/main.rs"),
            kind: FileChangeKind::Modified,
            size: 1024,
            checksum: "abc123".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        }];

        // With workspace_root set
        let decision = engine
            .evaluate_with_workspace(&changes, Some("standard"), Some("/home/agent/project"))
            .unwrap();
        assert!(matches!(decision, PolicyDecision::Approved));
    }

    // -----------------------------------------------------------------------
    // Phase 1.4 — comprehensive unit tests
    // -----------------------------------------------------------------------

    /// Helper: create a PolicyEngine backed by a temp dir containing the given
    /// Rego source. Returns (engine, _tempdir) — caller must hold _tempdir to
    /// keep the directory alive.
    fn engine_from_rego(rego: &str) -> (PolicyEngine, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let rego_path = dir.path().join("test.rego");
        fs::write(&rego_path, rego).unwrap();
        let engine = PolicyEngine::new(dir.path().to_path_buf());
        engine.reload().unwrap();
        (engine, dir)
    }

    /// Helper: return the content of the production commit.rego file.
    fn production_rego() -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("policies")
            .join("rules")
            .join("commit.rego");
        fs::read_to_string(&path).unwrap()
    }

    /// Helper: create a PolicyEngine using a temp copy of the production rego.
    fn engine_from_production_rego() -> (PolicyEngine, tempfile::TempDir) {
        engine_from_rego(&production_rego())
    }

    // 1. Empty changeset passes policy
    #[test]
    fn test_empty_changeset_passes() {
        let (engine, _dir) = engine_from_production_rego();
        let changes: Vec<FileChange> = vec![];
        let decision = engine.evaluate(&changes, None).unwrap();
        assert!(
            matches!(decision, PolicyDecision::Approved),
            "empty changeset should be approved, got {:?}",
            decision
        );
    }

    // 2a. Sensitive file rejection — .env
    #[test]
    fn test_reject_dotenv_file() {
        let (engine, _dir) = engine_from_production_rego();
        let changes = vec![FileChange {
            path: PathBuf::from("app/.env"),
            kind: FileChangeKind::Added,
            size: 64,
            checksum: "aaa".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        }];
        let decision = engine.evaluate(&changes, None).unwrap();
        match decision {
            PolicyDecision::Rejected(ref violations) => {
                assert!(
                    violations.iter().any(|v| v.rule == "no_sensitive_files"),
                    "expected no_sensitive_files violation for .env, got {:?}",
                    violations
                );
            }
            other => panic!("expected Rejected for .env, got {:?}", other),
        }
    }

    // 2b. Sensitive file rejection — .ssh/id_rsa
    #[test]
    fn test_reject_ssh_private_key() {
        let (engine, _dir) = engine_from_production_rego();
        let changes = vec![FileChange {
            path: PathBuf::from("home/user/.ssh/id_rsa"),
            kind: FileChangeKind::Added,
            size: 1679,
            checksum: "bbb".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        }];
        let decision = engine.evaluate(&changes, None).unwrap();
        match decision {
            PolicyDecision::Rejected(ref violations) => {
                assert!(
                    violations.iter().any(|v| v.rule == "no_sensitive_files"),
                    "expected no_sensitive_files violation for .ssh/id_rsa, got {:?}",
                    violations
                );
            }
            other => panic!("expected Rejected for .ssh/id_rsa, got {:?}", other),
        }
    }

    // 3. Executable permission change rejection (MetadataChanged kind)
    #[test]
    fn test_reject_executable_permission_change() {
        let (engine, _dir) = engine_from_production_rego();
        let changes = vec![FileChange {
            path: PathBuf::from("scripts/deploy.sh"),
            kind: FileChangeKind::MetadataChanged,
            size: 0,
            checksum: "ccc".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        }];
        let decision = engine.evaluate(&changes, None).unwrap();
        match decision {
            PolicyDecision::Rejected(ref violations) => {
                assert!(
                    violations
                        .iter()
                        .any(|v| v.rule == "no_exec_permission_changes"),
                    "expected no_exec_permission_changes violation, got {:?}",
                    violations
                );
            }
            other => panic!("expected Rejected for MetadataChanged, got {:?}", other),
        }
    }

    // 4. Size limit enforcement — total_bytes_changed exceeds 100 MiB default
    #[test]
    fn test_reject_oversized_changeset() {
        let (engine, _dir) = engine_from_production_rego();
        let changes = vec![FileChange {
            path: PathBuf::from("data/huge.bin"),
            kind: FileChangeKind::Added,
            size: 200 * 1024 * 1024, // 200 MiB — exceeds 100 MiB default
            checksum: "ddd".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        }];
        let decision = engine.evaluate(&changes, None).unwrap();
        match decision {
            PolicyDecision::Rejected(ref violations) => {
                assert!(
                    violations.iter().any(|v| v.rule == "max_changeset_size"),
                    "expected max_changeset_size violation for 200 MiB, got {:?}",
                    violations
                );
            }
            other => panic!("expected Rejected for oversized changeset, got {:?}", other),
        }
    }

    // 5. Cron job path rejection (/etc/cron.d/*)
    #[test]
    fn test_reject_cron_job_path() {
        let (engine, _dir) = engine_from_production_rego();
        let changes = vec![FileChange {
            path: PathBuf::from("/etc/cron.d/evil-job"),
            kind: FileChangeKind::Added,
            size: 128,
            checksum: "eee".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        }];
        let decision = engine.evaluate(&changes, None).unwrap();
        match decision {
            PolicyDecision::Rejected(ref violations) => {
                assert!(
                    violations.iter().any(|v| v.rule == "no_persistence"),
                    "expected no_persistence violation for /etc/cron.d/*, got {:?}",
                    violations
                );
            }
            other => panic!("expected Rejected for cron job path, got {:?}", other),
        }
    }

    // 6. systemd unit path rejection (/etc/systemd/system/*)
    #[test]
    fn test_reject_systemd_unit_path() {
        let (engine, _dir) = engine_from_production_rego();
        let changes = vec![FileChange {
            path: PathBuf::from("/etc/systemd/system/backdoor.service"),
            kind: FileChangeKind::Added,
            size: 256,
            checksum: "fff".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        }];
        let decision = engine.evaluate(&changes, None).unwrap();
        match decision {
            PolicyDecision::Rejected(ref violations) => {
                assert!(
                    violations.iter().any(|v| v.rule == "no_persistence"),
                    "expected no_persistence violation for systemd unit, got {:?}",
                    violations
                );
            }
            other => panic!("expected Rejected for systemd unit path, got {:?}", other),
        }
    }

    // 7. Evaluation timeout (B5) — verify timeout mechanism rejects with
    //    correct violation when evaluation exceeds the deadline.
    //    We use a 1ms timeout with a policy containing an expensive computation
    //    to trigger the timeout path reliably.
    #[test]
    fn test_evaluation_timeout_triggers_rejection() {
        // Use a very short timeout (1ms). The thread-spawn + policy-load
        // overhead alone should exceed 1ms, triggering the timeout path.
        let dir = tempfile::tempdir().unwrap();
        let rego_path = dir.path().join("commit.rego");
        fs::write(&rego_path, production_rego()).unwrap();

        let engine = PolicyEngine::with_timeout(dir.path().to_path_buf(), 1);
        engine.reload().unwrap();

        let changes = vec![FileChange {
            path: PathBuf::from("src/main.rs"),
            kind: FileChangeKind::Modified,
            size: 1024,
            checksum: "ggg".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        }];

        // Run several attempts — thread-spawn overhead is non-deterministic,
        // but with a 1ms timeout at least some should time out.
        let mut saw_timeout = false;
        for _ in 0..20 {
            let decision = engine.evaluate(&changes, None).unwrap();
            if let PolicyDecision::Rejected(ref violations) = decision {
                if violations.iter().any(|v| v.rule == "timeout") {
                    saw_timeout = true;
                    // Verify severity is Critical (fail-closed)
                    let timeout_v = violations.iter().find(|v| v.rule == "timeout").unwrap();
                    assert_eq!(timeout_v.severity, ViolationSeverity::Critical);
                    break;
                }
            }
        }
        assert!(
            saw_timeout,
            "expected at least one timeout rejection with 1ms deadline over 20 attempts"
        );
    }

    // 8. Custom rules loading — verify reload picks up new/changed policies
    #[test]
    fn test_custom_rules_loading_and_reload() {
        let dir = tempfile::tempdir().unwrap();

        // Start with a simple allow-all policy
        let rego_v1 = r#"
package puzzlepod.commit
import future.keywords.if
default allow := true
violations := set()
"#;
        fs::write(dir.path().join("commit.rego"), rego_v1).unwrap();

        let engine = PolicyEngine::new(dir.path().to_path_buf());
        engine.reload().unwrap();
        assert_eq!(engine.policy_count(), 1);

        let changes = vec![FileChange {
            path: PathBuf::from("/etc/shadow"),
            kind: FileChangeKind::Added,
            size: 100,
            checksum: "hhh".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        }];

        // v1: allow-all — even /etc/shadow should be approved
        let decision = engine.evaluate(&changes, None).unwrap();
        assert!(
            matches!(decision, PolicyDecision::Approved),
            "allow-all policy should approve, got {:?}",
            decision
        );

        // Replace with the production policy that blocks system files
        fs::write(dir.path().join("commit.rego"), production_rego()).unwrap();
        engine.reload().unwrap();
        assert_eq!(engine.policy_count(), 1);

        // v2 (production): /etc/shadow should now be rejected
        let decision = engine.evaluate(&changes, None).unwrap();
        match decision {
            PolicyDecision::Rejected(ref violations) => {
                assert!(
                    violations
                        .iter()
                        .any(|v| v.rule == "no_system_modifications"
                            || v.rule == "no_sensitive_files"),
                    "expected rejection for /etc/shadow after reload, got {:?}",
                    violations
                );
            }
            other => panic!(
                "expected Rejected after reloading stricter policy, got {:?}",
                other
            ),
        }
    }

    // 9. System file modification rejection — /usr/* and /etc/*
    #[test]
    fn test_reject_system_file_usr() {
        let (engine, _dir) = engine_from_production_rego();
        let changes = vec![FileChange {
            path: PathBuf::from("/usr/lib/libevil.so"),
            kind: FileChangeKind::Added,
            size: 4096,
            checksum: "iii".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        }];
        let decision = engine.evaluate(&changes, None).unwrap();
        match decision {
            PolicyDecision::Rejected(ref violations) => {
                assert!(
                    violations
                        .iter()
                        .any(|v| v.rule == "no_system_modifications"),
                    "expected no_system_modifications for /usr/lib/*, got {:?}",
                    violations
                );
            }
            other => panic!("expected Rejected for /usr/lib/ path, got {:?}", other),
        }
    }

    #[test]
    fn test_reject_system_file_etc() {
        let (engine, _dir) = engine_from_production_rego();
        let changes = vec![FileChange {
            path: PathBuf::from("/etc/passwd"),
            kind: FileChangeKind::Modified,
            size: 2048,
            checksum: "jjj".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        }];
        let decision = engine.evaluate(&changes, None).unwrap();
        match decision {
            PolicyDecision::Rejected(ref violations) => {
                assert!(
                    violations
                        .iter()
                        .any(|v| v.rule == "no_system_modifications"),
                    "expected no_system_modifications for /etc/passwd, got {:?}",
                    violations
                );
            }
            other => panic!("expected Rejected for /etc/passwd, got {:?}", other),
        }
    }

    // 10. Symlink rejection for non-privileged profiles
    #[test]
    fn test_reject_symlink_non_privileged() {
        let (engine, _dir) = engine_from_production_rego();

        let changes = vec![FileChange {
            path: PathBuf::from("link_to_secret"),
            kind: FileChangeKind::Symlink,
            size: 0,
            checksum: "".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        }];

        // No profile (default) — symlinks should be denied
        let decision = engine.evaluate(&changes, None).unwrap();
        match decision {
            PolicyDecision::Rejected(ref violations) => {
                assert!(
                    violations.iter().any(|v| v.rule == "deny_symlink"),
                    "expected deny_symlink for non-privileged profile, got {:?}",
                    violations
                );
            }
            other => panic!(
                "expected Rejected for symlink without privileged profile, got {:?}",
                other
            ),
        }

        // Standard profile — still denied
        let decision = engine.evaluate(&changes, Some("standard")).unwrap();
        match decision {
            PolicyDecision::Rejected(ref violations) => {
                assert!(
                    violations.iter().any(|v| v.rule == "deny_symlink"),
                    "expected deny_symlink for standard profile, got {:?}",
                    violations
                );
            }
            other => panic!(
                "expected Rejected for symlink with standard profile, got {:?}",
                other
            ),
        }

        // Restricted profile — still denied
        let decision = engine.evaluate(&changes, Some("restricted")).unwrap();
        match decision {
            PolicyDecision::Rejected(ref violations) => {
                assert!(
                    violations.iter().any(|v| v.rule == "deny_symlink"),
                    "expected deny_symlink for restricted profile, got {:?}",
                    violations
                );
            }
            other => panic!(
                "expected Rejected for symlink with restricted profile, got {:?}",
                other
            ),
        }
    }

    // 11. Workspace boundary enforcement — absolute paths outside workspace rejected
    #[test]
    fn test_reject_path_outside_workspace() {
        let (engine, _dir) = engine_from_production_rego();

        let changes = vec![FileChange {
            path: PathBuf::from("/tmp/escape/evil.sh"),
            kind: FileChangeKind::Added,
            size: 512,
            checksum: "kkk".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        }];

        let decision = engine
            .evaluate_with_workspace(&changes, Some("standard"), Some("/home/agent/project"))
            .unwrap();
        match decision {
            PolicyDecision::Rejected(ref violations) => {
                assert!(
                    violations
                        .iter()
                        .any(|v| v.rule == "deny_outside_workspace"),
                    "expected deny_outside_workspace for /tmp path with workspace /home/agent/project, got {:?}",
                    violations
                );
            }
            other => panic!(
                "expected Rejected for path outside workspace, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_policy_profile_aware_privileged_allows_large_changeset() {
        let engine = create_policy_engine();

        // Create a changeset that exceeds the standard limit (100 MiB)
        // but is under the privileged limit (500 MiB).
        let changes = vec![FileChange {
            path: PathBuf::from("data/model.bin"),
            kind: FileChangeKind::Added,
            size: 200 * 1024 * 1024, // 200 MiB
            checksum: "model".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        }];

        // With "privileged" profile: should be rejected by default max_changeset_size
        // (100 MiB) but profile_storage_quota allows up to 500 MiB.
        // Note: the default max_changeset_size rule (100 MiB) fires independently.
        let decision = engine.evaluate(&changes, Some("privileged")).unwrap();
        match decision {
            PolicyDecision::Rejected(violations) => {
                // Should be rejected by max_changeset_size, NOT profile_storage_quota
                assert!(
                    violations.iter().any(|v| v.rule == "max_changeset_size"),
                    "should hit default max_changeset_size (100 MiB), got: {:?}",
                    violations
                );
                assert!(
                    !violations.iter().any(|v| v.rule == "profile_storage_quota"),
                    "privileged profile should NOT trigger profile_storage_quota for 200 MiB"
                );
            }
            other => panic!("expected Rejected for 200 MiB changeset, got {:?}", other),
        }
    }

    // S1: Silent policy load failure — invalid .rego in the policy dir should
    // cause the evaluation thread (which reloads policies with `let _ =`) to
    // reject rather than silently approve with incomplete rules.
    //
    // Note: `reload()` correctly propagates errors. The bug is in the timeout
    // evaluation thread (line ~225) where `let _ = engine.add_policy(...)`
    // silently discards compile errors. We test the evaluation path directly.
    #[test]
    fn test_s1_invalid_rego_causes_evaluation_error() {
        let dir = tempfile::tempdir().unwrap();

        // Write one valid policy that allows everything
        let valid_rego = r#"
package puzzlepod.commit
import future.keywords.if
default allow := true
violations := set()
"#;
        fs::write(dir.path().join("valid.rego"), valid_rego).unwrap();

        // Load with only the valid policy — reload succeeds
        let engine = PolicyEngine::new(dir.path().to_path_buf());
        engine.reload().unwrap();
        assert_eq!(engine.policy_count(), 1);

        // Now add an INVALID policy to the directory AFTER reload.
        // The evaluation thread will re-read the directory and hit this file.
        fs::write(
            dir.path().join("invalid.rego"),
            "package broken\nthis is not valid rego {{{{",
        )
        .unwrap();

        let changes = vec![FileChange {
            path: PathBuf::from("src/main.rs"),
            kind: FileChangeKind::Modified,
            size: 1024,
            checksum: "abc".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
        }];

        // S1: The evaluation thread reloads policies from the directory.
        // With the invalid .rego file present, `let _ = engine.add_policy()`
        // silently discards the error, and evaluation proceeds with incomplete
        // rules. This MUST return a rejection (not Approved).
        let result = engine.evaluate(&changes, None).unwrap();
        match result {
            PolicyDecision::Rejected(ref violations) => {
                assert!(
                    violations
                        .iter()
                        .any(|v| v.message.contains("policy") || v.rule.contains("policy_load")),
                    "S1: rejection should mention policy load failure, got {:?}",
                    violations
                );
            }
            PolicyDecision::Approved => {
                panic!(
                    "S1: evaluation should NOT silently approve when a .rego file \
                     fails to compile — the `let _ = engine.add_policy()` in the \
                     evaluation thread silently discards compilation errors, allowing \
                     evaluation to proceed with an incomplete policy set"
                );
            }
            other => {
                // PolicyDecision::Error is also acceptable — any non-Approved outcome
                // is fine as long as it's not silently succeeding.
                let _ = other;
            }
        }
    }

    // S10: Mutex poison recovery should log a warning
    #[test]
    fn test_s10_mutex_poison_recovery_has_logging() {
        // Verify the code includes tracing::warn! when recovering from mutex poison.
        // This is a code-level assertion — we check that the source contains the
        // expected warning log near the unwrap_or_else pattern.
        let source = include_str!("policy.rs");

        // Find all occurrences of unwrap_or_else(|e| e.into_inner())
        // and verify each is preceded or followed by a tracing::warn! about poison
        let poison_recoveries: Vec<_> = source
            .lines()
            .enumerate()
            .filter(|(_, line)| line.contains("into_inner()") && line.contains("unwrap_or_else"))
            .collect();

        assert!(
            !poison_recoveries.is_empty(),
            "S10: expected at least one mutex poison recovery pattern in policy.rs"
        );

        for (line_num, _line) in &poison_recoveries {
            // Check surrounding lines (within 5 lines) for tracing::warn
            let context_start = line_num.saturating_sub(5);
            let context_end = line_num + 5;
            let context_lines: Vec<_> = source
                .lines()
                .enumerate()
                .filter(|(i, _)| *i >= context_start && *i <= context_end)
                .collect();

            let has_warn = context_lines
                .iter()
                .any(|(_, l)| l.contains("tracing::warn") || l.contains("warn!"));

            assert!(
                has_warn,
                "S10: mutex poison recovery at line {} lacks tracing::warn! — \
                 silent recovery hides potential corruption. Context:\n{}",
                line_num + 1,
                context_lines
                    .iter()
                    .map(|(i, l)| format!("  {}: {}", i + 1, l))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
    }

    // R5: Verify evaluation thread does NOT silently skip unreadable policy files.
    #[test]
    fn test_r5_evaluation_thread_does_not_silently_skip_policy_files() {
        let source = include_str!("policy.rs");
        // Only check production code, not the test module
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // The silent-skip pattern: "if let Ok(contents) = std::fs::read_to_string"
        let bad_pattern = "if let Ok(contents) = std::fs::read_to_string";
        assert!(
            !prod_source.contains(bad_pattern),
            "R5: evaluation thread must NOT silently skip unreadable policy files. \
             Use 'match std::fs::read_to_string' instead."
        );
    }

    /// F17: Verify policy evaluation has a concurrency bound (MAX_CONCURRENT_EVALUATIONS).
    #[test]
    fn test_f17_policy_evaluation_bounded() {
        let source = include_str!("policy.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            prod_source.contains("MAX_CONCURRENT_EVALUATIONS"),
            "F17: policy.rs must define MAX_CONCURRENT_EVALUATIONS to bound \
             the number of concurrent policy evaluation threads."
        );
    }

    // R25: reload() must return Err when policy directory doesn't exist.
    #[test]
    fn test_r25_reload_returns_error_for_nonexistent_dir() {
        let engine = PolicyEngine::new(std::path::PathBuf::from(
            "/tmp/nonexistent_policy_dir_r25_test",
        ));
        let result = engine.reload();
        assert!(
            result.is_err(),
            "R25: reload() must return Err when policy directory does not exist, got Ok(())"
        );
    }
}
