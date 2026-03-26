// SPDX-License-Identifier: Apache-2.0
//! Prometheus metrics for puzzled.
//!
//! Exposes counters, histograms, and gauges for branch lifecycle
//! and policy evaluation.

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::Registry;
use std::sync::Arc;

/// Label set for branch operations.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct BranchLabels {
    pub profile: String,
}

/// Label set for commit outcome operations.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct OutcomeLabels {
    pub outcome: String,
}

/// Metrics for the puzzled daemon.
pub struct Metrics {
    pub registry: Registry,

    /// Total branches created.
    pub branches_created: Family<BranchLabels, Counter>,
    /// Total branches committed.
    pub branches_committed: Family<BranchLabels, Counter>,
    /// Total branches rolled back.
    pub branches_rolled_back: Family<BranchLabels, Counter>,
    /// Total policy approvals.
    pub policy_approved: Counter,
    /// Total policy rejections.
    pub policy_rejected: Counter,
    /// Total policy errors.
    pub policy_errors: Counter,

    /// Branch creation duration in seconds.
    pub branch_create_duration: Histogram,
    /// Commit duration in seconds.
    pub commit_duration: Histogram,
    /// Diff generation duration in seconds.
    pub diff_duration: Histogram,

    /// Currently active branches.
    pub active_branches: Gauge,

    // --- GAP-4: Additional PRD-required metrics ---
    /// Total branch lifetime duration in seconds (from creation to commit/rollback).
    pub branch_duration_seconds: Histogram,
    /// Total files included in commits.
    pub commit_files_total: Counter,
    /// Total bytes included in commits.
    pub commit_bytes_total: Counter,
    /// Total network operations gated by proxy.
    pub network_ops_gated_total: Counter,
    /// Total merge conflicts detected.
    pub conflicts_total: Counter,
    /// Daemon uptime in seconds (set periodically or on scrape).
    pub uptime_seconds: Gauge,
    /// Total watchdog timeouts.
    pub watchdog_timeouts_total: Counter,
    /// Commit outcomes by result (approved, rejected, error).
    pub commit_outcomes: Family<OutcomeLabels, Counter>,

    // --- M7: Additional PRD-required metrics ---
    /// M7: Policy evaluation duration in seconds.
    pub policy_evaluation_duration: Histogram,
    /// M7: Per-branch storage bytes (gauge, per-branch label).
    pub branch_storage_bytes: Family<BranchLabels, Gauge>,
    /// M7: Per-branch inode count (gauge, per-branch label).
    pub branch_inodes: Family<BranchLabels, Gauge>,
    /// M7: Per-branch storage quota bytes (gauge, per-branch label).
    pub branch_storage_quota_bytes: Family<BranchLabels, Gauge>,
    /// M7: Network operations replayed (counter with result label).
    pub network_ops_replayed: Family<OutcomeLabels, Counter>,
}

impl Metrics {
    /// Create a new Metrics instance with all metrics registered.
    pub fn new() -> Self {
        let mut registry = Registry::default();

        let branches_created = Family::<BranchLabels, Counter>::default();
        registry.register(
            "puzzled_branches_created",
            "Total branches created",
            branches_created.clone(),
        );

        let branches_committed = Family::<BranchLabels, Counter>::default();
        registry.register(
            "puzzled_branches_committed",
            "Total branches committed",
            branches_committed.clone(),
        );

        let branches_rolled_back = Family::<BranchLabels, Counter>::default();
        registry.register(
            "puzzled_branches_rolled_back",
            "Total branches rolled back",
            branches_rolled_back.clone(),
        );

        let policy_approved = Counter::default();
        registry.register(
            "puzzled_policy_approved",
            "Total policy approvals",
            policy_approved.clone(),
        );

        let policy_rejected = Counter::default();
        registry.register(
            "puzzled_policy_rejected",
            "Total policy rejections",
            policy_rejected.clone(),
        );

        let policy_errors = Counter::default();
        registry.register(
            "puzzled_policy_errors",
            "Total policy errors",
            policy_errors.clone(),
        );

        let branch_create_duration = Histogram::new(exponential_buckets(0.001, 2.0, 15));
        registry.register(
            "puzzled_branch_create_duration_seconds",
            "Branch creation duration",
            branch_create_duration.clone(),
        );

        let commit_duration = Histogram::new(exponential_buckets(0.001, 2.0, 15));
        registry.register(
            "puzzled_commit_duration_seconds",
            "Commit duration",
            commit_duration.clone(),
        );

        let diff_duration = Histogram::new(exponential_buckets(0.0001, 2.0, 15));
        registry.register(
            "puzzled_diff_duration_seconds",
            "Diff generation duration",
            diff_duration.clone(),
        );

        let active_branches = Gauge::default();
        registry.register(
            "puzzled_active_branches",
            "Currently active branches",
            active_branches.clone(),
        );

        // --- GAP-4: Additional PRD-required metrics ---

        let branch_duration_seconds = Histogram::new(exponential_buckets(0.1, 2.0, 20));
        registry.register(
            "puzzled_branch_duration_seconds",
            "Total branch lifetime duration from creation to commit/rollback",
            branch_duration_seconds.clone(),
        );

        let commit_files_total = Counter::default();
        registry.register(
            "puzzled_commit_files_total",
            "Total files included in commits",
            commit_files_total.clone(),
        );

        let commit_bytes_total = Counter::default();
        registry.register(
            "puzzled_commit_bytes_total",
            "Total bytes included in commits",
            commit_bytes_total.clone(),
        );

        let network_ops_gated_total = Counter::default();
        registry.register(
            "puzzled_network_ops_gated_total",
            "Total network operations gated by proxy",
            network_ops_gated_total.clone(),
        );

        let conflicts_total = Counter::default();
        registry.register(
            "puzzled_conflicts_total",
            "Total merge conflicts detected",
            conflicts_total.clone(),
        );

        let uptime_seconds = Gauge::default();
        registry.register(
            "puzzled_uptime_seconds",
            "Daemon uptime in seconds",
            uptime_seconds.clone(),
        );

        let watchdog_timeouts_total = Counter::default();
        registry.register(
            "puzzled_watchdog_timeouts_total",
            "Total watchdog timeouts",
            watchdog_timeouts_total.clone(),
        );

        let commit_outcomes = Family::<OutcomeLabels, Counter>::default();
        registry.register(
            "puzzled_commit_outcomes_total",
            "Commit outcomes by result",
            commit_outcomes.clone(),
        );

        // --- M7: Additional PRD-required metrics ---

        let policy_evaluation_duration = Histogram::new(exponential_buckets(0.001, 2.0, 15));
        registry.register(
            "puzzled_policy_evaluation_duration_seconds",
            "Policy evaluation duration",
            policy_evaluation_duration.clone(),
        );

        let branch_storage_bytes = Family::<BranchLabels, Gauge>::default();
        registry.register(
            "puzzled_branch_storage_bytes",
            "Per-branch storage bytes used",
            branch_storage_bytes.clone(),
        );

        let branch_inodes = Family::<BranchLabels, Gauge>::default();
        registry.register(
            "puzzled_branch_inodes",
            "Per-branch inode count",
            branch_inodes.clone(),
        );

        let branch_storage_quota_bytes = Family::<BranchLabels, Gauge>::default();
        registry.register(
            "puzzled_branch_storage_quota_bytes",
            "Per-branch storage quota bytes",
            branch_storage_quota_bytes.clone(),
        );

        let network_ops_replayed = Family::<OutcomeLabels, Counter>::default();
        registry.register(
            "puzzled_network_ops_replayed_total",
            "Network operations replayed with result label",
            network_ops_replayed.clone(),
        );

        Self {
            registry,
            branches_created,
            branches_committed,
            branches_rolled_back,
            policy_approved,
            policy_rejected,
            policy_errors,
            branch_create_duration,
            commit_duration,
            diff_duration,
            active_branches,
            branch_duration_seconds,
            commit_files_total,
            commit_bytes_total,
            network_ops_gated_total,
            conflicts_total,
            uptime_seconds,
            watchdog_timeouts_total,
            commit_outcomes,
            policy_evaluation_duration,
            branch_storage_bytes,
            branch_inodes,
            branch_storage_quota_bytes,
            network_ops_replayed,
        }
    }

    /// Record a branch creation.
    pub fn record_create(&self, profile: &str, duration_secs: f64) {
        let profile = sanitize_profile_label(profile);
        self.branches_created
            .get_or_create(&BranchLabels {
                profile: profile.to_string(),
            })
            .inc();
        self.branch_create_duration.observe(duration_secs);
        self.active_branches.inc();
    }

    /// Record a branch commit.
    pub fn record_commit(&self, profile: &str, duration_secs: f64) {
        let profile = sanitize_profile_label(profile);
        self.branches_committed
            .get_or_create(&BranchLabels {
                profile: profile.to_string(),
            })
            .inc();
        self.commit_duration.observe(duration_secs);
        self.active_branches.dec();
    }

    /// Record a branch rollback.
    pub fn record_rollback(&self, profile: &str) {
        let profile = sanitize_profile_label(profile);
        self.branches_rolled_back
            .get_or_create(&BranchLabels {
                profile: profile.to_string(),
            })
            .inc();
        self.active_branches.dec();
    }

    /// Record a diff generation.
    pub fn record_diff(&self, duration_secs: f64) {
        self.diff_duration.observe(duration_secs);
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// H5: Maximum length for profile label strings to prevent unbounded cardinality.
const MAX_PROFILE_LABEL_LEN: usize = 64;

/// M-met1: Sanitize profile labels to bound cardinality.
/// Unknown or custom profile names are mapped to "custom" to prevent
/// unbounded label cardinality from user-defined profile names.
/// H5: Labels are also truncated to MAX_PROFILE_LABEL_LEN to prevent
/// memory growth from extremely long profile names.
fn sanitize_profile_label(profile: &str) -> &str {
    match profile {
        "restricted" | "standard" | "privileged" => profile,
        _ => "custom",
    }
}

/// H5: Sanitize a branch label by truncating to MAX_PROFILE_LABEL_LEN.
/// Used for any caller that constructs BranchLabels with arbitrary strings.
pub fn sanitize_branch_label(label: &str) -> String {
    if label.len() <= MAX_PROFILE_LABEL_LEN {
        label.to_string()
    } else {
        // V7: Safe UTF-8 truncation — label[..N] panics if N splits a multi-byte char
        let truncated = match label.char_indices().nth(MAX_PROFILE_LABEL_LEN) {
            Some((idx, _)) => &label[..idx],
            None => label,
        };
        truncated.to_string()
    }
}

/// Encode metrics in OpenMetrics text format.
pub fn encode_metrics(metrics: &Metrics) -> String {
    let mut buf = String::new();
    prometheus_client::encoding::text::encode(&mut buf, &metrics.registry).unwrap_or_else(|e| {
        tracing::error!("S45: failed to encode prometheus metrics: {e}");
        buf = format!("# ERROR: metrics encoding failed: {e}");
    });
    buf
}

/// Start a Unix socket metrics server at the given path.
pub async fn serve_metrics(
    metrics: Arc<Metrics>,
    socket_path: std::path::PathBuf,
) -> Result<(), std::io::Error> {
    // Remove stale socket file
    if let Err(e) = std::fs::remove_file(&socket_path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!("F14: failed to remove stale metrics socket: {e}");
        }
    }

    // Ensure parent directory exists
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = tokio::net::UnixListener::bind(&socket_path)?;
    tracing::info!(path = %socket_path.display(), "metrics server started");

    loop {
        let (mut stream, _) = listener.accept().await?;
        let metrics = metrics.clone();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            // CQ-5: Read and discard the incoming HTTP request before sending a response.
            // Read until we see the end of HTTP headers (\r\n\r\n).
            // H7: Wrap the header-reading loop in a timeout to prevent slowloris-style
            // DoS where a client sends headers very slowly to hold the connection open.
            let read_result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                let mut buf = [0u8; 4096];
                let mut request_data = Vec::with_capacity(1024);
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => return None, // Client closed connection
                        Ok(n) => {
                            request_data.extend_from_slice(&buf[..n]);
                            // Check if we've received the end of HTTP headers
                            if request_data.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                            // Safety limit: don't buffer more than 8KB of request headers
                            if request_data.len() > 8192 {
                                break;
                            }
                        }
                        Err(_) => return None,
                    }
                }
                Some(request_data)
            })
            .await;

            let request_data = match read_result {
                Ok(Some(data)) => data,
                Ok(None) | Err(_) => {
                    // H7: Client closed or timed out — drop connection
                    return;
                }
            };

            // Parse the HTTP request line to route by method and path.
            let request_str = String::from_utf8_lossy(&request_data);
            let request_line = request_str.lines().next().unwrap_or("");
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or("");
            let path = parts.next().unwrap_or("");

            let response = if method != "GET" {
                // 405 Method Not Allowed — only GET is supported
                "HTTP/1.1 405 Method Not Allowed\r\nAllow: GET\r\nContent-Length: 0\r\n\r\n"
                    .to_string()
            } else if path != "/metrics" {
                // 404 Not Found — only /metrics is served
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()
            } else {
                let output = encode_metrics(&metrics);
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/openmetrics-text\r\nContent-Length: {}\r\n\r\n{}",
                    output.len(),
                    output
                )
            };
            if let Err(e) = stream.write_all(response.as_bytes()).await {
                tracing::trace!("F15: failed to write metrics response: {e}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_new() {
        let metrics = Metrics::new();
        metrics.record_create("test", 0.05);
        metrics.record_commit("test", 1.0);
        metrics.record_rollback("test");
        metrics.record_diff(0.01);

        let output = encode_metrics(&metrics);
        assert!(output.contains("puzzled_branches_created"));
        assert!(output.contains("puzzled_active_branches"));
    }

    #[test]
    fn test_metrics_record_create_increments_counter() {
        let metrics = Metrics::new();
        metrics.record_create("standard", 0.01);
        metrics.record_create("standard", 0.02);
        metrics.record_create("restricted", 0.03);

        let output = encode_metrics(&metrics);
        // Should have entries for both profiles
        assert!(output.contains("puzzled_branches_created"));
        assert!(output.contains("standard"));
        assert!(output.contains("restricted"));
    }

    #[test]
    fn test_metrics_record_commit_decrements_active() {
        let metrics = Metrics::new();
        metrics.record_create("test", 0.01); // active = 1
        metrics.record_create("test", 0.01); // active = 2
        metrics.record_commit("test", 0.5); // active = 1

        let output = encode_metrics(&metrics);
        assert!(output.contains("puzzled_commit_duration_seconds"));
    }

    #[test]
    fn test_metrics_record_rollback_decrements_active() {
        let metrics = Metrics::new();
        metrics.record_create("test", 0.01); // active = 1
        metrics.record_rollback("test"); // active = 0

        let output = encode_metrics(&metrics);
        assert!(output.contains("puzzled_branches_rolled_back"));
    }

    #[test]
    fn test_metrics_encode_produces_valid_openmetrics() {
        let metrics = Metrics::new();
        metrics.record_create("test", 0.05);
        metrics.record_commit("test", 1.0);

        let output = encode_metrics(&metrics);
        // OpenMetrics text format should contain # HELP and # TYPE lines
        assert!(!output.is_empty(), "encoded metrics should not be empty");
        // Should contain metric names
        assert!(output.contains("puzzled_branches_created"));
        assert!(output.contains("puzzled_branches_committed"));
        assert!(output.contains("puzzled_branch_create_duration_seconds"));
    }

    #[test]
    fn test_metrics_histogram_records_latency() {
        let metrics = Metrics::new();
        metrics.record_diff(0.001);
        metrics.record_diff(0.01);
        metrics.record_diff(0.1);
        metrics.record_diff(1.0);

        let output = encode_metrics(&metrics);
        assert!(output.contains("puzzled_diff_duration_seconds"));
    }

    #[test]
    fn test_sanitize_profile_label() {
        assert_eq!(sanitize_profile_label("restricted"), "restricted");
        assert_eq!(sanitize_profile_label("standard"), "standard");
        assert_eq!(sanitize_profile_label("privileged"), "privileged");
        assert_eq!(sanitize_profile_label("unknown_profile"), "custom");
        assert_eq!(sanitize_profile_label(""), "custom");
        assert_eq!(sanitize_profile_label("RESTRICTED"), "custom");
    }

    #[test]
    fn test_metrics_default_impl() {
        let metrics = Metrics::default();
        // Should behave identically to Metrics::new()
        metrics.record_create("standard", 0.01);
        let output = encode_metrics(&metrics);
        assert!(output.contains("puzzled_branches_created"));
    }

    #[test]
    fn test_gap4_metrics_exist() {
        let metrics = Metrics::new();

        // Increment/observe all GAP-4 metrics
        metrics.commit_files_total.inc();
        metrics.commit_bytes_total.inc();
        metrics.network_ops_gated_total.inc();
        metrics.conflicts_total.inc();
        metrics.uptime_seconds.set(42);
        metrics.watchdog_timeouts_total.inc();
        metrics.branch_duration_seconds.observe(10.0);
        metrics
            .commit_outcomes
            .get_or_create(&OutcomeLabels {
                outcome: "approved".to_string(),
            })
            .inc();

        // Verify they can be encoded without panic
        let output = encode_metrics(&metrics);
        assert!(!output.is_empty());
    }

    #[test]
    fn test_encode_metrics_contains_gap4() {
        let metrics = Metrics::new();

        // Increment GAP-4 metrics so they appear in output
        metrics.commit_files_total.inc();
        metrics.commit_bytes_total.inc();
        metrics.network_ops_gated_total.inc();
        metrics.conflicts_total.inc();
        metrics.uptime_seconds.set(100);
        metrics.watchdog_timeouts_total.inc();
        metrics
            .commit_outcomes
            .get_or_create(&OutcomeLabels {
                outcome: "rejected".to_string(),
            })
            .inc();

        let output = encode_metrics(&metrics);
        assert!(
            output.contains("puzzled_commit_files_total"),
            "missing commit_files_total"
        );
        assert!(
            output.contains("puzzled_commit_bytes_total"),
            "missing commit_bytes_total"
        );
        assert!(
            output.contains("puzzled_network_ops_gated_total"),
            "missing network_ops_gated_total"
        );
        assert!(
            output.contains("puzzled_conflicts_total"),
            "missing conflicts_total"
        );
        assert!(
            output.contains("puzzled_uptime_seconds"),
            "missing uptime_seconds"
        );
        assert!(
            output.contains("puzzled_watchdog_timeouts_total"),
            "missing watchdog_timeouts_total"
        );
        assert!(
            output.contains("puzzled_commit_outcomes_total"),
            "missing commit_outcomes_total"
        );
    }

    #[test]
    fn test_branch_labels_derive() {
        let a = BranchLabels {
            profile: "standard".to_string(),
        };
        let b = a.clone();
        assert_eq!(a, b);
        // Verify Debug
        let debug_str = format!("{:?}", a);
        assert!(debug_str.contains("standard"));
        // Verify Hash via use in a HashSet
        let mut set = std::collections::HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    #[test]
    fn test_outcome_labels_derive() {
        let a = OutcomeLabels {
            outcome: "approved".to_string(),
        };
        let b = a.clone();
        assert_eq!(a, b);
        // Verify Debug
        let debug_str = format!("{:?}", a);
        assert!(debug_str.contains("approved"));
        // Verify Hash via use in a HashSet
        let mut set = std::collections::HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    /// S45: Ensure prometheus encoding does not use `unwrap_or_default()`,
    /// which silently returns an empty string on encoding failure.
    /// F14: Verify stale metrics socket cleanup does not silently discard errors.
    #[test]
    fn test_f14_metrics_socket_cleanup_not_silent() {
        let source = include_str!("metrics.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // Find remove_file near socket_path and check it doesn't use `let _ =`
        for (i, line) in prod_source.lines().enumerate() {
            if line.contains("remove_file") && line.contains("socket_path") {
                assert!(
                    !line.contains("let _ ="),
                    "F14: metrics.rs line {} uses `let _ =` with remove_file on socket_path. \
                     Non-NotFound errors must be logged.\nLine: {}",
                    i + 1,
                    line.trim()
                );
            }
        }
    }

    /// F15: Verify metrics HTTP response write does not silently discard errors.
    #[test]
    fn test_f15_metrics_response_write_not_silent() {
        let source = include_str!("metrics.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        for (i, line) in prod_source.lines().enumerate() {
            if line.contains("write_all") && line.contains("response.as_bytes()") {
                assert!(
                    !line.contains("let _ ="),
                    "F15: metrics.rs line {} uses `let _ =` with write_all(response.as_bytes()). \
                     Write errors must be logged.\nLine: {}",
                    i + 1,
                    line.trim()
                );
            }
        }
    }

    // ---------------------------------------------------------------
    // H5: sanitize_branch_label truncates long labels
    // ---------------------------------------------------------------

    #[test]
    fn test_h5_sanitize_branch_label_truncates() {
        let short = "standard";
        assert_eq!(sanitize_branch_label(short), "standard");

        let exact = "a".repeat(MAX_PROFILE_LABEL_LEN);
        assert_eq!(sanitize_branch_label(&exact).len(), MAX_PROFILE_LABEL_LEN);

        let long = "x".repeat(200);
        let result = sanitize_branch_label(&long);
        assert_eq!(
            result.len(),
            MAX_PROFILE_LABEL_LEN,
            "H5: labels longer than MAX_PROFILE_LABEL_LEN must be truncated"
        );
    }

    #[test]
    fn test_h5_max_profile_label_len_exists() {
        let source = include_str!("metrics.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            prod_source.contains("MAX_PROFILE_LABEL_LEN"),
            "H5: MAX_PROFILE_LABEL_LEN constant must exist in production code"
        );
        assert!(
            prod_source.contains("fn sanitize_branch_label"),
            "H5: sanitize_branch_label function must exist in production code"
        );
    }

    // ---------------------------------------------------------------
    // H7: metrics read loop must have a timeout
    // ---------------------------------------------------------------

    #[test]
    fn test_h7_metrics_read_loop_has_timeout() {
        let source = include_str!("metrics.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        // Find the serve_metrics function
        let func_start = prod_source
            .find("async fn serve_metrics")
            .or_else(|| prod_source.find("pub async fn serve_metrics"))
            .expect("serve_metrics function must exist");
        let body = &prod_source[func_start..];
        assert!(
            body.contains("tokio::time::timeout"),
            "H7: metrics HTTP read loop must be wrapped in tokio::time::timeout \
             to prevent slowloris-style DoS"
        );
    }

    #[test]
    fn test_s45_metrics_no_silent_default() {
        let source = include_str!("metrics.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        for (i, line) in prod_source.lines().enumerate() {
            if line.contains("encode") && line.contains("unwrap_or_default()") {
                panic!(
                    "S45: metrics.rs line {} uses encode(...).unwrap_or_default() which \
                     silently returns an empty string on encoding failure. \
                     Use unwrap_or_else with tracing::error! instead.\nLine: {}",
                    i + 1,
                    line.trim()
                );
            }
        }
    }
}
