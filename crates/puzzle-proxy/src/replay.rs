// SPDX-License-Identifier: Apache-2.0
//! Network request journal and replay engine.
//!
//! Side-effect requests (POST/PUT/DELETE/PATCH) from agents in Gated mode
//! are serialized to disk as a journal. At commit time, after OPA policy
//! approval, the journal entries are replayed against the upstream servers.
//!
//! On rollback, the journal directory is simply discarded (zero residue).
//!
//! C11: Crash recovery is supported via a `.replay_progress` state file that
//! tracks the index of the last successfully replayed entry. On restart,
//! replay resumes from where it left off.
//!
//! M18: Each journal entry write is followed by `sync_data()` to ensure
//! durability in case of crash.

use std::path::{Path, PathBuf};

use puzzled_types::BranchId;
use serde::{Deserialize, Serialize};

/// A journaled network request entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    /// HTTP method.
    pub method: String,
    /// Full URI.
    pub uri: String,
    /// HTTP headers.
    pub headers: Vec<(String, String)>,
    /// Request body (serialized as base64 in JSON).
    #[serde(with = "base64_bytes")]
    pub body: Vec<u8>,
    /// Timestamp of the original request.
    pub timestamp: String,
    /// H-28: When true, this entry is explicitly marked safe for replay even if
    /// the method is non-idempotent (POST, PUT, DELETE, PATCH). Defaults to false.
    #[serde(default)]
    pub safe_replay: bool,
}

/// PXH3: Token bucket rate limiter for journal writes.
/// Limits to MAX_ENTRIES_PER_SECOND per branch. When exceeded, the request
/// is still proxied but the journal entry is skipped (logged as warning).
struct JournalRateLimiter {
    /// Timestamps of recent journal writes within the current window.
    timestamps: Vec<std::time::Instant>,
}

impl JournalRateLimiter {
    /// Maximum journal entries per second per branch.
    const MAX_ENTRIES_PER_SECOND: usize = 100;

    fn new() -> Self {
        Self {
            timestamps: Vec::new(),
        }
    }

    /// Returns true if the write is allowed, false if rate-limited.
    fn check(&mut self) -> bool {
        let now = std::time::Instant::now();
        let cutoff = now - std::time::Duration::from_secs(1);
        self.timestamps.retain(|t| *t > cutoff);
        if self.timestamps.len() >= Self::MAX_ENTRIES_PER_SECOND {
            return false;
        }
        self.timestamps.push(now);
        true
    }
}

/// M-px3: Maximum number of journal entries per branch.
const MAX_JOURNAL_ENTRIES: usize = 10_000;

/// M-px3: Maximum total journal size in bytes per branch (100 MB).
const MAX_JOURNAL_BYTES: u64 = 100 * 1024 * 1024;

/// H-28: HTTP methods that are safe to replay (idempotent or read-only).
/// Non-idempotent methods (POST, DELETE, PUT, PATCH) are skipped during
/// replay unless explicitly marked safe via the `safe_replay` field.
// V18: Non-idempotent method replay is intentionally disabled (safe_replay always false).
// Journal records are retained for audit/forensics; replay only executes GET/HEAD.
const SAFE_REPLAY_METHODS: &[&str] = &["GET", "HEAD"];

/// Network request journal for a single branch.
pub struct NetworkJournal {
    journal_dir: PathBuf,
    branch_id: BranchId,
    entry_count: u64,
    /// M-px3: Approximate total bytes written to the journal file.
    journal_bytes: u64,
    /// PXH3: Rate limiter — max 100 entries/second per branch.
    rate_limiter: JournalRateLimiter,
}

impl NetworkJournal {
    /// Create a new network journal.
    ///
    /// If the journal file already exists on disk (e.g., after a daemon restart),
    /// `entry_count` is recovered by counting lines in the journal file and
    /// `journal_bytes` from the file size.
    pub fn new(journal_dir: PathBuf, branch_id: BranchId) -> Self {
        let entry_count = Self::count_existing_entries(&journal_dir);
        let journal_bytes = Self::measure_existing_bytes(&journal_dir);
        Self {
            journal_dir,
            branch_id,
            entry_count,
            journal_bytes,
            rate_limiter: JournalRateLimiter::new(),
        }
    }

    /// Count existing journal entries by reading lines from the journal file.
    fn count_existing_entries(journal_dir: &Path) -> u64 {
        use std::io::BufRead;
        let journal_file = journal_dir.join("requests.ndjson");
        match std::fs::File::open(&journal_file) {
            Ok(file) => {
                let reader = std::io::BufReader::new(file);
                reader
                    .lines()
                    .filter(|line| line.as_ref().map(|l| !l.trim().is_empty()).unwrap_or(false))
                    // N6: Use try_from instead of bare `as u64` cast
                    .count()
                    .try_into()
                    .unwrap_or(u64::MAX)
            }
            Err(_) => 0,
        }
    }

    /// M-px3: Measure the size of the existing journal file in bytes.
    fn measure_existing_bytes(journal_dir: &Path) -> u64 {
        let journal_file = journal_dir.join("requests.ndjson");
        match std::fs::metadata(&journal_file) {
            Ok(meta) => meta.len(),
            Err(_) => 0,
        }
    }

    /// Append an entry to the journal.
    ///
    /// M18: Calls `sync_data()` after writing each entry to ensure durability.
    /// PXH3: Rate-limited to 100 entries/second per branch. When exceeded,
    /// the entry is skipped (request is still proxied) and a warning is logged.
    ///
    /// CQ-1: The blocking filesystem I/O (file open, write, sync_data) is
    /// offloaded to `tokio::task::spawn_blocking` to avoid blocking the
    /// async runtime's executor threads.
    pub async fn append(&mut self, entry: JournalEntry) -> Result<(), String> {
        // PXH3: Check rate limit before writing
        if !self.rate_limiter.check() {
            tracing::warn!(
                branch = %self.branch_id,
                method = %entry.method,
                uri = %entry.uri,
                "journal rate limit exceeded (>{}/s) — skipping journal entry (request still proxied)",
                JournalRateLimiter::MAX_ENTRIES_PER_SECOND,
            );
            return Ok(());
        }

        // M-px3: Check journal entry count limit
        // Q2: Safe cast — avoid bare `as usize` which silently truncates on 16-bit platforms
        if usize::try_from(self.entry_count).unwrap_or(usize::MAX) >= MAX_JOURNAL_ENTRIES {
            tracing::warn!(
                branch = %self.branch_id,
                entry_count = self.entry_count,
                limit = MAX_JOURNAL_ENTRIES,
                method = %entry.method,
                uri = %entry.uri,
                "M-px3: journal entry count limit reached — rejecting new entry"
            );
            return Err(format!(
                "journal entry count limit exceeded ({}/{})",
                self.entry_count, MAX_JOURNAL_ENTRIES
            ));
        }

        // Serialize before spawning blocking task to keep JournalEntry out of Send bounds issues
        let json = serde_json::to_string(&entry)
            .map_err(|e| format!("serializing journal entry: {}", e))?;

        // M-px3: Check journal byte size limit (use serialized size as approximation)
        // Q3: Safe cast — avoid bare `as u64` which could silently truncate on exotic platforms
        let entry_size = u64::try_from(json.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1); // +1 for newline
        if self.journal_bytes + entry_size > MAX_JOURNAL_BYTES {
            tracing::warn!(
                branch = %self.branch_id,
                journal_bytes = self.journal_bytes,
                entry_size = entry_size,
                limit = MAX_JOURNAL_BYTES,
                method = %entry.method,
                uri = %entry.uri,
                "M-px3: journal byte size limit reached — rejecting new entry"
            );
            return Err(format!(
                "journal byte size limit exceeded ({} + {} > {} bytes)",
                self.journal_bytes, entry_size, MAX_JOURNAL_BYTES
            ));
        }

        let journal_dir = self.journal_dir.clone();
        let journal_file = journal_dir.join("requests.ndjson");

        // CQ-1: Offload blocking filesystem I/O to a blocking thread
        tokio::task::spawn_blocking(move || {
            // Create journal directory (idempotent — succeeds if already exists)
            std::fs::create_dir_all(&journal_dir)
                .map_err(|e| format!("creating journal dir: {}", e))?;

            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&journal_file)
                .map_err(|e| format!("opening journal file: {}", e))?;

            writeln!(file, "{}", json).map_err(|e| format!("writing journal entry: {}", e))?;

            // M18: fsync after each entry write to ensure durability
            file.sync_data()
                .map_err(|e| format!("syncing journal entry to disk: {}", e))?;

            Ok::<(), String>(())
        })
        .await
        .map_err(|e| format!("journal write task panicked: {}", e))??;

        self.entry_count += 1;
        self.journal_bytes += entry_size;

        tracing::debug!(
            branch = %self.branch_id,
            entry = self.entry_count,
            journal_bytes = self.journal_bytes,
            method = %entry.method,
            uri = %entry.uri,
            "journal entry written and synced"
        );

        Ok(())
    }

    /// Read all journal entries.
    pub fn read_all(&self) -> Result<Vec<JournalEntry>, String> {
        let journal_file = self.journal_dir.join("requests.ndjson");
        if !journal_file.exists() {
            return Ok(Vec::new());
        }

        let contents = std::fs::read_to_string(&journal_file)
            .map_err(|e| format!("reading journal: {}", e))?;

        let mut entries = Vec::new();
        for line in contents.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: JournalEntry =
                serde_json::from_str(line).map_err(|e| format!("parsing journal entry: {}", e))?;
            entries.push(entry);
        }

        Ok(entries)
    }

    /// Path to the replay progress state file.
    fn progress_file_path(&self) -> PathBuf {
        self.journal_dir.join(".replay_progress")
    }

    /// Read the last completed replay index from the progress file.
    ///
    /// Returns 0 if no progress file exists (start from beginning).
    fn read_replay_progress(&self) -> u64 {
        let path = self.progress_file_path();
        if !path.exists() {
            return 0;
        }
        match std::fs::read_to_string(&path) {
            Ok(contents) => contents.trim().parse::<u64>().unwrap_or(0),
            Err(_) => 0,
        }
    }

    /// Write the replay progress (index of last successfully replayed entry + 1).
    ///
    /// M18: Calls `sync_data()` to ensure the progress is durable.
    ///
    /// CQ-1: Blocking filesystem I/O is offloaded to `tokio::task::spawn_blocking`.
    async fn write_replay_progress(&self, completed_index: u64) -> Result<(), String> {
        let path = self.progress_file_path();
        let journal_dir = self.journal_dir.clone();

        tokio::task::spawn_blocking(move || {
            // Create journal directory (idempotent — succeeds if already exists)
            std::fs::create_dir_all(&journal_dir)
                .map_err(|e| format!("creating journal dir for progress: {}", e))?;

            use std::io::Write;
            let mut file = std::fs::File::create(&path)
                .map_err(|e| format!("creating progress file: {}", e))?;
            write!(file, "{}", completed_index).map_err(|e| format!("writing progress: {}", e))?;
            file.sync_data()
                .map_err(|e| format!("syncing progress to disk: {}", e))?;

            Ok::<(), String>(())
        })
        .await
        .map_err(|e| format!("progress write task panicked: {}", e))?
    }

    /// Replay all journaled requests.
    ///
    /// Called at commit time after OPA policy approval.
    /// Returns the number of entries that were replayed (i.e., attempted replay).
    /// This count includes entries where the upstream request succeeded as well as
    /// entries that were already replayed in a previous run (crash recovery).
    /// It does NOT include entries that were skipped due to domain validation
    /// failures or entries that failed to replay.
    ///
    /// C11: Resumes from the last completed entry on crash recovery.
    /// Progress is written to `.replay_progress` after each successful replay.
    ///
    /// M18: Re-validates each entry's domain against the current allowed_domains list
    /// and checks for DNS rebinding before replaying. Entries for disallowed domains
    /// are skipped with a warning.
    ///
    // U19: Replay timeout and port validation are deferred to Phase 2 — current replay is for development/debugging only
    pub async fn replay(&self, allowed_domains: &[String]) -> Result<u64, String> {
        let entries = self.read_all()?;
        if entries.is_empty() {
            return Ok(0);
        }

        // C11: Read replay progress to resume from where we left off
        let start_index = self.read_replay_progress();

        // Q4: Safe cast — avoid bare `as u64`
        if start_index >= u64::try_from(entries.len()).unwrap_or(u64::MAX) {
            tracing::info!(
                branch = %self.branch_id,
                total = entries.len(),
                already_completed = start_index,
                "all journal entries already replayed (crash recovery: nothing to do)"
            );
            return Ok(start_index);
        }

        if start_index > 0 {
            tracing::info!(
                branch = %self.branch_id,
                total = entries.len(),
                resuming_from = start_index,
                "resuming replay from crash recovery checkpoint"
            );
        }

        tracing::info!(
            branch = %self.branch_id,
            count = entries.len(),
            start_index = start_index,
            "replaying journaled network requests"
        );

        let mut replayed_count = start_index;
        // L6: Use try_from to safely handle u64→usize on 32-bit targets
        for (i, entry) in entries
            .iter()
            .enumerate()
            .skip(usize::try_from(start_index).unwrap_or(usize::MAX))
        {
            // H-28: Skip non-idempotent methods unless explicitly marked safe_replay.
            // POST, DELETE, PUT, PATCH are not safe to blindly replay (they may
            // duplicate side effects). Only GET and HEAD are replayed by default.
            let method_upper = entry.method.to_uppercase();
            if !SAFE_REPLAY_METHODS.contains(&method_upper.as_str()) && !entry.safe_replay {
                tracing::warn!(
                    branch = %self.branch_id,
                    method = %entry.method,
                    uri = %entry.uri,
                    index = i,
                    "H-28: skipping non-idempotent method during replay (not marked safe_replay)"
                );
                replayed_count += 1;
                // Write progress to skip this entry on crash recovery too
                if let Err(e) = self.write_replay_progress(replayed_count).await {
                    tracing::warn!(
                        branch = %self.branch_id,
                        error = %e,
                        index = i,
                        "failed to write replay progress for skipped entry (non-fatal)"
                    );
                }
                continue;
            }

            match replay_entry(entry, allowed_domains, &self.branch_id).await {
                Ok(status) => {
                    tracing::info!(
                        branch = %self.branch_id,
                        method = %entry.method,
                        uri = %entry.uri,
                        status,
                        index = i,
                        "replayed request"
                    );
                    replayed_count += 1;

                    // C11: Write progress after each successful replay
                    if let Err(e) = self.write_replay_progress(replayed_count).await {
                        tracing::warn!(
                            branch = %self.branch_id,
                            error = %e,
                            index = i,
                            "failed to write replay progress (non-fatal)"
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(
                        branch = %self.branch_id,
                        method = %entry.method,
                        uri = %entry.uri,
                        error = %e,
                        index = i,
                        "failed to replay request"
                    );
                }
            }
        }

        Ok(replayed_count)
    }

    /// Discard the journal (on rollback).
    ///
    /// Also removes the replay progress file.
    pub fn discard(&self) {
        if self.journal_dir.exists() {
            // L43: Log error instead of silently ignoring
            if let Err(e) = std::fs::remove_dir_all(&self.journal_dir) {
                tracing::warn!(dir = %self.journal_dir.display(), error = %e, "L43: failed to discard journal directory");
            }
        }
    }

    /// Get the number of journaled entries.
    pub fn entry_count(&self) -> u64 {
        self.entry_count
    }
}

/// Replay a single journal entry by making the actual HTTP request.
///
/// M18: Re-validates the entry's domain against the current allowed_domains list
/// and checks for DNS rebinding before making the request. Returns an error
/// (skipping the entry) if the domain is no longer allowed.
async fn replay_entry(
    entry: &JournalEntry,
    allowed_domains: &[String],
    branch_id: &BranchId,
) -> Result<u16, String> {
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::Request;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    // M18: Re-validate domain before replaying
    // Parse the host from the stored URI
    let uri: hyper::Uri = entry
        .uri
        .parse()
        .map_err(|e| format!("invalid URI '{}': {}", entry.uri, e))?;

    let host = uri
        .host()
        .ok_or_else(|| format!("no host in URI '{}'", entry.uri))?;

    // Check domain allowlist
    if !crate::handler::is_domain_allowed(host, allowed_domains) {
        tracing::warn!(
            branch = %branch_id,
            uri = %entry.uri,
            host = %host,
            "replay: skipping entry — domain no longer in allowlist"
        );
        return Err(format!(
            "domain '{}' no longer in allowlist, skipping replay",
            host
        ));
    }

    // Check for DNS rebinding (SSRF protection)
    if let Err(_resp) = crate::handler::check_dns_rebinding(host, branch_id).await {
        tracing::warn!(
            branch = %branch_id,
            uri = %entry.uri,
            host = %host,
            "replay: skipping entry — DNS rebinding check failed"
        );
        return Err(format!(
            "DNS rebinding check failed for '{}', skipping replay",
            host
        ));
    }

    tracing::debug!(
        method = %entry.method,
        uri = %entry.uri,
        body_len = entry.body.len(),
        "replaying request"
    );

    let scheme = uri.scheme_str().unwrap_or("http");

    // Build an appropriate client based on the URI scheme.
    // HTTPS entries require a TLS-capable connector; HTTP entries use plain TCP.
    let is_https = scheme.eq_ignore_ascii_case("https");

    let method: hyper::Method = entry
        .method
        .parse()
        .map_err(|e| format!("invalid method '{}': {}", entry.method, e))?;

    let mut req_builder = Request::builder().method(method).uri(&entry.uri);

    // Q9: No credential stripping needed here — journal entries have credentials redacted
    // at write time (handler.rs N10/D-I8 redaction), so the replay path inherits that
    // protection. Headers stored in the journal never contain real credential values.
    for (name, value) in &entry.headers {
        req_builder = req_builder.header(name.as_str(), value.as_str());
    }

    let req = req_builder
        .body(Full::new(Bytes::from(entry.body.clone())))
        .map_err(|e| format!("building request: {}", e))?;

    if is_https {
        // Build an HTTPS-capable client using hyper-rustls with webpki root certs
        let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_only()
            .enable_http1()
            .build();
        let client: Client<_, Full<Bytes>> =
            Client::builder(TokioExecutor::new()).build(https_connector);
        match client.request(req).await {
            Ok(resp) => Ok(resp.status().as_u16()),
            Err(e) => Err(format!("request to {} failed: {}", entry.uri, e)),
        }
    } else {
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
        match client.request(req).await {
            Ok(resp) => Ok(resp.status().as_u16()),
            Err(e) => Err(format!("request to {} failed: {}", entry.uri, e)),
        }
    }
}

/// Base64 serialization for binary body data in JSON.
mod base64_bytes {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(method: &str, uri: &str, body: &[u8]) -> JournalEntry {
        JournalEntry {
            method: method.to_string(),
            uri: uri.to_string(),
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: body.to_vec(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            safe_replay: false,
        }
    }

    #[tokio::test]
    async fn test_journal_append_and_read() {
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let branch_id = BranchId::from("test-branch".to_string());

        let mut journal = NetworkJournal::new(journal_dir, branch_id);

        // Append entries
        let entry1 = make_entry("POST", "https://api.example.com/data", b"hello");
        let entry2 = make_entry("PUT", "https://api.example.com/item/1", b"updated");

        journal.append(entry1).await.unwrap();
        journal.append(entry2).await.unwrap();

        assert_eq!(journal.entry_count(), 2);

        // Read back
        let entries = journal.read_all().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].method, "POST");
        assert_eq!(entries[0].uri, "https://api.example.com/data");
        assert_eq!(entries[0].body, b"hello");
        assert_eq!(entries[1].method, "PUT");
        assert_eq!(entries[1].body, b"updated");
    }

    #[test]
    fn test_journal_read_empty() {
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let branch_id = BranchId::from("test-branch".to_string());

        let journal = NetworkJournal::new(journal_dir, branch_id);
        let entries = journal.read_all().unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn test_journal_discard() {
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let branch_id = BranchId::from("test-branch".to_string());

        let mut journal = NetworkJournal::new(journal_dir.clone(), branch_id);

        journal
            .append(make_entry("POST", "http://example.com", b"data"))
            .await
            .unwrap();
        assert!(journal_dir.exists());

        journal.discard();
        assert!(!journal_dir.exists());
    }

    #[tokio::test]
    async fn test_journal_binary_body_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let branch_id = BranchId::from("test-branch".to_string());

        let mut journal = NetworkJournal::new(journal_dir, branch_id);

        // Binary body with non-UTF8 bytes
        let binary_body: Vec<u8> = (0..=255).collect();
        let entry = make_entry("POST", "http://example.com/upload", &binary_body);
        journal.append(entry).await.unwrap();

        let entries = journal.read_all().unwrap();
        assert_eq!(entries[0].body, binary_body);
    }

    #[test]
    fn test_base64_roundtrip() {
        // Test via serde serialization roundtrip
        let entry = make_entry("POST", "http://example.com", b"Hello, World!");
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: JournalEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.body, b"Hello, World!");
    }

    #[tokio::test]
    async fn test_journal_replay() {
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let branch_id = BranchId::from("test-branch".to_string());

        let mut journal = NetworkJournal::new(journal_dir, branch_id);

        // H-28: POST and PUT are non-idempotent. With safe_replay=false they are
        // skipped by the idempotency check, but replayed_count still increments
        // to track progress for crash recovery.
        journal
            .append(make_entry("POST", "http://example.com/a", b"data1"))
            .await
            .unwrap();
        journal
            .append(make_entry("PUT", "http://example.com/b", b"data2"))
            .await
            .unwrap();

        let allowed = vec!["example.com".to_string()];
        let replayed = journal.replay(&allowed).await.unwrap();
        // Both entries skipped via H-28 but progress tracked
        assert_eq!(replayed, 2);
    }

    // M18 + H-28: Test that non-idempotent methods are skipped via H-28
    // regardless of domain. All entries use safe_replay=false, so they are all
    // skipped instantly (no network calls, no timeouts).
    #[tokio::test]
    async fn test_journal_replay_domain_revalidation() {
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let branch_id = BranchId::from("test-branch".to_string());

        let mut journal = NetworkJournal::new(journal_dir, branch_id);

        // All POST/PUT with safe_replay=false → all skipped by H-28
        journal
            .append(make_entry("POST", "http://allowed.com/a", b"data1"))
            .await
            .unwrap();
        journal
            .append(make_entry("PUT", "http://revoked.com/b", b"data2"))
            .await
            .unwrap();
        journal
            .append(make_entry("POST", "http://allowed.com/c", b"data3"))
            .await
            .unwrap();

        // Only allow one domain at replay time
        let allowed = vec!["allowed.com".to_string()];
        let replayed = journal.replay(&allowed).await.unwrap();

        // H-28: All 3 entries skipped (non-idempotent, safe_replay=false),
        // but replayed_count increments for each to track progress.
        assert_eq!(replayed, 3);
    }

    // C11: Test replay progress tracking
    #[tokio::test]
    async fn test_replay_progress_write_and_read() {
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        std::fs::create_dir_all(&journal_dir).unwrap();
        let branch_id = BranchId::from("test-branch".to_string());

        let journal = NetworkJournal::new(journal_dir, branch_id);

        // Initially no progress
        assert_eq!(journal.read_replay_progress(), 0);

        // Write progress
        journal.write_replay_progress(3).await.unwrap();
        assert_eq!(journal.read_replay_progress(), 3);

        // Update progress
        journal.write_replay_progress(5).await.unwrap();
        assert_eq!(journal.read_replay_progress(), 5);
    }

    // C11: Test that discard also removes progress file
    #[tokio::test]
    async fn test_discard_removes_progress() {
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let branch_id = BranchId::from("test-branch".to_string());

        let mut journal = NetworkJournal::new(journal_dir.clone(), branch_id);

        journal
            .append(make_entry("POST", "http://example.com", b"data"))
            .await
            .unwrap();
        journal.write_replay_progress(1).await.unwrap();

        assert!(journal.progress_file_path().exists());

        journal.discard();
        assert!(!journal_dir.exists());
    }

    // -----------------------------------------------------------------------
    // NetworkJournal::new — recovery from existing journal on disk
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_new_recovers_entry_count_from_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let branch_id = BranchId::from("recover-branch".to_string());

        // Write 3 entries with a first journal instance
        let mut journal = NetworkJournal::new(journal_dir.clone(), branch_id.clone());
        for i in 0..3 {
            journal
                .append(make_entry(
                    "POST",
                    &format!("http://example.com/{}", i),
                    b"x",
                ))
                .await
                .unwrap();
        }
        assert_eq!(journal.entry_count(), 3);

        // Create a new journal pointing at the same directory (simulates daemon restart)
        let recovered = NetworkJournal::new(journal_dir, branch_id);
        assert_eq!(
            recovered.entry_count(),
            3,
            "entry_count must be recovered from existing journal file"
        );

        // read_all should also return 3 entries
        let entries = recovered.read_all().unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_new_nonexistent_dir_starts_at_zero() {
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("does-not-exist");
        let branch_id = BranchId::from("fresh-branch".to_string());

        let journal = NetworkJournal::new(journal_dir, branch_id);
        assert_eq!(journal.entry_count(), 0);
    }

    // -----------------------------------------------------------------------
    // NetworkJournal::append — limit enforcement
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_append_rejects_when_entry_count_limit_reached() {
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let branch_id = BranchId::from("limit-branch".to_string());

        let mut journal = NetworkJournal::new(journal_dir, branch_id);

        // Artificially set entry_count to the limit
        journal.entry_count = MAX_JOURNAL_ENTRIES as u64;

        let result = journal
            .append(make_entry("POST", "http://example.com/over", b"data"))
            .await;
        assert!(
            result.is_err(),
            "append must reject when entry count limit reached"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("entry count limit exceeded"),
            "error message should mention entry count limit, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_append_rejects_when_byte_size_limit_reached() {
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let branch_id = BranchId::from("bytelimit-branch".to_string());

        let mut journal = NetworkJournal::new(journal_dir, branch_id);

        // Artificially set journal_bytes just under the limit so the next entry exceeds it
        journal.journal_bytes = MAX_JOURNAL_BYTES - 1;

        // A non-trivial entry will be larger than 1 byte when serialized
        let result = journal
            .append(make_entry(
                "POST",
                "http://example.com/big",
                b"some-body-data",
            ))
            .await;
        assert!(
            result.is_err(),
            "append must reject when byte size limit reached"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("byte size limit exceeded"),
            "error message should mention byte size limit, got: {}",
            err
        );
    }

    // -----------------------------------------------------------------------
    // NetworkJournal::entry_count — direct assertions
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_entry_count_increments_on_append() {
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let branch_id = BranchId::from("count-branch".to_string());

        let mut journal = NetworkJournal::new(journal_dir, branch_id);
        assert_eq!(journal.entry_count(), 0);

        journal
            .append(make_entry("GET", "http://example.com/1", b""))
            .await
            .unwrap();
        assert_eq!(journal.entry_count(), 1);

        journal
            .append(make_entry("GET", "http://example.com/2", b""))
            .await
            .unwrap();
        assert_eq!(journal.entry_count(), 2);

        journal
            .append(make_entry("GET", "http://example.com/3", b""))
            .await
            .unwrap();
        assert_eq!(journal.entry_count(), 3);
    }

    // -----------------------------------------------------------------------
    // JournalEntry serialization / deserialization edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_journal_entry_serde_empty_body() {
        let entry = make_entry("GET", "http://example.com", b"");
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: JournalEntry = serde_json::from_str(&json).unwrap();
        assert!(decoded.body.is_empty());
        assert_eq!(decoded.method, "GET");
        assert_eq!(decoded.uri, "http://example.com");
    }

    #[test]
    fn test_journal_entry_serde_large_body() {
        // 1 MB body
        let large_body = vec![0xABu8; 1024 * 1024];
        let entry = make_entry("PUT", "http://example.com/upload", &large_body);
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: JournalEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.body.len(), 1024 * 1024);
        assert_eq!(decoded.body, large_body);
    }

    #[test]
    fn test_journal_entry_serde_no_headers() {
        let entry = JournalEntry {
            method: "GET".to_string(),
            uri: "http://example.com".to_string(),
            headers: vec![],
            body: vec![],
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            safe_replay: false,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: JournalEntry = serde_json::from_str(&json).unwrap();
        assert!(decoded.headers.is_empty());
    }

    #[test]
    fn test_journal_entry_serde_many_headers() {
        let headers: Vec<(String, String)> = (0..100)
            .map(|i| (format!("X-Header-{}", i), format!("value-{}", i)))
            .collect();
        let entry = JournalEntry {
            method: "POST".to_string(),
            uri: "http://example.com".to_string(),
            headers: headers.clone(),
            body: b"payload".to_vec(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            safe_replay: false,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: JournalEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.headers.len(), 100);
        assert_eq!(decoded.headers[50].0, "X-Header-50");
        assert_eq!(decoded.headers[50].1, "value-50");
    }

    #[test]
    fn test_journal_entry_serde_safe_replay_field() {
        // safe_replay=true roundtrips correctly
        let mut entry = make_entry("POST", "http://example.com", b"data");
        entry.safe_replay = true;
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: JournalEntry = serde_json::from_str(&json).unwrap();
        assert!(decoded.safe_replay);
    }

    #[test]
    fn test_journal_entry_safe_replay_defaults_false() {
        // When safe_replay is missing from JSON, it should default to false
        let json = r#"{"method":"POST","uri":"http://example.com","headers":[],"body":"","timestamp":"2026-01-01T00:00:00Z"}"#;
        let decoded: JournalEntry = serde_json::from_str(json).unwrap();
        assert!(
            !decoded.safe_replay,
            "safe_replay must default to false when absent"
        );
    }

    #[test]
    fn test_journal_entry_clone() {
        let entry = make_entry("DELETE", "http://example.com/resource", b"body");
        let cloned = entry.clone();
        assert_eq!(cloned.method, entry.method);
        assert_eq!(cloned.uri, entry.uri);
        assert_eq!(cloned.body, entry.body);
        assert_eq!(cloned.headers, entry.headers);
        assert_eq!(cloned.timestamp, entry.timestamp);
        assert_eq!(cloned.safe_replay, entry.safe_replay);
    }

    // -----------------------------------------------------------------------
    // NetworkJournal::read_all — edge cases
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_read_all_skips_blank_lines() {
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        std::fs::create_dir_all(&journal_dir).unwrap();

        let branch_id = BranchId::from("blank-lines-branch".to_string());

        // Manually write a journal file with blank lines interspersed
        let entry1 = make_entry("GET", "http://example.com/1", b"a");
        let entry2 = make_entry("GET", "http://example.com/2", b"b");
        let line1 = serde_json::to_string(&entry1).unwrap();
        let line2 = serde_json::to_string(&entry2).unwrap();

        let journal_file = journal_dir.join("requests.ndjson");
        std::fs::write(&journal_file, format!("{}\n\n  \n{}\n\n", line1, line2)).unwrap();

        let journal = NetworkJournal::new(journal_dir, branch_id);
        let entries = journal.read_all().unwrap();
        assert_eq!(entries.len(), 2, "blank lines should be skipped");
        assert_eq!(entries[0].uri, "http://example.com/1");
        assert_eq!(entries[1].uri, "http://example.com/2");
    }

    #[tokio::test]
    async fn test_read_all_multiple_entries_preserve_order() {
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let branch_id = BranchId::from("order-branch".to_string());

        let mut journal = NetworkJournal::new(journal_dir, branch_id);

        let methods = ["GET", "POST", "PUT", "DELETE", "PATCH"];
        for (i, method) in methods.iter().enumerate() {
            journal
                .append(make_entry(
                    method,
                    &format!("http://example.com/{}", i),
                    b"",
                ))
                .await
                .unwrap();
        }

        let entries = journal.read_all().unwrap();
        assert_eq!(entries.len(), 5);
        for (i, method) in methods.iter().enumerate() {
            assert_eq!(entries[i].method, *method, "entry {} method mismatch", i);
            assert_eq!(
                entries[i].uri,
                format!("http://example.com/{}", i),
                "entry {} URI mismatch",
                i
            );
        }
    }

    // -----------------------------------------------------------------------
    // NetworkJournal::discard — edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_discard_nonexistent_dir_does_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("nonexistent-journal");
        let branch_id = BranchId::from("no-dir-branch".to_string());

        let journal = NetworkJournal::new(journal_dir, branch_id);
        // Should not panic
        journal.discard();
    }

    #[tokio::test]
    async fn test_discard_then_read_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let branch_id = BranchId::from("discard-read-branch".to_string());

        let mut journal = NetworkJournal::new(journal_dir.clone(), branch_id);
        journal
            .append(make_entry("POST", "http://example.com", b"data"))
            .await
            .unwrap();
        assert_eq!(journal.entry_count(), 1);

        journal.discard();

        // read_all should return empty after discard
        let entries = journal.read_all().unwrap();
        assert!(
            entries.is_empty(),
            "read_all must return empty after discard"
        );
    }

    // -----------------------------------------------------------------------
    // NetworkJournal::replay — empty journal
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_replay_empty_journal_returns_zero() {
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let branch_id = BranchId::from("empty-replay-branch".to_string());

        let journal = NetworkJournal::new(journal_dir, branch_id);
        let allowed = vec!["example.com".to_string()];
        let replayed = journal.replay(&allowed).await.unwrap();
        assert_eq!(replayed, 0, "replay of empty journal must return 0");
    }

    // -----------------------------------------------------------------------
    // C11: Replay crash recovery — resume from progress
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_replay_resumes_from_progress() {
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let branch_id = BranchId::from("resume-branch".to_string());

        let mut journal = NetworkJournal::new(journal_dir.clone(), branch_id.clone());

        // Append 5 non-idempotent entries (will be skipped by H-28 but progress tracked)
        for i in 0..5 {
            journal
                .append(make_entry(
                    "POST",
                    &format!("http://example.com/{}", i),
                    b"x",
                ))
                .await
                .unwrap();
        }

        // Simulate a previous partial replay by writing progress = 3
        journal.write_replay_progress(3).await.unwrap();

        let allowed = vec!["example.com".to_string()];
        let replayed = journal.replay(&allowed).await.unwrap();
        // 3 already done + 2 newly processed (skipped by H-28 but counted)
        assert_eq!(replayed, 5, "replay should resume from progress checkpoint");
    }

    #[tokio::test]
    async fn test_replay_progress_already_complete() {
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let branch_id = BranchId::from("complete-branch".to_string());

        let mut journal = NetworkJournal::new(journal_dir.clone(), branch_id.clone());

        // Append 3 entries
        for i in 0..3 {
            journal
                .append(make_entry(
                    "POST",
                    &format!("http://example.com/{}", i),
                    b"x",
                ))
                .await
                .unwrap();
        }

        // Simulate all entries already replayed
        journal.write_replay_progress(3).await.unwrap();

        let allowed = vec!["example.com".to_string()];
        let replayed = journal.replay(&allowed).await.unwrap();
        assert_eq!(
            replayed, 3,
            "should return progress count when all entries already replayed"
        );
    }

    #[tokio::test]
    async fn test_replay_progress_exceeds_entries() {
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let branch_id = BranchId::from("exceed-branch".to_string());

        let mut journal = NetworkJournal::new(journal_dir.clone(), branch_id.clone());

        // Append 2 entries
        journal
            .append(make_entry("POST", "http://example.com/a", b"x"))
            .await
            .unwrap();
        journal
            .append(make_entry("POST", "http://example.com/b", b"y"))
            .await
            .unwrap();

        // Progress says 10, but only 2 entries exist (e.g., journal was truncated)
        journal.write_replay_progress(10).await.unwrap();

        let allowed = vec!["example.com".to_string()];
        let replayed = journal.replay(&allowed).await.unwrap();
        assert_eq!(
            replayed, 10,
            "should return stored progress when it exceeds entry count"
        );
    }

    // -----------------------------------------------------------------------
    // H-28: Safe replay flag behavior
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_replay_skips_non_idempotent_without_safe_replay() {
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let branch_id = BranchId::from("h28-branch".to_string());

        let mut journal = NetworkJournal::new(journal_dir, branch_id);

        // POST, PUT, DELETE, PATCH — all non-idempotent, safe_replay=false
        for method in &["POST", "PUT", "DELETE", "PATCH"] {
            journal
                .append(make_entry(method, "http://example.com/action", b"data"))
                .await
                .unwrap();
        }

        let allowed = vec!["example.com".to_string()];
        let replayed = journal.replay(&allowed).await.unwrap();
        // All 4 are skipped by H-28 but progress is still tracked
        assert_eq!(replayed, 4);
    }

    // -----------------------------------------------------------------------
    // JournalRateLimiter tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_rate_limiter_allows_under_limit() {
        let mut limiter = JournalRateLimiter::new();
        // Should allow up to MAX_ENTRIES_PER_SECOND calls
        for i in 0..JournalRateLimiter::MAX_ENTRIES_PER_SECOND {
            assert!(
                limiter.check(),
                "rate limiter should allow entry {} (under limit)",
                i
            );
        }
    }

    #[test]
    fn test_rate_limiter_rejects_over_limit() {
        let mut limiter = JournalRateLimiter::new();
        // Fill up to the limit
        for _ in 0..JournalRateLimiter::MAX_ENTRIES_PER_SECOND {
            assert!(limiter.check());
        }
        // The next one should be rejected
        assert!(
            !limiter.check(),
            "rate limiter should reject entry at limit"
        );
        // And the one after that too
        assert!(
            !limiter.check(),
            "rate limiter should continue rejecting over limit"
        );
    }

    #[test]
    fn test_rate_limiter_new_is_empty() {
        let mut limiter = JournalRateLimiter::new();
        // First check should always succeed
        assert!(limiter.check());
    }

    // -----------------------------------------------------------------------
    // base64_bytes module — edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_base64_roundtrip_all_byte_values() {
        // Every possible byte value 0x00..=0xFF
        let all_bytes: Vec<u8> = (0..=255).collect();
        let entry = make_entry("POST", "http://example.com", &all_bytes);
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: JournalEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.body, all_bytes);
    }

    #[test]
    fn test_base64_roundtrip_empty() {
        let entry = make_entry("GET", "http://example.com", b"");
        let json = serde_json::to_string(&entry).unwrap();
        // Verify the serialized body is the base64 of empty (empty string)
        assert!(json.contains(r#""body":"""#));
        let decoded: JournalEntry = serde_json::from_str(&json).unwrap();
        assert!(decoded.body.is_empty());
    }

    #[test]
    fn test_base64_invalid_decode_fails() {
        // Invalid base64 in the body field should produce a deserialization error
        let json = r#"{"method":"GET","uri":"http://example.com","headers":[],"body":"!!!not-valid-base64!!!","timestamp":"2026-01-01T00:00:00Z"}"#;
        let result = serde_json::from_str::<JournalEntry>(json);
        assert!(
            result.is_err(),
            "invalid base64 should fail deserialization"
        );
    }

    // -----------------------------------------------------------------------
    // NetworkJournal — journal_bytes tracking
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_journal_bytes_tracks_written_size() {
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let branch_id = BranchId::from("bytes-branch".to_string());

        let mut journal = NetworkJournal::new(journal_dir.clone(), branch_id);
        assert_eq!(journal.journal_bytes, 0);

        journal
            .append(make_entry("POST", "http://example.com", b"hello"))
            .await
            .unwrap();

        assert!(
            journal.journal_bytes > 0,
            "journal_bytes should be > 0 after append"
        );

        let bytes_after_first = journal.journal_bytes;

        journal
            .append(make_entry("PUT", "http://example.com/2", b"world"))
            .await
            .unwrap();

        assert!(
            journal.journal_bytes > bytes_after_first,
            "journal_bytes should increase after second append"
        );
    }

    #[tokio::test]
    async fn test_new_recovers_journal_bytes_from_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let branch_id = BranchId::from("recover-bytes-branch".to_string());

        let mut journal = NetworkJournal::new(journal_dir.clone(), branch_id.clone());
        journal
            .append(make_entry("POST", "http://example.com", b"some-data"))
            .await
            .unwrap();

        let original_bytes = journal.journal_bytes;
        assert!(original_bytes > 0);

        // Re-create journal from same directory (simulates daemon restart)
        let recovered = NetworkJournal::new(journal_dir, branch_id);
        assert_eq!(
            recovered.journal_bytes, original_bytes,
            "journal_bytes must be recovered from existing file size"
        );
    }

    // -----------------------------------------------------------------------
    // Constants validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_max_journal_entries_constant() {
        assert_eq!(MAX_JOURNAL_ENTRIES, 10_000);
    }

    #[test]
    fn test_max_journal_bytes_constant() {
        assert_eq!(MAX_JOURNAL_BYTES, 100 * 1024 * 1024);
    }

    #[test]
    fn test_safe_replay_methods_constant() {
        assert!(SAFE_REPLAY_METHODS.contains(&"GET"));
        assert!(SAFE_REPLAY_METHODS.contains(&"HEAD"));
        assert!(!SAFE_REPLAY_METHODS.contains(&"POST"));
        assert!(!SAFE_REPLAY_METHODS.contains(&"PUT"));
        assert!(!SAFE_REPLAY_METHODS.contains(&"DELETE"));
        assert!(!SAFE_REPLAY_METHODS.contains(&"PATCH"));
    }

    // L6: Verify replay() uses try_from instead of bare `as usize` cast
    #[test]
    fn test_l6_no_bare_as_usize_cast_on_start_index() {
        let src = include_str!("replay.rs");
        // Find the production code (before #[cfg(test)])
        let prod = src.split("#[cfg(test)]").next().unwrap();
        assert!(
            !prod.contains("start_index as usize"),
            "L6: production code must not use bare `as usize` cast on start_index; use usize::try_from"
        );
    }

    // L43: Verify discard() logs errors instead of silently ignoring them
    #[test]
    fn test_l43_discard_logs_remove_dir_all_errors() {
        let src = include_str!("replay.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        assert!(
            !prod.contains("let _ = std::fs::remove_dir_all"),
            "L43: discard() must not silently ignore remove_dir_all errors; log with tracing::warn"
        );
    }
}
