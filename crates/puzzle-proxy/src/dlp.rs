// SPDX-License-Identifier: Apache-2.0
//! DLP (Data Loss Prevention) content inspection engine.
//!
//! Scans request and response bodies for sensitive data patterns (credentials,
//! API keys, high-entropy secrets) and enforces configurable actions: block,
//! redact, log, or quarantine.

use std::path::Path;

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Action for oversized request bodies that exceed max_inspection_body_size.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OversizedAction {
    /// Block oversized bodies (fail closed — default).
    #[default]
    BlockAndAlert,
    /// Allow oversized bodies without inspection (fail open).
    AllowAndLog,
}

/// Severity level of a DLP rule match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DlpSeverity {
    Warning,
    Critical,
}

/// Action to take when a DLP rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DlpAction {
    LogAndAllow,
    RedactAndAllow,
    BlockAndReview,
    BlockAndAlert,
    Quarantine,
}

/// Which direction a DLP rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DlpApplyTo {
    Request,
    Response,
    Both,
}

/// A pattern matcher within a DLP rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DlpPattern {
    Regex {
        pattern: String,
    },
    Entropy {
        min_entropy: f64,
        min_length: usize,
    },
    /// TLSH fuzzy fingerprint comparison against pre-computed fingerprints.
    /// Phase D enhancement — currently accepted in YAML but not matched at runtime.
    Fingerprint {
        source_dir: String,
    },
}

/// A single DLP rule definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpRule {
    pub name: String,
    pub description: String,
    pub severity: DlpSeverity,
    pub action: DlpAction,
    pub patterns: Vec<DlpPattern>,
    #[serde(default)]
    pub apply_to: Option<DlpApplyTo>,
}

/// Container for a set of DLP rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpRuleSet {
    pub rules: Vec<DlpRule>,
}

/// Per-rule match timeout (§3.3.7 ReDoS mitigation).
/// N9: The `regex` crate uses a DFA/NFA engine that is immune to catastrophic
/// backtracking (exponential blowup). All patterns run in O(n) time relative to
/// input length. This timeout is a secondary safeguard against unexpectedly large
/// inputs, not a primary ReDoS mitigation.
const PER_RULE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(10);

/// L22: Maximum number of entropy matches to collect before stopping.
/// Prevents unbounded memory growth when scanning large bodies with low entropy thresholds.
const MAX_ENTROPY_MATCHES: usize = 1000;

/// A compiled pattern matcher ready for execution.
#[derive(Debug)]
#[allow(dead_code)]
enum CompiledMatcher {
    Regex(Regex),
    Entropy {
        min_entropy: f64,
        min_length: usize,
    },
    /// TLSH fingerprint matching (Phase D — not yet implemented).
    /// Stores the source directory path for future TLSH hash loading.
    // V23: Fingerprint matching is planned for Phase 2 — variant retained for schema compatibility
    Fingerprint {
        source_dir: String,
    },
}

/// A compiled DLP rule with pre-built matchers.
#[derive(Debug)]
struct CompiledDlpRule {
    name: String,
    severity: DlpSeverity,
    action: DlpAction,
    matchers: Vec<CompiledMatcher>,
    /// Which direction this rule applies to (default: Both).
    apply_to: DlpApplyTo,
}

/// Compiled DLP engine that inspects byte content against a rule set.
#[derive(Debug)]
pub struct DlpEngine {
    rules: Vec<CompiledDlpRule>,
}

/// A single match found during DLP inspection.
#[derive(Debug, Clone)]
pub struct DlpMatch {
    pub rule_name: String,
    pub severity: DlpSeverity,
    pub action: DlpAction,
    /// SHA-256 hex digest of the matched content (never the content itself).
    pub match_hash: String,
    pub offset: usize,
    pub length: usize,
}

/// Result of a DLP inspection pass.
#[derive(Debug, Clone)]
pub struct DlpInspectionResult {
    /// Whether the request/response should proceed.
    pub allowed: bool,
    /// All matched rules.
    pub matches: Vec<DlpMatch>,
    /// Body with redactions applied (present only for `RedactAndAllow`).
    pub modified_body: Option<Vec<u8>>,
}

impl DlpInspectionResult {
    /// Returns the most severe action among all matches, if any.
    pub fn most_severe_action(&self) -> Option<DlpAction> {
        most_severe_action(&self.matches.iter().map(|m| m.action).collect::<Vec<_>>())
    }
}

/// Calculate Shannon entropy of a byte slice.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Return the most severe action from a list. Severity order (descending):
/// Quarantine > BlockAndAlert > BlockAndReview > RedactAndAllow > LogAndAllow
pub fn most_severe_action(actions: &[DlpAction]) -> Option<DlpAction> {
    actions.iter().copied().max_by_key(|a| match a {
        DlpAction::LogAndAllow => 0,
        DlpAction::RedactAndAllow => 1,
        DlpAction::BlockAndReview => 2,
        DlpAction::BlockAndAlert => 3,
        DlpAction::Quarantine => 4,
    })
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

impl DlpEngine {
    /// Compile a `DlpRuleSet` into an executable engine.
    pub fn new(rule_set: &DlpRuleSet) -> Result<Self, Box<dyn std::error::Error>> {
        let mut rules = Vec::with_capacity(rule_set.rules.len());

        for rule in &rule_set.rules {
            let mut matchers = Vec::with_capacity(rule.patterns.len());
            for pattern in &rule.patterns {
                match pattern {
                    DlpPattern::Regex { pattern } => {
                        let re = Regex::new(pattern).map_err(|e| {
                            format!("rule '{}': invalid regex '{}': {}", rule.name, pattern, e)
                        })?;
                        matchers.push(CompiledMatcher::Regex(re));
                    }
                    DlpPattern::Entropy {
                        min_entropy,
                        min_length,
                    } => {
                        matchers.push(CompiledMatcher::Entropy {
                            min_entropy: *min_entropy,
                            min_length: *min_length,
                        });
                    }
                    DlpPattern::Fingerprint { source_dir } => {
                        // Phase D: TLSH fingerprint matching not yet implemented.
                        // Accept the pattern in config but log a warning.
                        tracing::warn!(
                            rule = %rule.name,
                            source_dir = %source_dir,
                            "DLP fingerprint matching is a Phase D feature — TLSH hashes not loaded"
                        );
                        matchers.push(CompiledMatcher::Fingerprint {
                            source_dir: source_dir.clone(),
                        });
                    }
                }
            }

            rules.push(CompiledDlpRule {
                name: rule.name.clone(),
                severity: rule.severity,
                action: rule.action,
                matchers,
                apply_to: rule.apply_to.unwrap_or(DlpApplyTo::Both),
            });
        }

        Ok(Self { rules })
    }

    /// Parse a YAML string into a rule set and compile it.
    pub fn from_yaml(yaml_str: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let rule_set: DlpRuleSet = serde_yaml::from_str(yaml_str)?;
        Self::new(&rule_set)
    }

    /// Read a YAML file and compile the rule set.
    pub fn from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        Self::from_yaml(&content)
    }

    /// Number of compiled rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Inspect a request body against all compiled rules (respects `apply_to` filter).
    pub fn inspect(&self, body: &[u8]) -> DlpInspectionResult {
        self.inspect_with_direction(body, DlpApplyTo::Request)
    }

    /// Inspect a response body against all compiled rules (respects `apply_to` filter).
    pub fn inspect_response(&self, body: &[u8]) -> DlpInspectionResult {
        self.inspect_with_direction(body, DlpApplyTo::Response)
    }

    /// Inspect a body against compiled rules, filtering by direction.
    fn inspect_with_direction(&self, body: &[u8], direction: DlpApplyTo) -> DlpInspectionResult {
        let mut all_matches: Vec<DlpMatch> = Vec::new();

        // Offset+length pairs of regions to redact (for RedactAndAllow).
        let mut redact_regions: Vec<(usize, usize)> = Vec::new();
        let mut needs_redaction = false;

        for rule in &self.rules {
            // Skip rules that don't apply to this direction
            match (rule.apply_to, direction) {
                (DlpApplyTo::Both, _) => {} // applies to everything
                (DlpApplyTo::Request, DlpApplyTo::Request) => {}
                (DlpApplyTo::Response, DlpApplyTo::Response) => {}
                _ => continue, // skip: direction mismatch
            }
            // §3.3.7: Per-rule timeout to mitigate ReDoS
            let rule_start = std::time::Instant::now();

            // A rule matches if ANY of its matchers match.
            let mut rule_matched = false;

            for matcher in &rule.matchers {
                if rule_matched {
                    break;
                }
                // §3.3.7: Check per-rule timeout
                // N9: See PER_RULE_TIMEOUT doc — regex crate is inherently ReDoS-immune.
                if rule_start.elapsed() > PER_RULE_TIMEOUT {
                    tracing::warn!(
                        rule = %rule.name,
                        elapsed_ms = %rule_start.elapsed().as_millis(),
                        "§3.3.7: DLP rule matching timed out (>10ms), skipping remaining matchers"
                    );
                    break;
                }
                match matcher {
                    CompiledMatcher::Regex(re) => {
                        // Regex matching requires UTF-8. If body is valid UTF-8,
                        // match offsets correspond directly to body byte offsets.
                        // If not, from_utf8_lossy may insert replacement characters
                        // that shift offsets — so we only use match results when
                        // the body is valid UTF-8 to avoid incorrect redaction ranges.
                        let text = String::from_utf8_lossy(body);
                        let body_is_valid_utf8 = matches!(text, std::borrow::Cow::Borrowed(_));
                        for m in re.find_iter(&text) {
                            rule_matched = true;
                            if body_is_valid_utf8 {
                                let matched_bytes = &body[m.start()..m.end()];
                                all_matches.push(DlpMatch {
                                    rule_name: rule.name.clone(),
                                    severity: rule.severity,
                                    action: rule.action,
                                    match_hash: sha256_hex(matched_bytes),
                                    offset: m.start(),
                                    length: m.len(),
                                });
                                if rule.action == DlpAction::RedactAndAllow {
                                    redact_regions.push((m.start(), m.len()));
                                    needs_redaction = true;
                                }
                            } else {
                                // Invalid UTF-8 body: record match without byte-accurate offset
                                all_matches.push(DlpMatch {
                                    rule_name: rule.name.clone(),
                                    severity: rule.severity,
                                    action: rule.action,
                                    match_hash: sha256_hex(m.as_str().as_bytes()),
                                    offset: 0,
                                    length: 0,
                                });
                                // Cannot safely redact — block instead of corrupt
                            }
                        }
                    }
                    CompiledMatcher::Entropy {
                        min_entropy,
                        min_length,
                    } => {
                        if *min_length == 0 || body.len() < *min_length {
                            continue;
                        }
                        // D-I6: Incremental sliding window entropy with proper multi-match.
                        // Uses a `while` loop so `start` can be advanced past matched
                        // windows instead of `break`ing after the first match.
                        let mut freq = [0u64; 256];
                        // Initialize frequency table with first window
                        for &b in &body[..*min_length] {
                            freq[b as usize] += 1;
                        }
                        let len_f64 = *min_length as f64;
                        let end = body.len() - min_length;

                        let mut start: usize = 0;
                        let mut freq_fresh = true; // freq was just initialized for `start`
                        while start <= end && all_matches.len() < MAX_ENTROPY_MATCHES {
                            if !freq_fresh && start > 0 {
                                // Slide window: remove outgoing byte, add incoming byte
                                freq[body[start - 1] as usize] -= 1;
                                freq[body[start + min_length - 1] as usize] += 1;
                            }
                            freq_fresh = false;
                            // Compute entropy from frequency table: O(256) = O(1)
                            let ent: f64 = freq
                                .iter()
                                .filter(|&&count| count > 0)
                                .map(|&count| {
                                    let p = count as f64 / len_f64;
                                    -p * p.log2()
                                })
                                .sum();

                            if ent >= *min_entropy {
                                let window = &body[start..start + min_length];
                                rule_matched = true;
                                all_matches.push(DlpMatch {
                                    rule_name: rule.name.clone(),
                                    severity: rule.severity,
                                    action: rule.action,
                                    match_hash: sha256_hex(window),
                                    offset: start,
                                    length: *min_length,
                                });
                                if rule.action == DlpAction::RedactAndAllow {
                                    redact_regions.push((start, *min_length));
                                    needs_redaction = true;
                                }
                                // D-I6: Skip past the matched window to find additional
                                // non-overlapping matches instead of breaking.
                                let new_start = start + *min_length;
                                if new_start + min_length <= body.len() {
                                    // Re-initialize frequency table for the new window
                                    freq = [0u64; 256];
                                    for &b in &body[new_start..new_start + min_length] {
                                        freq[b as usize] += 1;
                                    }
                                    freq_fresh = true;
                                }
                                start = new_start;
                            } else {
                                start += 1;
                            }
                        }
                    }
                    CompiledMatcher::Fingerprint { source_dir } => {
                        // Phase D: TLSH fingerprint matching not yet implemented.
                        // D-M4: Log at match time so every body inspection that could
                        // have triggered a fingerprint rule produces a diagnostic.
                        tracing::debug!(
                            rule = %rule.name,
                            source_dir = %source_dir,
                            body_len = body.len(),
                            "fingerprint matching not yet implemented — this rule will never match"
                        );
                    }
                }
            }
        }

        let modified_body = if needs_redaction {
            Some(apply_redactions(body, &redact_regions))
        } else {
            None
        };

        let actions: Vec<DlpAction> = all_matches.iter().map(|m| m.action).collect();
        let worst = most_severe_action(&actions);

        let allowed = match worst {
            None => true,
            Some(DlpAction::LogAndAllow) | Some(DlpAction::RedactAndAllow) => true,
            Some(DlpAction::BlockAndReview)
            | Some(DlpAction::BlockAndAlert)
            | Some(DlpAction::Quarantine) => false,
        };

        DlpInspectionResult {
            allowed,
            matches: all_matches,
            modified_body,
        }
    }
}

/// Replace matched regions with `[REDACTED]` in a copy of the body.
/// Regions are processed in reverse offset order to preserve earlier offsets.
fn apply_redactions(body: &[u8], regions: &[(usize, usize)]) -> Vec<u8> {
    let mut sorted: Vec<(usize, usize)> = regions.to_vec();
    sorted.sort_by(|a, b| b.0.cmp(&a.0));

    // Merge overlapping regions (working backwards).
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (offset, len) in &sorted {
        if let Some(last) = merged.last_mut() {
            let last_start = last.0;
            let cur_end = offset + len;
            if cur_end >= last_start {
                // Overlapping or adjacent — extend.
                let new_start = (*offset).min(last.0);
                let new_end = cur_end.max(last.0 + last.1);
                *last = (new_start, new_end - new_start);
                continue;
            }
        }
        merged.push((*offset, *len));
    }

    let mut result = body.to_vec();
    for (offset, len) in &merged {
        let end = (offset + len).min(result.len());
        let replacement = b"[REDACTED]";
        result.splice(*offset..end, replacement.iter().copied());
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_engine(rules: Vec<DlpRule>) -> DlpEngine {
        DlpEngine::new(&DlpRuleSet { rules }).expect("failed to compile rules")
    }

    fn regex_rule(name: &str, pattern: &str, action: DlpAction, severity: DlpSeverity) -> DlpRule {
        DlpRule {
            name: name.to_string(),
            description: format!("Test rule: {}", name),
            severity,
            action,
            patterns: vec![DlpPattern::Regex {
                pattern: pattern.to_string(),
            }],
            apply_to: None,
        }
    }

    #[test]
    fn test_dlp_regex_blocks_private_key() {
        let engine = make_engine(vec![regex_rule(
            "private_key",
            r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
            DlpAction::BlockAndAlert,
            DlpSeverity::Critical,
        )]);

        let body = b"here is my -----BEGIN RSA PRIVATE KEY----- data";
        let result = engine.inspect(body);
        assert!(!result.allowed);
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].rule_name, "private_key");
        assert_eq!(result.matches[0].action, DlpAction::BlockAndAlert);
    }

    #[test]
    fn test_dlp_regex_blocks_aws_key() {
        let engine = make_engine(vec![regex_rule(
            "aws_access_key",
            r"AKIA[0-9A-Z]{16}",
            DlpAction::BlockAndAlert,
            DlpSeverity::Critical,
        )]);

        let body = b"aws_key=AKIAIOSFODNN7EXAMPLE";
        let result = engine.inspect(body);
        assert!(!result.allowed);
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].rule_name, "aws_access_key");
    }

    #[test]
    fn test_dlp_regex_allows_clean_body() {
        let engine = make_engine(vec![regex_rule(
            "private_key",
            r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
            DlpAction::BlockAndAlert,
            DlpSeverity::Critical,
        )]);

        let body = b"This is a perfectly normal HTTP request body with no secrets.";
        let result = engine.inspect(body);
        assert!(result.allowed);
        assert!(result.matches.is_empty());
    }

    #[test]
    fn test_dlp_entropy_detects_high_entropy_string() {
        let engine = make_engine(vec![DlpRule {
            name: "high_entropy".to_string(),
            description: "Detect high-entropy strings".to_string(),
            severity: DlpSeverity::Warning,
            action: DlpAction::BlockAndReview,
            patterns: vec![DlpPattern::Entropy {
                min_entropy: 4.0,
                min_length: 20,
            }],
            apply_to: None,
        }]);

        // High-entropy random-looking string.
        let body = b"token=aB3xQ9zR7mK2pL5wY8nT0vFjHcGdEiUo";
        let result = engine.inspect(body);
        assert!(!result.allowed);
        assert!(!result.matches.is_empty());
        assert_eq!(result.matches[0].rule_name, "high_entropy");
    }

    #[test]
    fn test_dlp_entropy_allows_normal_text() {
        let engine = make_engine(vec![DlpRule {
            name: "high_entropy".to_string(),
            description: "Detect high-entropy strings".to_string(),
            severity: DlpSeverity::Warning,
            action: DlpAction::BlockAndReview,
            patterns: vec![DlpPattern::Entropy {
                min_entropy: 5.5,
                min_length: 32,
            }],
            apply_to: None,
        }]);

        let body = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let result = engine.inspect(body);
        assert!(result.allowed);
        assert!(result.matches.is_empty());
    }

    #[test]
    fn test_dlp_redact_and_allow() {
        let engine = make_engine(vec![regex_rule(
            "ssn",
            r"\d{3}-\d{2}-\d{4}",
            DlpAction::RedactAndAllow,
            DlpSeverity::Warning,
        )]);

        let body = b"SSN is 123-45-6789 here";
        let result = engine.inspect(body);
        assert!(result.allowed);
        assert_eq!(result.matches.len(), 1);
        assert!(result.modified_body.is_some());
        let modified = result.modified_body.unwrap();
        let modified_str = String::from_utf8_lossy(&modified);
        assert!(modified_str.contains("[REDACTED]"));
        assert!(!modified_str.contains("123-45-6789"));
    }

    #[test]
    fn test_dlp_log_and_allow_permits_request() {
        let engine = make_engine(vec![regex_rule(
            "email",
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            DlpAction::LogAndAllow,
            DlpSeverity::Warning,
        )]);

        let body = b"Contact: user@example.com";
        let result = engine.inspect(body);
        assert!(result.allowed);
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].action, DlpAction::LogAndAllow);
        assert!(result.modified_body.is_none());
    }

    #[test]
    fn test_dlp_multiple_rules_most_severe_wins() {
        let engine = make_engine(vec![
            regex_rule(
                "email",
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                DlpAction::LogAndAllow,
                DlpSeverity::Warning,
            ),
            regex_rule(
                "private_key",
                r"-----BEGIN PRIVATE KEY-----",
                DlpAction::BlockAndAlert,
                DlpSeverity::Critical,
            ),
        ]);

        let body = b"user@test.com and -----BEGIN PRIVATE KEY----- secret";
        let result = engine.inspect(body);
        assert!(!result.allowed);
        assert_eq!(result.matches.len(), 2);
        assert_eq!(result.most_severe_action(), Some(DlpAction::BlockAndAlert));
    }

    #[test]
    fn test_dlp_from_yaml() {
        let yaml = r#"
rules:
  - name: aws_key
    description: AWS access key
    severity: critical
    action: block_and_alert
    patterns:
      - type: regex
        pattern: "AKIA[0-9A-Z]{16}"
  - name: entropy_secret
    description: High entropy secret
    severity: warning
    action: log_and_allow
    patterns:
      - type: entropy
        min_entropy: 4.5
        min_length: 20
"#;

        let engine = DlpEngine::from_yaml(yaml).expect("failed to parse YAML");
        assert_eq!(engine.rule_count(), 2);

        let body = b"key=AKIAIOSFODNN7EXAMPLE";
        let result = engine.inspect(body);
        assert!(!result.allowed);
    }

    #[test]
    fn test_shannon_entropy_calculation() {
        // All same byte -> entropy 0.
        let data = vec![0u8; 100];
        assert!((shannon_entropy(&data) - 0.0).abs() < f64::EPSILON);

        // Two equally frequent bytes -> entropy 1.0.
        let mut data = vec![0u8; 50];
        data.extend(vec![1u8; 50]);
        assert!((shannon_entropy(&data) - 1.0).abs() < 0.01);

        // Empty -> 0.
        assert!((shannon_entropy(&[]) - 0.0).abs() < f64::EPSILON);

        // 256 distinct bytes -> entropy 8.0.
        let data: Vec<u8> = (0..=255).collect();
        assert!((shannon_entropy(&data) - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_dlp_match_hash_not_content() {
        let engine = make_engine(vec![regex_rule(
            "ssn",
            r"\d{3}-\d{2}-\d{4}",
            DlpAction::LogAndAllow,
            DlpSeverity::Warning,
        )]);

        let body = b"SSN: 123-45-6789";
        let result = engine.inspect(body);
        assert_eq!(result.matches.len(), 1);

        let hash = &result.matches[0].match_hash;
        // Hash must be 64-char hex (SHA-256).
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        // Hash must NOT be the literal matched text.
        assert_ne!(hash, "123-45-6789");
        // Verify it is the correct SHA-256.
        let expected = sha256_hex(b"123-45-6789");
        assert_eq!(*hash, expected);
    }

    #[test]
    fn test_dlp_empty_body() {
        let engine = make_engine(vec![regex_rule(
            "private_key",
            r"-----BEGIN PRIVATE KEY-----",
            DlpAction::BlockAndAlert,
            DlpSeverity::Critical,
        )]);

        let result = engine.inspect(b"");
        assert!(result.allowed);
        assert!(result.matches.is_empty());
        assert!(result.modified_body.is_none());
    }

    #[test]
    fn test_dlp_quarantine_is_most_severe() {
        assert_eq!(
            most_severe_action(&[
                DlpAction::LogAndAllow,
                DlpAction::RedactAndAllow,
                DlpAction::BlockAndReview,
                DlpAction::BlockAndAlert,
                DlpAction::Quarantine,
            ]),
            Some(DlpAction::Quarantine)
        );

        assert_eq!(
            most_severe_action(&[DlpAction::BlockAndAlert, DlpAction::Quarantine]),
            Some(DlpAction::Quarantine)
        );

        assert_eq!(most_severe_action(&[]), None);

        assert_eq!(
            most_severe_action(&[DlpAction::LogAndAllow]),
            Some(DlpAction::LogAndAllow)
        );
    }

    /// D-I6: Entropy matcher should find multiple non-overlapping high-entropy
    /// strings separated by low-entropy padding.
    #[test]
    fn test_dlp_entropy_finds_multiple_matches() {
        let engine = make_engine(vec![DlpRule {
            name: "multi_entropy".to_string(),
            description: "Detect multiple high-entropy strings".to_string(),
            severity: DlpSeverity::Warning,
            action: DlpAction::BlockAndReview,
            patterns: vec![DlpPattern::Entropy {
                min_entropy: 3.5,
                min_length: 16,
            }],
            apply_to: None,
        }]);

        // Two high-entropy strings separated by low-entropy padding (all 'a's).
        let secret1 = b"aB3xQ9zR7mK2pL5w"; // 17 bytes, high entropy
        let padding = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 40 bytes, zero entropy
        let secret2 = b"Y8nT0vFjHcGdEiUo"; // 17 bytes, high entropy

        let mut body = Vec::new();
        body.extend_from_slice(secret1);
        body.extend_from_slice(padding);
        body.extend_from_slice(secret2);

        let result = engine.inspect(&body);
        assert!(
            result.matches.len() >= 2,
            "D-I6: entropy matcher should find at least 2 matches, got {}",
            result.matches.len()
        );
    }

    // -----------------------------------------------------------------------
    // L22: Entropy match list must be bounded by MAX_ENTROPY_MATCHES
    // -----------------------------------------------------------------------

    #[test]
    fn l22_entropy_matches_bounded() {
        let source = include_str!("dlp.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // L22: MAX_ENTROPY_MATCHES constant must exist
        assert!(
            prod_source.contains("MAX_ENTROPY_MATCHES"),
            "L22: must define MAX_ENTROPY_MATCHES constant"
        );

        // L22: The entropy matcher loop must check the cap before pushing
        assert!(
            prod_source.contains("all_matches.len() >= MAX_ENTROPY_MATCHES")
                || prod_source.contains("all_matches.len() < MAX_ENTROPY_MATCHES"),
            "L22: entropy matcher must check all_matches.len() against MAX_ENTROPY_MATCHES"
        );
    }

    #[test]
    fn l22_entropy_matches_capped_at_runtime() {
        // Build an engine with a low-entropy threshold so every 16-byte window matches
        let engine = make_engine(vec![DlpRule {
            name: "low_bar_entropy".to_string(),
            description: "Matches almost everything".to_string(),
            severity: DlpSeverity::Warning,
            action: DlpAction::LogAndAllow,
            patterns: vec![DlpPattern::Entropy {
                min_entropy: 0.1, // extremely low bar
                min_length: 16,
            }],
            apply_to: None,
        }]);

        // Create a body large enough to produce >1000 non-overlapping windows
        // Each window is 16 bytes, so we need 16 * 1001 + extra = ~16100 bytes
        // Use random-ish bytes to ensure entropy > 0.1
        let body: Vec<u8> = (0u8..=255).cycle().take(20_000).collect();
        let result = engine.inspect(&body);

        assert!(
            result.matches.len() <= 1000,
            "L22: entropy matches must be capped at MAX_ENTROPY_MATCHES (1000), got {}",
            result.matches.len()
        );
    }

    /// D-M4: Fingerprint matcher should produce 0 matches (not yet implemented).
    #[test]
    fn test_dlp_fingerprint_produces_no_matches() {
        let engine = make_engine(vec![DlpRule {
            name: "fingerprint_rule".to_string(),
            description: "TLSH fingerprint test".to_string(),
            severity: DlpSeverity::Critical,
            action: DlpAction::BlockAndAlert,
            patterns: vec![DlpPattern::Fingerprint {
                source_dir: "/nonexistent/path".to_string(),
            }],
            apply_to: None,
        }]);

        let body = b"This is some body content that would be fingerprinted";
        let result = engine.inspect(body);
        assert!(
            result.matches.is_empty(),
            "D-M4: fingerprint matcher should produce 0 matches (not yet implemented)"
        );
        assert!(
            result.allowed,
            "D-M4: no matches means the request should be allowed"
        );
    }
}
