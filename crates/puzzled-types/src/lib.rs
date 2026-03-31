// SPDX-License-Identifier: Apache-2.0
//! Shared types for the PuzzlePod daemon (`puzzled`) and CLI (`puzzlectl`).

pub mod attestation;
pub mod audit;
pub mod behavioral;
pub mod branch;
pub mod change;
pub mod credential;
pub mod identity;
pub mod policy;
pub mod profile;
pub mod provenance;
pub mod trust;

// Explicit re-exports — makes the public API clear and prevents name collisions.
pub use attestation::{AgentIdentity, ConsistencyProof, GovernanceDecision, InclusionProof};
pub use audit::{AuditRecord, AuditRecordEvent};
pub use behavioral::{BehavioralTrigger, BudgetStatus, BudgetTier};
pub use branch::{BranchId, BranchInfo, BranchState};
pub use change::{FileChange, FileChangeKind};
pub use credential::{
    CredentialBackendType, CredentialConfig, CredentialExposure, CredentialFormat, CredentialMode,
    CredentialProxyConfig, CredentialSpec, DataResidencyConfig, GeoEnforcement, GeoException,
};
pub use identity::{
    ContainmentClaims, DelegationMetadata, GovernanceClaims, GovernanceClaimsMetadata,
    IdentityInjectionMode,
};
pub use policy::{
    is_governance_significant, AuditFilter, CommitResult, Conflict, ConflictKind,
    ConflictResolution, PolicyDecision, Violation, ViolationSeverity,
};
pub use profile::{
    AgentProfile, BehavioralConfig, EnforcementRequirements, FailMode, FilesystemRules,
    NetworkConfig, NetworkMode, ResourceLimits, SeccompMode,
};
pub use provenance::{ProvenanceRecord, ProvenanceType};
pub use trust::{BaselineSeverity, ScoringRule, TrustEvent, TrustLevel, TrustState};

// ---------------------------------------------------------------------------
// Merkle tree crypto utilities (A-M1: deduplicated from attestation.rs + puzzlectl)
// ---------------------------------------------------------------------------

/// Shared Merkle tree cryptographic functions used by both `puzzled` (attestation)
/// and `puzzlectl` (verification). Domain-separated hashing per RFC 6962.
pub mod merkle {
    use sha2::{Digest, Sha256};

    /// Domain separation prefix for leaf nodes (RFC 6962 §2.1).
    const LEAF_PREFIX: u8 = 0x00;
    /// Domain separation prefix for internal nodes (RFC 6962 §2.1).
    const NODE_PREFIX: u8 = 0x01;

    /// Compute domain-separated leaf hash: SHA-256(0x00 || data).
    pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([LEAF_PREFIX]);
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Compute domain-separated internal node hash: SHA-256(0x01 || left || right).
    pub fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([NODE_PREFIX]);
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }

    /// Largest power of 2 strictly less than `n`.
    pub fn largest_power_of_2_less_than(n: u64) -> u64 {
        if n <= 1 {
            return 0;
        }
        1u64 << (63 - (n - 1).leading_zeros())
    }

    /// Encode a byte slice as a lowercase hex string.
    pub fn hex_encode(bytes: &[u8]) -> String {
        const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(HEX_CHARS[(b >> 4) as usize] as char);
            s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
        }
        s
    }

    /// Decode a hex string to bytes.
    ///
    /// Returns an error for odd-length strings, non-ASCII input, or invalid hex digits.
    pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
        // A-M3: Guard against multi-byte UTF-8 input which would cause panics
        // in the byte-offset indexing below (&s[i..i + 2]).
        if !s.is_ascii() {
            return Err("non-ASCII characters in hex string".to_string());
        }
        if !s.len().is_multiple_of(2) {
            return Err("odd-length hex string".to_string());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16)
                    .map_err(|e| format!("invalid hex at position {}: {}", i, e))
            })
            .collect()
    }

    /// Recompute root hash from an inclusion proof (bottom-up traversal).
    ///
    /// Proof elements are consumed bottom-up via `pos` index, matching the
    /// order they were generated (leaf-level sibling first, root-level last).
    pub fn compute_root_from_inclusion(
        leaf_index: u64,
        tree_size: u64,
        leaf_hash: &[u8; 32],
        proof: &[[u8; 32]],
        pos: &mut usize,
    ) -> Option<[u8; 32]> {
        if tree_size <= 1 {
            return Some(*leaf_hash);
        }
        let k = largest_power_of_2_less_than(tree_size);
        if leaf_index < k {
            let left = compute_root_from_inclusion(leaf_index, k, leaf_hash, proof, pos)?;
            let right = *proof.get(*pos)?;
            *pos += 1;
            Some(hash_node(&left, &right))
        } else {
            let right =
                compute_root_from_inclusion(leaf_index - k, tree_size - k, leaf_hash, proof, pos)?;
            let left = *proof.get(*pos)?;
            *pos += 1;
            Some(hash_node(&left, &right))
        }
    }

    /// Verify a Merkle inclusion proof against an expected root hash.
    ///
    /// Returns `Ok(true)` if the proof is valid, `Ok(false)` if the computed root
    /// doesn't match, or `Err` if the proof is malformed.
    pub fn verify_merkle_inclusion(
        leaf_hash: &[u8; 32],
        proof: &super::InclusionProof,
        expected_root: &[u8; 32],
    ) -> Result<bool, String> {
        let proof_hashes: Vec<[u8; 32]> = proof
            .proof_hashes
            .iter()
            .map(|h| {
                let bytes = hex_decode(h)?;
                if bytes.len() != 32 {
                    return Err(format!("proof hash must be 32 bytes, got {}", bytes.len()));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(arr)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut pos = 0;
        let computed = compute_root_from_inclusion(
            proof.leaf_index,
            proof.tree_size,
            leaf_hash,
            &proof_hashes,
            &mut pos,
        )
        .ok_or_else(|| "malformed inclusion proof: insufficient proof hashes".to_string())?;

        // RFC 6962: all proof hashes must be consumed
        if pos != proof_hashes.len() {
            return Err(format!(
                "malformed inclusion proof: {} extra hashes",
                proof_hashes.len() - pos
            ));
        }

        Ok(computed == *expected_root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // -----------------------------------------------------------------------
    // 1. BranchId
    // -----------------------------------------------------------------------

    #[test]
    fn branch_id_new_generates_unique_ids() {
        let a = BranchId::new();
        let b = BranchId::new();
        assert_ne!(a, b, "Two new BranchIds must be distinct");
    }

    #[test]
    fn branch_id_from_string_roundtrip() {
        let raw = "test-branch-42".to_string();
        let id = BranchId::from(raw.clone());
        assert_eq!(id.as_str(), "test-branch-42");
    }

    #[test]
    fn branch_id_display() {
        let id = BranchId::from("display-me".to_string());
        assert_eq!(format!("{id}"), "display-me");
    }

    #[test]
    fn branch_id_validated_accepts_valid() {
        assert!(BranchId::validated("test-branch-42".to_string()).is_ok());
        assert!(BranchId::validated("my_branch_99".to_string()).is_ok());
        assert!(BranchId::validated("abc".to_string()).is_ok());
    }

    #[test]
    fn branch_id_validated_rejects_path_traversal() {
        assert!(BranchId::validated("../../etc".to_string()).is_err());
        assert!(BranchId::validated("foo/bar".to_string()).is_err());
        assert!(BranchId::validated("a..b".to_string()).is_err());
    }

    #[test]
    fn branch_id_validated_rejects_null_and_control() {
        assert!(BranchId::validated("foo\0bar".to_string()).is_err());
        assert!(BranchId::validated("foo\nbar".to_string()).is_err());
        assert!(BranchId::validated("foo\rbar".to_string()).is_err());
        assert!(BranchId::validated("foo\tbar".to_string()).is_err());
    }

    #[test]
    fn branch_id_validated_rejects_empty() {
        assert!(BranchId::validated("".to_string()).is_err());
    }

    #[test]
    fn branch_id_validated_rejects_special_chars() {
        assert!(BranchId::validated("foo bar".to_string()).is_err());
        assert!(BranchId::validated("foo=bar".to_string()).is_err());
        assert!(BranchId::validated("foo;bar".to_string()).is_err());
        assert!(BranchId::validated("foo\"bar".to_string()).is_err());
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "BranchId::from() called with invalid input")]
    fn branch_id_from_panics_on_invalid_debug() {
        let _id = BranchId::from("../../etc/passwd".to_string());
    }

    // H80: Test now expects panic in all builds (impl always panics on invalid input).
    #[test]
    #[should_panic(expected = "BranchId::from() called with invalid input")]
    fn branch_id_from_fallback_on_invalid_release() {
        let _id = BranchId::from("../../etc/passwd".to_string());
    }

    #[test]
    fn branch_id_serde_json_roundtrip() {
        let id = BranchId::from("serde-test".to_string());
        let json = serde_json::to_string(&id).unwrap();
        let back: BranchId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    // -----------------------------------------------------------------------
    // 2. BranchState
    // -----------------------------------------------------------------------

    #[test]
    fn branch_state_display_all_variants() {
        assert_eq!(BranchState::Creating.to_string(), "creating");
        assert_eq!(BranchState::Ready.to_string(), "ready");
        assert_eq!(BranchState::Active.to_string(), "active");
        assert_eq!(BranchState::Frozen.to_string(), "frozen");
        assert_eq!(BranchState::Committing.to_string(), "committing");
        assert_eq!(
            BranchState::GovernanceReview.to_string(),
            "governance_review"
        );
        assert_eq!(BranchState::Committed.to_string(), "committed");
        assert_eq!(BranchState::RolledBack.to_string(), "rolled_back");
        assert_eq!(BranchState::Failed.to_string(), "failed");
        assert_eq!(BranchState::Degraded.to_string(), "degraded");
        assert_eq!(BranchState::Exited.to_string(), "exited");
        assert_eq!(BranchState::Terminated.to_string(), "terminated");
    }

    #[test]
    fn branch_state_partial_eq() {
        assert_eq!(BranchState::Active, BranchState::Active);
        assert_ne!(BranchState::Active, BranchState::Frozen);
    }

    #[test]
    fn branch_state_copy() {
        let a = BranchState::Active;
        let b = a; // Copy
        assert_eq!(a, b);
    }

    #[test]
    fn branch_state_serde_json_roundtrip() {
        for state in [
            BranchState::Creating,
            BranchState::Ready,
            BranchState::Active,
            BranchState::Frozen,
            BranchState::Committing,
            BranchState::GovernanceReview,
            BranchState::Committed,
            BranchState::RolledBack,
            BranchState::Failed,
            BranchState::Degraded,
            BranchState::Exited,
            BranchState::Terminated,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let back: BranchState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, back);
        }
    }

    // -----------------------------------------------------------------------
    // 3. FileChange + FileChangeKind
    // -----------------------------------------------------------------------

    #[test]
    fn file_change_kind_serde_json_roundtrip() {
        for kind in [
            FileChangeKind::Added,
            FileChangeKind::Modified,
            FileChangeKind::Deleted,
            FileChangeKind::MetadataChanged,
            FileChangeKind::Renamed,
            FileChangeKind::Symlink,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: FileChangeKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn file_change_serde_json_roundtrip() {
        let change = FileChange {
            path: PathBuf::from("src/main.rs"),
            kind: FileChangeKind::Modified,
            size: 2048,
            checksum: "abc123def456".to_string(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
            entropy: None,
            has_base64_blocks: None,
        };
        let json = serde_json::to_string(&change).unwrap();
        let back: FileChange = serde_json::from_str(&json).unwrap();
        assert_eq!(back.path, PathBuf::from("src/main.rs"));
        assert_eq!(back.kind, FileChangeKind::Modified);
        assert_eq!(back.size, 2048);
        assert_eq!(back.checksum, "abc123def456");
    }

    #[test]
    fn file_change_deleted_has_zero_size() {
        let change = FileChange {
            path: PathBuf::from("old_file.txt"),
            kind: FileChangeKind::Deleted,
            size: 0,
            checksum: String::new(),
            old_size: None,
            old_mode: None,
            new_mode: None,
            timestamp: None,
            target: None,
            entropy: None,
            has_base64_blocks: None,
        };
        assert_eq!(change.size, 0);
        assert!(change.checksum.is_empty());
    }

    /// G28: BranchId::From<String> must always validate, not just debug_assert.
    #[test]
    fn test_g28_branch_id_from_validates() {
        let source = include_str!("branch.rs");

        // Find the From<String> impl
        let from_impl = source
            .find("fn from(s: String) -> Self")
            .expect("From<String> impl must exist for BranchId");
        let from_block = &source[from_impl..];
        let from_end = from_block.find("\n}").unwrap_or(from_block.len());
        let from_body = &from_block[..from_end];

        // Must call validated() — this is already present
        assert!(
            from_body.contains("validated"),
            "G28: BranchId::from() must call validated()"
        );

        // Must NOT silently accept invalid input in release — should panic or reject
        // The old code had `Self(s)` fallback that silently accepted invalid input.
        // The fix must not contain a bare `Self(s)` fallback.
        assert!(
            !from_body.contains("Self(s)"),
            "G28: BranchId::from() must not silently accept invalid input \
             via bare Self(s) fallback in release builds"
        );
    }

    // -----------------------------------------------------------------------
    // 4. PolicyDecision
    // -----------------------------------------------------------------------

    #[test]
    fn policy_decision_approved_serde_roundtrip() {
        let decision = PolicyDecision::Approved;
        let json = serde_json::to_string(&decision).unwrap();
        let back: PolicyDecision = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, PolicyDecision::Approved));
    }

    #[test]
    fn policy_decision_rejected_serde_roundtrip() {
        let violations = vec![
            Violation {
                rule: "no_credentials".to_string(),
                message: "Found .env file".to_string(),
                severity: ViolationSeverity::Error,
            },
            Violation {
                rule: "size_limit".to_string(),
                message: "Changeset too large".to_string(),
                severity: ViolationSeverity::Warning,
            },
        ];
        let decision = PolicyDecision::Rejected(violations);
        let json = serde_json::to_string(&decision).unwrap();
        let back: PolicyDecision = serde_json::from_str(&json).unwrap();
        match back {
            PolicyDecision::Rejected(v) => {
                assert_eq!(v.len(), 2);
                assert_eq!(v[0].rule, "no_credentials");
                assert_eq!(v[1].severity, ViolationSeverity::Warning);
            }
            _ => panic!("Expected PolicyDecision::Rejected"),
        }
    }

    #[test]
    fn policy_decision_error_serde_roundtrip() {
        let decision = PolicyDecision::Error("OPA engine timeout".to_string());
        let json = serde_json::to_string(&decision).unwrap();
        let back: PolicyDecision = serde_json::from_str(&json).unwrap();
        match back {
            PolicyDecision::Error(msg) => assert_eq!(msg, "OPA engine timeout"),
            _ => panic!("Expected PolicyDecision::Error"),
        }
    }

    // -----------------------------------------------------------------------
    // 5. Violation + ViolationSeverity
    // -----------------------------------------------------------------------

    #[test]
    fn violation_creation_and_serde() {
        let v = Violation {
            rule: "no_persistence".to_string(),
            message: "Attempted to create a cron job".to_string(),
            severity: ViolationSeverity::Critical,
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: Violation = serde_json::from_str(&json).unwrap();
        assert_eq!(back.rule, "no_persistence");
        assert_eq!(back.message, "Attempted to create a cron job");
        assert_eq!(back.severity, ViolationSeverity::Critical);
    }

    #[test]
    fn violation_severity_all_variants_serde() {
        for sev in [
            ViolationSeverity::Warning,
            ViolationSeverity::Error,
            ViolationSeverity::Critical,
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            let back: ViolationSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(sev, back);
        }
    }

    // -----------------------------------------------------------------------
    // 6. CommitResult
    // -----------------------------------------------------------------------

    #[test]
    fn commit_result_serde_json_roundtrip() {
        let result = CommitResult {
            branch_id: BranchId::from("commit-test-branch".to_string()),
            files_committed: 42,
            bytes_committed: 1_048_576,
            policy_result: PolicyDecision::Approved,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: CommitResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.branch_id.as_str(), "commit-test-branch");
        assert_eq!(back.files_committed, 42);
        assert_eq!(back.bytes_committed, 1_048_576);
        assert!(matches!(back.policy_result, PolicyDecision::Approved));
    }

    // -----------------------------------------------------------------------
    // 7. ResourceLimits: Default values
    // -----------------------------------------------------------------------

    #[test]
    fn resource_limits_default_values_are_sensible() {
        let defaults = ResourceLimits::default();
        assert!(defaults.memory_bytes > 0, "memory_bytes must be non-zero");
        assert_eq!(defaults.memory_bytes, 512 * 1024 * 1024); // 512 MiB
        assert!(defaults.cpu_shares > 0, "cpu_shares must be non-zero");
        assert!(defaults.io_weight > 0, "io_weight must be non-zero");
        assert!(defaults.max_pids > 0, "max_pids must be non-zero");
        assert!(
            defaults.storage_quota_mb > 0,
            "storage_quota_mb must be non-zero"
        );
        assert!(defaults.inode_quota > 0, "inode_quota must be non-zero");
    }

    #[test]
    fn resource_limits_serde_roundtrip() {
        let limits = ResourceLimits::default();
        let json = serde_json::to_string(&limits).unwrap();
        let back: ResourceLimits = serde_json::from_str(&json).unwrap();
        assert_eq!(back.memory_bytes, limits.memory_bytes);
        assert_eq!(back.max_pids, limits.max_pids);
    }

    #[test]
    fn resource_limits_validate_defaults_pass() {
        let limits = ResourceLimits::default();
        assert!(limits.validate().is_empty(), "defaults should validate");
    }

    #[test]
    fn resource_limits_validate_cpu_shares_range() {
        let limits = ResourceLimits {
            cpu_shares: 0,
            ..Default::default()
        };
        assert!(!limits.validate().is_empty());
        let limits = ResourceLimits {
            cpu_shares: 10001,
            ..Default::default()
        };
        assert!(!limits.validate().is_empty());
        let limits = ResourceLimits {
            cpu_shares: 10000,
            ..Default::default()
        };
        assert!(limits.validate().is_empty());
    }

    #[test]
    fn resource_limits_validate_io_weight_range() {
        let limits = ResourceLimits {
            io_weight: 0,
            ..Default::default()
        };
        assert!(!limits.validate().is_empty());
        let limits = ResourceLimits {
            io_weight: 10001,
            ..Default::default()
        };
        assert!(!limits.validate().is_empty());
    }

    #[test]
    fn resource_limits_validate_max_pids_range() {
        let limits = ResourceLimits {
            max_pids: 0,
            ..Default::default()
        };
        assert!(!limits.validate().is_empty());
        let limits = ResourceLimits {
            max_pids: 4_194_305,
            ..Default::default()
        };
        assert!(!limits.validate().is_empty());
        let limits = ResourceLimits {
            max_pids: 4_194_304,
            ..Default::default()
        };
        assert!(limits.validate().is_empty());
    }

    #[test]
    fn resource_limits_validate_inode_quota() {
        let limits = ResourceLimits {
            inode_quota: 0,
            ..Default::default()
        };
        assert!(!limits.validate().is_empty());
    }

    // -----------------------------------------------------------------------
    // 8. AgentProfile: full YAML roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn agent_profile_serde_yaml_roundtrip() {
        let profile = AgentProfile {
            name: "test-agent".to_string(),
            description: "A test agent profile".to_string(),
            filesystem: FilesystemRules {
                read_allowlist: vec![PathBuf::from("/home/agent"), PathBuf::from("/usr/lib")],
                write_allowlist: vec![PathBuf::from("/home/agent/workspace")],
                denylist: vec![PathBuf::from("/etc/shadow"), PathBuf::from("/root")],
                read_denylist: vec![],
                write_denylist: vec![],
            },
            exec_allowlist: vec!["/usr/bin/python3".to_string(), "/usr/bin/git".to_string()],
            exec_denylist: vec![],
            resource_limits: ResourceLimits::default(),
            network: NetworkConfig {
                mode: NetworkMode::Gated,
                allowed_domains: vec!["api.example.com".to_string()],
                data_residency: None,
                dlp_rules_path: None,
            },
            behavioral: BehavioralConfig::default(),
            fail_mode: FailMode::FailClosed,
            capabilities: vec![],
            enforcement: Default::default(),
            seccomp_mode: SeccompMode::default(),
            allow_symlinks: false,
            allow_exec_overlay: false,
            credentials: None,
            extends: None,
        };

        let yaml = serde_yaml::to_string(&profile).unwrap();
        let back: AgentProfile = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(back.name, "test-agent");
        assert_eq!(back.description, "A test agent profile");
        assert_eq!(back.filesystem.read_allowlist.len(), 2);
        assert_eq!(back.filesystem.write_allowlist.len(), 1);
        assert_eq!(back.filesystem.denylist.len(), 2);
        assert_eq!(back.exec_allowlist.len(), 2);
        assert_eq!(back.resource_limits.memory_bytes, 512 * 1024 * 1024);
        assert_eq!(back.network.mode, NetworkMode::Gated);
        assert_eq!(back.network.allowed_domains, vec!["api.example.com"]);
        assert_eq!(back.behavioral.max_deletions, 50);
        assert_eq!(back.fail_mode, FailMode::FailClosed);
    }

    #[test]
    fn agent_profile_serde_json_roundtrip() {
        let profile = AgentProfile {
            name: "json-test".to_string(),
            description: "JSON roundtrip test".to_string(),
            filesystem: FilesystemRules {
                read_allowlist: vec![PathBuf::from("/tmp")],
                write_allowlist: vec![PathBuf::from("/tmp/out")],
                denylist: vec![],
                read_denylist: vec![],
                write_denylist: vec![],
            },
            exec_allowlist: vec!["/bin/echo".to_string()],
            exec_denylist: vec![],
            resource_limits: ResourceLimits {
                memory_bytes: 256 * 1024 * 1024,
                cpu_shares: 50,
                io_weight: 50,
                max_pids: 16,
                storage_quota_mb: 256,
                inode_quota: 5000,
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
            },
            network: NetworkConfig {
                mode: NetworkMode::Blocked,
                allowed_domains: vec![],
                data_residency: None,
                dlp_rules_path: None,
            },
            behavioral: BehavioralConfig {
                max_deletions: 10,
                max_reads_per_minute: 500,
                credential_access_alert: false,
                phantom_token_prefixes: Vec::new(),
            },
            fail_mode: FailMode::FailSafeState,
            capabilities: vec!["CAP_NET_RAW".to_string()],
            enforcement: Default::default(),
            seccomp_mode: SeccompMode::Strict,
            allow_symlinks: false,
            allow_exec_overlay: false,
            credentials: None,
            extends: None,
        };

        let json = serde_json::to_string_pretty(&profile).unwrap();
        let back: AgentProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "json-test");
        assert_eq!(back.fail_mode, FailMode::FailSafeState);
        assert_eq!(back.resource_limits.cpu_shares, 50);
    }

    // -----------------------------------------------------------------------
    // 9. NetworkMode: all variants
    // -----------------------------------------------------------------------

    #[test]
    fn network_mode_all_variants() {
        let modes = [
            NetworkMode::Blocked,
            NetworkMode::Gated,
            NetworkMode::Monitored,
            NetworkMode::Unrestricted,
        ];
        for mode in modes {
            let json = serde_json::to_string(&mode).unwrap();
            let back: NetworkMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, back);
        }
    }

    #[test]
    fn network_mode_partial_eq() {
        assert_eq!(NetworkMode::Blocked, NetworkMode::Blocked);
        assert_ne!(NetworkMode::Blocked, NetworkMode::Gated);
        assert_ne!(NetworkMode::Monitored, NetworkMode::Unrestricted);
    }

    // -----------------------------------------------------------------------
    // 10. BehavioralConfig: Default values
    // -----------------------------------------------------------------------

    #[test]
    fn behavioral_config_default_values() {
        let config = BehavioralConfig::default();
        assert_eq!(config.max_deletions, 50);
        assert_eq!(config.max_reads_per_minute, 1000);
        assert!(config.credential_access_alert);
    }

    #[test]
    fn behavioral_config_serde_roundtrip() {
        let config = BehavioralConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: BehavioralConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_deletions, config.max_deletions);
        assert_eq!(back.max_reads_per_minute, config.max_reads_per_minute);
        assert_eq!(back.credential_access_alert, config.credential_access_alert);
    }

    // -----------------------------------------------------------------------
    // 11. FailMode: Default is FailClosed
    // -----------------------------------------------------------------------

    #[test]
    fn fail_mode_default_is_fail_closed() {
        assert_eq!(FailMode::default(), FailMode::FailClosed);
    }

    #[test]
    fn fail_mode_all_variants_serde() {
        for mode in [
            FailMode::FailClosed,
            FailMode::FailSilent,
            FailMode::FailOperational,
            FailMode::FailSafeState,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: FailMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, back);
        }
    }

    // -----------------------------------------------------------------------
    // 12. SeccompMode: Default is Permissive
    // -----------------------------------------------------------------------

    #[test]
    fn seccomp_mode_default_is_permissive() {
        assert_eq!(SeccompMode::default(), SeccompMode::Permissive);
    }

    #[test]
    fn seccomp_mode_display() {
        assert_eq!(SeccompMode::Permissive.to_string(), "permissive");
        assert_eq!(SeccompMode::Strict.to_string(), "strict");
    }

    #[test]
    fn seccomp_mode_all_variants_serde() {
        for mode in [SeccompMode::Permissive, SeccompMode::Strict] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: SeccompMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, back);
        }
    }

    #[test]
    fn seccomp_mode_partial_eq() {
        assert_eq!(SeccompMode::Permissive, SeccompMode::Permissive);
        assert_eq!(SeccompMode::Strict, SeccompMode::Strict);
        assert_ne!(SeccompMode::Permissive, SeccompMode::Strict);
    }

    // -----------------------------------------------------------------------
    // 13. BudgetTier: Default is Restricted
    // -----------------------------------------------------------------------

    #[test]
    fn budget_tier_default_is_restricted() {
        assert_eq!(BudgetTier::default(), BudgetTier::Restricted);
    }

    #[test]
    fn budget_tier_all_variants_serde() {
        for tier in [
            BudgetTier::Restricted,
            BudgetTier::Standard,
            BudgetTier::Extended,
        ] {
            let json = serde_json::to_string(&tier).unwrap();
            let back: BudgetTier = serde_json::from_str(&json).unwrap();
            assert_eq!(tier, back);
        }
    }

    // -----------------------------------------------------------------------
    // 13. ConflictKind: PartialEq
    // -----------------------------------------------------------------------

    #[test]
    fn conflict_kind_partial_eq() {
        assert_eq!(ConflictKind::BothModified, ConflictKind::BothModified);
        assert_eq!(
            ConflictKind::ModifiedAndDeleted,
            ConflictKind::ModifiedAndDeleted
        );
        assert_eq!(ConflictKind::BothCreated, ConflictKind::BothCreated);
        assert_ne!(ConflictKind::BothModified, ConflictKind::BothCreated);
        assert_ne!(ConflictKind::ModifiedAndDeleted, ConflictKind::BothModified);
    }

    #[test]
    fn conflict_serde_roundtrip() {
        let conflict = Conflict {
            path: PathBuf::from("shared/config.yaml"),
            conflicting_branches: vec![
                BranchId::from("branch-a".to_string()),
                BranchId::from("branch-b".to_string()),
            ],
            kind: ConflictKind::BothModified,
        };
        let json = serde_json::to_string(&conflict).unwrap();
        let back: Conflict = serde_json::from_str(&json).unwrap();
        assert_eq!(back.path, PathBuf::from("shared/config.yaml"));
        assert_eq!(back.conflicting_branches.len(), 2);
        assert_eq!(back.kind, ConflictKind::BothModified);
    }

    #[test]
    fn conflict_resolution_default_is_reject() {
        assert_eq!(ConflictResolution::default(), ConflictResolution::Reject);
    }

    // -----------------------------------------------------------------------
    // 14. AuditFilter: optional fields default to None
    // -----------------------------------------------------------------------

    #[test]
    fn audit_filter_optional_fields_default_to_none() {
        // Deserialize from an empty JSON object — all fields should be None.
        let filter: AuditFilter = serde_json::from_str(
            r#"{"branch_id": null, "event_type": null, "since": null, "limit": null}"#,
        )
        .unwrap();
        assert!(filter.branch_id.is_none());
        assert!(filter.event_type.is_none());
        assert!(filter.since.is_none());
        assert!(filter.limit.is_none());
    }

    #[test]
    fn audit_filter_with_values_serde_roundtrip() {
        let filter = AuditFilter {
            branch_id: Some("branch-123".to_string()),
            event_type: Some("commit".to_string()),
            since: Some("2026-01-01T00:00:00Z".to_string()),
            limit: Some(100),
        };
        let json = serde_json::to_string(&filter).unwrap();
        let back: AuditFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(back.branch_id.as_deref(), Some("branch-123"));
        assert_eq!(back.event_type.as_deref(), Some("commit"));
        assert_eq!(back.since.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(back.limit, Some(100));
    }

    // -----------------------------------------------------------------------
    // Extra: BehavioralTrigger serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn behavioral_trigger_mass_deletion_serde() {
        let trigger = BehavioralTrigger::MassDeletion {
            count: 100,
            threshold: 50,
        };
        let json = serde_json::to_string(&trigger).unwrap();
        let back: BehavioralTrigger = serde_json::from_str(&json).unwrap();
        match back {
            BehavioralTrigger::MassDeletion { count, threshold } => {
                assert_eq!(count, 100);
                assert_eq!(threshold, 50);
            }
            _ => panic!("Expected MassDeletion"),
        }
    }

    #[test]
    fn behavioral_trigger_excessive_reads_serde() {
        let trigger = BehavioralTrigger::ExcessiveReads {
            rate: 5000,
            threshold: 1000,
        };
        let json = serde_json::to_string(&trigger).unwrap();
        let back: BehavioralTrigger = serde_json::from_str(&json).unwrap();
        match back {
            BehavioralTrigger::ExcessiveReads { rate, threshold } => {
                assert_eq!(rate, 5000);
                assert_eq!(threshold, 1000);
            }
            _ => panic!("Expected ExcessiveReads"),
        }
    }

    #[test]
    fn behavioral_trigger_queue_overflow_serde() {
        let trigger = BehavioralTrigger::QueueOverflow;
        let json = serde_json::to_string(&trigger).unwrap();
        let back: BehavioralTrigger = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, BehavioralTrigger::QueueOverflow));
    }

    #[test]
    fn behavioral_trigger_credential_access_serde() {
        let trigger = BehavioralTrigger::CredentialAccess {
            path: "/etc/shadow".to_string(),
        };
        let json = serde_json::to_string(&trigger).unwrap();
        let back: BehavioralTrigger = serde_json::from_str(&json).unwrap();
        match back {
            BehavioralTrigger::CredentialAccess { path } => {
                assert_eq!(path, "/etc/shadow");
            }
            _ => panic!("Expected CredentialAccess"),
        }
    }

    // -----------------------------------------------------------------------
    // Extra: BranchInfo serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn branch_info_serde_json_roundtrip() {
        let info = BranchInfo {
            id: BranchId::from("info-test".to_string()),
            profile: "standard".to_string(),
            base_path: PathBuf::from("/var/lib/puzzled/base"),
            upper_dir: PathBuf::from("/var/lib/puzzled/branches/info-test/upper"),
            work_dir: PathBuf::from("/var/lib/puzzled/branches/info-test/work"),
            state: BranchState::Active,
            created_at: chrono::Utc::now(),
            expires_at: None,
            pid: Some(12345),
            uid: 1000,
            selinux_context: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: BranchInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id.as_str(), "info-test");
        assert_eq!(back.profile, "standard");
        assert_eq!(back.state, BranchState::Active);
        assert_eq!(back.pid, Some(12345));
        assert_eq!(back.uid, 1000);
    }

    // -----------------------------------------------------------------------
    // Extra: BudgetStatus serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn budget_status_serde_roundtrip() {
        let status = BudgetStatus {
            branch_id: BranchId::from("budget-branch".to_string()),
            tier: BudgetTier::Standard,
            clean_commits: 10,
            violations: 1,
        };
        let json = serde_json::to_string(&status).unwrap();
        let back: BudgetStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back.branch_id.as_str(), "budget-branch");
        assert_eq!(back.tier, BudgetTier::Standard);
        assert_eq!(back.clean_commits, 10);
        assert_eq!(back.violations, 1);
    }

    // -----------------------------------------------------------------------
    // Governance significance
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_governance_significant() {
        // Governance-significant events
        assert!(is_governance_significant("branch_created"));
        assert!(is_governance_significant("branch_committed"));
        assert!(is_governance_significant("branch_rolled_back"));
        assert!(is_governance_significant("policy_violation"));
        assert!(is_governance_significant("commit_rejected"));
        assert!(is_governance_significant("sandbox_escape"));
        assert!(is_governance_significant("behavioral_trigger"));
        assert!(is_governance_significant("agent_killed"));

        // High-frequency events are NOT governance-significant
        assert!(!is_governance_significant("exec_gated"));
        assert!(!is_governance_significant("connect_gated"));
        assert!(!is_governance_significant("branch_frozen"));
        assert!(!is_governance_significant("profile_loaded"));
        assert!(!is_governance_significant("policy_reloaded"));
        assert!(!is_governance_significant(""));
        assert!(!is_governance_significant("unknown_event"));
    }

    // -----------------------------------------------------------------------
    // F2: Property-based tests (proptest)
    // -----------------------------------------------------------------------

    mod proptest_tests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// F2: BranchId::validated never panics on arbitrary input.
            /// It returns Ok or Err, but never crashes.
            #[test]
            fn branch_id_validated_never_panics(s in "\\PC{0,512}") {
                let _ = BranchId::validated(s);
            }

            /// F2: BranchId::validated accepts all UUID-format strings.
            #[test]
            fn branch_id_validated_accepts_uuid(
                a in "[0-9a-f]{8}",
                b in "[0-9a-f]{4}",
                c in "[0-9a-f]{4}",
                d in "[0-9a-f]{4}",
                e in "[0-9a-f]{12}",
            ) {
                let uuid_str = format!("{a}-{b}-{c}-{d}-{e}");
                prop_assert!(BranchId::validated(uuid_str).is_ok());
            }

            /// F2: BranchId::validated rejects strings containing path traversal.
            #[test]
            fn branch_id_rejects_path_traversal(
                prefix in "[a-z]{0,10}",
                suffix in "[a-z]{0,10}",
            ) {
                let with_dotdot = format!("{prefix}../{suffix}");
                prop_assert!(BranchId::validated(with_dotdot).is_err());
            }

            /// F2: BranchId::validated rejects strings with null bytes.
            #[test]
            fn branch_id_rejects_null_bytes(
                prefix in "[a-z]{1,10}",
                suffix in "[a-z]{1,10}",
            ) {
                let with_null = format!("{prefix}\0{suffix}");
                prop_assert!(BranchId::validated(with_null).is_err());
            }

            /// F2: FileChange serialization roundtrips correctly.
            #[test]
            fn file_change_roundtrip(
                path in "[a-z/]{1,50}",
                size in 0u64..1_000_000,
                checksum in "[0-9a-f]{64}",
            ) {
                let change = FileChange {
                    path: PathBuf::from(&path),
                    kind: FileChangeKind::Added,
                    size,
                    checksum: checksum.clone(),
                    old_size: None,
                    old_mode: None,
                    new_mode: None,
                    timestamp: None,
                    target: None,
                    entropy: None,
                    has_base64_blocks: None,
                };
                let json = serde_json::to_string(&change).unwrap();
                let back: FileChange = serde_json::from_str(&json).unwrap();
                prop_assert_eq!(back.path, PathBuf::from(&path));
                prop_assert_eq!(back.size, size);
                prop_assert_eq!(back.checksum, checksum);
            }
        }
    }

    // -----------------------------------------------------------------------
    // §4.1 TrustLevel
    // -----------------------------------------------------------------------

    #[test]
    fn trust_level_from_score_boundaries() {
        assert_eq!(TrustLevel::from_score(0), TrustLevel::Untrusted);
        assert_eq!(TrustLevel::from_score(19), TrustLevel::Untrusted);
        assert_eq!(TrustLevel::from_score(20), TrustLevel::Restricted);
        assert_eq!(TrustLevel::from_score(39), TrustLevel::Restricted);
        assert_eq!(TrustLevel::from_score(40), TrustLevel::Standard);
        assert_eq!(TrustLevel::from_score(59), TrustLevel::Standard);
        assert_eq!(TrustLevel::from_score(60), TrustLevel::Elevated);
        assert_eq!(TrustLevel::from_score(79), TrustLevel::Elevated);
        assert_eq!(TrustLevel::from_score(80), TrustLevel::Trusted);
        assert_eq!(TrustLevel::from_score(100), TrustLevel::Trusted);
    }

    #[test]
    fn trust_level_as_str_all_variants() {
        assert_eq!(TrustLevel::Untrusted.as_str(), "untrusted");
        assert_eq!(TrustLevel::Restricted.as_str(), "restricted");
        assert_eq!(TrustLevel::Standard.as_str(), "standard");
        assert_eq!(TrustLevel::Elevated.as_str(), "elevated");
        assert_eq!(TrustLevel::Trusted.as_str(), "trusted");
    }

    #[test]
    fn trust_level_display() {
        assert_eq!(format!("{}", TrustLevel::Untrusted), "untrusted");
        assert_eq!(format!("{}", TrustLevel::Restricted), "restricted");
        assert_eq!(format!("{}", TrustLevel::Standard), "standard");
        assert_eq!(format!("{}", TrustLevel::Elevated), "elevated");
        assert_eq!(format!("{}", TrustLevel::Trusted), "trusted");
    }

    #[test]
    fn trust_level_serde_roundtrip() {
        for level in [
            TrustLevel::Untrusted,
            TrustLevel::Restricted,
            TrustLevel::Standard,
            TrustLevel::Elevated,
            TrustLevel::Trusted,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let back: TrustLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, back);
        }
    }

    // -----------------------------------------------------------------------
    // §4.1 TrustState
    // -----------------------------------------------------------------------

    #[test]
    fn trust_state_new_defaults() {
        let state = TrustState::new(1000, 50);
        assert_eq!(state.uid, 1000);
        assert_eq!(state.score, 50);
        assert_eq!(state.level, TrustLevel::Standard);
        assert_eq!(state.clean_commits, 0);
        assert_eq!(state.violations, 0);
        assert!(!state.override_active);
        assert!(state.override_expires.is_none());
        assert!(state.override_level.is_none());
    }

    #[test]
    fn trust_state_new_clamps_at_100() {
        let state = TrustState::new(1000, 200);
        assert_eq!(state.score, 100);
        assert_eq!(state.level, TrustLevel::Trusted);
    }

    #[test]
    fn trust_state_apply_delta_positive() {
        let mut state = TrustState::new(1000, 50);
        state.apply_delta(10);
        assert_eq!(state.score, 60);
        assert_eq!(state.level, TrustLevel::Elevated);
    }

    #[test]
    fn trust_state_apply_delta_negative() {
        let mut state = TrustState::new(1000, 50);
        state.apply_delta(-30);
        assert_eq!(state.score, 20);
        assert_eq!(state.level, TrustLevel::Restricted);
    }

    #[test]
    fn trust_state_apply_delta_clamps_at_zero() {
        let mut state = TrustState::new(1000, 10);
        state.apply_delta(-100);
        assert_eq!(state.score, 0);
        assert_eq!(state.level, TrustLevel::Untrusted);
    }

    #[test]
    fn trust_state_apply_delta_clamps_at_100() {
        let mut state = TrustState::new(1000, 90);
        state.apply_delta(50);
        assert_eq!(state.score, 100);
        assert_eq!(state.level, TrustLevel::Trusted);
    }

    /// S48: Ensure apply_delta uses saturating arithmetic to prevent wrapping
    /// on extreme delta values.
    #[test]
    fn test_s48_trust_score_saturating() {
        let source = include_str!("trust.rs");
        // Find the apply_delta method
        let fn_start = source
            .find("pub fn apply_delta")
            .expect("apply_delta function must exist in trust.rs");
        let fn_block = &source[fn_start..];
        let fn_end = fn_block[1..]
            .find("\n    pub fn ")
            .or_else(|| fn_block[1..].find("\n}"))
            .map(|p| p + 1)
            .unwrap_or(fn_block.len());
        let fn_body = &fn_block[..fn_end];

        assert!(
            fn_body.contains("saturating_add"),
            "S48: apply_delta must use saturating_add to prevent wrapping \
             on extreme delta values. Found:\n{}",
            fn_body
        );
    }

    #[test]
    fn trust_state_effective_level_no_override() {
        let state = TrustState::new(1000, 50);
        assert_eq!(state.effective_level(), TrustLevel::Standard);
    }

    #[test]
    fn trust_state_effective_level_with_active_override() {
        let mut state = TrustState::new(1000, 50);
        state.override_active = true;
        // Set expiry far in the future
        let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        state.override_expires = Some(future);
        state.override_level = Some(TrustLevel::Trusted);
        assert_eq!(state.effective_level(), TrustLevel::Trusted);
    }

    #[test]
    fn trust_state_effective_level_expired_override() {
        let mut state = TrustState::new(1000, 50);
        state.override_active = true;
        // Set expiry in the past
        let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        state.override_expires = Some(past);
        state.override_level = Some(TrustLevel::Trusted);
        // Expired override should fall back to normal level
        assert_eq!(state.effective_level(), TrustLevel::Standard);
    }

    #[test]
    fn trust_state_clear_expired_override() {
        let mut state = TrustState::new(1000, 50);
        state.override_active = true;
        state.override_level = Some(TrustLevel::Trusted);
        let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        state.override_expires = Some(past);

        // Should clear and return true.
        assert!(state.clear_expired_override());
        assert!(!state.override_active);
        assert!(state.override_level.is_none());
        assert!(state.override_expires.is_none());

        // Second call is a no-op.
        assert!(!state.clear_expired_override());
    }

    #[test]
    fn trust_state_serde_roundtrip() {
        let state = TrustState::new(1000, 75);
        let json = serde_json::to_string(&state).unwrap();
        let back: TrustState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.uid, 1000);
        assert_eq!(back.score, 75);
        assert_eq!(back.level, TrustLevel::Elevated);
        assert_eq!(back.clean_commits, 0);
        assert_eq!(back.violations, 0);
        assert!(!back.override_active);
    }

    // -----------------------------------------------------------------------
    // §4.3 ProvenanceRecord + ProvenanceType serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn provenance_record_request_serde_roundtrip() {
        let record = ProvenanceRecord {
            id: "prov-001".to_string(),
            record_type: ProvenanceType::Request {
                request_id: "req-1".to_string(),
                user_uid: 1000,
                prompt_hash: "abc123".to_string(),
            },
            branch_id: "branch-42".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: ProvenanceRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "prov-001");
        assert_eq!(back.branch_id, "branch-42");
        match back.record_type {
            ProvenanceType::Request {
                request_id,
                user_uid,
                prompt_hash,
            } => {
                assert_eq!(request_id, "req-1");
                assert_eq!(user_uid, 1000);
                assert_eq!(prompt_hash, "abc123");
            }
            _ => panic!("Expected ProvenanceType::Request"),
        }
    }

    #[test]
    fn provenance_type_governance_serde_roundtrip() {
        let ptype = ProvenanceType::Governance {
            decision_id: "dec-1".to_string(),
            change_ids: vec!["c1".to_string(), "c2".to_string()],
            policy_version: "1.0.0".to_string(),
            result: "approved".to_string(),
            violations: vec![],
            manifest_hash: Some("deadbeef".to_string()),
        };
        let json = serde_json::to_string(&ptype).unwrap();
        let back: ProvenanceType = serde_json::from_str(&json).unwrap();
        match back {
            ProvenanceType::Governance {
                decision_id,
                change_ids,
                policy_version,
                result,
                violations,
                manifest_hash,
            } => {
                assert_eq!(decision_id, "dec-1");
                assert_eq!(change_ids.len(), 2);
                assert_eq!(policy_version, "1.0.0");
                assert_eq!(result, "approved");
                assert!(violations.is_empty());
                assert_eq!(manifest_hash, Some("deadbeef".to_string()));
            }
            _ => panic!("Expected ProvenanceType::Governance"),
        }
    }

    // -----------------------------------------------------------------------
    // §4.5 GovernanceClaims serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn governance_claims_serde_roundtrip() {
        let claims = GovernanceClaims {
            sub: "spiffe://example.com/agent/branch-1".to_string(),
            iss: "puzzled".to_string(),
            aud: vec!["api.example.com".to_string()],
            iat: 1700000000,
            exp: 1700003600,
            branch_id: "branch-1".to_string(),
            agent_profile: "standard".to_string(),
            trust_level: "elevated".to_string(),
            trust_score: 65,
            governance: GovernanceClaimsMetadata {
                enforcement_layers: vec!["landlock".to_string(), "seccomp".to_string()],
                policy_version: "1.2.3".to_string(),
                attestation_chain_hash: Some("cafe0000".to_string()),
                attestation_chain_length: 42,
            },
            containment: Some(ContainmentClaims {
                filesystem_scope: "/workspace".to_string(),
                network_mode: "gated".to_string(),
                allowed_domains: vec!["api.example.com".to_string()],
                exec_allowlist_count: 5,
            }),
            delegation: None,
        };
        let json = serde_json::to_string(&claims).unwrap();
        let back: GovernanceClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(back.sub, claims.sub);
        assert_eq!(back.iss, "puzzled");
        assert_eq!(back.branch_id, "branch-1");
        assert_eq!(back.trust_score, 65);
        assert_eq!(back.governance.enforcement_layers.len(), 2);
        assert_eq!(back.governance.attestation_chain_length, 42);
        let c = back.containment.unwrap();
        assert_eq!(c.filesystem_scope, "/workspace");
        assert_eq!(c.exec_allowlist_count, 5);
    }

    #[test]
    fn governance_claims_without_containment_serde_roundtrip() {
        let claims = GovernanceClaims {
            sub: "spiffe://example.com/agent/branch-2".to_string(),
            iss: "puzzled".to_string(),
            aud: vec![],
            iat: 1700000000,
            exp: 1700003600,
            branch_id: "branch-2".to_string(),
            agent_profile: "restricted".to_string(),
            trust_level: "untrusted".to_string(),
            trust_score: 10,
            governance: GovernanceClaimsMetadata {
                enforcement_layers: vec![],
                policy_version: "0.1.0".to_string(),
                attestation_chain_hash: None,
                attestation_chain_length: 0,
            },
            containment: None,
            delegation: None,
        };
        let json = serde_json::to_string(&claims).unwrap();
        let back: GovernanceClaims = serde_json::from_str(&json).unwrap();
        assert!(back.containment.is_none());
        assert_eq!(back.trust_score, 10);
    }

    /// F26: Verify that apply_delta has a debug_assert protecting against
    /// trust scores exceeding the expected 0-100 range before the i32 cast.
    #[test]
    fn test_f26_trust_score_has_debug_assert() {
        let source = include_str!("trust.rs");

        let mut found = false;
        let lines: Vec<&str> = source.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.contains("pub fn apply_delta") {
                // Check the next ~5 lines for debug_assert!
                let body = lines[i..std::cmp::min(i + 8, lines.len())].join("\n");
                if body.contains("debug_assert!") {
                    found = true;
                }
            }
        }

        assert!(
            found,
            "F26: apply_delta must contain a debug_assert! to guard against \
             trust score exceeding expected range before the i32 cast"
        );
    }

    // -----------------------------------------------------------------------
    // H89: ResourceLimits validate() catches zero memory_bytes and storage_quota_mb
    // -----------------------------------------------------------------------

    #[test]
    fn h89_resource_limits_validate_zero_memory_bytes() {
        let limits = ResourceLimits {
            memory_bytes: 0,
            ..Default::default()
        };
        let errors = limits.validate();
        assert!(
            errors.iter().any(|e| e.contains("memory_bytes")),
            "H89: validate() must catch memory_bytes: 0, got errors: {:?}",
            errors
        );
    }

    #[test]
    fn h89_resource_limits_validate_zero_storage_quota_mb() {
        let limits = ResourceLimits {
            storage_quota_mb: 0,
            ..Default::default()
        };
        let errors = limits.validate();
        assert!(
            errors.iter().any(|e| e.contains("storage_quota_mb")),
            "H89: validate() must catch storage_quota_mb: 0, got errors: {:?}",
            errors
        );
    }

    #[test]
    fn h89_resource_limits_default_passes_validate() {
        let limits = ResourceLimits::default();
        let errors = limits.validate();
        assert!(
            errors.is_empty(),
            "H89: Default ResourceLimits must pass validation, got: {:?}",
            errors
        );
    }

    // -----------------------------------------------------------------------
    // H97: ResourceLimits::validate() doc comment documents caller obligation
    // -----------------------------------------------------------------------

    #[test]
    fn h97_validate_doc_comment_documents_caller_obligation() {
        let source = include_str!("profile.rs");
        assert!(
            source.contains("Callers MUST call `validate()` after deserialization"),
            "H97: ResourceLimits::validate() must document that callers MUST call it after deserialization"
        );
    }

    // J69: Upper bound validation for memory_bytes and storage_quota_mb
    #[test]
    fn j69_resource_limits_validate_excessive_memory_bytes() {
        let limits = ResourceLimits {
            memory_bytes: ResourceLimits::MAX_MEMORY_BYTES + 1,
            ..Default::default()
        };
        let errors = limits.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("J69") && e.contains("memory_bytes")),
            "J69: validate() must catch memory_bytes exceeding 64 TiB, got errors: {:?}",
            errors
        );
    }

    #[test]
    fn j69_resource_limits_validate_excessive_storage_quota_mb() {
        let limits = ResourceLimits {
            storage_quota_mb: ResourceLimits::MAX_STORAGE_QUOTA_MB + 1,
            ..Default::default()
        };
        let errors = limits.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("J69") && e.contains("storage_quota_mb")),
            "J69: validate() must catch storage_quota_mb exceeding 1 PiB, got errors: {:?}",
            errors
        );
    }

    #[test]
    fn j69_resource_limits_at_max_passes() {
        let limits = ResourceLimits {
            memory_bytes: ResourceLimits::MAX_MEMORY_BYTES,
            storage_quota_mb: ResourceLimits::MAX_STORAGE_QUOTA_MB,
            ..Default::default()
        };
        let errors = limits.validate();
        assert!(
            !errors.iter().any(|e| e.contains("J69")),
            "J69: values at exactly the max should pass, got errors: {:?}",
            errors
        );
    }
}
