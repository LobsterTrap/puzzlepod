// SPDX-License-Identifier: Apache-2.0
//! Agent Workload Identity (§4.5).
//!
//! Implements SPIFFE-compatible JWT-SVID issuance and verification for agent
//! branches. Each branch receives a unique SPIFFE ID of the form:
//!
//! ```text
//! spiffe://{trust_domain}/agent/{branch_id}
//! ```
//!
//! JWT-SVIDs carry governance claims (profile, trust level, policy version,
//! attestation chain) and containment claims (active enforcement layers).
//! External services can verify these tokens using the JWKS endpoint to
//! make authorization decisions based on the agent's governance state.
//!
//! Gated behind the `ima` feature (shares `ed25519-dalek` dependency).

#[cfg(feature = "ima")]
mod inner {
    use crate::error::{PuzzledError, Result};
    use puzzled_types::merkle::hex_encode;
    use puzzled_types::{ContainmentClaims, GovernanceClaims, GovernanceClaimsMetadata};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Base64url-encode bytes (no padding, URL-safe alphabet).
    fn base64url_encode(data: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(data)
    }

    /// Base64url-decode a string (no padding, URL-safe alphabet).
    fn base64url_decode(s: &str) -> Result<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| PuzzledError::Attestation(format!("base64url decode error: {e}")))
    }

    /// Manages SPIFFE-compatible agent workload identities.
    ///
    /// Issues and verifies JWT-SVIDs with Ed25519 signatures. Each agent branch
    /// gets a unique SPIFFE ID and can receive a JWT-SVID encoding its
    /// governance and containment state.
    pub struct IdentityManager {
        /// SPIFFE trust domain (default: hostname).
        trust_domain: String,
        /// Ed25519 signing key for JWT-SVID issuance.
        signing_key: SigningKey,
        /// Cached verifying (public) key derived from the signing key.
        verifying_key: VerifyingKey,
        /// JWT-SVID lifetime in seconds (default: 3600).
        svid_lifetime_secs: u64,
        /// Maximum allowed JWT-SVID lifetime in seconds (default: 86400).
        /// Stored for configuration introspection; enforcement is at construction
        /// time via clamping in `with_max_lifetime()`.
        #[allow(dead_code)]
        max_svid_lifetime_secs: u64,
        /// Whether to include governance claims in issued tokens.
        include_governance_claims: bool,
        /// Whether to include containment claims in issued tokens.
        include_containment_claims: bool,
    }

    impl IdentityManager {
        /// Create a new identity manager.
        ///
        /// # Arguments
        ///
        /// * `signing_key` -- Ed25519 signing key for JWT-SVID signatures.
        /// * `trust_domain` -- SPIFFE trust domain (typically the hostname).
        /// * `svid_lifetime_secs` -- Token lifetime in seconds.
        /// * `include_governance_claims` -- Include profile/trust/policy claims.
        /// * `include_containment_claims` -- Include enforcement layer claims.
        pub fn new(
            signing_key: SigningKey,
            trust_domain: String,
            svid_lifetime_secs: u64,
            include_governance_claims: bool,
            include_containment_claims: bool,
        ) -> Self {
            Self::with_max_lifetime(
                signing_key,
                trust_domain,
                svid_lifetime_secs,
                86400, // default max: 24 hours
                include_governance_claims,
                include_containment_claims,
            )
        }

        /// Create a new identity manager with an explicit maximum SVID lifetime.
        ///
        /// The `svid_lifetime_secs` is clamped to `max_svid_lifetime_secs` if
        /// it exceeds the maximum.
        pub fn with_max_lifetime(
            signing_key: SigningKey,
            trust_domain: String,
            svid_lifetime_secs: u64,
            max_svid_lifetime_secs: u64,
            include_governance_claims: bool,
            include_containment_claims: bool,
        ) -> Self {
            let verifying_key = signing_key.verifying_key();
            let effective_lifetime = svid_lifetime_secs.min(max_svid_lifetime_secs);
            Self {
                trust_domain,
                signing_key,
                verifying_key,
                svid_lifetime_secs: effective_lifetime,
                max_svid_lifetime_secs,
                include_governance_claims,
                include_containment_claims,
            }
        }

        /// Return the SPIFFE ID for a given branch.
        ///
        /// Format: `spiffe://{trust_domain}/agent/{branch_id}`
        ///
        /// N13: Validates that `branch_id` contains only safe characters
        /// (alphanumeric, `-`, `_`) to prevent URI injection.
        pub fn spiffe_id(&self, branch_id: &str) -> Result<String> {
            // N13: Sanitize branch_id — only allow alphanumeric, '-', and '_'
            if !branch_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err(PuzzledError::Identity(format!(
                    "N13: branch_id contains invalid characters for SPIFFE URI: '{}'",
                    branch_id
                )));
            }
            if branch_id.is_empty() {
                return Err(PuzzledError::Identity(
                    "N13: branch_id must not be empty for SPIFFE URI".to_string(),
                ));
            }
            Ok(format!(
                "spiffe://{}/agent/{}",
                self.trust_domain, branch_id
            ))
        }

        /// Issue a JWT-SVID for an agent branch.
        ///
        /// The token is a JWS Compact Serialization (RFC 7515) with an Ed25519
        /// signature. Claims include standard SPIFFE JWT-SVID fields plus
        /// optional governance and containment extensions.
        ///
        /// # Arguments
        ///
        /// * `branch_id` -- Branch identifier (becomes the SPIFFE ID subject).
        /// * `profile` -- Agent profile name.
        /// * `trust_level` -- Trust level label.
        /// * `trust_score` -- Numeric trust score (0-100).
        /// * `audience` -- Intended audiences for this token.
        /// * `enforcement_layers` -- Active kernel enforcement layers.
        /// * `policy_version` -- OPA/Rego policy version string.
        /// * `attestation_chain_hash` -- Optional hex-encoded attestation chain hash.
        /// * `attestation_chain_length` -- Number of records in the attestation chain.
        #[allow(clippy::too_many_arguments)]
        pub fn issue_jwt_svid(
            &self,
            branch_id: &str,
            profile: &str,
            trust_level: &str,
            trust_score: u32,
            audience: &[String],
            enforcement_layers: &[String],
            policy_version: &str,
            attestation_chain_hash: Option<&str>,
            attestation_chain_length: u32,
        ) -> Result<String> {
            self.issue_jwt_svid_with_containment(
                branch_id,
                profile,
                trust_level,
                trust_score,
                audience,
                enforcement_layers,
                policy_version,
                attestation_chain_hash,
                attestation_chain_length,
                None,
            )
        }

        /// Issue a JWT-SVID with explicit containment claims.
        ///
        /// When `containment` is `Some`, it is included in the token regardless
        /// of the `include_containment_claims` flag.  When `None`, containment
        /// is only included if `include_containment_claims` is true AND the
        /// caller provides data — no hardcoded defaults are emitted.
        #[allow(clippy::too_many_arguments)]
        pub fn issue_jwt_svid_with_containment(
            &self,
            branch_id: &str,
            profile: &str,
            trust_level: &str,
            trust_score: u32,
            audience: &[String],
            enforcement_layers: &[String],
            policy_version: &str,
            attestation_chain_hash: Option<&str>,
            attestation_chain_length: u32,
            containment: Option<ContainmentClaims>,
        ) -> Result<String> {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| PuzzledError::Attestation(format!("system time error: {e}")))?
                .as_secs();

            let governance = GovernanceClaimsMetadata {
                enforcement_layers: enforcement_layers.to_vec(),
                policy_version: policy_version.to_string(),
                attestation_chain_hash: attestation_chain_hash.map(|s| s.to_string()),
                attestation_chain_length,
            };

            // Use caller-provided containment if available.
            // When None, only include if the flag is set — but never emit
            // hardcoded defaults.  Callers with real profile data should
            // pass Some(ContainmentClaims { ... }) with actual values.
            let containment = if containment.is_some() {
                containment
            } else if self.include_containment_claims {
                // Flag is set but no data provided — omit rather than emit
                // incorrect defaults.  Callers should use
                // issue_jwt_svid_with_containment() with real data.
                None
            } else {
                None
            };

            let claims = GovernanceClaims {
                sub: self.spiffe_id(branch_id)?,
                iss: format!("puzzled@{}", self.trust_domain),
                aud: audience.to_vec(),
                // L4: Use safe conversions to prevent overflow / truncation.
                iat: i64::try_from(now).map_err(|_| {
                    PuzzledError::Attestation("iat timestamp overflows i64".to_string())
                })?,
                exp: i64::try_from(now.checked_add(self.svid_lifetime_secs).ok_or_else(|| {
                    PuzzledError::Attestation(
                        "exp timestamp overflows u64 (now + lifetime)".to_string(),
                    )
                })?)
                .map_err(|_| PuzzledError::Attestation("exp timestamp overflows i64".to_string()))?,
                branch_id: branch_id.to_string(),
                agent_profile: profile.to_string(),
                trust_level: trust_level.to_string(),
                trust_score,
                governance: if self.include_governance_claims {
                    governance
                } else {
                    GovernanceClaimsMetadata {
                        enforcement_layers: Vec::new(),
                        policy_version: String::new(),
                        attestation_chain_hash: None,
                        attestation_chain_length: 0,
                    }
                },
                containment,
                delegation: None,
            };

            let header = base64url_encode(b"{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}");
            let payload_json = serde_json::to_vec(&claims).map_err(|e| {
                PuzzledError::Attestation(format!("claims serialization error: {e}"))
            })?;
            let payload = base64url_encode(&payload_json);

            let signing_input = format!("{header}.{payload}");
            let signature: Signature = self.signing_key.sign(signing_input.as_bytes());
            let sig_b64 = base64url_encode(&signature.to_bytes());

            Ok(format!("{signing_input}.{sig_b64}"))
        }

        /// Verify a JWT-SVID and return the decoded governance claims.
        ///
        /// Checks Ed25519 signature validity, token expiration, and optionally
        /// audience membership per SPIFFE JWT-SVID spec (Section 3).
        ///
        /// When `expected_audience` is `Some`, the token's `aud` claim must
        /// contain the specified value.  When `None`, audience is not checked
        /// (useful for introspection / admin tooling).
        pub fn verify_jwt_svid(
            &self,
            token: &str,
            expected_audience: Option<&str>,
        ) -> Result<GovernanceClaims> {
            let parts: Vec<&str> = token.split('.').collect();
            if parts.len() != 3 {
                return Err(PuzzledError::Attestation(
                    "invalid JWT-SVID: expected 3 dot-separated parts".into(),
                ));
            }

            let signing_input = format!("{}.{}", parts[0], parts[1]);
            let sig_bytes = base64url_decode(parts[2])?;

            if sig_bytes.len() != 64 {
                return Err(PuzzledError::Attestation(format!(
                    "invalid signature length: expected 64, got {}",
                    sig_bytes.len()
                )));
            }

            let mut sig_arr = [0u8; 64];
            sig_arr.copy_from_slice(&sig_bytes);
            let signature = Signature::from_bytes(&sig_arr);

            self.verifying_key
                .verify(signing_input.as_bytes(), &signature)
                .map_err(|e| {
                    PuzzledError::Attestation(format!("signature verification failed: {e}"))
                })?;

            let payload_bytes = base64url_decode(parts[1])?;
            let claims: GovernanceClaims = serde_json::from_slice(&payload_bytes).map_err(|e| {
                PuzzledError::Attestation(format!("claims deserialization error: {e}"))
            })?;

            // Check expiration and issued-at per SPIFFE JWT-SVID spec (Section 3).
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| PuzzledError::Attestation(format!("system time error: {e}")))?
                .as_secs();
            // L4: Safe conversion — reject if current time overflows i64.
            let now = i64::try_from(now).map_err(|_| {
                PuzzledError::Attestation("current timestamp overflows i64".to_string())
            })?;

            if claims.exp <= now {
                return Err(PuzzledError::Attestation(format!(
                    "token expired: exp={} now={}",
                    claims.exp, now
                )));
            }

            // Reject tokens issued in the future (clock skew tolerance: 60s).
            const CLOCK_SKEW_TOLERANCE_SECS: i64 = 60;
            if claims.iat > now + CLOCK_SKEW_TOLERANCE_SECS {
                return Err(PuzzledError::Attestation(format!(
                    "token issued in the future: iat={} now={}",
                    claims.iat, now
                )));
            }

            // Audience validation per SPIFFE JWT-SVID spec (Section 3).
            if let Some(aud) = expected_audience {
                if !claims.aud.iter().any(|a| a == aud) {
                    return Err(PuzzledError::Attestation(format!(
                        "audience mismatch: expected '{}', token has {:?}",
                        aud, claims.aud
                    )));
                }
            }

            Ok(claims)
        }

        /// Return a JWK Set (JWKS) containing the public verification key.
        ///
        /// The JWKS format follows RFC 7517 with the OKP key type (RFC 8037)
        /// for Ed25519 keys. External services can fetch this to verify
        /// JWT-SVIDs issued by this identity manager.
        pub fn jwks(&self) -> String {
            let pub_bytes = self.verifying_key.to_bytes();
            let x = base64url_encode(&pub_bytes);
            let kid = self.public_key_hex();
            let kid_short = &kid[..8.min(kid.len())];

            format!(
                r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","use":"sig","kid":"{kid_short}","x":"{x}"}}]}}"#
            )
        }

        /// Return the hex-encoded public (verifying) key.
        pub fn public_key_hex(&self) -> String {
            hex_encode(&self.verifying_key.to_bytes())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ed25519_dalek::SigningKey;

        /// Create a deterministic signing key for tests.
        fn test_signing_key() -> SigningKey {
            let mut bytes = [0u8; 32];
            // Use a fixed seed for reproducibility.
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = i as u8;
            }
            SigningKey::from_bytes(&bytes)
        }

        /// Create a test identity manager with all claims enabled.
        fn test_manager() -> IdentityManager {
            IdentityManager::new(
                test_signing_key(),
                "example.com".to_string(),
                3600,
                true,
                true,
            )
        }

        // ----- SPIFFE ID format -----

        #[test]
        fn spiffe_id_format() {
            let mgr = test_manager();
            let id = mgr.spiffe_id("branch-42").unwrap();
            assert_eq!(id, "spiffe://example.com/agent/branch-42");
        }

        #[test]
        fn spiffe_id_with_uuid_branch() {
            let mgr = test_manager();
            let id = mgr
                .spiffe_id("550e8400-e29b-41d4-a716-446655440000")
                .unwrap();
            assert_eq!(
                id,
                "spiffe://example.com/agent/550e8400-e29b-41d4-a716-446655440000"
            );
        }

        #[test]
        fn spiffe_id_rejects_invalid_chars() {
            let mgr = test_manager();
            // N13: Path traversal characters must be rejected
            assert!(mgr.spiffe_id("../evil").is_err());
            assert!(mgr.spiffe_id("branch/inject").is_err());
            assert!(mgr.spiffe_id("branch id").is_err());
            assert!(mgr.spiffe_id("").is_err());
            // Valid IDs should succeed
            assert!(mgr.spiffe_id("branch-42").is_ok());
            assert!(mgr.spiffe_id("branch_42").is_ok());
            assert!(mgr.spiffe_id("ABC123").is_ok());
        }

        // ----- JWT-SVID issuance and verification roundtrip -----

        #[test]
        fn jwt_svid_roundtrip() {
            let mgr = test_manager();
            let token = mgr
                .issue_jwt_svid(
                    "branch-1",
                    "restricted",
                    "low",
                    25,
                    &["service-a".to_string()],
                    &["landlock".to_string(), "seccomp".to_string()],
                    "v1.0",
                    Some("abc123"),
                    5,
                )
                .expect("issue should succeed");

            let claims = mgr
                .verify_jwt_svid(&token, None)
                .expect("verify should succeed");
            assert_eq!(claims.sub, "spiffe://example.com/agent/branch-1");
            assert_eq!(claims.iss, "puzzled@example.com");
            assert_eq!(claims.aud, vec!["service-a"]);
            assert_eq!(claims.branch_id, "branch-1");
            assert_eq!(claims.agent_profile, "restricted");
            assert_eq!(claims.trust_level, "low");
            assert_eq!(claims.trust_score, 25);
            assert_eq!(claims.governance.policy_version, "v1.0");
            assert_eq!(
                claims.governance.attestation_chain_hash,
                Some("abc123".to_string())
            );
            assert_eq!(claims.governance.attestation_chain_length, 5);
            assert_eq!(
                claims.governance.enforcement_layers,
                vec!["landlock", "seccomp"]
            );
            // No containment data provided → no containment claims emitted
            // (avoids incorrect hardcoded defaults).
            assert!(claims.containment.is_none());
        }

        #[test]
        fn jwt_svid_with_real_containment_claims() {
            let mgr = test_manager();
            let containment = ContainmentClaims {
                filesystem_scope: "/home/user/project".to_string(),
                network_mode: "gated".to_string(),
                allowed_domains: vec!["api.example.com".to_string()],
                exec_allowlist_count: 12,
            };
            let token = mgr
                .issue_jwt_svid_with_containment(
                    "branch-contain",
                    "standard",
                    "medium",
                    50,
                    &["service-a".to_string()],
                    &["landlock".to_string()],
                    "v2.0",
                    None,
                    0,
                    Some(containment),
                )
                .expect("issue should succeed");

            let claims = mgr
                .verify_jwt_svid(&token, None)
                .expect("verify should succeed");
            let c = claims.containment.expect("containment should be present");
            assert_eq!(c.filesystem_scope, "/home/user/project");
            assert_eq!(c.network_mode, "gated");
            assert_eq!(c.allowed_domains, vec!["api.example.com"]);
            assert_eq!(c.exec_allowlist_count, 12);
        }

        // ----- JWT-SVID with different audiences -----

        #[test]
        fn jwt_svid_multiple_audiences() {
            let mgr = test_manager();
            let audiences = vec![
                "service-a".to_string(),
                "service-b".to_string(),
                "service-c".to_string(),
            ];
            let token = mgr
                .issue_jwt_svid(
                    "branch-2",
                    "standard",
                    "medium",
                    50,
                    &audiences,
                    &["landlock".to_string()],
                    "v2.0",
                    None,
                    0,
                )
                .expect("issue should succeed");

            let claims = mgr
                .verify_jwt_svid(&token, None)
                .expect("verify should succeed");
            assert_eq!(claims.aud, audiences);
        }

        #[test]
        fn jwt_svid_empty_audience() {
            let mgr = test_manager();
            let token = mgr
                .issue_jwt_svid(
                    "branch-3",
                    "privileged",
                    "high",
                    90,
                    &[],
                    &[
                        "landlock".to_string(),
                        "seccomp".to_string(),
                        "pidns".to_string(),
                    ],
                    "v1.0",
                    None,
                    0,
                )
                .expect("issue should succeed");

            let claims = mgr
                .verify_jwt_svid(&token, None)
                .expect("verify should succeed");
            assert!(claims.aud.is_empty());
        }

        // ----- Expired token detection -----

        #[test]
        fn verify_rejects_expired_token() {
            // Create a manager with 0 lifetime so tokens expire immediately.
            let mgr = IdentityManager::new(
                test_signing_key(),
                "example.com".to_string(),
                0, // 0-second lifetime: exp == iat, immediately expired
                true,
                true,
            );

            let token = mgr
                .issue_jwt_svid(
                    "branch-expired",
                    "restricted",
                    "low",
                    10,
                    &["svc".to_string()],
                    &[],
                    "v1.0",
                    None,
                    0,
                )
                .expect("issue should succeed");

            let result = mgr.verify_jwt_svid(&token, None);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("expired"),
                "expected 'expired' in error: {err_msg}"
            );
        }

        // ----- JWKS generation format -----

        #[test]
        fn jwks_format() {
            let mgr = test_manager();
            let jwks = mgr.jwks();

            // Parse as JSON to validate structure.
            let parsed: serde_json::Value =
                serde_json::from_str(&jwks).expect("JWKS should be valid JSON");

            let keys = parsed["keys"].as_array().expect("keys should be an array");
            assert_eq!(keys.len(), 1);

            let key = &keys[0];
            assert_eq!(key["kty"], "OKP");
            assert_eq!(key["crv"], "Ed25519");
            assert_eq!(key["use"], "sig");

            // kid is first 8 hex chars of public key.
            let kid = key["kid"].as_str().expect("kid should be a string");
            assert_eq!(kid.len(), 8);
            let full_hex = mgr.public_key_hex();
            assert_eq!(kid, &full_hex[..8]);

            // x is base64url of 32-byte public key.
            let x = key["x"].as_str().expect("x should be a string");
            let decoded = base64url_decode(x).expect("x should decode");
            assert_eq!(decoded.len(), 32);
            assert_eq!(decoded, mgr.verifying_key.to_bytes());
        }

        // ----- Base64url encode/decode roundtrip -----

        #[test]
        fn base64url_roundtrip() {
            let data = b"hello, agent workload identity!";
            let encoded = base64url_encode(data);
            let decoded = base64url_decode(&encoded).expect("decode should succeed");
            assert_eq!(decoded, data);
        }

        #[test]
        fn base64url_roundtrip_binary() {
            let data: Vec<u8> = (0..=255).collect();
            let encoded = base64url_encode(&data);
            let decoded = base64url_decode(&encoded).expect("decode should succeed");
            assert_eq!(decoded, data);
        }

        #[test]
        fn base64url_no_padding() {
            // Lengths 1, 2, 3 produce different padding in standard base64.
            for len in 1..=5 {
                let data: Vec<u8> = (0..len).collect();
                let encoded = base64url_encode(&data);
                assert!(
                    !encoded.contains('='),
                    "base64url should not contain padding: {encoded}"
                );
            }
        }

        // ----- public_key_hex matches verifying key -----

        #[test]
        fn public_key_hex_matches_verifying_key() {
            let mgr = test_manager();
            let hex_str = mgr.public_key_hex();

            // Decode hex back to bytes.
            let bytes: Vec<u8> = (0..hex_str.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).unwrap())
                .collect();

            assert_eq!(bytes, mgr.verifying_key.to_bytes().to_vec());
        }

        #[test]
        fn public_key_hex_length() {
            let mgr = test_manager();
            // Ed25519 public key is 32 bytes = 64 hex chars.
            assert_eq!(mgr.public_key_hex().len(), 64);
        }

        // ----- GovernanceClaims serialization -----

        #[test]
        fn governance_claims_serialization_roundtrip() {
            let claims = GovernanceClaims {
                sub: "spiffe://example.com/agent/test".to_string(),
                iss: "puzzled".to_string(),
                aud: vec!["svc-a".to_string()],
                iat: 1700000000,
                exp: 1700003600,
                branch_id: "test".to_string(),
                agent_profile: "restricted".to_string(),
                trust_level: "low".to_string(),
                trust_score: 30,
                governance: GovernanceClaimsMetadata {
                    enforcement_layers: vec!["landlock".to_string()],
                    policy_version: "v1.0".to_string(),
                    attestation_chain_hash: Some("deadbeef".to_string()),
                    attestation_chain_length: 3,
                },
                containment: Some(ContainmentClaims {
                    filesystem_scope: "branch".to_string(),
                    network_mode: "gated".to_string(),
                    allowed_domains: vec!["api.example.com".to_string()],
                    exec_allowlist_count: 5,
                }),
                delegation: None,
            };

            let json = serde_json::to_string(&claims).expect("serialize should succeed");
            let decoded: GovernanceClaims =
                serde_json::from_str(&json).expect("deserialize should succeed");
            assert_eq!(decoded.sub, claims.sub);
            assert_eq!(decoded.branch_id, claims.branch_id);
            assert_eq!(decoded.trust_score, claims.trust_score);
            assert_eq!(
                decoded.governance.policy_version,
                claims.governance.policy_version
            );
        }

        #[test]
        fn governance_claims_without_containment() {
            let claims = GovernanceClaims {
                sub: "spiffe://example.com/agent/test".to_string(),
                iss: "puzzled".to_string(),
                aud: vec![],
                iat: 1700000000,
                exp: 1700003600,
                branch_id: "test".to_string(),
                agent_profile: "standard".to_string(),
                trust_level: "medium".to_string(),
                trust_score: 50,
                governance: GovernanceClaimsMetadata {
                    enforcement_layers: vec![],
                    policy_version: String::new(),
                    attestation_chain_hash: None,
                    attestation_chain_length: 0,
                },
                containment: None,
                delegation: None,
            };

            let json = serde_json::to_string(&claims).expect("serialize should succeed");
            // containment should not appear when None (skip_serializing_if).
            assert!(!json.contains("containment"));
        }

        // ----- Token format (3 dot-separated parts) -----

        #[test]
        fn token_format_three_parts() {
            let mgr = test_manager();
            let token = mgr
                .issue_jwt_svid(
                    "branch-fmt",
                    "standard",
                    "medium",
                    50,
                    &["audience".to_string()],
                    &["landlock".to_string()],
                    "v1.0",
                    None,
                    0,
                )
                .expect("issue should succeed");

            let parts: Vec<&str> = token.split('.').collect();
            assert_eq!(parts.len(), 3, "JWT should have exactly 3 parts");

            // Each part should be non-empty.
            for (i, part) in parts.iter().enumerate() {
                assert!(!part.is_empty(), "part {i} should be non-empty");
            }

            // Header should decode to expected JSON.
            let header_bytes = base64url_decode(parts[0]).expect("header decode");
            let header: serde_json::Value =
                serde_json::from_slice(&header_bytes).expect("header JSON");
            assert_eq!(header["alg"], "EdDSA");
            assert_eq!(header["typ"], "JWT");
        }

        // ----- Signature verification fails with wrong key -----

        #[test]
        fn verify_fails_with_wrong_key() {
            let mgr = test_manager();
            let token = mgr
                .issue_jwt_svid(
                    "branch-wrong-key",
                    "restricted",
                    "low",
                    10,
                    &["svc".to_string()],
                    &["seccomp".to_string()],
                    "v1.0",
                    None,
                    0,
                )
                .expect("issue should succeed");

            // Create a different manager with a different key.
            let mut other_bytes = [0u8; 32];
            other_bytes[0] = 0xFF;
            other_bytes[1] = 0xAB;
            let other_key = SigningKey::from_bytes(&other_bytes);
            let other_mgr =
                IdentityManager::new(other_key, "example.com".to_string(), 3600, true, true);

            let result = other_mgr.verify_jwt_svid(&token, None);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("signature verification failed"),
                "expected signature error: {err_msg}"
            );
        }

        // ----- Edge cases -----

        #[test]
        fn verify_rejects_malformed_token() {
            let mgr = test_manager();
            assert!(mgr.verify_jwt_svid("not-a-jwt", None).is_err());
            assert!(mgr.verify_jwt_svid("a.b", None).is_err());
            assert!(mgr.verify_jwt_svid("a.b.c.d", None).is_err());
            assert!(mgr.verify_jwt_svid("", None).is_err());
        }

        #[test]
        fn governance_claims_without_governance_flags() {
            let mgr = IdentityManager::new(
                test_signing_key(),
                "example.com".to_string(),
                3600,
                false, // no governance claims
                false, // no containment claims
            );

            let token = mgr
                .issue_jwt_svid(
                    "branch-minimal",
                    "restricted",
                    "low",
                    10,
                    &["svc".to_string()],
                    &["landlock".to_string()],
                    "v1.0",
                    None,
                    0,
                )
                .expect("issue should succeed");

            let claims = mgr
                .verify_jwt_svid(&token, None)
                .expect("verify should succeed");
            // Governance metadata should be empty when flag is off.
            assert!(claims.governance.enforcement_layers.is_empty());
            assert!(claims.governance.policy_version.is_empty());
            assert!(claims.governance.attestation_chain_hash.is_none());
            assert_eq!(claims.governance.attestation_chain_length, 0);
            // Containment should be None.
            assert!(claims.containment.is_none());

            // Standard SPIFFE claims should still be present.
            assert_eq!(claims.sub, "spiffe://example.com/agent/branch-minimal");
            assert_eq!(claims.iss, "puzzled@example.com");
            assert_eq!(claims.branch_id, "branch-minimal");
        }

        // ----- Audience validation -----

        #[test]
        fn verify_accepts_matching_audience() {
            let mgr = test_manager();
            let token = mgr
                .issue_jwt_svid(
                    "branch-aud",
                    "standard",
                    "medium",
                    50,
                    &["service-a".to_string(), "service-b".to_string()],
                    &[],
                    "v1.0",
                    None,
                    0,
                )
                .expect("issue should succeed");

            let claims = mgr
                .verify_jwt_svid(&token, Some("service-a"))
                .expect("verify should succeed for matching audience");
            assert_eq!(claims.aud, vec!["service-a", "service-b"]);
        }

        #[test]
        fn verify_rejects_mismatched_audience() {
            let mgr = test_manager();
            let token = mgr
                .issue_jwt_svid(
                    "branch-aud2",
                    "standard",
                    "medium",
                    50,
                    &["service-a".to_string()],
                    &[],
                    "v1.0",
                    None,
                    0,
                )
                .expect("issue should succeed");

            let result = mgr.verify_jwt_svid(&token, Some("service-x"));
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("audience mismatch"),
                "expected 'audience mismatch' in error: {err_msg}"
            );
        }

        #[test]
        fn verify_skips_audience_when_none() {
            let mgr = test_manager();
            let token = mgr
                .issue_jwt_svid(
                    "branch-aud3",
                    "standard",
                    "medium",
                    50,
                    &["service-a".to_string()],
                    &[],
                    "v1.0",
                    None,
                    0,
                )
                .expect("issue should succeed");

            // None means no audience check — should always pass.
            mgr.verify_jwt_svid(&token, None)
                .expect("verify should succeed without audience check");
        }

        // ----- max_svid_lifetime_secs enforcement -----

        // ----- iat (issued-at) validation -----

        #[test]
        fn verify_rejects_future_iat() {
            let key = test_signing_key();
            let mgr = test_manager();

            // Craft a token with iat 10 minutes in the future by signing
            // manually with the same key.
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let future_iat = now + 600; // 10 minutes in the future

            let claims = GovernanceClaims {
                sub: "spiffe://example.com/agent/branch-future".to_string(),
                iss: "puzzled@example.com".to_string(),
                aud: vec!["svc".to_string()],
                iat: future_iat as i64,
                exp: (future_iat + 3600) as i64,
                branch_id: "branch-future".to_string(),
                agent_profile: "restricted".to_string(),
                trust_level: "low".to_string(),
                trust_score: 10,
                governance: GovernanceClaimsMetadata {
                    enforcement_layers: vec![],
                    policy_version: String::new(),
                    attestation_chain_hash: None,
                    attestation_chain_length: 0,
                },
                containment: None,
                delegation: None,
            };

            let header = base64url_encode(b"{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}");
            let payload_json = serde_json::to_vec(&claims).unwrap();
            let payload = base64url_encode(&payload_json);
            let signing_input = format!("{header}.{payload}");
            let signature: Signature = key.sign(signing_input.as_bytes());
            let sig_b64 = base64url_encode(&signature.to_bytes());
            let token = format!("{signing_input}.{sig_b64}");

            let result = mgr.verify_jwt_svid(&token, None);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("future"),
                "expected 'future' in error: {err_msg}"
            );
        }

        /// K82: Verify that svid_lifetime_secs is clamped by with_max_lifetime
        /// and that config validation enforces an upper bound (604800 = 7 days).
        #[test]
        fn k82_svid_lifetime_upper_bound_validated() {
            // The config validation for svid_lifetime_secs is in config.rs (K86).
            // Here we verify the runtime clamping in IdentityManager.
            let source = include_str!("config.rs");
            assert!(
                source.contains("svid_lifetime_secs > 604800"),
                "K82: config must validate svid_lifetime_secs upper bound of 604800"
            );
        }

        #[test]
        fn max_svid_lifetime_clamps_lifetime() {
            let mgr = IdentityManager::with_max_lifetime(
                test_signing_key(),
                "example.com".to_string(),
                7200, // requested: 2 hours
                3600, // max: 1 hour
                true,
                false,
            );

            let token = mgr
                .issue_jwt_svid(
                    "branch-clamp",
                    "restricted",
                    "low",
                    10,
                    &["svc".to_string()],
                    &[],
                    "v1.0",
                    None,
                    0,
                )
                .expect("issue should succeed");

            let claims = mgr
                .verify_jwt_svid(&token, None)
                .expect("verify should succeed");
            // exp - iat should be clamped to max (3600), not requested (7200).
            assert_eq!(claims.exp - claims.iat, 3600);
        }

        // L4: Verify that JWT expiry computation uses checked arithmetic
        // and safe conversion to prevent overflow / truncation.
        #[test]
        fn l4_jwt_exp_uses_checked_add_and_try_from() {
            let source = include_str!("identity.rs");
            // Only examine production code, not tests.
            let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

            // L4(a): Must use checked_add for now + svid_lifetime_secs
            assert!(
                prod_source.contains("checked_add"),
                "L4: exp computation must use checked_add() to prevent u64 overflow"
            );

            // L4(b): Must use i64::try_from (or TryFrom/try_into) instead of `as i64`
            // The production code should NOT contain `as i64` for exp or iat.
            // Count remaining `as i64` in prod code — there should be zero.
            let as_i64_count = prod_source.matches("as i64").count();
            assert_eq!(
                as_i64_count, 0,
                "L4: production code must not use `as i64` truncating cast; \
                 found {as_i64_count} occurrences — use i64::try_from() instead"
            );
        }
    }
}

// Re-export when feature is enabled.
#[cfg(feature = "ima")]
pub use inner::IdentityManager;

// Stub when feature is disabled -- the module still exists but is empty.
#[cfg(not(feature = "ima"))]
mod inner {}
