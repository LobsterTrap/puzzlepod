// SPDX-License-Identifier: Apache-2.0
use puzzled_types::AgentProfile;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::error::{PuzzledError, Result};

/// Known valid Linux capability names.
const VALID_LINUX_CAPS: &[&str] = &[
    "CAP_AUDIT_CONTROL",
    "CAP_AUDIT_READ",
    "CAP_AUDIT_WRITE",
    "CAP_BLOCK_SUSPEND",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_KILL",
    "CAP_LEASE",
    "CAP_LINUX_IMMUTABLE",
    "CAP_MAC_ADMIN",
    "CAP_MAC_OVERRIDE",
    "CAP_MKNOD",
    "CAP_NET_ADMIN",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_RAW",
    "CAP_PERFMON",
    "CAP_SETFCAP",
    "CAP_SETGID",
    "CAP_SETPCAP",
    "CAP_SETUID",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_CHROOT",
    "CAP_SYS_MODULE",
    "CAP_SYS_NICE",
    "CAP_SYS_PACCT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
];

/// M26: Validate an agent profile for semantic correctness.
///
/// Checks resource limits are positive, capabilities are valid Linux cap names,
/// exec_denylist does not overlap with exec_allowlist, and fail_mode is
/// appropriate for the profile's risk level.
pub fn validate_profile(profile: &AgentProfile) -> std::result::Result<(), String> {
    let mut errors = Vec::new();

    // Resource limit checks
    if profile.resource_limits.memory_bytes == 0 {
        errors.push("memory_bytes must be > 0".to_string());
    }
    if profile.resource_limits.max_pids == 0 {
        errors.push("max_pids must be > 0".to_string());
    }
    if profile.resource_limits.storage_quota_mb == 0 {
        errors.push("storage_quota_mb must be > 0".to_string());
    }

    // M-prf1: Delegate to ResourceLimits::validate() for range checks
    let rl_errors = profile.resource_limits.validate();
    errors.extend(rl_errors);

    // M-prf1: Check all paths in read_allowlist, write_allowlist, denylist are absolute
    for path in &profile.filesystem.read_allowlist {
        if !path.is_absolute() {
            errors.push(format!(
                "read_allowlist path must be absolute, got '{}'",
                path.display()
            ));
        }
    }
    for path in &profile.filesystem.write_allowlist {
        if !path.is_absolute() {
            errors.push(format!(
                "write_allowlist path must be absolute, got '{}'",
                path.display()
            ));
        }
    }
    for path in &profile.filesystem.denylist {
        if !path.is_absolute() {
            errors.push(format!(
                "denylist path must be absolute, got '{}'",
                path.display()
            ));
        }
    }

    // M-prf1: Validate inode_quota > 0
    if profile.resource_limits.inode_quota == 0 {
        errors.push("inode_quota must be > 0".to_string());
    }

    // M-prf1: Validate max_pids <= 4194304
    if profile.resource_limits.max_pids > 4_194_304 {
        errors.push(format!(
            "max_pids must be <= 4194304, got {}",
            profile.resource_limits.max_pids
        ));
    }

    // M-prf2: Behavioral threshold validation — zero means "disabled" (skip triggering).
    // Only reject zero for max_reads_per_minute which should not be disabled.
    if profile.behavioral.max_reads_per_minute == 0 {
        errors.push("behavioral.max_reads_per_minute must be > 0 (use a large value to effectively disable)".to_string());
    }

    // Validate capabilities are known Linux cap names
    let valid_caps: HashSet<&str> = VALID_LINUX_CAPS.iter().copied().collect();
    for cap in &profile.capabilities {
        if !valid_caps.contains(cap.as_str()) {
            errors.push(format!("unknown Linux capability: {}", cap));
        }
    }

    // Check exec_denylist does not overlap with exec_allowlist
    if !profile.exec_denylist.is_empty() && !profile.exec_allowlist.is_empty() {
        let allowset: HashSet<&str> = profile.exec_allowlist.iter().map(|s| s.as_str()).collect();
        for denied in &profile.exec_denylist {
            if allowset.contains(denied.as_str()) {
                errors.push(format!(
                    "exec_denylist entry '{}' overlaps with exec_allowlist",
                    denied
                ));
            }
        }
    }

    // Validate fail_mode is appropriate for profile risk level.
    // Profiles with broad capabilities or unrestricted network should not use
    // FailOperational (which applies a subset of changes), as partially
    // applied changes from a highly privileged agent could be dangerous.
    if profile.fail_mode == puzzled_types::FailMode::FailOperational {
        let has_dangerous_caps = profile
            .capabilities
            .iter()
            .any(|c| c == "CAP_SYS_ADMIN" || c == "CAP_SYS_PTRACE" || c == "CAP_SYS_MODULE");
        if has_dangerous_caps {
            errors.push(
                "fail_mode FailOperational is not permitted for profiles with dangerous capabilities (CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_SYS_MODULE)".to_string()
            );
        }
        if profile.network.mode == puzzled_types::NetworkMode::Unrestricted {
            errors.push(
                "fail_mode FailOperational is not permitted for profiles with Unrestricted network"
                    .to_string(),
            );
        }
    }

    // §3.4 G18: Validate credential configuration
    if let Some(ref cred_config) = profile.credentials {
        // Validate credential secrets (PRD §3.4.10)
        let mappings = cred_config.credential_mappings();
        let mut seen_domains = HashSet::new();
        for (domain, credential_ref, env_var, _required) in &mappings {
            if domain.is_empty() {
                errors.push("credential mapping domain must not be empty".to_string());
            }
            if credential_ref.is_empty() {
                errors.push("credential mapping credential_ref must not be empty".to_string());
            }
            if env_var.is_empty() {
                errors.push("credential mapping env_var must not be empty".to_string());
            }
            if !seen_domains.insert(domain) {
                errors.push(format!("duplicate credential mapping domain: {}", domain));
            }

            // Validate credential domains are subset of network allowed_domains (if Gated)
            if profile.network.mode == puzzled_types::NetworkMode::Gated
                && !profile.network.allowed_domains.is_empty()
            {
                let in_allowlist =
                    profile.network.allowed_domains.iter().any(|allowed| {
                        allowed == domain || domain_matches_pattern(domain, allowed)
                    });
                if !in_allowlist {
                    errors.push(format!(
                        "credential domain '{}' is not in network.allowed_domains",
                        domain
                    ));
                }
            }
        }

        // M8: Call validate_credential_specs for comprehensive §3.4.10 validation
        // (TTL, max_credential_size, expose, wildcard domains, dangerous wildcards).
        // Uses default dangerous wildcards if none configured.
        let default_dangerous = crate::config::default_dangerous_wildcards();
        let spec_errors = validate_credential_specs(
            &cred_config.secrets,
            &profile.network.allowed_domains,
            &default_dangerous,
        );
        errors.extend(spec_errors);

        // M9: Validate proxy ports non-empty when proxy is enabled
        if cred_config.proxy.enabled && cred_config.proxy.ports.is_empty() {
            errors.push(
                "credentials.proxy.ports must not be empty when proxy is enabled".to_string(),
            );
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// §3.4 G18/G39: Validate a list of `CredentialSpec` entries.
///
/// This validates the extended credential specification types (PRD §3.4.10).
/// Called when profiles use the new `CredentialSpec` format.
pub fn validate_credential_specs(
    specs: &[puzzled_types::CredentialSpec],
    network_allowed_domains: &[String],
    dangerous_wildcards: &[String],
) -> Vec<String> {
    let mut errors = Vec::new();
    let mut seen_names = HashSet::new();

    for spec in specs {
        // Unique names
        if !seen_names.insert(&spec.name) {
            errors.push(format!("duplicate credential name: '{}'", spec.name));
        }

        // Non-empty domains when phantom_token is true
        if spec.phantom_token && spec.domains.is_empty() {
            errors.push(format!(
                "credential '{}': domains must not be empty when phantom_token is true",
                spec.name
            ));
        }

        // TTL > 0
        if spec.ttl_seconds == 0 {
            errors.push(format!(
                "credential '{}': ttl_seconds must be > 0",
                spec.name
            ));
        }

        // max_credential_size bounds
        if spec.max_credential_size == 0 || spec.max_credential_size > 65536 {
            errors.push(format!(
                "credential '{}': max_credential_size must be between 1 and 65536, got {}",
                spec.name, spec.max_credential_size
            ));
        }

        // At least one exposure entry
        if spec.expose.is_empty() {
            errors.push(format!(
                "credential '{}': must have at least one expose entry",
                spec.name
            ));
        }

        // L3: Per-backend backend_config validation
        match spec.backend {
            puzzled_types::CredentialBackendType::EncryptedFile
            | puzzled_types::CredentialBackendType::SystemdCreds => {
                // encrypted-file and systemd-creds require a "path" in backend_config
                if let Some(obj) = spec.backend_config.as_object() {
                    if !obj.is_empty() && obj.get("path").is_none() {
                        errors.push(format!(
                            "credential '{}': {} backend_config should include a 'path' field",
                            spec.name,
                            serde_json::to_string(&spec.backend).unwrap_or_default()
                        ));
                    }
                }
            }
            puzzled_types::CredentialBackendType::EnvPassthrough => {
                // L4: Warn about env-passthrough at profile validation time
                tracing::warn!(
                    credential = %spec.name,
                    "§3.4 L4: env-passthrough backend exposes credentials in the host \
                     process environment — use only for development/CI"
                );
                // env-passthrough requires a "var" in backend_config
                if let Some(obj) = spec.backend_config.as_object() {
                    if !obj.is_empty() && obj.get("var").is_none() {
                        errors.push(format!(
                            "credential '{}': env-passthrough backend_config should include a 'var' field",
                            spec.name
                        ));
                    }
                }
            }
            puzzled_types::CredentialBackendType::Vault
            | puzzled_types::CredentialBackendType::Openbao => {
                // vault/openbao require "path" in backend_config
                if let Some(obj) = spec.backend_config.as_object() {
                    if obj.get("path").is_none() && !obj.is_empty() {
                        errors.push(format!(
                            "credential '{}': vault/openbao backend_config requires a 'path' field",
                            spec.name
                        ));
                    }
                }
            }
            puzzled_types::CredentialBackendType::AwsSts => {
                // aws-sts requires "role_arn" in backend_config
                if let Some(obj) = spec.backend_config.as_object() {
                    if obj.get("role_arn").is_none() && !obj.is_empty() {
                        errors.push(format!(
                            "credential '{}': aws-sts backend_config requires a 'role_arn' field",
                            spec.name
                        ));
                    }
                }
            }
        }

        // Domain validation
        for domain in &spec.domains {
            // Wildcard domains require opt-in
            if domain.contains('*') && !spec.allow_wildcard_domains {
                errors.push(format!(
                    "credential '{}': wildcard domain '{}' requires allow_wildcard_domains: true",
                    spec.name, domain
                ));
            }

            // §3.4 G39: Dangerous multi-tenant wildcard rejection
            if domain.contains('*') {
                for dangerous in dangerous_wildcards {
                    if domain_matches_pattern(domain, dangerous)
                        || domain_matches_pattern(dangerous, domain)
                    {
                        errors.push(format!(
                            "credential '{}': domain '{}' matches dangerous multi-tenant wildcard '{}'. \
                             Use exact domain names instead (e.g., 'myapp.github.io' not '*.github.io')",
                            spec.name, domain, dangerous
                        ));
                    }
                }
            }

            // Domain subset of network allowed_domains (if provided)
            if !network_allowed_domains.is_empty() {
                let in_allowlist = network_allowed_domains
                    .iter()
                    .any(|allowed| allowed == domain || domain_matches_pattern(domain, allowed));
                if !in_allowlist {
                    errors.push(format!(
                        "credential '{}': domain '{}' is not in network.allowed_domains",
                        spec.name, domain
                    ));
                }
            }
        }
    }

    errors
}

/// Check if a domain matches a glob-style pattern (e.g., "*.example.com").
fn domain_matches_pattern(domain: &str, pattern: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        domain.ends_with(suffix) && domain.len() > suffix.len()
    } else {
        domain == pattern
    }
}

/// Loads and manages agent profiles from YAML files on disk.
pub struct ProfileLoader {
    profiles_dir: PathBuf,
    profiles: HashMap<String, AgentProfile>,
}

impl ProfileLoader {
    pub fn new(profiles_dir: PathBuf) -> Self {
        Self {
            profiles_dir,
            profiles: HashMap::new(),
        }
    }

    /// Load all `.yaml` profiles from the profiles directory.
    ///
    /// M2: Loads into a temporary map first, then swaps with `self.profiles`
    /// only on full success. If any profile fails to load or validate, the
    /// existing profiles remain unchanged and an error is returned.
    pub fn load_all(&mut self) -> Result<()> {
        let entries = std::fs::read_dir(&self.profiles_dir).map_err(|e| {
            PuzzledError::Profile(format!(
                "cannot read profiles dir {}: {}",
                self.profiles_dir.display(),
                e
            ))
        })?;

        let mut new_profiles = HashMap::new();

        for entry in entries {
            let entry = entry.map_err(|e| PuzzledError::Profile(e.to_string()))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
                let profile = Self::load_one(&path)?;
                new_profiles.insert(profile.name.clone(), profile);
            }
        }

        // M2: Atomic swap — only replace profiles if all loaded successfully.
        self.profiles = new_profiles;

        tracing::info!(count = self.profiles.len(), "loaded agent profiles");
        Ok(())
    }

    /// Load a single profile from a YAML file.
    ///
    /// M26: After deserialization, the profile is validated for semantic
    /// correctness (positive resource limits, valid capabilities, no
    /// denylist/allowlist overlap, appropriate fail mode).
    fn load_one(path: &Path) -> Result<AgentProfile> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| PuzzledError::Profile(format!("{}: {}", path.display(), e)))?;
        let profile: AgentProfile = serde_yaml::from_str(&contents)
            .map_err(|e| PuzzledError::Profile(format!("{}: {}", path.display(), e)))?;

        validate_profile(&profile).map_err(|e| {
            PuzzledError::Profile(format!("{}: validation failed: {}", path.display(), e))
        })?;

        Ok(profile)
    }

    /// Get a profile by name.
    pub fn get(&self, name: &str) -> Option<&AgentProfile> {
        self.profiles.get(name)
    }

    /// List all loaded profile names.
    pub fn list(&self) -> Vec<&str> {
        self.profiles.keys().map(|s| s.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const VALID_PROFILE_YAML: &str = r#"
name: test-profile
description: Test profile
filesystem:
  read_allowlist: []
  write_allowlist: []
  denylist: []
exec_allowlist: []
resource_limits:
  memory_bytes: 1073741824
  cpu_shares: 100
  io_weight: 100
  max_pids: 64
  storage_quota_mb: 1024
  inode_quota: 10000
network:
  mode: Blocked
  allowed_domains: []
behavioral:
  max_deletions: 100
  max_reads_per_minute: 1000
  credential_access_alert: false
fail_mode: FailClosed
"#;

    #[test]
    fn test_profile_loader_empty_dir() {
        let dir = TempDir::new().unwrap();
        let mut loader = ProfileLoader::new(dir.path().to_path_buf());
        loader.load_all().unwrap();
        assert_eq!(loader.list().len(), 0);
    }

    #[test]
    fn test_profile_loader_load_and_get() {
        let dir = TempDir::new().unwrap();
        let profile_path = dir.path().join("test-profile.yaml");
        std::fs::write(&profile_path, VALID_PROFILE_YAML).unwrap();

        let mut loader = ProfileLoader::new(dir.path().to_path_buf());
        loader.load_all().unwrap();

        let profile = loader.get("test-profile");
        assert!(profile.is_some());
        let profile = profile.unwrap();
        assert_eq!(profile.name, "test-profile");
        assert_eq!(profile.description, "Test profile");
        assert_eq!(profile.resource_limits.memory_bytes, 1073741824);
        assert_eq!(profile.exec_allowlist.len(), 0);
    }

    #[test]
    fn test_profile_loader_list() {
        let dir = TempDir::new().unwrap();

        // Write two profiles
        let yaml_a = VALID_PROFILE_YAML.replace("test-profile", "alpha");
        let yaml_b = VALID_PROFILE_YAML.replace("test-profile", "beta");
        std::fs::write(dir.path().join("alpha.yaml"), &yaml_a).unwrap();
        std::fs::write(dir.path().join("beta.yaml"), &yaml_b).unwrap();

        let mut loader = ProfileLoader::new(dir.path().to_path_buf());
        loader.load_all().unwrap();

        let mut names = loader.list();
        names.sort();
        assert_eq!(names, vec!["alpha", "beta"]);
    }

    #[test]
    fn test_profile_loader_invalid_yaml() {
        let dir = TempDir::new().unwrap();
        let profile_path = dir.path().join("bad.yaml");
        std::fs::write(&profile_path, "not: [valid: yaml: for: profile").unwrap();

        let mut loader = ProfileLoader::new(dir.path().to_path_buf());
        let result = loader.load_all();
        assert!(result.is_err());
    }

    #[test]
    fn test_profile_loader_ignores_non_yaml() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("readme.txt"), "not a profile").unwrap();
        std::fs::write(dir.path().join("notes.md"), "# Notes").unwrap();

        let mut loader = ProfileLoader::new(dir.path().to_path_buf());
        loader.load_all().unwrap();
        assert_eq!(loader.list().len(), 0);
    }

    #[test]
    fn test_profile_loader_get_missing() {
        let dir = TempDir::new().unwrap();
        let mut loader = ProfileLoader::new(dir.path().to_path_buf());
        loader.load_all().unwrap();
        assert!(loader.get("nonexistent").is_none());
    }

    // --- M26: Profile semantic validation tests ---

    fn make_valid_profile() -> AgentProfile {
        serde_yaml::from_str(VALID_PROFILE_YAML).unwrap()
    }

    #[test]
    fn test_validate_profile_valid() {
        let profile = make_valid_profile();
        assert!(validate_profile(&profile).is_ok());
    }

    #[test]
    fn test_validate_profile_zero_memory() {
        let mut profile = make_valid_profile();
        profile.resource_limits.memory_bytes = 0;
        let err = validate_profile(&profile).unwrap_err();
        assert!(err.contains("memory_bytes"), "error: {}", err);
    }

    #[test]
    fn test_validate_profile_zero_max_pids() {
        let mut profile = make_valid_profile();
        profile.resource_limits.max_pids = 0;
        let err = validate_profile(&profile).unwrap_err();
        assert!(err.contains("max_pids"), "error: {}", err);
    }

    #[test]
    fn test_validate_profile_zero_storage_quota() {
        let mut profile = make_valid_profile();
        profile.resource_limits.storage_quota_mb = 0;
        let err = validate_profile(&profile).unwrap_err();
        assert!(err.contains("storage_quota_mb"), "error: {}", err);
    }

    #[test]
    fn test_validate_profile_invalid_capability() {
        let mut profile = make_valid_profile();
        profile.capabilities = vec!["CAP_FAKE_THING".to_string()];
        let err = validate_profile(&profile).unwrap_err();
        assert!(err.contains("unknown Linux capability"), "error: {}", err);
    }

    #[test]
    fn test_validate_profile_valid_capability() {
        let mut profile = make_valid_profile();
        profile.capabilities = vec!["CAP_NET_RAW".to_string(), "CAP_CHOWN".to_string()];
        assert!(validate_profile(&profile).is_ok());
    }

    #[test]
    fn test_validate_profile_denylist_allowlist_overlap() {
        let mut profile = make_valid_profile();
        profile.exec_allowlist = vec!["/usr/bin/curl".to_string()];
        profile.exec_denylist = vec!["/usr/bin/curl".to_string()];
        let err = validate_profile(&profile).unwrap_err();
        assert!(err.contains("overlaps"), "error: {}", err);
    }

    #[test]
    fn test_validate_profile_fail_operational_with_dangerous_caps() {
        let mut profile = make_valid_profile();
        profile.fail_mode = puzzled_types::FailMode::FailOperational;
        profile.capabilities = vec!["CAP_SYS_ADMIN".to_string()];
        let err = validate_profile(&profile).unwrap_err();
        assert!(err.contains("FailOperational"), "error: {}", err);
    }

    #[test]
    fn test_validate_profile_fail_operational_with_unrestricted_network() {
        let mut profile = make_valid_profile();
        profile.fail_mode = puzzled_types::FailMode::FailOperational;
        profile.network.mode = puzzled_types::NetworkMode::Unrestricted;
        let err = validate_profile(&profile).unwrap_err();
        assert!(err.contains("FailOperational"), "error: {}", err);
    }

    #[test]
    fn test_validate_profile_multiple_errors() {
        let mut profile = make_valid_profile();
        profile.resource_limits.memory_bytes = 0;
        profile.resource_limits.max_pids = 0;
        profile.capabilities = vec!["INVALID_CAP".to_string()];
        let err = validate_profile(&profile).unwrap_err();
        // Should contain all three errors joined by "; "
        assert!(err.contains("memory_bytes"), "error: {}", err);
        assert!(err.contains("max_pids"), "error: {}", err);
        assert!(err.contains("unknown Linux capability"), "error: {}", err);
    }

    #[test]
    fn test_validate_profile_denylist_paths_must_be_absolute() {
        // Phase 1.13: Every path in denylist must be absolute.
        let mut profile = make_valid_profile();
        profile.filesystem.denylist = vec![
            PathBuf::from("/etc/shadow"),   // absolute — OK
            PathBuf::from("relative/path"), // relative — should fail
        ];
        let err = validate_profile(&profile).unwrap_err();
        assert!(
            err.contains("denylist path must be absolute"),
            "error: {}",
            err
        );
    }

    #[test]
    fn test_validate_profile_read_allowlist_paths_must_be_absolute() {
        // Phase 1.13: Every path in read_allowlist must be absolute.
        let mut profile = make_valid_profile();
        profile.filesystem.read_allowlist = vec![PathBuf::from("relative/read")];
        let err = validate_profile(&profile).unwrap_err();
        assert!(
            err.contains("read_allowlist path must be absolute"),
            "error: {}",
            err
        );
    }

    #[test]
    fn test_validate_profile_write_allowlist_paths_must_be_absolute() {
        // Phase 1.13: Every path in write_allowlist must be absolute.
        let mut profile = make_valid_profile();
        profile.filesystem.write_allowlist = vec![PathBuf::from("relative/write")];
        let err = validate_profile(&profile).unwrap_err();
        assert!(
            err.contains("write_allowlist path must be absolute"),
            "error: {}",
            err
        );
    }

    #[test]
    fn test_validate_profile_exec_allowlist_no_overlap_with_denylist() {
        // Phase 1.13: exec_allowlist and exec_denylist must not have overlapping entries.
        // When they are disjoint, validation should pass.
        let mut profile = make_valid_profile();
        profile.exec_allowlist = vec!["/usr/bin/python3".to_string()];
        profile.exec_denylist = vec!["/usr/bin/curl".to_string()];
        assert!(validate_profile(&profile).is_ok());
    }

    #[test]
    fn test_validate_profile_zero_inode_quota() {
        // Phase 1.13: inode_quota must be > 0.
        let mut profile = make_valid_profile();
        profile.resource_limits.inode_quota = 0;
        let err = validate_profile(&profile).unwrap_err();
        assert!(err.contains("inode_quota"), "error: {}", err);
    }

    #[test]
    fn test_validate_profile_max_pids_exceeds_limit() {
        // Phase 1.13: max_pids must be <= 4194304.
        let mut profile = make_valid_profile();
        profile.resource_limits.max_pids = 5_000_000;
        let err = validate_profile(&profile).unwrap_err();
        assert!(err.contains("max_pids"), "error: {}", err);
    }

    #[test]
    fn test_load_profile_with_zero_memory_fails() {
        let dir = TempDir::new().unwrap();
        let yaml = VALID_PROFILE_YAML.replace("memory_bytes: 1073741824", "memory_bytes: 0");
        let profile_path = dir.path().join("bad.yaml");
        std::fs::write(&profile_path, &yaml).unwrap();

        let mut loader = ProfileLoader::new(dir.path().to_path_buf());
        let result = loader.load_all();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("memory_bytes"));
    }

    // §3.4 G18/G39 tests

    fn make_valid_credential_spec(name: &str) -> puzzled_types::CredentialSpec {
        puzzled_types::CredentialSpec {
            name: name.to_string(),
            backend: puzzled_types::CredentialBackendType::EncryptedFile,
            backend_config: serde_json::Value::Null,
            expose: vec![puzzled_types::CredentialExposure::Env {
                var: "API_KEY".to_string(),
                field: None,
            }],
            phantom_token: true,
            domains: vec!["api.example.com".to_string()],
            allow_wildcard_domains: false,
            ttl_seconds: 900,
            swap_headers: vec!["authorization".to_string()],
            max_credential_size: 4096,
            required: true,
        }
    }

    #[test]
    fn test_credential_spec_valid() {
        let specs = vec![make_valid_credential_spec("test-key")];
        let errors = validate_credential_specs(&specs, &[], &[]);
        assert!(errors.is_empty(), "unexpected errors: {:?}", errors);
    }

    #[test]
    fn test_credential_spec_duplicate_names() {
        let specs = vec![
            make_valid_credential_spec("dup"),
            make_valid_credential_spec("dup"),
        ];
        let errors = validate_credential_specs(&specs, &[], &[]);
        assert!(errors
            .iter()
            .any(|e| e.contains("duplicate credential name")));
    }

    #[test]
    fn test_credential_spec_empty_domains() {
        let mut spec = make_valid_credential_spec("no-domains");
        spec.domains = vec![];
        let errors = validate_credential_specs(&[spec], &[], &[]);
        assert!(errors
            .iter()
            .any(|e| e.contains("domains must not be empty")));
    }

    #[test]
    fn test_credential_spec_zero_ttl() {
        let mut spec = make_valid_credential_spec("zero-ttl");
        spec.ttl_seconds = 0;
        let errors = validate_credential_specs(&[spec], &[], &[]);
        assert!(errors.iter().any(|e| e.contains("ttl_seconds must be > 0")));
    }

    #[test]
    fn test_credential_spec_wildcard_without_opt_in() {
        let mut spec = make_valid_credential_spec("wildcard");
        spec.domains = vec!["*.example.com".to_string()];
        spec.allow_wildcard_domains = false;
        let errors = validate_credential_specs(&[spec], &[], &[]);
        assert!(errors.iter().any(|e| e.contains("allow_wildcard_domains")));
    }

    #[test]
    fn test_credential_spec_dangerous_wildcard_rejected() {
        let mut spec = make_valid_credential_spec("dangerous");
        spec.domains = vec!["*.github.io".to_string()];
        spec.allow_wildcard_domains = true;
        let dangerous = vec!["*.github.io".to_string()];
        let errors = validate_credential_specs(&[spec], &[], &dangerous);
        assert!(errors.iter().any(|e| e.contains("dangerous multi-tenant")));
    }

    #[test]
    fn test_credential_spec_domain_not_in_allowlist() {
        let spec = make_valid_credential_spec("not-allowed");
        let allowed = vec!["other.example.com".to_string()];
        let errors = validate_credential_specs(&[spec], &allowed, &[]);
        assert!(errors
            .iter()
            .any(|e| e.contains("not in network.allowed_domains")));
    }

    #[test]
    fn test_credential_spec_max_size_bounds() {
        let mut spec = make_valid_credential_spec("big");
        spec.max_credential_size = 0;
        let errors = validate_credential_specs(&[spec], &[], &[]);
        assert!(errors.iter().any(|e| e.contains("max_credential_size")));

        let mut spec2 = make_valid_credential_spec("too-big");
        spec2.max_credential_size = 100_000;
        let errors2 = validate_credential_specs(&[spec2], &[], &[]);
        assert!(errors2.iter().any(|e| e.contains("max_credential_size")));
    }
}
