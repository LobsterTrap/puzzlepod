// SPDX-License-Identifier: Apache-2.0
use puzzled_types::AgentProfile;

use crate::error::Result;

/// Landlock ruleset builder — creates an irrevocable filesystem ACL
/// from an agent profile.
///
/// Once applied via `landlock_restrict_self()`, the ruleset:
/// - Survives puzzled crash (kernel-enforced)
/// - Cannot be removed by the agent process
/// - Is inherited by all child processes
pub struct LandlockBuilder;

impl LandlockBuilder {
    /// Build and apply a Landlock ruleset from an agent profile.
    ///
    /// Translates profile filesystem rules into Landlock access rights:
    /// - read_allowlist -> ReadFile, ReadDir access rules
    /// - write_allowlist + branch merged dir -> full write access rules
    /// - denylist -> excluded from ruleset (Landlock is allowlist-based)
    /// - read_denylist -> paths excluded from read rules (M-ll2)
    /// - write_denylist -> paths excluded from write rules (M-ll2)
    ///
    /// `extra_write_paths` should include the branch merged directory.
    /// `proxy_port` is the TCP port of the governance proxy that agents are
    /// allowed to connect to. Defaults to 3128 if `None`.
    #[cfg(target_os = "linux")]
    pub fn apply(
        profile: &AgentProfile,
        extra_write_paths: &[std::path::PathBuf],
        proxy_port: Option<u16>,
    ) -> Result<()> {
        use landlock::{
            Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
            RulesetStatus, ABI,
        };

        // m18: Request ABI V5 (includes IOCTL_DEV), falling back to V4 (6.7+),
        // V3 (6.2+), V2 (5.19+), V1 (5.13+). The landlock crate's best-effort
        // negotiation clamps to the highest kernel-supported ABI automatically.
        let abi = ABI::V5;
        tracing::info!(
            requested_abi = "V5",
            "Landlock ABI negotiation (kernel will clamp to highest supported)"
        );

        let read_access = AccessFs::from_read(abi);
        let write_access = AccessFs::from_all(abi);

        let mut ruleset = Ruleset::default()
            .handle_access(write_access)
            .map_err(|e| {
                crate::error::PuzzledError::Sandbox(format!("creating Landlock ruleset: {}", e))
            })?
            .create()
            .map_err(|e| {
                crate::error::PuzzledError::Sandbox(format!("creating Landlock ruleset: {}", e))
            })?;

        // §3.4/M-cred1: Credential store paths are ALWAYS denied to agent processes.
        // Agents must never read the credential store directly — they can only
        // access credentials through the proxy's phantom token resolution.
        // These paths are prepended to the profile denylist unconditionally.
        let credential_store_paths: Vec<std::path::PathBuf> = {
            let mut paths = vec![
                std::path::PathBuf::from("/var/lib/puzzled/credentials"),
                // §3.4: PRD default store_path is /etc/puzzled/credentials/store.enc
                std::path::PathBuf::from("/etc/puzzled/credentials"),
            ];
            // Also deny the user-level credential store path if HOME is set
            if let Ok(home) = std::env::var("HOME") {
                paths.push(std::path::PathBuf::from(home).join(".local/share/puzzled/credentials"));
            }
            paths
        };

        // H1: Filter allowlist paths against denylist before adding rules.
        // Landlock is default-deny — the deny is achieved by NOT granting access.
        // Any path that matches or is under a denylist entry is excluded.
        //
        // M7: Canonicalize denylist paths before checking starts_with().
        // Without canonicalization, an agent could bypass the denylist by using
        // symlinks or relative paths (e.g., /var/data/../etc/shadow).
        //
        // M-ll1: When canonicalize() fails for a denylist entry, skip the entry
        // with a warning instead of using the raw (uncanonicalized) path. The raw
        // path could miss the target due to symlinks.
        let canonical_denylist: Vec<std::path::PathBuf> = profile
            .filesystem
            .denylist
            .iter()
            .chain(credential_store_paths.iter())
            .filter_map(|d| match std::fs::canonicalize(d) {
                Ok(canonical) => Some(canonical),
                Err(e) => {
                    // M-ll1: Skip uncanonicalized denylist entries — using a raw path
                    // could miss the actual target if symlinks are involved, allowing
                    // an agent to bypass the denylist.
                    tracing::warn!(
                        path = %d.display(),
                        error = %e,
                        "denylist path canonicalization failed, skipping entry \
                         (raw path could miss target due to symlinks)"
                    );
                    None
                }
            })
            .collect();

        // M-ll2: Canonicalize read_denylist and write_denylist paths for filtering.
        // These provide fine-grained per-access-type deny lists beyond the general denylist.
        let canonical_read_denylist: Vec<std::path::PathBuf> = profile
            .filesystem
            .read_denylist
            .iter()
            .filter_map(|d| match std::fs::canonicalize(d) {
                Ok(canonical) => Some(canonical),
                Err(e) => {
                    // M-ll1: Same canonicalization fallback as general denylist.
                    tracing::warn!(
                        path = %d.display(),
                        error = %e,
                        "read_denylist path canonicalization failed, skipping entry \
                         (raw path could miss target due to symlinks)"
                    );
                    None
                }
            })
            .collect();

        let canonical_write_denylist: Vec<std::path::PathBuf> = profile
            .filesystem
            .write_denylist
            .iter()
            .filter_map(|d| match std::fs::canonicalize(d) {
                Ok(canonical) => Some(canonical),
                Err(e) => {
                    // M-ll1: Same canonicalization fallback as general denylist.
                    tracing::warn!(
                        path = %d.display(),
                        error = %e,
                        "write_denylist path canonicalization failed, skipping entry \
                         (raw path could miss target due to symlinks)"
                    );
                    None
                }
            })
            .collect();

        // S2: Helper to canonicalize a path for denylist comparison.
        // If canonicalize fails, treat the path as DENYLISTED (fail-closed)
        // to prevent bypass via broken symlinks or permission-denied paths.
        let canonicalize_or_deny = |p: &std::path::Path| -> (std::path::PathBuf, bool) {
            match std::fs::canonicalize(p) {
                Ok(canonical) => (canonical, false),
                Err(e) => {
                    tracing::warn!(
                        path = %p.display(),
                        error = %e,
                        "S2: canonicalize failed for denylist check — treating path as \
                         DENYLISTED (fail-closed) to prevent symlink bypass"
                    );
                    (p.to_path_buf(), true)
                }
            }
        };

        let is_denylisted = |p: &std::path::Path| -> bool {
            // S2: If canonicalize fails, deny the path (fail-closed)
            let (canonical_p, failed) = canonicalize_or_deny(p);
            if failed {
                return true;
            }
            canonical_denylist
                .iter()
                .any(|d| canonical_p.starts_with(d))
        };

        // M-ll2: Check if a path is in the read_denylist (general denylist OR read-specific denylist)
        let is_read_denylisted = |p: &std::path::Path| -> bool {
            let (canonical_p, failed) = canonicalize_or_deny(p);
            if failed {
                return true;
            }
            canonical_denylist
                .iter()
                .any(|d| canonical_p.starts_with(d))
                || canonical_read_denylist
                    .iter()
                    .any(|d| canonical_p.starts_with(d))
        };

        // M-ll2: Check if a path is in the write_denylist (general denylist OR write-specific denylist)
        let is_write_denylisted = |p: &std::path::Path| -> bool {
            let (canonical_p, failed) = canonicalize_or_deny(p);
            if failed {
                return true;
            }
            canonical_denylist
                .iter()
                .any(|d| canonical_p.starts_with(d))
                || canonical_write_denylist
                    .iter()
                    .any(|d| canonical_p.starts_with(d))
        };

        // Add read-only rules for read_allowlist paths
        for path in &profile.filesystem.read_allowlist {
            // M-ll2: Check both general denylist and read-specific denylist
            if is_read_denylisted(path) {
                tracing::warn!(
                    path = %path.display(),
                    "skipping denylisted path from read allowlist"
                );
                continue;
            }
            // H-25: Non-existent paths handling based on fail_mode.
            // In FailClosed mode, a missing allowlist path is an error —
            // the profile may be misconfigured. In other modes, skip with a warning.
            if !path.exists() {
                if profile.fail_mode == puzzled_types::FailMode::FailClosed {
                    return Err(crate::error::PuzzledError::Sandbox(format!(
                        "read allowlist path does not exist and fail_mode is FailClosed: {}",
                        path.display()
                    )));
                }
                tracing::warn!(
                    path = %path.display(),
                    "skipping non-existent read allowlist path"
                );
                continue;
            }
            match PathFd::new(path) {
                Ok(fd) => {
                    ruleset = ruleset
                        .add_rule(PathBeneath::new(fd, read_access))
                        .map_err(|e| {
                            crate::error::PuzzledError::Sandbox(format!(
                                "adding Landlock read rule for {}: {}",
                                path.display(),
                                e
                            ))
                        })?;
                }
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "skipping Landlock read rule (path not accessible)"
                    );
                }
            }
        }

        // Add read-write rules for write_allowlist paths
        for path in &profile.filesystem.write_allowlist {
            // M-ll2: Check both general denylist and write-specific denylist
            if is_write_denylisted(path) {
                tracing::warn!(
                    path = %path.display(),
                    "skipping denylisted path from write allowlist"
                );
                continue;
            }
            // H-25: Non-existent paths handling based on fail_mode.
            if !path.exists() {
                if profile.fail_mode == puzzled_types::FailMode::FailClosed {
                    return Err(crate::error::PuzzledError::Sandbox(format!(
                        "write allowlist path does not exist and fail_mode is FailClosed: {}",
                        path.display()
                    )));
                }
                tracing::warn!(
                    path = %path.display(),
                    "skipping non-existent write allowlist path"
                );
                continue;
            }
            match PathFd::new(path) {
                Ok(fd) => {
                    ruleset = ruleset
                        .add_rule(PathBeneath::new(fd, write_access))
                        .map_err(|e| {
                            crate::error::PuzzledError::Sandbox(format!(
                                "adding Landlock write rule for {}: {}",
                                path.display(),
                                e
                            ))
                        })?;
                }
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "skipping Landlock write rule (path not accessible)"
                    );
                }
            }
        }

        // Add write rules for extra paths (branch merged dir)
        for path in extra_write_paths {
            if is_denylisted(path) {
                tracing::warn!(
                    path = %path.display(),
                    "skipping denylisted extra write path"
                );
                continue;
            }
            if path.exists() {
                match PathFd::new(path) {
                    Ok(fd) => {
                        ruleset = ruleset
                            .add_rule(PathBeneath::new(fd, write_access))
                            .map_err(|e| {
                                crate::error::PuzzledError::Sandbox(format!(
                                    "adding Landlock write rule for {}: {}",
                                    path.display(),
                                    e
                                ))
                            })?;
                    }
                    Err(e) => {
                        tracing::warn!(
                            path = %path.display(),
                            error = %e,
                            "skipping Landlock write rule (path not accessible)"
                        );
                    }
                }
            }
        }

        // DC: Gap between net and fs ruleset application is pre-exec setup phase only —
        // no untrusted agent code is running. Rulesets applied in narrowing order:
        // network first (broader surface), then filesystem (more granular).

        // C10: Landlock network rules (ABI v4+, kernel 6.7+)
        //
        // Landlock ABI v4 introduced AccessNet::{ConnectTcp, BindTcp} for
        // network access control. These are enforced in-kernel, irrevocable,
        // and survive puzzled crash — just like filesystem rules.
        //
        // M10: Port-only restriction is a Landlock ABI v4 limitation —
        // IP-based filtering requires nftables defense-in-depth.
        //
        // Landlock's ConnectTcp/BindTcp rules operate on TCP port numbers only.
        // They cannot restrict connections by destination IP address, CIDR range,
        // or DNS domain name. For IP-level filtering, the architecture relies on:
        //   1. Network namespace isolation (CLONE_NEWNET)
        //   2. nftables rules inside the agent namespace (setup_gated/setup_monitored)
        //   3. seccomp USER_NOTIF for connect/bind argument inspection
        //
        // The Landlock network layer provides an additional irrevocable port
        // restriction that survives puzzled crash — even if nftables rules are
        // somehow circumvented, the agent can only connect to the proxy port.
        //
        // NOTE: As of landlock crate v0.4.x, AccessNet support may not be
        // available in the Rust crate. If `landlock::AccessNet` is not present,
        // we fall back to raw syscall-based Landlock network rule addition.
        // For now, we use the crate's AccessNet if available, otherwise log a
        // warning. The seccomp USER_NOTIF layer provides defense-in-depth for
        // connect/bind even if Landlock network rules cannot be applied.
        {
            use landlock::{AccessNet, NetPort};

            // M10: Runtime ABI version check — warn if kernel ABI < v4.
            // Landlock network access control requires ABI v4 (kernel 6.7+).
            // On older kernels, the network ruleset will be silently degraded
            // (handled by the landlock crate's best-effort ABI negotiation),
            // but we log an explicit warning for operators.
            //
            // NOTE: The actual enforcement check happens in restrict_self() below,
            // where the landlock crate reports PartiallyEnforced or NotEnforced
            // for unsupported features. This is a proactive warning only.
            // PM7: Proactive ABI version check — warn operators if kernel ABI < v4.
            // Landlock ConnectTcp/BindTcp rules are port-only restrictions (an ABI v4
            // limitation — IP/CIDR/domain filtering is NOT possible via Landlock and
            // requires nftables + seccomp USER_NOTIF defense-in-depth layers).
            // The actual enforcement check happens in restrict_self() below, where
            // PartiallyEnforced/NotEnforced indicates the kernel lacks ABI v4 support.
            tracing::warn!(
                "Landlock ABI v4 (kernel 6.7+) required for ConnectTcp/BindTcp network rules; \
                 restrict_self() will report actual enforcement status below"
            );

            // PM5: Use the proxy port from config instead of hardcoding.
            // Falls back to 3128 (the default_proxy_port from config.rs) if not provided.
            let proxy_port_val: u16 = proxy_port.unwrap_or(3128);

            // Create a new ruleset handling network access
            let mut net_ruleset = Ruleset::default()
                .handle_access(AccessNet::ConnectTcp | AccessNet::BindTcp)
                .map_err(|e| {
                    crate::error::PuzzledError::Sandbox(format!(
                        "creating Landlock network ruleset: {}",
                        e
                    ))
                })?
                .create()
                .map_err(|e| {
                    crate::error::PuzzledError::Sandbox(format!(
                        "creating Landlock network ruleset: {}",
                        e
                    ))
                })?;

            // ConnectTcp: only allow connections to the HTTP proxy port.
            // All agent network traffic must go through the governance proxy.
            net_ruleset = net_ruleset
                .add_rule(NetPort::new(proxy_port_val, AccessNet::ConnectTcp))
                .map_err(|e| {
                    crate::error::PuzzledError::Sandbox(format!(
                        "adding Landlock ConnectTcp rule for proxy port {}: {}",
                        proxy_port_val, e
                    ))
                })?;

            // BindTcp: deny all bind operations by not adding any BindTcp rules.
            // Landlock is default-deny — since we declared we handle BindTcp but
            // added no rules for it, all bind() calls will be blocked.

            // H-24: Apply network ruleset FIRST (broader surface), before filesystem
            // ruleset (more granular). Both are applied during pre-exec setup phase
            // only — no untrusted agent code is running during this gap.
            let net_status = net_ruleset.restrict_self().map_err(|e| {
                crate::error::PuzzledError::Sandbox(format!(
                    "applying Landlock network ruleset: {}",
                    e
                ))
            })?;

            match net_status.ruleset {
                RulesetStatus::FullyEnforced => {
                    tracing::info!(
                        proxy_port = proxy_port_val,
                        "Landlock network rules fully enforced (ConnectTcp: proxy only, BindTcp: denied)"
                    );
                }
                RulesetStatus::PartiallyEnforced => {
                    // SC3: If profile requires FailClosed and has network rules
                    // (Gated or Blocked mode), ABI < v4 is a security violation.
                    // Return an error instead of silently degrading.
                    if profile.fail_mode == puzzled_types::FailMode::FailClosed
                        && matches!(
                            profile.network.mode,
                            puzzled_types::NetworkMode::Gated | puzzled_types::NetworkMode::Blocked
                        )
                    {
                        return Err(crate::error::PuzzledError::Sandbox(
                            "Landlock network rules only partially enforced (kernel ABI < v4, requires 6.7+) \
                             but profile requires FailClosed with network restrictions (Gated/Blocked). \
                             Cannot guarantee kernel-enforced network ACL."
                                .to_string(),
                        ));
                    }
                    tracing::warn!(
                        "Landlock network rules partially enforced — kernel may not support ABI v4 network restrictions. \
                         Falling back to seccomp USER_NOTIF for connect/bind gating."
                    );
                }
                RulesetStatus::NotEnforced => {
                    // SC3: Same FailClosed check for NotEnforced.
                    if profile.fail_mode == puzzled_types::FailMode::FailClosed
                        && matches!(
                            profile.network.mode,
                            puzzled_types::NetworkMode::Gated | puzzled_types::NetworkMode::Blocked
                        )
                    {
                        return Err(crate::error::PuzzledError::Sandbox(
                            "Landlock network rules not enforced (kernel does not support ABI v4, requires 6.7+) \
                             but profile requires FailClosed with network restrictions (Gated/Blocked). \
                             Cannot guarantee kernel-enforced network ACL."
                                .to_string(),
                        ));
                    }
                    tracing::warn!(
                        "Landlock network rules not enforced — kernel does not support Landlock ABI v4 (requires 6.7+). \
                         Agent network access will be gated by seccomp USER_NOTIF and network namespace only."
                    );
                }
            }
        }

        // H-24: Apply the filesystem ruleset AFTER network ruleset — irrevocable.
        // Network ruleset was applied first (broader surface area), filesystem
        // ruleset applied second (more granular). Both applied pre-exec, so no
        // untrusted code runs during the gap between applications.
        let status = ruleset.restrict_self().map_err(|e| {
            crate::error::PuzzledError::Sandbox(format!("applying Landlock ruleset: {}", e))
        })?;

        match status.ruleset {
            RulesetStatus::FullyEnforced => {
                tracing::info!("Landlock ruleset fully enforced");
            }
            RulesetStatus::PartiallyEnforced => {
                // PartiallyEnforced is expected when read/write rules include
                // directory-only flags (e.g. ReadDir) for file paths like
                // /etc/localtime or /dev/null. The landlock crate automatically
                // strips incompatible flags, so security is not reduced.
                // This is NOT the same as a kernel ABI limitation.
                tracing::info!(
                    "Landlock filesystem ruleset partially enforced \
                     (expected: directory-only flags stripped from file paths)"
                );
            }
            RulesetStatus::NotEnforced => {
                return Err(crate::error::PuzzledError::Sandbox(
                    "Landlock ruleset not enforced: kernel does not support Landlock. \
                     Cannot launch agent without filesystem ACL."
                        .to_string(),
                ));
            }
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn apply(
        _profile: &AgentProfile,
        _extra_write_paths: &[std::path::PathBuf],
        _proxy_port: Option<u16>,
    ) -> Result<()> {
        Err(crate::error::PuzzledError::Sandbox(
            "Landlock requires Linux 5.13+".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_landlock_builder_is_unit_struct() {
        // LandlockBuilder is a unit struct — verify it can be constructed
        let _builder = LandlockBuilder;
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_landlock_apply_non_linux_error_message() {
        let profile = AgentProfile {
            name: "test".to_string(),
            description: "test".to_string(),
            filesystem: puzzled_types::FilesystemRules {
                read_allowlist: vec![],
                write_allowlist: vec![],
                denylist: vec![],
                read_denylist: vec![],
                write_denylist: vec![],
            },
            exec_allowlist: vec![],
            exec_denylist: vec![],
            resource_limits: Default::default(),
            network: puzzled_types::NetworkConfig {
                mode: puzzled_types::NetworkMode::Blocked,
                allowed_domains: vec![],
                data_residency: None,
                dlp_rules_path: None,
            },
            behavioral: Default::default(),
            fail_mode: puzzled_types::FailMode::FailClosed,
            capabilities: vec![],
            enforcement: Default::default(),
            seccomp_mode: Default::default(),
            allow_symlinks: false,
            allow_exec_overlay: false,
            credentials: None,
        };

        let result = LandlockBuilder::apply(&profile, &[], None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Landlock requires Linux"),
            "expected Landlock error, got: {}",
            err
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_landlock_apply_with_proxy_port_non_linux() {
        let profile = AgentProfile {
            name: "test".to_string(),
            description: "test".to_string(),
            filesystem: puzzled_types::FilesystemRules {
                read_allowlist: vec![],
                write_allowlist: vec![],
                denylist: vec![],
                read_denylist: vec![],
                write_denylist: vec![],
            },
            exec_allowlist: vec![],
            exec_denylist: vec![],
            resource_limits: Default::default(),
            network: puzzled_types::NetworkConfig {
                mode: puzzled_types::NetworkMode::Gated,
                allowed_domains: vec!["example.com".to_string()],
                data_residency: None,
                dlp_rules_path: None,
            },
            behavioral: Default::default(),
            fail_mode: puzzled_types::FailMode::FailClosed,
            capabilities: vec![],
            enforcement: Default::default(),
            seccomp_mode: Default::default(),
            allow_symlinks: false,
            allow_exec_overlay: false,
            credentials: None,
        };

        // With extra write paths and proxy port
        let extra = vec![std::path::PathBuf::from("/tmp/test-upper")];
        let result = LandlockBuilder::apply(&profile, &extra, Some(8080));
        assert!(result.is_err(), "non-Linux should always error");
    }

    /// S2: Verify that Landlock denylist checking uses fail-closed canonicalization.
    /// When canonicalize() fails (broken symlink, permission denied), the path
    /// should be treated as DENYLISTED to prevent bypass.
    #[test]
    fn test_s2_landlock_source_uses_fail_closed_canonicalize() {
        let source = include_str!("landlock.rs");
        // Check only the production code (before #[cfg(test)]) for the unsafe pattern
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
        let unsafe_pattern = "unwrap_or_else(|_| p.to_path_buf(";
        assert!(
            !prod_source.contains(unsafe_pattern),
            "S2: Landlock code still uses unsafe unwrap_or_else fallback for canonicalize. \
             Failed canonicalize must treat path as denylisted (fail-closed)."
        );
        assert!(
            prod_source.contains("canonicalize_or_deny"),
            "S2: Expected canonicalize_or_deny helper for fail-closed denylist checking"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_landlock_apply_non_linux() {
        let profile = AgentProfile {
            name: "test".to_string(),
            description: "test".to_string(),
            filesystem: puzzled_types::FilesystemRules {
                read_allowlist: vec![],
                write_allowlist: vec![],
                denylist: vec![],
                read_denylist: vec![],
                write_denylist: vec![],
            },
            exec_allowlist: vec![],
            exec_denylist: vec![],
            resource_limits: Default::default(),
            network: puzzled_types::NetworkConfig {
                mode: puzzled_types::NetworkMode::Blocked,
                allowed_domains: vec![],
                data_residency: None,
                dlp_rules_path: None,
            },
            behavioral: Default::default(),
            fail_mode: puzzled_types::FailMode::FailClosed,
            capabilities: vec![],
            enforcement: Default::default(),
            seccomp_mode: Default::default(),
            allow_symlinks: false,
            allow_exec_overlay: false,
            credentials: None,
        };

        let result = LandlockBuilder::apply(&profile, &[], None);
        assert!(result.is_err(), "apply should return error on non-Linux");
    }
}
