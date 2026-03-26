// SPDX-License-Identifier: Apache-2.0
// Functions in this module are pub(crate) for test access but only called from
// libseccomp_v2_5-gated code at runtime, so they appear unused without that cfg.
#![allow(dead_code)]

use puzzled_types::AgentProfile;

#[cfg(target_os = "linux")]
use super::procmem::read_sockaddr_from_proc_mem;
#[cfg(target_os = "linux")]
use super::procmem::read_string_from_proc_mem;

// ---------------------------------------------------------------------------
// Pure matching functions (testable without root/real processes)
// ---------------------------------------------------------------------------

/// Check if a path matches an exec allowlist.
///
/// Supports exact matches and trailing glob patterns (e.g., "/usr/bin/*").
///
/// C3: Callers must canonicalize paths before calling this function.
/// The debug_assert catches path traversal attempts in development/testing.
/// In production, `validate_execve_with_path` canonicalizes via `/proc/<pid>/root`.
pub(crate) fn path_matches_exec_allowlist(path: &str, allowlist: &[String]) -> bool {
    debug_assert!(
        !path.contains("/../") && !path.ends_with("/.."),
        "C3: path_matches_exec_allowlist called with non-canonical path containing '..': {path}"
    );
    if allowlist.is_empty() {
        return false;
    }
    allowlist.iter().any(|pattern| {
        if pattern.ends_with('*') {
            let prefix = &pattern[..pattern.len() - 1];
            path.starts_with(prefix)
        } else {
            path == *pattern
        }
    })
}

/// Check if a path matches an exec denylist.
///
/// Deny overrides allow — if a path matches the denylist, it is blocked
/// regardless of the allowlist.
///
/// C3: Callers must canonicalize paths before calling this function.
pub(crate) fn path_matches_exec_denylist(path: &str, denylist: &[String]) -> bool {
    debug_assert!(
        !path.contains("/../") && !path.ends_with("/.."),
        "C3: path_matches_exec_denylist called with non-canonical path containing '..': {path}"
    );
    if denylist.is_empty() {
        return false;
    }
    denylist.iter().any(|pattern| {
        if pattern.ends_with('*') {
            let prefix = &pattern[..pattern.len() - 1];
            path.starts_with(prefix)
        } else {
            path == *pattern
        }
    })
}

/// Evaluate exec policy: allowed by allowlist AND not denied by denylist.
pub(crate) fn is_exec_allowed(path: &str, profile: &AgentProfile) -> bool {
    if !path_matches_exec_allowlist(path, &profile.exec_allowlist) {
        return false;
    }
    !path_matches_exec_denylist(path, &profile.exec_denylist)
}

/// Check if a connect destination should be allowed under the given network config.
///
/// `ip` is the destination IP address string, `is_loopback` indicates localhost.
pub(crate) fn is_connect_allowed_by_policy(
    ip: &str,
    is_loopback: bool,
    profile: &AgentProfile,
) -> bool {
    use puzzled_types::NetworkMode;

    match profile.network.mode {
        NetworkMode::Blocked => false,
        NetworkMode::Unrestricted | NetworkMode::Monitored => true,
        NetworkMode::Gated => {
            if is_loopback {
                return true;
            }
            profile
                .network
                .allowed_domains
                .iter()
                .any(|domain| *domain == ip || domain == "*")
        }
    }
}

/// Check if a bind operation should be allowed.
///
/// In Gated mode, only loopback binds are permitted.
pub(crate) fn is_bind_allowed_by_policy(
    _ip: &str,
    is_loopback: bool,
    profile: &AgentProfile,
) -> bool {
    use puzzled_types::NetworkMode;

    match profile.network.mode {
        NetworkMode::Blocked => false,
        NetworkMode::Unrestricted | NetworkMode::Monitored => true,
        NetworkMode::Gated => is_loopback,
    }
}

/// Validate an execve syscall against the profile's exec_allowlist.
///
/// Reads the binary path from the agent's memory, canonicalizes it to
/// resolve path traversal (e.g., `/usr/bin/../../etc/shadow`), and checks
/// against allowed patterns. Landlock remains the backstop for filesystem
/// access, but this prevents obvious seccomp bypasses.
#[cfg(target_os = "linux")]
#[allow(dead_code)] // H6: Kept for fallback; validate_execve_with_path is preferred
pub(super) fn validate_execve(pid: u32, path_addr: usize, profile: &AgentProfile) -> bool {
    let raw_path = match read_string_from_proc_mem(pid, path_addr) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(pid, error = %e, "failed to read execve path, denying");
            return false;
        }
    };
    validate_execve_with_path(pid, &raw_path, profile)
}

/// H6: Validate an execve syscall using a pre-read path string.
///
/// This variant accepts a path that has already been read from
/// `/proc/<pid>/mem`, eliminating the TOCTOU window that exists when the
/// path is read separately by `validate_execve()` and `inject_fd_for_execve()`.
/// The caller reads the path once and passes the same string to both functions.
///
/// Canonicalizes the path to resolve path traversal, then checks against
/// the profile's exec_allowlist and exec_denylist.
#[cfg(target_os = "linux")]
pub(super) fn validate_execve_with_path(pid: u32, raw_path: &str, profile: &AgentProfile) -> bool {
    // If exec_allowlist is empty, deny all execs
    if profile.exec_allowlist.is_empty() {
        tracing::info!(pid, path = %raw_path, "execve denied: empty allowlist");
        return false;
    }

    // Canonicalize the path to resolve traversal (.. components).
    // Use /proc/<pid>/root to resolve relative to the agent's filesystem view.
    let path = match std::fs::canonicalize(format!("/proc/{}/root/{}", pid, raw_path)) {
        Ok(canonical) => {
            // Strip the /proc/<pid>/root prefix to get the agent-relative path
            let root_prefix = format!("/proc/{}/root", pid);
            canonical
                .to_string_lossy()
                .strip_prefix(&root_prefix)
                .unwrap_or(&canonical.to_string_lossy())
                .to_string()
        }
        Err(_) => {
            // M2: Normalize path traversal components even when canonicalize fails.
            // Landlock is the backstop defense, but seccomp should not be weakened.
            normalize_path_components(raw_path)
        }
    };

    if path != raw_path {
        tracing::debug!(
            pid,
            raw = %raw_path,
            canonical = %path,
            "execve path canonicalized (traversal resolved)"
        );
    }

    // Check if the path matches any allowed pattern.
    // Check BOTH the raw path and the canonical path. Allowlist entries
    // like "/usr/bin/python3" should match even when the binary is a
    // symlink to "/usr/bin/python3.13". The raw path is what the profile
    // author specified; the canonical path catches traversal bypasses.
    let matches_allowlist = |p: &str| -> bool {
        profile.exec_allowlist.iter().any(|pattern| {
            if pattern.ends_with('*') {
                let prefix = &pattern[..pattern.len() - 1];
                p.starts_with(prefix)
            } else {
                p == *pattern
            }
        })
    };
    let allowed = matches_allowlist(&path) || matches_allowlist(raw_path);

    // Check exec_denylist — deny overrides allow
    // P2-N4: Check both canonical path AND raw_path against denylist,
    // mirroring the allowlist pattern to prevent bypass via symlinks.
    if allowed && !profile.exec_denylist.is_empty() {
        let matches_denylist = |p: &str| -> bool {
            profile.exec_denylist.iter().any(|pattern| {
                if pattern.ends_with('*') {
                    let prefix = &pattern[..pattern.len() - 1];
                    p.starts_with(prefix)
                } else {
                    p == *pattern
                }
            })
        };
        let denied = matches_denylist(&path) || matches_denylist(raw_path);
        if denied {
            tracing::info!(
                pid,
                path = %path,
                raw_path = %raw_path,
                "execve denied: matched exec_denylist (deny overrides allow)"
            );
            return false;
        }
    }

    if !allowed {
        tracing::info!(
            pid,
            path = %path,
            "execve denied: not in allowlist"
        );
    } else {
        tracing::debug!(
            pid,
            path = %path,
            "execve allowed"
        );
    }

    allowed
}

/// Validate a connect syscall against the profile's network config.
///
/// Reads the sockaddr from agent memory and checks against allowed domains/IPs.
#[cfg(target_os = "linux")]
pub(super) fn validate_connect(
    pid: u32,
    addr: usize,
    len: usize,
    profile: &AgentProfile,
    credential_proxy: Option<&crate::seccomp_handler::CredentialProxyContext>,
) -> bool {
    use puzzled_types::NetworkMode;

    match profile.network.mode {
        NetworkMode::Blocked => {
            tracing::info!(pid, "connect denied: network mode is Blocked");
            return false;
        }
        NetworkMode::Unrestricted | NetworkMode::Monitored => {
            // Still check gateway blocking for credential proxy even in unrestricted mode
        }
        NetworkMode::Gated => {
            // Fall through to domain checking
        }
    }

    let (family, ip, port) = match read_sockaddr_from_proc_mem(pid, addr, len) {
        Ok(sa) => sa,
        Err(e) => {
            tracing::warn!(pid, error = %e, "failed to read connect sockaddr, denying");
            return false;
        }
    };

    // §3.4 G23: Block direct connections to the credential proxy gateway.
    // Agents must use the transparent proxy (DNAT) — direct connections to the
    // gateway IP on the proxy port range bypass credential isolation.
    if let Some(ctx) = credential_proxy {
        if ctx.enabled {
            // Parse the IP from sockaddr for type-safe comparison. This handles
            // IPv6 normalization (e.g., ::ffff:10.0.2.2 vs 10.0.2.2) correctly.
            let is_gateway = ip
                .parse::<std::net::IpAddr>()
                .is_ok_and(|parsed| parsed == ctx.proxy_gateway_ip);
            if is_gateway {
                // Block connections to any port in the global proxy port range
                // (cross-branch defense: prevents connecting to another branch's proxy)
                if ctx.global_port_range.contains(&port) {
                    tracing::error!(
                        pid,
                        ip = %ip,
                        port,
                        "§3.4 G23: BLOCKED — direct connect to credential proxy gateway \
                         on proxy port range (bypass attempt)"
                    );
                    return false;
                }
                // Block connections to gateway on non-proxied ports too — only DNAT'd
                // traffic (on proxied_ports like 80/443) should reach the gateway
                if !ctx.proxied_ports.contains(&port) {
                    tracing::error!(
                        pid,
                        ip = %ip,
                        port,
                        "§3.4 G23: BLOCKED — direct connect to credential proxy gateway \
                         on non-proxied port"
                    );
                    return false;
                }
            }
        }
    }

    // For Unrestricted/Monitored, allow after gateway check
    if matches!(
        profile.network.mode,
        NetworkMode::Unrestricted | NetworkMode::Monitored
    ) {
        return true;
    }

    // H7: AF_UNIX sockets are no longer unconditionally allowed.
    // Gate through policy — only allow if the socket path matches the
    // profile's allowed_domains list (which may include Unix socket paths).
    // If no Unix socket paths are configured, block AF_UNIX by default
    // (fail-closed). This prevents agents from connecting to arbitrary
    // Unix domain sockets (e.g., Docker socket, D-Bus system bus).
    if family as i32 == libc::AF_UNIX {
        // Check if any allowed_domains entry looks like a Unix socket path
        let unix_allowed = profile.network.allowed_domains.iter().any(|entry| {
            // Wildcard allows everything including Unix sockets
            entry == "*"
            // Entries starting with "/" are treated as Unix socket path patterns
            || (entry.starts_with('/') && {
                if entry.ends_with('*') {
                    ip.starts_with(&entry[..entry.len() - 1])
                } else {
                    ip == *entry
                }
            })
        });
        if !unix_allowed {
            tracing::warn!(
                pid,
                socket_path = %ip,
                "connect denied: AF_UNIX socket not in allowed_domains (H7: no longer unconditionally allowed)"
            );
        } else {
            tracing::debug!(pid, socket_path = %ip, "AF_UNIX connect allowed by policy");
        }
        return unix_allowed;
    }

    // U8: Block connect to 0.0.0.0 (INADDR_ANY) — should not be a connect target
    if ip == "0.0.0.0" {
        tracing::warn!(
            pid,
            "connect denied: 0.0.0.0 (INADDR_ANY) is not a valid connect target"
        );
        return false;
    }

    // U13: Loopback connections are always allowed — agents need localhost for proxy communication
    // T8: Include IPv4-mapped IPv6 loopback; T10: remove dead "::1" (formatter uses expanded form)
    if ip == "127.0.0.1" || ip == "0:0:0:0:0:0:0:1" || ip == "0:0:0:0:0:ffff:7f00:1" {
        return true;
    }

    // For Gated mode, check against allowed domains list.
    // Since we have an IP address, not a hostname, we check if the IP matches
    // any allowed domain. In practice, the HTTP proxy handles domain-level
    // filtering; seccomp connect gating catches direct IP connections.
    let allowed = profile.network.allowed_domains.iter().any(|domain| {
        // Check if the domain entry is an IP address or CIDR
        *domain == ip || domain == "*"
    });

    if !allowed {
        tracing::info!(
            pid,
            ip = %ip,
            port,
            "connect denied: not in allowed domains"
        );
    } else {
        tracing::debug!(pid, ip = %ip, port, "connect allowed");
    }

    allowed
}

/// Validate a bind syscall against the profile's network config.
///
/// Checks if the agent is allowed to bind to the requested port.
#[cfg(target_os = "linux")]
pub(super) fn validate_bind(pid: u32, addr: usize, len: usize, profile: &AgentProfile) -> bool {
    use puzzled_types::NetworkMode;

    match profile.network.mode {
        NetworkMode::Blocked => {
            tracing::info!(pid, "bind denied: network mode is Blocked");
            return false;
        }
        NetworkMode::Unrestricted | NetworkMode::Monitored => {
            return true;
        }
        NetworkMode::Gated => {
            // Fall through to validation
        }
    }

    let (_family, ip, port) = match read_sockaddr_from_proc_mem(pid, addr, len) {
        Ok(sa) => sa,
        Err(e) => {
            tracing::warn!(pid, error = %e, "failed to read bind sockaddr, denying");
            return false;
        }
    };

    // V31: Port 0 binding allowed — ephemeral port in namespaced network is bounded
    // T8: Include IPv4-mapped IPv6 loopback; T10: remove dead "::1"
    if ip == "127.0.0.1" || ip == "0:0:0:0:0:0:0:1" || ip == "0:0:0:0:0:ffff:7f00:1" {
        return true;
    }

    // In Gated mode, deny binding to non-loopback addresses
    // Agents should only listen on loopback; external access goes through proxy
    tracing::info!(
        pid,
        ip = %ip,
        port,
        "bind denied: non-loopback bind in Gated mode"
    );
    false
}

/// M2: Normalize path by resolving `.` and `..` components without touching the filesystem.
/// This prevents path traversal attacks when `canonicalize()` fails (e.g., file doesn't exist yet).
fn normalize_path_components(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    format!("/{}", parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{create_restricted_profile, create_test_profile};

    // --- Exec allowlist matching ---

    #[test]
    fn test_exec_exact_match() {
        let profile = create_test_profile("test");
        assert!(is_exec_allowed("/usr/bin/python3", &profile));
        assert!(is_exec_allowed("/usr/bin/cat", &profile));
    }

    #[test]
    fn test_exec_glob_match() {
        let profile = create_test_profile("test");
        assert!(is_exec_allowed("/usr/local/bin/myapp", &profile));
        assert!(is_exec_allowed("/usr/local/bin/anything", &profile));
    }

    #[test]
    fn test_exec_not_in_allowlist() {
        let profile = create_test_profile("test");
        assert!(!is_exec_allowed("/usr/sbin/reboot", &profile));
        assert!(!is_exec_allowed("/bin/sh", &profile));
    }

    #[test]
    fn test_exec_empty_allowlist_denies_all() {
        let profile = create_restricted_profile();
        assert!(!is_exec_allowed("/usr/bin/python3", &profile));
        assert!(!is_exec_allowed("/bin/sh", &profile));
        assert!(!is_exec_allowed("", &profile));
    }

    #[test]
    fn test_exec_denylist_overrides_allowlist() {
        let profile = create_test_profile("test");
        // /usr/bin/rm is in the denylist
        assert!(!is_exec_allowed("/usr/bin/rm", &profile));
        // /usr/bin/cat is in the allowlist and NOT in the denylist
        assert!(is_exec_allowed("/usr/bin/cat", &profile));
    }

    #[test]
    fn test_exec_path_traversal_raw_string() {
        // C3: After adding the debug_assert, this test verifies that
        // canonicalized paths are handled correctly. The raw traversal
        // test is removed because validate_execve_with_path always
        // canonicalizes before calling path_matches_exec_allowlist.
        let allowlist = vec!["/usr/bin/*".to_string()];
        // After canonicalization, /usr/bin/../../etc/passwd becomes /etc/passwd
        // which should NOT match /usr/bin/*
        assert!(!path_matches_exec_allowlist("/etc/passwd", &allowlist));
        // A canonical path under /usr/bin/ should match
        assert!(path_matches_exec_allowlist("/usr/bin/python3", &allowlist));
    }

    // --- Connect policy ---

    #[test]
    fn test_connect_blocked_mode_denies_all() {
        let profile = create_restricted_profile();
        assert!(!is_connect_allowed_by_policy("1.2.3.4", false, &profile));
        assert!(!is_connect_allowed_by_policy("127.0.0.1", true, &profile));
    }

    #[test]
    fn test_connect_gated_allows_loopback() {
        let profile = create_test_profile("test");
        assert!(is_connect_allowed_by_policy("127.0.0.1", true, &profile));
    }

    #[test]
    fn test_connect_gated_denies_unknown_ip() {
        let profile = create_test_profile("test");
        assert!(!is_connect_allowed_by_policy("1.2.3.4", false, &profile));
    }

    #[test]
    fn test_connect_unrestricted_allows_all() {
        let mut profile = create_test_profile("test");
        profile.network.mode = puzzled_types::NetworkMode::Unrestricted;
        assert!(is_connect_allowed_by_policy("1.2.3.4", false, &profile));
    }

    #[test]
    fn test_connect_monitored_allows_all() {
        let mut profile = create_test_profile("test");
        profile.network.mode = puzzled_types::NetworkMode::Monitored;
        assert!(is_connect_allowed_by_policy("1.2.3.4", false, &profile));
    }

    // --- Bind policy ---

    #[test]
    fn test_bind_blocked_denies() {
        let profile = create_restricted_profile();
        assert!(!is_bind_allowed_by_policy("127.0.0.1", true, &profile));
    }

    #[test]
    fn test_bind_gated_allows_loopback() {
        let profile = create_test_profile("test");
        assert!(is_bind_allowed_by_policy("127.0.0.1", true, &profile));
    }

    #[test]
    fn test_bind_gated_denies_non_loopback() {
        let profile = create_test_profile("test");
        assert!(!is_bind_allowed_by_policy("0.0.0.0", false, &profile));
    }

    // --- Unix socket policy ---

    #[test]
    fn test_unix_socket_default_denied_in_gated() {
        let mut profile = create_test_profile("test");
        // allowed_domains has "example.com" — no unix socket paths
        profile.network.allowed_domains = vec!["example.com".to_string()];
        // Unix sockets should be denied by default in Gated mode
        // (tested via is_connect_allowed_by_policy since it checks mode)
        assert!(!is_connect_allowed_by_policy(
            "/var/run/docker.sock",
            false,
            &profile
        ));
    }

    // --- M2: Path normalization tests ---

    #[test]
    fn m2_normalize_path_components_resolves_traversal() {
        // M2: normalize_path_components must strip .. traversal components
        assert_eq!(
            normalize_path_components("/usr/bin/../../etc/passwd"),
            "/etc/passwd"
        );
        assert_eq!(
            normalize_path_components("/usr/bin/../sbin/reboot"),
            "/usr/sbin/reboot"
        );
        assert_eq!(
            normalize_path_components("/usr/bin/python3"),
            "/usr/bin/python3"
        );
        assert_eq!(normalize_path_components("/"), "/");
        assert_eq!(normalize_path_components("/a/b/c/../../d"), "/a/d");
        // Dots should be removed
        assert_eq!(
            normalize_path_components("/usr/./bin/./python3"),
            "/usr/bin/python3"
        );
        // Excessive .. should not go above root
        assert_eq!(
            normalize_path_components("/usr/../../../../etc/passwd"),
            "/etc/passwd"
        );
    }

    #[test]
    fn m2_canonicalize_fallback_normalizes_path() {
        let source = include_str!("validate.rs");
        let production_code = source
            .split("#[cfg(test)]")
            .next()
            .expect("should have production code before test module");
        // The fallback must NOT use raw_path directly — it must normalize
        assert!(
            !production_code.contains("raw_path.to_string()\n        }"),
            "M2: canonicalize fallback must not use raw_path directly — must normalize"
        );
        assert!(
            production_code.contains("normalize_path_components(raw_path)"),
            "M2: canonicalize fallback must call normalize_path_components"
        );
    }
}
