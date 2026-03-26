// SPDX-License-Identifier: Apache-2.0
//! Network isolation and gating for agent sandboxes.
//!
//! Implements three network modes:
//! - **Blocked**: Empty network namespace with no interfaces (existing behavior)
//! - **Gated**: veth pair (agent NS ↔ host NS) with nftables restricting agent
//!   to HTTP proxy only; proxy does domain-level filtering
//! - **Monitored**: veth pair with full routing, nftables logging
//!
//! The agent's environment gets `HTTP_PROXY` / `HTTPS_PROXY` pointing to the
//! in-namespace proxy endpoint for transparent domain filtering.

#[cfg(target_os = "linux")]
use crate::error::PuzzledError;
use crate::error::Result;
use puzzled_types::NetworkMode;
use std::net::SocketAddr;

/// Network configuration for a running sandbox.
pub struct NetworkSetup {
    /// Network mode in use.
    pub mode: NetworkMode,
    /// veth interface name on the host side (if Gated/Monitored).
    pub host_veth: Option<String>,
    /// veth interface name inside the agent namespace (if Gated/Monitored).
    pub agent_veth: Option<String>,
    /// Proxy address the agent should use (if Gated).
    pub proxy_addr: Option<SocketAddr>,
    /// nftables ruleset name (for cleanup).
    pub nft_table: Option<String>,
    /// Named network namespace (for cleanup).
    pub netns_name: Option<String>,
}

impl NetworkSetup {
    /// Set up network isolation for a branch.
    ///
    /// For Blocked mode, the named network namespace (created by the parent
    /// before clone3 and joined by the child via setns) provides an empty
    /// network namespace — no additional setup needed.
    ///
    /// For Gated/Monitored modes, creates a veth pair and configures nftables.
    /// `netns_name` is the named network namespace created by
    /// `create_named_netns()` before clone3.
    #[cfg(target_os = "linux")]
    pub fn configure(
        branch_id: &str,
        mode: NetworkMode,
        netns_name: &str,
        proxy_port: u16,
    ) -> Result<Self> {
        match mode {
            NetworkMode::Blocked => {
                tracing::info!(
                    branch_id,
                    "network mode: Blocked (empty namespace, no interfaces)"
                );
                Ok(Self {
                    mode,
                    host_veth: None,
                    agent_veth: None,
                    proxy_addr: None,
                    nft_table: None,
                    netns_name: None,
                })
            }
            NetworkMode::Gated => Self::setup_gated(branch_id, netns_name, proxy_port),
            NetworkMode::Monitored => Self::setup_monitored(branch_id, netns_name),
            NetworkMode::Unrestricted => {
                tracing::warn!(branch_id, "network mode: Unrestricted (no isolation)");
                Ok(Self {
                    mode,
                    host_veth: None,
                    agent_veth: None,
                    proxy_addr: None,
                    nft_table: None,
                    netns_name: None,
                })
            }
        }
    }

    /// Set up Gated network mode.
    ///
    /// Creates a veth pair, assigns IP addresses, and configures nftables
    /// to restrict the agent to only communicate with the HTTP proxy.
    #[cfg(target_os = "linux")]
    fn setup_gated(branch_id: &str, netns_name: &str, proxy_port: u16) -> Result<Self> {
        // M9: Generate deterministic, collision-resistant veth names using CRC32
        // of the full branch_id. This avoids collisions that occur when using
        // branch_id[..8] for branches with shared prefixes (e.g., UUIDs).
        // The CRC32 hash produces an 8-char hex string, fitting within IFNAMSIZ (15).
        let short_id = format!("{:08x}", crc32fast::hash(branch_id.as_bytes()));
        let host_veth = format!("vh{}", &short_id);
        let agent_veth = format!("va{}", &short_id);

        // L7: Randomized /30 subnet allocation to avoid IP collision when
        // multiple branches are active. Uses SHA256 of branch_id plus a random
        // salt for entropy. If a collision is detected (ip addr add fails),
        // retries with additional randomness up to MAX_SUBNET_RETRIES times.
        const MAX_SUBNET_RETRIES: u32 = 5;
        let mut retry = 0u32;

        // Clean up stale veth pair from a previous failed run (if any).
        // This prevents "RTNETLINK answers: File exists" errors when re-creating
        // veth pairs after a crash or test failure that left interfaces behind.
        // Q3: Log stale veth cleanup failures instead of silently discarding
        if let Err(e) = run_ip_cmd(&["link", "del", &host_veth]) {
            tracing::trace!(error = %e, veth = %host_veth, "Q3: stale veth cleanup failed (may not exist)");
        }

        // Create veth pair (before subnet assignment — subnet retries only re-do IP config)
        run_ip_cmd(&[
            "link",
            "add",
            &host_veth,
            "type",
            "veth",
            "peer",
            "name",
            &agent_veth,
        ])?;

        // Move agent-side veth into the agent's network namespace.
        // Uses the named netns (created from pidfd via setns) instead of PID-based
        // /proc/<pid>/ns/net, which may not be visible on some VM configurations.
        if let Err(e) = run_ip_cmd(&["link", "set", &agent_veth, "netns", netns_name]) {
            let _ = run_ip_cmd(&["link", "del", &host_veth]);
            return Err(PuzzledError::Network(format!(
                "moving veth to netns '{}': {}",
                netns_name, e
            )));
        }

        let (_host_ip, agent_ip, proxy_ip) = loop {
            let (octet3, octet4_base) = {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(branch_id.as_bytes());
                // Mix in retry counter for collision recovery
                hasher.update(retry.to_le_bytes());
                // Mix in PID and timestamp for additional entropy across restarts
                hasher.update(std::process::id().to_le_bytes());
                hasher.update(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos()
                        .to_le_bytes(),
                );
                let hash = hasher.finalize();
                (hash[0], hash[1] & 0xFC) // /30 subnet: 4 addresses per subnet
            };
            let h_ip = format!("10.42.{}.{}/30", octet3, octet4_base | 1);
            let a_ip = format!("10.42.{}.{}/30", octet3, octet4_base | 2);
            let p_ip = format!("10.42.{}.{}", octet3, octet4_base | 1);

            // Try to assign the IP — failure likely means subnet collision
            match run_ip_cmd(&["addr", "add", &h_ip, "dev", &host_veth]) {
                Ok(()) => break (h_ip, a_ip, p_ip),
                Err(e) => {
                    retry += 1;
                    if retry >= MAX_SUBNET_RETRIES {
                        return Err(PuzzledError::Network(format!(
                            "failed to allocate non-colliding /30 subnet after {} retries: {}",
                            MAX_SUBNET_RETRIES, e
                        )));
                    }
                    tracing::warn!(
                        branch_id,
                        retry,
                        subnet = format!("10.42.{}.{}/30", octet3, octet4_base),
                        "subnet collision detected, retrying with different hash"
                    );
                }
            }
        };
        run_ip_cmd(&["link", "set", &host_veth, "up"])?;

        // Configure agent side (via named netns)
        run_netns_ip(netns_name, &["addr", "add", &agent_ip, "dev", &agent_veth])?;
        run_netns_ip(netns_name, &["link", "set", &agent_veth, "up"])?;
        run_netns_ip(netns_name, &["link", "set", "lo", "up"])?;
        run_netns_ip(netns_name, &["route", "add", "default", "via", &proxy_ip])?;

        // G15: Validate proxy_ip matches expected 10.42.x.y pattern before
        // interpolation into nftables rules to prevent injection attacks.
        debug_assert!(
            proxy_ip.starts_with("10.42."),
            "G15: proxy_ip must be in 10.42.0.0/16 subnet"
        );
        if !proxy_ip.starts_with("10.42.") {
            return Err(PuzzledError::Network(format!(
                "G15: unexpected proxy_ip '{}' — must be in 10.42.0.0/16",
                proxy_ip
            )));
        }

        // H30: Validate short_id contains only hex chars before interpolation
        // into nftables rules to prevent injection attacks.
        if !short_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(PuzzledError::Network(format!(
                "H30: short_id '{}' contains non-hex characters",
                short_id
            )));
        }

        // Configure nftables: agent can only reach proxy on host side
        let nft_table = format!("agent_{}", short_id);
        let nft_rules = format!(
            r#"table inet {table} {{
    chain agent_output {{
        type filter hook output priority 0; policy drop;
        # Allow loopback
        oifname "lo" accept
        # Allow traffic to proxy
        ip daddr {proxy_ip} tcp dport {proxy_port} accept
        # U11: UDP 53 is intentional — DNS resolution for Gated mode. DNS tunneling is mitigated by the proxy's domain allowlist.
        ip daddr {proxy_ip} udp dport 53 accept
        # Allow established/related
        ct state established,related accept
        # Log and drop everything else
        log prefix "agent-drop: " drop
    }}
}}"#,
            table = nft_table,
            proxy_ip = proxy_ip,
            proxy_port = proxy_port,
        );

        // Apply nftables rules inside agent namespace
        run_netns_nft(netns_name, &nft_rules)?;

        let proxy_addr: SocketAddr = format!("{}:{}", proxy_ip, proxy_port)
            .parse()
            .map_err(|e| PuzzledError::Network(format!("invalid proxy addr: {}", e)))?;

        tracing::info!(
            branch_id,
            host_veth = %host_veth,
            agent_veth = %agent_veth,
            proxy_addr = %proxy_addr,
            "network mode: Gated (veth + nftables + proxy)"
        );

        Ok(Self {
            mode: NetworkMode::Gated,
            host_veth: Some(host_veth),
            agent_veth: Some(agent_veth),
            proxy_addr: Some(proxy_addr),
            nft_table: Some(nft_table),
            netns_name: Some(netns_name.to_string()),
        })
    }

    /// Set up Monitored network mode.
    ///
    /// Creates a veth pair with full routing but adds nftables logging
    /// for all network activity.
    #[cfg(target_os = "linux")]
    fn setup_monitored(branch_id: &str, netns_name: &str) -> Result<Self> {
        // M9: Use CRC32 hash for deterministic, collision-resistant veth names
        let short_id = format!("{:08x}", crc32fast::hash(branch_id.as_bytes()));
        let host_veth = format!("vh{}", &short_id);
        let agent_veth = format!("va{}", &short_id);

        // L7: Randomized /30 subnet allocation (see setup_gated for full rationale)
        const MAX_SUBNET_RETRIES: u32 = 5;
        let mut retry = 0u32;

        // Clean up stale veth pair from a previous failed run (if any).
        // Q3: Log stale veth cleanup failures instead of silently discarding
        if let Err(e) = run_ip_cmd(&["link", "del", &host_veth]) {
            tracing::trace!(error = %e, veth = %host_veth, "Q3: stale veth cleanup failed (may not exist)");
        }

        // Create veth pair
        run_ip_cmd(&[
            "link",
            "add",
            &host_veth,
            "type",
            "veth",
            "peer",
            "name",
            &agent_veth,
        ])?;

        // Move agent-side veth into the agent's network namespace.
        if let Err(e) = run_ip_cmd(&["link", "set", &agent_veth, "netns", netns_name]) {
            let _ = run_ip_cmd(&["link", "del", &host_veth]);
            return Err(PuzzledError::Network(format!(
                "moving veth to netns '{}': {}",
                netns_name, e
            )));
        }

        let (_host_ip, agent_ip, proxy_ip) = loop {
            let (octet3, octet4_base) = {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(branch_id.as_bytes());
                hasher.update(retry.to_le_bytes());
                hasher.update(std::process::id().to_le_bytes());
                hasher.update(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos()
                        .to_le_bytes(),
                );
                let hash = hasher.finalize();
                (hash[0], hash[1] & 0xFC)
            };
            let h_ip = format!("10.42.{}.{}/30", octet3, octet4_base | 1);
            let a_ip = format!("10.42.{}.{}/30", octet3, octet4_base | 2);
            let p_ip = format!("10.42.{}.{}", octet3, octet4_base | 1);

            match run_ip_cmd(&["addr", "add", &h_ip, "dev", &host_veth]) {
                Ok(()) => break (h_ip, a_ip, p_ip),
                Err(e) => {
                    retry += 1;
                    if retry >= MAX_SUBNET_RETRIES {
                        return Err(PuzzledError::Network(format!(
                            "failed to allocate non-colliding /30 subnet after {} retries: {}",
                            MAX_SUBNET_RETRIES, e
                        )));
                    }
                    tracing::warn!(
                        branch_id,
                        retry,
                        subnet = format!("10.42.{}.{}/30", octet3, octet4_base),
                        "subnet collision detected, retrying with different hash"
                    );
                }
            }
        };
        run_ip_cmd(&["link", "set", &host_veth, "up"])?;

        run_netns_ip(netns_name, &["addr", "add", &agent_ip, "dev", &agent_veth])?;
        run_netns_ip(netns_name, &["link", "set", &agent_veth, "up"])?;
        run_netns_ip(netns_name, &["link", "set", "lo", "up"])?;
        run_netns_ip(netns_name, &["route", "add", "default", "via", &proxy_ip])?;

        // T13: Enable IP forwarding in the agent's network namespace only (not globally).
        // Writing to the namespace-specific sysctl avoids modifying host-wide routing state.
        let ns_forward_path = format!("/proc/sys/net/ipv4/conf/{}/forwarding", host_veth);
        if let Err(e) = std::fs::write(&ns_forward_path, "1") {
            // U9: Removed global ip_forward fallback — too dangerous to leak forwarding to all interfaces
            tracing::error!(
                error = %e,
                path = %ns_forward_path,
                "failed to enable forwarding on veth — monitored network mode may not route traffic \
                 (global ip_forward fallback removed for safety)"
            );
        }

        // H30: Validate short_id contains only hex chars before interpolation
        // into nftables rules to prevent injection attacks.
        if !short_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(PuzzledError::Network(format!(
                "H30: short_id '{}' contains non-hex characters",
                short_id
            )));
        }

        // Nftables: log all agent network activity
        // V30: No nftables log rate limit — syslog rotation/rate-limiting should be configured
        // at the system level (journald RateLimitBurst, rsyslog rate limiting) for Monitored mode.
        let nft_table = format!("agent_{}", short_id);
        let nft_rules = format!(
            r#"table inet {table} {{
    chain agent_output {{
        type filter hook output priority 0; policy accept;
        log prefix "agent-monitor: " accept
    }}
}}"#,
            table = nft_table,
        );

        run_netns_nft(netns_name, &nft_rules)?;

        tracing::info!(
            branch_id,
            host_veth = %host_veth,
            "network mode: Monitored (veth + logging)"
        );

        Ok(Self {
            mode: NetworkMode::Monitored,
            host_veth: Some(host_veth),
            agent_veth: Some(agent_veth),
            proxy_addr: None,
            nft_table: Some(nft_table),
            netns_name: Some(netns_name.to_string()),
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn configure(
        _branch_id: &str,
        _mode: NetworkMode,
        _netns_name: &str,
        _proxy_port: u16,
    ) -> Result<Self> {
        Err(crate::error::PuzzledError::Sandbox(
            "Network namespace setup requires Linux".to_string(),
        ))
    }

    /// Clean up network resources for a branch.
    pub fn cleanup(&self) {
        #[cfg(target_os = "linux")]
        {
            // Removing the host veth automatically removes the peer
            if let Some(ref veth) = self.host_veth {
                let _ = run_ip_cmd(&["link", "del", veth]);
            }
            // Clean up named network namespace
            if let Some(ref name) = self.netns_name {
                delete_named_netns(name);
            }
            // nftables table is inside the namespace and dies with it
        }
    }

    /// Get environment variables the agent process should have set.
    pub fn agent_env(&self) -> Vec<(String, String)> {
        let mut env = Vec::new();
        if let Some(addr) = self.proxy_addr {
            let proxy_url = format!("http://{}", addr);
            env.push(("HTTP_PROXY".to_string(), proxy_url.clone()));
            env.push(("HTTPS_PROXY".to_string(), proxy_url.clone()));
            env.push(("http_proxy".to_string(), proxy_url.clone()));
            env.push(("https_proxy".to_string(), proxy_url));
        }
        env
    }
}

// ---------------------------------------------------------------------------
// Shell command helpers (Linux-only)
// ---------------------------------------------------------------------------

/// Run an `ip` command.
#[cfg(target_os = "linux")]
fn run_ip_cmd(args: &[&str]) -> Result<()> {
    let output = std::process::Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| PuzzledError::Network(format!("running ip {}: {}", args.join(" "), e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(PuzzledError::Network(format!(
            "ip {} failed: {}",
            args.join(" "),
            stderr.trim()
        )));
    }
    Ok(())
}

/// Run an `ip` command inside a named network namespace via nsenter.
#[cfg(target_os = "linux")]
fn run_netns_ip(netns_name: &str, args: &[&str]) -> Result<()> {
    let netns_arg = format!("--net=/var/run/netns/{}", netns_name);
    let mut cmd = std::process::Command::new("nsenter");
    cmd.args([netns_arg.as_str(), "ip"]);
    cmd.args(args);

    let output = cmd
        .output()
        .map_err(|e| PuzzledError::Network(format!("nsenter ip {}: {}", args.join(" "), e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(PuzzledError::Network(format!(
            "nsenter ip {} failed: {}",
            args.join(" "),
            stderr.trim()
        )));
    }
    Ok(())
}

/// Apply nftables rules inside a named network namespace.
#[cfg(target_os = "linux")]
fn run_netns_nft(netns_name: &str, rules: &str) -> Result<()> {
    let netns_arg = format!("--net=/var/run/netns/{}", netns_name);
    let output = std::process::Command::new("nsenter")
        .args([netns_arg.as_str(), "nft", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(rules.as_bytes())?;
            }
            child.wait_with_output()
        })
        .map_err(|e| PuzzledError::Network(format!("nsenter nft: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(PuzzledError::Network(format!(
            "nft rules failed: {}",
            stderr.trim()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Named network namespace management (Linux-only)
// ---------------------------------------------------------------------------

/// Create a named network namespace using `ip netns add`.
///
/// This creates an empty network namespace with a persistent reference at
/// `/var/run/netns/<name>`. The parent calls this BEFORE clone3 so the
/// named netns is visible in the parent's mount namespace. The child then
/// joins it via `setns()`.
///
/// This approach avoids the problems with:
/// R4: Validate network namespace name to prevent path traversal.
/// Names must not contain '/', '\0', or '..' components.
#[allow(dead_code)] // called from #[cfg(target_os = "linux")] code only
fn validate_netns_name(name: &str) -> crate::error::Result<()> {
    use crate::error::PuzzledError;
    if name.is_empty() {
        return Err(PuzzledError::Network("netns name must not be empty".into()));
    }
    if name.contains('/') || name.contains('\0') || name.contains("..") {
        return Err(PuzzledError::Network(format!(
            "R4: netns name '{}' contains path traversal characters",
            name
        )));
    }
    if name.len() > 64 {
        return Err(PuzzledError::Network(format!(
            "R4: netns name too long ({} > 64)",
            name.len()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn create_named_netns(name: &str) -> Result<()> {
    // R4: Validate name before using in path construction
    validate_netns_name(name)?;

    // Clean up any stale netns from a previous failed run
    delete_named_netns(name);

    let output = std::process::Command::new("ip")
        .args(["netns", "add", name])
        .output()
        .map_err(|e| PuzzledError::Network(format!("running ip netns add {}: {}", name, e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(PuzzledError::Network(format!(
            "ip netns add {} failed: {}",
            name,
            stderr.trim()
        )));
    }

    // Verify the netns file exists
    let netns_path = format!("/var/run/netns/{}", name);
    if !std::path::Path::new(&netns_path).exists() {
        return Err(PuzzledError::Network(format!(
            "ip netns add {} succeeded but {} does not exist",
            name, netns_path
        )));
    }

    tracing::debug!(name, path = %netns_path, "created named network namespace");
    Ok(())
}

/// Non-Linux stub.
#[cfg(not(target_os = "linux"))]
pub fn create_named_netns(_name: &str) -> Result<()> {
    Ok(())
}

/// Delete a named network namespace.
#[cfg(target_os = "linux")]
pub fn delete_named_netns(name: &str) {
    // R4: Validate name to prevent path traversal in umount2/remove_file
    if name.contains('/') || name.contains('\0') || name.contains("..") || name.is_empty() {
        tracing::error!(name, "R4: rejecting netns delete with unsafe name");
        return;
    }
    let netns_path = format!("/var/run/netns/{}", name);
    if let Ok(path_c) = std::ffi::CString::new(netns_path.as_str()) {
        unsafe { libc::umount2(path_c.as_ptr(), libc::MNT_DETACH) };
    }
    // J4: Log unexpected remove_file errors instead of silently discarding
    if let Err(e) = std::fs::remove_file(&netns_path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(
                name,
                path = %netns_path,
                error = %e,
                "J4: unexpected error removing netns file"
            );
        }
    }
}

/// Non-Linux stub.
#[cfg(not(target_os = "linux"))]
pub fn delete_named_netns(_name: &str) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn test_blocked_mode_no_interfaces() {
        let setup =
            NetworkSetup::configure("test-branch", NetworkMode::Blocked, "test_netns", 8080)
                .unwrap();

        assert_eq!(setup.mode, NetworkMode::Blocked);
        assert!(setup.host_veth.is_none());
        assert!(setup.agent_veth.is_none());
        assert!(setup.proxy_addr.is_none());
        assert!(setup.nft_table.is_none());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_unrestricted_mode_no_interfaces() {
        let setup =
            NetworkSetup::configure("test-branch", NetworkMode::Unrestricted, "test_netns", 8080)
                .unwrap();

        assert_eq!(setup.mode, NetworkMode::Unrestricted);
        assert!(setup.host_veth.is_none());
        assert!(setup.proxy_addr.is_none());
    }

    #[test]
    fn test_agent_env_blocked_mode() {
        let setup = NetworkSetup {
            mode: NetworkMode::Blocked,
            host_veth: None,
            agent_veth: None,
            proxy_addr: None,
            nft_table: None,
            netns_name: None,
        };

        let env = setup.agent_env();
        assert!(env.is_empty());
    }

    #[test]
    fn test_agent_env_gated_mode() {
        let proxy_addr: std::net::SocketAddr = "10.42.0.1:8080".parse().unwrap();
        let setup = NetworkSetup {
            mode: NetworkMode::Gated,
            host_veth: Some("veth-h-abc".to_string()),
            agent_veth: Some("veth-a-abc".to_string()),
            proxy_addr: Some(proxy_addr),
            nft_table: Some("agent_abc".to_string()),
            netns_name: Some("test_netns".to_string()),
        };

        let env = setup.agent_env();
        assert_eq!(env.len(), 4);

        let http_proxy = env.iter().find(|(k, _)| k == "HTTP_PROXY").unwrap();
        assert_eq!(http_proxy.1, "http://10.42.0.1:8080");

        let https_proxy = env.iter().find(|(k, _)| k == "HTTPS_PROXY").unwrap();
        assert_eq!(https_proxy.1, "http://10.42.0.1:8080");
    }

    /// M9: Verify CRC32-based veth names are within IFNAMSIZ (15 chars) and deterministic.
    #[test]
    fn test_veth_name_within_ifnamsiz() {
        let branch_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
        let short_id = format!("{:08x}", crc32fast::hash(branch_id.as_bytes()));
        let host_veth = format!("vh{}", &short_id);
        let agent_veth = format!("va{}", &short_id);

        // IFNAMSIZ is 16 (including null terminator), so max 15 chars
        assert!(
            host_veth.len() <= 15,
            "host veth name exceeds IFNAMSIZ: {}",
            host_veth
        );
        assert!(
            agent_veth.len() <= 15,
            "agent veth name exceeds IFNAMSIZ: {}",
            agent_veth
        );

        // Deterministic: same input produces same output
        let short_id2 = format!("{:08x}", crc32fast::hash(branch_id.as_bytes()));
        assert_eq!(short_id, short_id2, "CRC32 hash should be deterministic");

        // Different inputs produce different outputs
        let other_id = "different-branch-id";
        let other_short = format!("{:08x}", crc32fast::hash(other_id.as_bytes()));
        assert_ne!(
            short_id, other_short,
            "different branch_ids should produce different hashes"
        );
    }

    #[test]
    fn test_cleanup_no_panic_on_empty() {
        let setup = NetworkSetup {
            mode: NetworkMode::Blocked,
            host_veth: None,
            agent_veth: None,
            proxy_addr: None,
            nft_table: None,
            netns_name: None,
        };

        // Should not panic
        setup.cleanup();
    }

    #[test]
    fn test_cleanup_no_panic_with_stale_veth() {
        // Cleanup with nonexistent veth names should not panic
        let setup = NetworkSetup {
            mode: NetworkMode::Gated,
            host_veth: Some("nonexistent_veth".to_string()),
            agent_veth: Some("nonexistent_va".to_string()),
            proxy_addr: Some("10.42.0.1:8080".parse().unwrap()),
            nft_table: Some("agent_test".to_string()),
            netns_name: Some("nonexistent_ns".to_string()),
        };

        // Should not panic even with invalid names
        setup.cleanup();
    }

    #[test]
    fn test_agent_env_with_different_ports() {
        let proxy_addr: std::net::SocketAddr = "10.42.1.1:3128".parse().unwrap();
        let setup = NetworkSetup {
            mode: NetworkMode::Gated,
            host_veth: None,
            agent_veth: None,
            proxy_addr: Some(proxy_addr),
            nft_table: None,
            netns_name: None,
        };

        let env = setup.agent_env();
        assert_eq!(env.len(), 4);

        // Verify all four env vars point to the same proxy URL
        let expected = "http://10.42.1.1:3128";
        for (key, val) in &env {
            assert_eq!(val, expected, "env var {} has wrong value", key);
        }

        // Verify both upper and lower case variants are present
        let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"HTTP_PROXY"));
        assert!(keys.contains(&"HTTPS_PROXY"));
        assert!(keys.contains(&"http_proxy"));
        assert!(keys.contains(&"https_proxy"));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_network_configure_non_linux_returns_error() {
        // S26: Non-Linux stub must return Err for all modes to prevent
        // silently creating a non-functional NetworkSetup (consistent
        // with Landlock and SELinux stubs).
        for mode in [
            NetworkMode::Blocked,
            NetworkMode::Gated,
            NetworkMode::Monitored,
            NetworkMode::Unrestricted,
        ] {
            let result = NetworkSetup::configure("test", mode, "ns", 8080);
            assert!(
                result.is_err(),
                "non-Linux should return error for {:?}",
                mode
            );
            let err = result.err().unwrap().to_string();
            assert!(
                err.contains("requires Linux"),
                "error should mention Linux, got: {}",
                err
            );
        }
    }

    /// G15: proxy_ip must be validated to be in the 10.42.0.0/16 subnet
    /// before interpolation into nftables rules.
    #[test]
    fn test_g15_proxy_ip_validated() {
        let source = include_str!("network.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];

        // Find the nft_rules section in setup_gated
        let nft_idx = production_code
            .find("nft_rules")
            .expect("G15: must have nft_rules in production code");
        let before_nft = &production_code[..nft_idx];

        // There must be a validation of proxy_ip against 10.42. prefix
        assert!(
            before_nft.contains("10.42.")
                && (before_nft.contains("starts_with") || before_nft.contains("proxy_ip")),
            "G15: proxy_ip must be validated to start with '10.42.' before \
             interpolation into nftables rules to prevent injection.\n\
             Searched in code before nft_rules."
        );

        // More specific: check that there's a starts_with("10.42.") check
        // in the setup_gated function
        let gated_fn = production_code
            .find("fn setup_gated")
            .expect("G15: must have setup_gated function");
        let gated_body = &production_code[gated_fn..nft_idx];
        assert!(
            gated_body.contains(r#"starts_with("10.42.")"#),
            "G15: setup_gated must validate proxy_ip with starts_with(\"10.42.\") \
             before nftables rule interpolation.\nFunction body:\n{}",
            &gated_body[gated_body.len().saturating_sub(300)..]
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_create_named_netns_non_linux() {
        // Non-Linux stub should succeed (no-op)
        let result = create_named_netns("test_ns");
        assert!(result.is_ok());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_delete_named_netns_non_linux() {
        // Non-Linux stub should not panic
        delete_named_netns("test_ns");
    }

    #[test]
    fn test_crc32_veth_names_different_branches() {
        // Verify different branch IDs produce different veth names
        let branches = [
            "branch-1",
            "branch-2",
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "aaaaaaaa-bbbb-cccc-dddd-ffffffffffff",
        ];

        let mut names: std::collections::HashSet<String> = std::collections::HashSet::new();
        for branch in &branches {
            let short_id = format!("{:08x}", crc32fast::hash(branch.as_bytes()));
            let host_veth = format!("vh{}", &short_id);
            assert!(
                names.insert(host_veth.clone()),
                "collision detected for branch {}",
                branch
            );
        }
    }

    /// S33: Verify that ip_forward write does not use `let _ =` to silently
    /// discard errors. Failed ip_forward means no routing in monitored mode.
    #[test]
    fn test_s33_ip_forward_not_silent() {
        let source = include_str!("network.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        // Find the ip_forward write and verify it's not silenced with `let _ =`
        for (i, line) in production_code.lines().enumerate() {
            if line.contains("ip_forward") && line.trim().starts_with("let _ =") {
                panic!(
                    "S33: ip_forward write at line {} uses `let _ =` which silently \
                     discards errors. Use `if let Err(e) = ...` with logging instead.\n\
                     Line: {}",
                    i + 1,
                    line.trim()
                );
            }
        }
    }

    /// R4: validate_netns_name must reject path traversal characters.
    #[test]
    #[cfg(target_os = "linux")]
    fn test_r4_netns_name_rejects_path_traversal() {
        assert!(super::validate_netns_name("agentns_12345678").is_ok());
        assert!(super::validate_netns_name("../etc/passwd").is_err());
        assert!(super::validate_netns_name("name/with/slash").is_err());
        assert!(super::validate_netns_name("").is_err());
        assert!(super::validate_netns_name("name\0null").is_err());
        assert!(super::validate_netns_name("name..traversal").is_err());
        let long = "a".repeat(65);
        assert!(super::validate_netns_name(&long).is_err());
    }

    /// J4: Verify no bare `let _ = std::fs::remove_file` in production code.
    #[test]
    fn test_j4_no_silent_remove_file() {
        let source = include_str!("network.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        assert!(
            !production_code.contains("let _ = std::fs::remove_file"),
            "J4: production code must not use `let _ = std::fs::remove_file` — \
             errors other than NotFound must be logged"
        );
    }

    /// H30: Verify short_id is validated for hex-only chars before nft interpolation.
    #[test]
    fn test_h30_short_id_hex_validation() {
        let source = include_str!("network.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];
        // Both setup_gated and setup_monitored must validate short_id
        assert!(
            production_code.contains("is_ascii_hexdigit"),
            "H30: short_id must be validated to contain only hex characters \
             before interpolation into nftables rules"
        );
        // Check it appears in both functions
        let gated_fn = production_code
            .find("fn setup_gated")
            .expect("must have setup_gated");
        let monitored_fn = production_code
            .find("fn setup_monitored")
            .expect("must have setup_monitored");
        let gated_body = &production_code[gated_fn..monitored_fn];
        let monitored_body = &production_code[monitored_fn..];
        assert!(
            gated_body.contains("is_ascii_hexdigit"),
            "H30: setup_gated must validate short_id for hex chars"
        );
        assert!(
            monitored_body.contains("is_ascii_hexdigit"),
            "H30: setup_monitored must validate short_id for hex chars"
        );
    }
}
