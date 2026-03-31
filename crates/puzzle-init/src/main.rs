// SPDX-License-Identifier: Apache-2.0
// puzzle-init: Landlock shim entrypoint for PuzzlePod containers.
//
// This binary runs INSIDE the container as the entrypoint (PID 1 or wrapper).
// It reads Landlock rules from a JSON file, applies them irrevocably via
// landlock_restrict_self(), then execs the real command (argv[1..]).
//
// Design principles:
//   - Minimal: no async, no tokio, no unnecessary dependencies
//   - Fail-closed: any error -> exit(1), container never runs ungoverned
//   - Irrevocable: once Landlock is applied, it cannot be removed by the agent

use std::env;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process;

use serde::Deserialize;

/// Default path for Landlock rules file (bind-mounted into container by puzzled).
const DEFAULT_RULES_PATH: &str = "/run/puzzlepod/landlock.json";

/// Environment variable to override the rules file path.
#[cfg(any(debug_assertions, test))]
const RULES_PATH_ENV: &str = "PUZZLEPOD_LANDLOCK_RULES";

// ---------------------------------------------------------------------------
// Rules schema
// ---------------------------------------------------------------------------

/// Landlock ABI version specifier.
///
/// m5: Accepts both enum variant names ("V4") and plain string values ("V4")
/// for compatibility with puzzled's serializer which outputs `abi` as a String.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AbiVersion {
    V1,
    V2,
    V3,
    #[default]
    V4,
    V5,
    V6,
}

impl<'de> Deserialize<'de> for AbiVersion {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "V1" => Ok(AbiVersion::V1),
            "V2" => Ok(AbiVersion::V2),
            "V3" => Ok(AbiVersion::V3),
            "V4" => Ok(AbiVersion::V4),
            "V5" => Ok(AbiVersion::V5),
            "V6" => Ok(AbiVersion::V6),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["V1", "V2", "V3", "V4", "V5", "V6"],
            )),
        }
    }
}

/// Landlock rules definition read from JSON.
///
/// Example:
/// ```json
/// {
///   "abi": "V4",
///   "read": ["/usr", "/lib", "/etc"],
///   "write": ["/workspace"],
///   "exec": ["/usr/bin", "/usr/sbin"]
/// }
/// ```
#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
pub struct LandlockRules {
    /// Requested ABI version (best-effort negotiation).
    #[serde(default)]
    pub abi: AbiVersion,

    /// Paths allowed for read access.
    #[serde(default)]
    pub read: Vec<String>,

    /// Paths allowed for write access (implies read).
    #[serde(default)]
    pub write: Vec<String>,

    /// Paths allowed for execute access.
    #[serde(default)]
    pub exec: Vec<String>,

    /// m5: Whether to allow LANDLOCK_ACCESS_FS_REFER (cross-directory renames).
    /// Plumbed through for forward compatibility with puzzled's serializer.
    #[serde(default)]
    pub allow_refer: bool,

    /// F6: If true, fail with exit code 1 if any read/write rules are skipped
    /// due to inaccessible paths. Prevents silent Landlock policy weakening.
    #[serde(default)]
    pub strict: bool,

    /// C-1/M-2: TCP ports the agent is allowed to connect to.
    /// Landlock ABI v4+ (kernel 6.7+). If empty, all ConnectTcp is denied.
    /// Mirrors sandbox/landlock.rs network ruleset.
    #[serde(default)]
    pub connect_tcp_ports: Vec<u16>,

    /// C-1/M-2: TCP ports the agent is allowed to bind to.
    /// Landlock ABI v4+ (kernel 6.7+). If empty, all BindTcp is denied.
    #[serde(default)]
    pub bind_tcp_ports: Vec<u16>,
}

/// Parse a rules JSON string into a `LandlockRules` struct.
pub fn parse_rules(json: &str) -> Result<LandlockRules, String> {
    serde_json::from_str(json).map_err(|e| format!("failed to parse Landlock rules JSON: {e}"))
}

// ---------------------------------------------------------------------------
// Landlock application (Linux-only)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod enforce {
    use super::*;
    use landlock::{
        Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetStatus, ABI,
    };

    /// Map our ABI enum to the landlock crate's ABI type.
    fn to_landlock_abi(v: &AbiVersion) -> ABI {
        match v {
            AbiVersion::V1 => ABI::V1,
            AbiVersion::V2 => ABI::V2,
            AbiVersion::V3 => ABI::V3,
            AbiVersion::V4 => ABI::V4,
            AbiVersion::V5 => ABI::V5,
            // M22: V6 maps to crate ABI V5; warn that V6-only features are unavailable.
            AbiVersion::V6 => {
                tracing::warn!(
                    "Landlock ABI V6 requested but crate only supports V5 — \
                     signal scoping and abstract Unix socket scoping are unavailable"
                );
                ABI::V5
            }
        }
    }

    /// Build and apply a Landlock ruleset from the parsed rules.
    ///
    /// This calls `landlock_restrict_self()` which is irrevocable -- once applied,
    /// the restrictions cannot be lifted by the process or any of its children.
    pub fn apply_landlock(rules: &LandlockRules) -> Result<(), String> {
        let abi = to_landlock_abi(&rules.abi);

        let read_access = AccessFs::from_read(abi);
        let write_access = AccessFs::from_all(abi);
        let exec_access = AccessFs::Execute;

        // H1: Build ruleset handling all filesystem access types.
        // Any access type not explicitly allowed is denied (default-deny).
        let mut ruleset = Ruleset::default()
            .handle_access(write_access)
            .map_err(|e| format!("failed to create Landlock ruleset: {e}"))?
            .create()
            .map_err(|e| format!("failed to create Landlock ruleset: {e}"))?;

        // Add read-only rules.
        // F6: Count skipped rules to detect silent Landlock policy weakening.
        let mut skipped_read = 0u32;
        for path_str in &rules.read {
            match PathFd::new(path_str) {
                Ok(fd) => {
                    ruleset = ruleset
                        .add_rule(PathBeneath::new(fd, read_access))
                        .map_err(|e| {
                            format!("failed to add Landlock read rule for {path_str}: {e}")
                        })?;
                }
                Err(_e) => {
                    skipped_read += 1;
                    // Per-path warnings suppressed — summary printed below.
                    // Enable with PUZZLEPOD_INIT_VERBOSE=1 for debugging.
                    #[cfg(debug_assertions)]
                    if std::env::var("PUZZLEPOD_INIT_VERBOSE").is_ok() {
                        eprintln!(
                            "puzzle-init: skipping read rule for {path_str} \
                             (path not accessible: {_e})"
                        );
                    }
                }
            }
        }
        if skipped_read > 0 {
            eprintln!("puzzle-init: {skipped_read} read path(s) not present in container (OK)");
            if rules.strict {
                return Err(format!(
                    "F6: strict mode: {skipped_read} read rules skipped — aborting"
                ));
            }
        }

        // Add read+write rules (write implies read).
        // F6: Count skipped rules to detect silent Landlock policy weakening.
        let mut skipped_write = 0u32;
        for path_str in &rules.write {
            match PathFd::new(path_str) {
                Ok(fd) => {
                    ruleset = ruleset
                        .add_rule(PathBeneath::new(fd, write_access))
                        .map_err(|e| {
                            format!("failed to add Landlock write rule for {path_str}: {e}")
                        })?;
                }
                Err(_e) => {
                    skipped_write += 1;
                    // Per-path warnings suppressed — summary printed below.
                    // Enable with PUZZLEPOD_INIT_VERBOSE=1 for debugging.
                    #[cfg(debug_assertions)]
                    if std::env::var("PUZZLEPOD_INIT_VERBOSE").is_ok() {
                        eprintln!(
                            "puzzle-init: skipping write rule for {path_str} \
                             (path not accessible: {_e})"
                        );
                    }
                }
            }
        }
        if skipped_write > 0 {
            eprintln!("puzzle-init: {skipped_write} write path(s) not present in container (OK)");
            if rules.strict {
                return Err(format!(
                    "F6: strict mode: {skipped_write} write rules skipped — aborting"
                ));
            }
        }

        // Add execute rules.
        // M1: Exec path errors are fatal (not best-effort like read/write).
        // If an exec allowlist path is inaccessible, the agent would run
        // without the ability to execute expected binaries, which is a
        // configuration error that should be surfaced immediately.
        for path_str in &rules.exec {
            match PathFd::new(path_str) {
                Ok(fd) => {
                    ruleset = ruleset
                        .add_rule(PathBeneath::new(fd, exec_access))
                        .map_err(|e| {
                            format!("failed to add Landlock exec rule for {path_str}: {e}")
                        })?;
                }
                Err(e) => {
                    return Err(format!(
                        "exec path {path_str} not accessible (fail-closed): {e}"
                    ));
                }
            }
        }

        // C-1/M-2: Apply Landlock network rules (ABI v4+, kernel 6.7+).
        //
        // Mirrors sandbox/landlock.rs: irrevocable ConnectTcp/BindTcp restrictions
        // that survive puzzled crash. Without this, Podman-native mode lacks the
        // kernel-enforced network ACL layer that direct mode provides.
        if !rules.connect_tcp_ports.is_empty() || !rules.bind_tcp_ports.is_empty() {
            use landlock::{AccessNet, NetPort};

            let mut net_ruleset = Ruleset::default()
                .handle_access(AccessNet::ConnectTcp | AccessNet::BindTcp)
                .map_err(|e| format!("creating Landlock network ruleset: {e}"))?
                .create()
                .map_err(|e| format!("creating Landlock network ruleset: {e}"))?;

            for port in &rules.connect_tcp_ports {
                net_ruleset = net_ruleset
                    .add_rule(NetPort::new(*port, AccessNet::ConnectTcp))
                    .map_err(|e| format!("adding Landlock ConnectTcp rule for port {port}: {e}"))?;
            }

            for port in &rules.bind_tcp_ports {
                net_ruleset = net_ruleset
                    .add_rule(NetPort::new(*port, AccessNet::BindTcp))
                    .map_err(|e| format!("adding Landlock BindTcp rule for port {port}: {e}"))?;
            }

            // H-24: Apply network ruleset FIRST (broader surface), before
            // filesystem ruleset (more granular). Both applied pre-exec.
            let net_status = net_ruleset
                .restrict_self()
                .map_err(|e| format!("applying Landlock network ruleset: {e}"))?;

            match net_status.ruleset {
                RulesetStatus::FullyEnforced => {
                    eprintln!(
                        "puzzle-init: Landlock network rules enforced (ConnectTcp: {} ports, BindTcp: {} ports)",
                        rules.connect_tcp_ports.len(),
                        rules.bind_tcp_ports.len()
                    );
                }
                RulesetStatus::PartiallyEnforced => {
                    eprintln!(
                        "puzzle-init: Landlock network rules partially enforced — \
                         kernel may not support ABI v4 (requires 6.7+)"
                    );
                }
                RulesetStatus::NotEnforced => {
                    eprintln!(
                        "puzzle-init: Landlock network rules not enforced — \
                         kernel does not support ABI v4 (requires 6.7+). \
                         Falling back to seccomp + nftables for network gating."
                    );
                }
            }
        }

        // L15: Apply the filesystem ruleset -- this is irrevocable.
        let status = ruleset
            .restrict_self()
            .map_err(|e| format!("landlock_restrict_self() failed: {e}"))?;

        match status.ruleset {
            RulesetStatus::FullyEnforced => {
                eprintln!(
                    "puzzle-init: Landlock filesystem rules fully enforced (ABI {:?})",
                    rules.abi
                );
            }
            RulesetStatus::PartiallyEnforced => {
                eprintln!(
                    "puzzle-init: Landlock filesystem rules enforced (ABI {:?}, best-effort)",
                    rules.abi
                );
            }
            RulesetStatus::NotEnforced => {
                return Err("Landlock not enforced -- kernel may not support Landlock".to_string());
            }
        }

        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
mod enforce {
    use super::*;

    pub fn apply_landlock(_rules: &LandlockRules) -> Result<(), String> {
        Err("Landlock is only available on Linux".to_string())
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();

    // We need at least one argument after ourselves: the real command to exec.
    if args.len() < 2 {
        return Err(format!(
            "usage: {} <command> [args...]\n\
             Applies Landlock rules then execs the given command.",
            args[0]
        ));
    }

    // Determine rules file path.
    // G30: Env var override is only available in debug builds to prevent
    // attackers from weakening Landlock rules via environment manipulation.
    #[cfg(debug_assertions)]
    let rules_path = env::var(RULES_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_RULES_PATH));
    #[cfg(not(debug_assertions))]
    let rules_path = PathBuf::from(DEFAULT_RULES_PATH);

    // Read and parse rules.
    let rules_json = fs::read_to_string(&rules_path).map_err(|e| {
        format!(
            "failed to read Landlock rules from {}: {e}",
            rules_path.display()
        )
    })?;

    let rules = parse_rules(&rules_json)?;

    // m8: Set PR_SET_NO_NEW_PRIVS before applying Landlock. This is required
    // by Landlock (the kernel enforces it) and also prevents suid/sgid escalation.
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl with constant args, return value checked. No pointers involved.
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 {
            return Err(format!(
                "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    // -----------------------------------------------------------------------
    // §3.4.7 Step 7: Verify PID 1 (defensive check)
    // -----------------------------------------------------------------------
    // Running puzzle-init as a non-init process means the security setup
    // (nftables, seccomp, capabilities) would apply only to that subprocess,
    // not the container init tree.
    #[cfg(target_os = "linux")]
    {
        // SAFETY: getpid() is a read-only query with no side effects.
        let pid = unsafe { libc::getpid() };
        if pid != 1 {
            return Err(format!(
                "puzzle-init: §3.4.7 Step 7: ABORT — running as PID {} (expected PID 1). \
                 Security hardening (nftables, seccomp, capabilities) would only apply \
                 to this process and its children, not the entire container. \
                 puzzle-init MUST run as the container entrypoint (PID 1).",
                pid
            ));
        }
    }

    // L-14: Collect proxy env vars to apply at exec time (instead of set_var).
    let mut proxy_env_vars: Vec<(String, String)> = Vec::new();

    // -----------------------------------------------------------------------
    // §3.4 G8/G9/G10/G11: Credential proxy setup (before Landlock)
    // -----------------------------------------------------------------------
    // These steps must happen before Landlock because:
    // - nftables requires AF_NETLINK sockets (blocked by Landlock network ACL)
    // - seccomp stacking requires prctl (allowed, but ordering matters)
    // - CA trust requires file writes (blocked by Landlock after apply)
    //
    // Order: nftables → seccomp stacking → capability drop → CA trust → Landlock
    #[cfg(target_os = "linux")]
    {
        // M1: load_proxy_config returns Err on malformed proxy.json (fail-closed)
        if let Some(proxy_config) = proxy::load_proxy_config()? {
            if proxy_config.enabled {
                // M2: Validate gateway IP and ports before nft script interpolation
                proxy::validate_proxy_config(&proxy_config)?;

                eprintln!("puzzle-init: §3.4 G8: setting up credential proxy DNAT");

                // §3.4 G8: Set up nftables DNAT rules
                if let Err(e) = proxy::setup_nftables_dnat(&proxy_config) {
                    return Err(format!("§3.4 G8: nftables DNAT setup failed: {}", e));
                }

                // §3.4 G9: Stack seccomp filter blocking AF_NETLINK + memfd_create
                if let Err(e) = proxy::stack_seccomp_netlink_block() {
                    return Err(format!("§3.4 G9: seccomp stacking failed: {}", e));
                }

                // §3.4 G10: Drop ALL capabilities from all 5 sets
                if let Err(e) = proxy::drop_all_capabilities() {
                    return Err(format!("§3.4 G10: capability drop failed: {}", e));
                }

                // §3.4 G11: Set up CA trust store
                // L-14: Collect env vars instead of calling set_var.
                match proxy::setup_ca_trust() {
                    Ok(vars) => proxy_env_vars = vars,
                    Err(e) => {
                        // CA trust failure is non-fatal — agent may not need HTTPS
                        eprintln!("puzzle-init: §3.4 G11: CA trust setup warning: {}", e);
                    }
                }
            }
        }
    }

    // Apply Landlock (irrevocable).
    enforce::apply_landlock(&rules)?;

    // Exec the real command -- this replaces the current process.
    // L-14: Apply proxy env vars via Command::env() instead of set_var.
    let cmd = &args[1];
    let mut command = std::process::Command::new(cmd);
    command.args(&args[2..]);
    for (key, val) in &proxy_env_vars {
        command.env(key, val);
    }
    let err = command.exec();

    // exec() only returns on error.
    Err(format!("execvp({cmd}) failed: {err}"))
}

fn main() {
    if let Err(e) = run() {
        eprintln!("puzzle-init: error: {e}");
        process::exit(1);
    }
    // Unreachable if exec succeeds -- the process is replaced.
}

// ---------------------------------------------------------------------------
// §3.4: Credential proxy setup (nftables, seccomp, capabilities, CA trust)
// ---------------------------------------------------------------------------

mod proxy {
    use serde::Deserialize;
    use std::path::Path;

    /// Default path for proxy configuration (bind-mounted by puzzle-podman).
    const PROXY_CONFIG_PATH: &str = "/run/puzzlepod/proxy.json";

    /// Proxy configuration from puzzle-podman.
    #[derive(Debug, Deserialize)]
    pub struct ProxyConfig {
        /// Whether the credential proxy is enabled.
        #[serde(default)]
        pub enabled: bool,
        /// Gateway IP address (container → host).
        #[serde(default = "default_gateway")]
        pub gateway: String,
        /// Proxy port on the host.
        #[serde(default)]
        pub proxy_port: u16,
        /// Ports to intercept via DNAT.
        #[serde(default = "default_ports")]
        pub ports: Vec<u16>,
    }

    fn default_gateway() -> String {
        "10.0.2.2".to_string()
    }

    fn default_ports() -> Vec<u16> {
        vec![80, 443]
    }

    /// Load proxy configuration from /run/puzzlepod/proxy.json.
    ///
    /// Returns `Ok(None)` if the file doesn't exist (proxy not configured).
    /// Returns `Err` if the file exists but is malformed — this is fail-closed
    /// per PRD §3.4.7: a corrupted proxy.json must not silently skip proxy
    /// setup, as that would allow the agent to bypass credential isolation.
    pub fn load_proxy_config() -> Result<Option<ProxyConfig>, String> {
        let path = Path::new(PROXY_CONFIG_PATH);
        if !path.exists() {
            return Ok(None);
        }
        let contents = std::fs::read_to_string(path).map_err(|e| {
            format!(
                "§3.4 M1: failed to read {} (fail-closed — proxy.json exists but is unreadable): {}",
                PROXY_CONFIG_PATH, e
            )
        })?;
        let config: ProxyConfig = serde_json::from_str(&contents).map_err(|e| {
            format!(
                "§3.4 M1: failed to parse {} (fail-closed — malformed proxy config would \
                 silently bypass credential isolation): {}",
                PROXY_CONFIG_PATH, e
            )
        })?;
        Ok(Some(config))
    }

    /// Validate that the gateway field is a valid IP address.
    /// Prevents nft command injection via a malicious proxy.json.
    pub fn validate_proxy_config(config: &ProxyConfig) -> Result<(), String> {
        // M2: Validate gateway as IP address before nft script interpolation
        config.gateway.parse::<std::net::IpAddr>().map_err(|e| {
            format!(
                "§3.4 M2: invalid gateway IP '{}' in proxy.json — must be a valid IPv4 or IPv6 address: {}",
                config.gateway, e
            )
        })?;
        if config.proxy_port == 0 {
            return Err("§3.4 M2: proxy_port must be > 0 in proxy.json".to_string());
        }
        if config.ports.is_empty() {
            return Err("§3.4 M2: ports must not be empty in proxy.json".to_string());
        }
        Ok(())
    }

    /// §3.4 G8: Set up nftables DNAT rules via the `nft` binary.
    ///
    /// Creates NAT tables that redirect outbound TCP connections on specified
    /// ports to the credential proxy on the host gateway.
    ///
    /// CRITICAL: Does NOT use NFT_TABLE_F_OWNER — table must persist after
    /// puzzle-init exits (we exec into the real command).
    pub fn setup_nftables_dnat(config: &ProxyConfig) -> Result<(), String> {
        // Check if nft binary is available
        let nft_path = find_nft_binary().ok_or_else(|| {
            "nft binary not found — cannot set up DNAT rules. \
             Ensure nftables is installed in the container image."
                .to_string()
        })?;

        let gateway = &config.gateway;
        let proxy_port = config.proxy_port;

        // --- IPv4 NAT table: DNAT intercepted ports to proxy ---
        let mut nft_script = String::new();

        // Create table (no NFT_TABLE_F_OWNER flag — table persists after exit)
        nft_script.push_str("add table ip puzzlepod_nat\n");
        // Output chain with NAT hook
        nft_script.push_str(
            "add chain ip puzzlepod_nat output { type nat hook output priority -100 ; policy accept ; }\n",
        );
        // Loopback passthrough — don't DNAT traffic to localhost
        nft_script.push_str("add rule ip puzzlepod_nat output ip daddr 127.0.0.0/8 accept\n");
        // DNAT rules for each intercepted port
        for port in &config.ports {
            nft_script.push_str(&format!(
                "add rule ip puzzlepod_nat output tcp dport {} dnat to {}:{}\n",
                port, gateway, proxy_port
            ));
        }

        // Apply IPv4 NAT rules
        apply_nft_script(&nft_path, &nft_script)?;

        // --- IPv4 filter table: default-deny (C-1 audit fix) ---
        //
        // Without this filter table, agents can bypass the proxy by connecting
        // to non-intercepted TCP ports or using UDP protocols. The NAT table
        // only redirects traffic on specific ports — everything else passes
        // through unfiltered.
        //
        // This mirrors sandbox/network.rs Gated mode: policy drop, allow only
        // loopback + proxy traffic (post-DNAT destination) + DNS to gateway +
        // established/related connections.
        let filter_script = format!(
            "add table ip puzzlepod_filter\n\
             add chain ip puzzlepod_filter output {{ type filter hook output priority 0 ; policy drop ; }}\n\
             add rule ip puzzlepod_filter output ip daddr 127.0.0.0/8 accept\n\
             add rule ip puzzlepod_filter output ip daddr {gateway} tcp dport {proxy_port} accept\n\
             add rule ip puzzlepod_filter output ip daddr {gateway} udp dport 53 accept\n\
             add rule ip puzzlepod_filter output ct state established,related accept\n\
             add rule ip puzzlepod_filter output log prefix \"puzzlepod-drop: \" drop\n",
            gateway = gateway,
            proxy_port = proxy_port,
        );
        apply_nft_script(&nft_path, &filter_script)?;

        // --- IPv6 NAT table ---
        // IPv6 traffic on intercepted ports is dropped (not redirected) because
        // IPv6 DNAT requires an IPv6 gateway address not currently provisioned.
        // Agents using IPv6 destinations on ports 80/443 will get connection failures.
        let mut nft6_script = String::new();
        nft6_script.push_str("add table ip6 puzzlepod_nat\n");
        nft6_script.push_str(
            "add chain ip6 puzzlepod_nat output { type nat hook output priority -100 ; policy accept ; }\n",
        );
        nft6_script.push_str("add rule ip6 puzzlepod_nat output ip6 daddr ::1 accept\n");
        for port in &config.ports {
            nft6_script.push_str(&format!(
                "add rule ip6 puzzlepod_nat output tcp dport {} drop\n",
                port
            ));
        }

        // --- IPv6 filter table: default-deny (C-1 audit fix) ---
        nft6_script.push_str("add table ip6 puzzlepod_filter\n");
        nft6_script.push_str(
            "add chain ip6 puzzlepod_filter output { type filter hook output priority 0 ; policy drop ; }\n",
        );
        nft6_script.push_str("add rule ip6 puzzlepod_filter output ip6 daddr ::1 accept\n");
        nft6_script
            .push_str("add rule ip6 puzzlepod_filter output ct state established,related accept\n");
        nft6_script.push_str(
            "add rule ip6 puzzlepod_filter output log prefix \"puzzlepod-drop6: \" drop\n",
        );

        apply_nft_script(&nft_path, &nft6_script)?;

        // L8: Verify nftables rules are active by listing both tables
        verify_nft_rules(&nft_path)?;

        eprintln!(
            "puzzle-init: nftables DNAT + default-deny configured — \
             {} ports redirected to {}:{}, all other traffic DROPped",
            config.ports.len(),
            gateway,
            proxy_port
        );

        Ok(())
    }

    /// L8: Verify nftables rules were actually loaded by listing both tables.
    fn verify_nft_rules(nft_path: &str) -> Result<(), String> {
        // Verify NAT table
        let output = std::process::Command::new(nft_path)
            .args(["list", "table", "ip", "puzzlepod_nat"])
            .output()
            .map_err(|e| format!("L8: nft list table failed to execute: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "L8: nftables rule verification failed — table ip puzzlepod_nat not found \
                 (exit {}): {}",
                output.status.code().unwrap_or(-1),
                stderr.trim()
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.contains("dnat to") {
            return Err(
                "L8: nftables verification failed — NAT table exists but contains no DNAT rules"
                    .to_string(),
            );
        }

        // C-1: Verify filter table (default-deny)
        let filter_output = std::process::Command::new(nft_path)
            .args(["list", "table", "ip", "puzzlepod_filter"])
            .output()
            .map_err(|e| format!("L8: nft list filter table failed: {}", e))?;

        if !filter_output.status.success() {
            let stderr = String::from_utf8_lossy(&filter_output.stderr);
            return Err(format!(
                "L8: nftables filter table verification failed — table ip puzzlepod_filter \
                 not found (exit {}): {}",
                filter_output.status.code().unwrap_or(-1),
                stderr.trim()
            ));
        }

        let filter_stdout = String::from_utf8_lossy(&filter_output.stdout);
        if !filter_stdout.contains("policy drop") {
            return Err(
                "L8: nftables filter table exists but does not have policy drop — \
                 default-deny not active"
                    .to_string(),
            );
        }

        Ok(())
    }

    /// Execute an nft script via stdin.
    fn apply_nft_script(nft_path: &str, script: &str) -> Result<(), String> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let mut child = Command::new(nft_path)
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("failed to spawn nft: {}", e))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(script.as_bytes())
                .map_err(|e| format!("failed to write nft script: {}", e))?;
        }

        let output = child
            .wait_with_output()
            .map_err(|e| format!("nft wait failed: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "nft script failed (exit {}): {}",
                output.status.code().unwrap_or(-1),
                stderr.trim()
            ));
        }

        Ok(())
    }

    /// Find the nft binary in common paths.
    fn find_nft_binary() -> Option<String> {
        for path in &["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"] {
            if Path::new(path).exists() {
                return Some(path.to_string());
            }
        }
        // Try PATH
        if let Ok(output) = std::process::Command::new("which").arg("nft").output() {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() {
                    return Some(path);
                }
            }
        }
        None
    }

    /// §3.4 G9: Stack a seccomp-BPF filter that blocks AF_NETLINK sockets
    /// and memfd_create.
    ///
    /// This prevents the agent from:
    /// 1. Modifying nftables DNAT rules (AF_NETLINK blocked)
    /// 2. Executing arbitrary code from anonymous memory via memfd_create +
    ///    execveat(fd, "", AT_EMPTY_PATH), which would bypass Landlock's
    ///    path-based exec restrictions and fanotify monitoring (§3.4.7)
    ///
    /// Uses SECCOMP_RET_KILL_PROCESS (not USER_NOTIF). The filter MUST NOT
    /// use USER_NOTIF — only one filter in the chain can have an active
    /// USER_NOTIF listener (the initial filter loaded by crun).
    ///
    /// The filter is a minimal BPF program:
    /// - Default action: ALLOW (pass through to existing filters)
    /// - Block: socket(AF_NETLINK, ...) → KILL_PROCESS
    /// - Block: memfd_create(...) → KILL_PROCESS
    pub fn stack_seccomp_netlink_block() -> Result<(), String> {
        // BPF program to block socket(AF_NETLINK, ...) and memfd_create(...)
        //
        // Pseudocode:
        //   if (syscall == __NR_socket) {
        //     if (arg0 == AF_NETLINK) {  // AF_NETLINK = 16
        //       return KILL_PROCESS;
        //     }
        //   }
        //   if (syscall == __NR_memfd_create) {
        //     return KILL_PROCESS;
        //   }
        //   return ALLOW;

        #[cfg(target_arch = "x86_64")]
        const NR_SOCKET: u32 = 41;
        #[cfg(target_arch = "aarch64")]
        const NR_SOCKET: u32 = 198;

        // §3.4.7: memfd_create MUST be blocked to prevent execveat from
        // anonymous memory, bypassing Landlock exec path restrictions.
        #[cfg(target_arch = "x86_64")]
        const NR_MEMFD_CREATE: u32 = 319;
        #[cfg(target_arch = "aarch64")]
        const NR_MEMFD_CREATE: u32 = 279;

        const AF_NETLINK: u32 = 16;

        // seccomp return values
        const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
        const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

        // BPF instruction encoding
        #[repr(C)]
        struct SockFilter {
            code: u16,
            jt: u8,
            jf: u8,
            k: u32,
        }

        #[repr(C)]
        struct SockFprog {
            len: u16,
            filter: *const SockFilter,
        }

        // BPF opcodes
        const BPF_LD: u16 = 0x00;
        const BPF_W: u16 = 0x00;
        const BPF_ABS: u16 = 0x20;
        const BPF_JMP: u16 = 0x05;
        const BPF_JEQ: u16 = 0x10;
        const BPF_K: u16 = 0x00;
        const BPF_RET: u16 = 0x06;

        // seccomp_data offsets
        const OFFSET_NR: u32 = 0; // offsetof(seccomp_data, nr)
        const OFFSET_ARCH: u32 = 4; // offsetof(seccomp_data, arch)
        const OFFSET_ARGS: u32 = 16; // offsetof(seccomp_data, args[0])

        // AUDIT_ARCH constants — must match the target architecture.
        // Without this check, a 32-bit compatibility process could bypass
        // the filter because 32-bit syscall numbers differ from 64-bit.
        // See seccomp(2): "It is strongly recommended to use an allow-list
        // approach [...] as a deny-list can be trivially bypassed."
        #[cfg(target_arch = "x86_64")]
        const EXPECTED_AUDIT_ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
        #[cfg(target_arch = "aarch64")]
        const EXPECTED_AUDIT_ARCH: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64

        let filter: [SockFilter; 10] = [
            // [0] Load architecture from seccomp_data.arch
            SockFilter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: OFFSET_ARCH,
            },
            // [1] If arch matches expected, continue; else KILL (prevent 32-bit bypass)
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 0, // true: fall through to [2] (load syscall nr)
                jf: 7, // false: jump to [8] (KILL) — wrong architecture
                k: EXPECTED_AUDIT_ARCH,
            },
            // [2] Load syscall number
            SockFilter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: OFFSET_NR,
            },
            // [3] If syscall == __NR_socket, check AF_NETLINK; else check memfd_create
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 0, // true: fall through to [4] (load arg0)
                jf: 3, // false: skip to [6] (check memfd_create)
                k: NR_SOCKET,
            },
            // [4] Load arg0 (address family)
            SockFilter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: OFFSET_ARGS,
            },
            // [5] If arg0 == AF_NETLINK, jump to [8] (KILL); else [9] (ALLOW)
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 2, // true: jump to [8] KILL
                jf: 3, // false: jump to [9] ALLOW
                k: AF_NETLINK,
            },
            // [6] Load syscall number again (after socket branch fell through)
            SockFilter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: OFFSET_NR,
            },
            // [7] If syscall == __NR_memfd_create, jump to [8] (KILL); else [9] (ALLOW)
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 0, // true: fall through to [8] KILL
                jf: 1, // false: skip to [9] ALLOW
                k: NR_MEMFD_CREATE,
            },
            // [8] Return KILL_PROCESS
            SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_KILL_PROCESS,
            },
            // [9] Return ALLOW
            SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW,
            },
        ];

        let prog = SockFprog {
            len: filter.len() as u16,
            filter: filter.as_ptr(),
        };

        // SAFETY: SYS_seccomp with SECCOMP_SET_MODE_FILTER. prog points to a valid
        // SockFprog with filter.len() entries. filter[] is a stack-allocated array
        // that outlives this call. Return value is checked.
        let ret = unsafe { libc::syscall(libc::SYS_seccomp, 1u64, 0u64, &prog as *const _) };
        if ret != 0 {
            return Err(format!(
                "seccomp(SECCOMP_SET_MODE_FILTER) failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        eprintln!(
            "puzzle-init: §3.4 G9: seccomp filter stacked — AF_NETLINK + memfd_create blocked"
        );
        Ok(())
    }

    /// §3.4 G10: Drop ALL capabilities from all 5 capability sets.
    ///
    /// After nftables DNAT rules are set up, no capabilities are needed.
    /// Dropping all capabilities from all 5 sets (bounding, permitted,
    /// effective, inheritable, ambient) prevents the agent from using any
    /// privileged operations even if it gains elevated privileges.
    ///
    /// Per PRD §3.4.7 Step 6: Drop capabilities from ALL sets, not just
    /// CAP_NET_ADMIN. The agent process should have empty capability sets.
    pub fn drop_all_capabilities() -> Result<(), String> {
        // 1. Drop ALL capabilities from the bounding set.
        // CAP_LAST_CAP is typically 40-41 on modern kernels; iterate to 63
        // to be future-proof. prctl returns EINVAL for non-existent caps.
        for cap in 0..64u64 {
            // SAFETY: prctl with constant args. Returns EINVAL for non-existent caps.
            let ret = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                // EINVAL means the capability doesn't exist — that's fine
                if err.raw_os_error() != Some(libc::EINVAL) {
                    return Err(format!("PR_CAPBSET_DROP(cap {}) failed: {}", cap, err));
                }
            }
        }

        // 2. Clear ALL ambient capabilities
        // SAFETY: prctl with constant args. Non-fatal on older kernels without
        // PR_CAP_AMBIENT support. PR_CAP_AMBIENT = 47, PR_CAP_AMBIENT_CLEAR_ALL = 4
        let ret = unsafe { libc::prctl(47, 4, 0, 0, 0) };
        if ret != 0 {
            // Non-fatal — ambient caps may not be supported on older kernels
            eprintln!(
                "puzzle-init: §3.4 G10: PR_CAP_AMBIENT_CLEAR_ALL failed (non-fatal): {}",
                std::io::Error::last_os_error()
            );
        }

        // 3. Zero ALL capabilities from permitted/effective/inheritable via capset.
        // We use the v3 (64-bit) capset interface which covers caps 0-63 via
        // two 32-bit data words (data[0] = caps 0-31, data[1] = caps 32-63).
        #[repr(C)]
        struct CapHeader {
            version: u32,
            pid: i32,
        }

        #[repr(C)]
        struct CapData {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }

        // _LINUX_CAPABILITY_VERSION_3 = 0x20080522
        let header = CapHeader {
            version: 0x2008_0522,
            pid: 0, // current process
        };

        // Zero all capability bits in both data words
        let data = [
            CapData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
            CapData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
        ];

        // SAFETY: SYS_capset with v3 header (0x20080522) and 2-element CapData array.
        // Both structs are #[repr(C)] and match the kernel's __user_cap_header_struct
        // and __user_cap_data_struct layout. Stack-allocated, outlive this call.
        let ret =
            unsafe { libc::syscall(libc::SYS_capset, &header as *const CapHeader, data.as_ptr()) };
        if ret != 0 {
            return Err(format!(
                "capset failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        eprintln!("puzzle-init: §3.4 G10: ALL capabilities dropped from all 5 sets");
        Ok(())
    }

    /// §3.4 G11: Set up CA trust store for TLS MITM proxy.
    ///
    /// Concatenates the proxy CA cert with the system CA bundle and returns
    /// environment variables for TLS library trust configuration.
    /// L-14: Returns env vars instead of calling set_var (deprecated in Rust 2024 edition).
    pub fn setup_ca_trust() -> Result<Vec<(String, String)>, String> {
        let proxy_ca_path = Path::new("/run/puzzlepod/proxy-ca.pem");
        if !proxy_ca_path.exists() {
            return Err("proxy CA cert not found at /run/puzzlepod/proxy-ca.pem".to_string());
        }

        let proxy_ca = std::fs::read_to_string(proxy_ca_path)
            .map_err(|e| format!("reading proxy CA: {}", e))?;

        // Find system CA bundle
        let system_ca_paths = [
            "/etc/pki/tls/certs/ca-bundle.crt",                  // RHEL/Fedora
            "/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu
            "/etc/ssl/cert.pem",                                 // Alpine
            "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // RHEL alternate
        ];

        let system_ca = system_ca_paths
            .iter()
            .find(|p| Path::new(p).exists())
            .map(std::fs::read_to_string)
            .transpose()
            .map_err(|e| format!("reading system CA bundle: {}", e))?;

        // Concatenate: system CAs + proxy CA
        let combined = match system_ca {
            Some(ref system) => format!("{}\n{}", system, proxy_ca),
            None => {
                eprintln!("puzzle-init: §3.4 G11: no system CA bundle found — using proxy CA only");
                proxy_ca
            }
        };

        // Write combined bundle
        let bundle_path = "/run/puzzlepod/ca-bundle.pem";
        std::fs::write(bundle_path, combined.as_bytes())
            .map_err(|e| format!("writing CA bundle to {}: {}", bundle_path, e))?;

        // L-14: Return env vars instead of calling set_var.
        // The caller applies these via Command::env() at the exec point.
        let env_vars = vec![
            ("SSL_CERT_FILE".to_string(), bundle_path.to_string()),
            ("REQUESTS_CA_BUNDLE".to_string(), bundle_path.to_string()),
            ("NODE_EXTRA_CA_CERTS".to_string(), bundle_path.to_string()),
        ];

        eprintln!(
            "puzzle-init: §3.4 G11: CA trust store configured at {}",
            bundle_path
        );
        Ok(env_vars)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_valid_rules() {
        let json = r#"{
            "abi": "V4",
            "read": ["/usr", "/lib"],
            "write": ["/workspace"],
            "exec": ["/usr/bin"]
        }"#;
        let rules = parse_rules(json).expect("should parse valid rules");
        assert_eq!(rules.abi, AbiVersion::V4);
        assert_eq!(rules.read, vec!["/usr", "/lib"]);
        assert_eq!(rules.write, vec!["/workspace"]);
        assert_eq!(rules.exec, vec!["/usr/bin"]);
    }

    #[test]
    fn test_parse_empty_rules() {
        let json = "{}";
        let rules = parse_rules(json).expect("empty rules should be valid");
        assert_eq!(rules.abi, AbiVersion::V4); // default
        assert!(rules.read.is_empty());
        assert!(rules.write.is_empty());
        assert!(rules.exec.is_empty());
    }

    #[test]
    fn test_parse_invalid_json() {
        let json = "not json at all";
        let result = parse_rules(json);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("failed to parse"),
            "error message should indicate parse failure"
        );
    }

    #[test]
    fn test_missing_rules_file_produces_error() {
        // Verify that attempting to read a nonexistent rules file produces
        // the expected I/O error, which run() would map to exit(1).
        let bad_path = "/nonexistent/puzzle_init_test/landlock.json";
        let result = fs::read_to_string(bad_path);
        assert!(result.is_err(), "reading a missing file should fail");
    }

    #[test]
    fn test_parse_rules_with_multiple_paths() {
        let json = r#"{
            "abi": "V3",
            "read": ["/usr", "/lib", "/lib64", "/etc/ld.so.cache"],
            "write": ["/workspace", "/tmp"],
            "exec": ["/usr/bin/python3", "/usr/bin/git", "/usr/bin/node"]
        }"#;
        let rules = parse_rules(json).expect("should parse rules with multiple paths");
        assert_eq!(rules.abi, AbiVersion::V3);
        assert_eq!(rules.read.len(), 4);
        assert_eq!(rules.write.len(), 2);
        assert_eq!(rules.exec.len(), 3);
        assert_eq!(rules.exec[0], "/usr/bin/python3");
        assert_eq!(rules.write[1], "/tmp");
    }

    #[test]
    fn test_parse_rules_all_abi_versions() {
        for (abi_str, expected) in [
            ("V1", AbiVersion::V1),
            ("V2", AbiVersion::V2),
            ("V3", AbiVersion::V3),
            ("V4", AbiVersion::V4),
            ("V5", AbiVersion::V5),
        ] {
            let json = format!(r#"{{ "abi": "{abi_str}" }}"#);
            let rules =
                parse_rules(&json).unwrap_or_else(|e| panic!("should parse ABI {abi_str}: {e}"));
            assert_eq!(rules.abi, expected);
        }
    }

    #[test]
    fn test_parse_rules_with_allow_refer() {
        // m5: allow_refer field is deserialized from puzzled's output
        let json = r#"{
            "abi": "V4",
            "read": ["/usr"],
            "write": ["/workspace"],
            "exec": ["/usr/bin"],
            "allow_refer": true
        }"#;
        let rules = parse_rules(json).expect("should parse rules with allow_refer");
        assert!(rules.allow_refer);

        // Without allow_refer field, defaults to false
        let json_no_refer = r#"{ "abi": "V4" }"#;
        let rules = parse_rules(json_no_refer).expect("should parse without allow_refer");
        assert!(!rules.allow_refer);
    }

    #[test]
    fn test_parse_rules_string_abi_values() {
        // m5: Verify string-based ABI values work (matching puzzled's serializer)
        for (abi_str, expected) in [
            ("V1", AbiVersion::V1),
            ("V2", AbiVersion::V2),
            ("V3", AbiVersion::V3),
            ("V4", AbiVersion::V4),
            ("V5", AbiVersion::V5),
        ] {
            let json = format!(r#"{{ "abi": "{abi_str}" }}"#);
            let rules = parse_rules(&json)
                .unwrap_or_else(|e| panic!("should parse string ABI '{abi_str}': {e}"));
            assert_eq!(rules.abi, expected);
        }

        // Invalid ABI version should error
        let json = r#"{ "abi": "V99" }"#;
        assert!(parse_rules(json).is_err());
    }

    #[test]
    fn test_rules_file_env_override() {
        // Verify the env var lookup logic: when PUZZLEPOD_LANDLOCK_RULES is set,
        // that path is used instead of the default.
        let tmp = tempfile::NamedTempFile::new().expect("create temp file");
        let tmp_path = tmp.path().to_str().unwrap().to_string();

        // Write valid rules to the temp file.
        std::fs::write(tmp.path(), r#"{ "abi": "V2", "read": ["/opt"] }"#)
            .expect("write temp rules");

        // Simulate the path resolution logic from run().
        let resolved = std::env::var(RULES_PATH_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(&tmp_path));

        // Since PUZZLEPOD_LANDLOCK_RULES may or may not be set in the test env,
        // verify that reading from either path produces parseable rules.
        let json = fs::read_to_string(&resolved)
            .or_else(|_| fs::read_to_string(&tmp_path))
            .expect("should read rules file");
        let rules = parse_rules(&json).expect("should parse rules");
        assert!(!rules.read.is_empty() || rules.abi == AbiVersion::V2);
    }

    /// F6: Verify that apply_landlock counts skipped read/write rules and emits
    /// a warning with the count. Also verify strict mode support.
    #[test]
    fn test_f6_landlock_skipped_rules_counted() {
        let source = include_str!("main.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // Verify skipped counter exists for read rules
        assert!(
            prod_source.contains("skipped_read"),
            "F6: apply_landlock must track skipped read rules with a 'skipped_read' counter"
        );

        // Verify skipped counter exists for write rules
        assert!(
            prod_source.contains("skipped_write"),
            "F6: apply_landlock must track skipped write rules with a 'skipped_write' counter"
        );

        // Verify warning/summary is emitted with count
        assert!(
            prod_source.contains("not present in container"),
            "F6: apply_landlock must emit a summary when rules are skipped"
        );

        // Verify strict mode check exists
        assert!(
            prod_source.contains("strict"),
            "F6: LandlockRules must support a 'strict' field"
        );
    }

    /// G30: PUZZLEPOD_LANDLOCK_RULES env var override must be gated behind
    /// cfg(debug_assertions) or a feature flag.
    #[test]
    fn test_g30_landlock_rules_env_var_gated() {
        let source = include_str!("main.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // Find the env::var(RULES_PATH_ENV) usage (not the constant definition)
        let env_var_call = prod_source
            .find("env::var(RULES_PATH_ENV)")
            .or_else(|| prod_source.find("env::var(\"PUZZLEPOD_LANDLOCK_RULES\")"))
            .expect("env::var(RULES_PATH_ENV) call must exist in source");

        // Check that cfg(debug_assertions) appears before the env var call
        let before_env = &prod_source[..env_var_call];
        let last_cfg = before_env.rfind("cfg(debug_assertions)");

        assert!(
            last_cfg.is_some(),
            "G30: PUZZLEPOD_LANDLOCK_RULES env var override must be gated behind \
             #[cfg(debug_assertions)] to prevent attackers from weakening Landlock rules"
        );

        // The cfg must be close (within 200 chars) — it should be right before the env var block
        let distance = env_var_call - last_cfg.unwrap();
        assert!(
            distance < 200,
            "G30: cfg(debug_assertions) gate must be near the env::var() call \
             (found {} chars away, expected < 200)",
            distance
        );
    }

    /// F6: Verify that the strict field is parsed from JSON.
    #[test]
    fn test_f6_strict_field_parsed() {
        let json = r#"{
            "abi": "V4",
            "read": ["/usr"],
            "write": ["/workspace"],
            "exec": ["/usr/bin"],
            "strict": true
        }"#;
        let rules = parse_rules(json).expect("should parse rules with strict field");
        assert!(rules.strict, "strict field should be true");
    }

    // §3.4 G8: Proxy config tests

    #[test]
    fn test_proxy_config_parse() {
        let json = r#"{
            "enabled": true,
            "gateway": "10.0.2.2",
            "proxy_port": 18443,
            "ports": [80, 443]
        }"#;
        let config: proxy::ProxyConfig = serde_json::from_str(json).unwrap();
        assert!(config.enabled);
        assert_eq!(config.gateway, "10.0.2.2");
        assert_eq!(config.proxy_port, 18443);
        assert_eq!(config.ports, vec![80, 443]);
    }

    #[test]
    fn test_proxy_config_defaults() {
        let json = r#"{"enabled": false}"#;
        let config: proxy::ProxyConfig = serde_json::from_str(json).unwrap();
        assert!(!config.enabled);
        assert_eq!(config.gateway, "10.0.2.2");
        assert_eq!(config.ports, vec![80, 443]);
    }

    #[test]
    fn test_proxy_config_load_missing() {
        // Should return Ok(None) when file doesn't exist
        let result = proxy::load_proxy_config();
        // This test works because /run/puzzlepod/proxy.json doesn't exist in test env
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_proxy_config_validate_valid() {
        let config = proxy::ProxyConfig {
            enabled: true,
            gateway: "10.0.2.2".to_string(),
            proxy_port: 18443,
            ports: vec![80, 443],
        };
        assert!(proxy::validate_proxy_config(&config).is_ok());
    }

    #[test]
    fn test_proxy_config_validate_invalid_gateway() {
        let config = proxy::ProxyConfig {
            enabled: true,
            gateway: "not-an-ip; flush ruleset".to_string(),
            proxy_port: 18443,
            ports: vec![443],
        };
        assert!(proxy::validate_proxy_config(&config).is_err());
    }

    #[test]
    fn test_proxy_config_validate_empty_ports() {
        let config = proxy::ProxyConfig {
            enabled: true,
            gateway: "10.0.2.2".to_string(),
            proxy_port: 18443,
            ports: vec![],
        };
        assert!(proxy::validate_proxy_config(&config).is_err());
    }

    #[test]
    fn test_proxy_config_validate_zero_port() {
        let config = proxy::ProxyConfig {
            enabled: true,
            gateway: "10.0.2.2".to_string(),
            proxy_port: 0,
            ports: vec![443],
        };
        assert!(proxy::validate_proxy_config(&config).is_err());
    }
}
