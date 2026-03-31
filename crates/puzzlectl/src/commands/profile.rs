// SPDX-License-Identifier: Apache-2.0
use anyhow::{Context, Result};
use puzzled_types::{AgentProfile, FileChange};
use std::path::{Path, PathBuf};

use crate::cli::OutputFormat;
use crate::output::{format_bytes, truncate};

/// List available profiles from a directory.
pub fn cmd_profile_list(dir: &str, output: OutputFormat) -> Result<()> {
    let dir_path = Path::new(dir);
    if !dir_path.exists() {
        anyhow::bail!("profiles directory not found: {}", dir);
    }

    let mut profiles = Vec::new();

    for entry in std::fs::read_dir(dir_path).context("reading profiles directory")? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
            let contents = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            match serde_yaml::from_str::<AgentProfile>(&contents) {
                Ok(profile) => profiles.push(profile),
                Err(e) => {
                    eprintln!("Warning: skipping {}: {}", path.display(), e);
                }
            }
        }
    }

    match output {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&profiles).context("serializing profiles")?
            );
        }
        OutputFormat::Text => {
            if profiles.is_empty() {
                println!("No profiles found in {}", dir);
            } else {
                println!(
                    "{:<15} {:<50} {:>10} {:>8} {:>12}",
                    "NAME", "DESCRIPTION", "MEMORY", "PIDS", "NETWORK"
                );
                println!("{}", "-".repeat(95));
                for p in &profiles {
                    let mem = format_bytes(p.resource_limits.memory_bytes);
                    println!(
                        "{:<15} {:<50} {:>10} {:>8} {:>12}",
                        p.name,
                        truncate(&p.description, 50),
                        mem,
                        p.resource_limits.max_pids,
                        format!("{:?}", p.network.mode),
                    );
                }
            }
        }
    }

    Ok(())
}

/// Show a specific profile's contents.
pub fn cmd_profile_show(name: &str, dir: &str, output: OutputFormat) -> Result<()> {
    // G29: Validate profile name against path traversal.
    // If the name is an existing file path, allow it (used by tests and direct file access).
    // If it's a bare name (no path sep), validate it does not contain "..".
    // If it contains path separators but is NOT an existing file, block it.
    if !Path::new(name).exists() && (name.contains('/') || name.contains("..")) {
        anyhow::bail!(
            "G29: profile name must not contain path separators or '..' \
             (got '{}'). Use a plain profile name.",
            name
        );
    }
    // Try as a direct file path first
    let path = if Path::new(name).exists() {
        PathBuf::from(name)
    } else {
        PathBuf::from(dir).join(format!("{}.yaml", name))
    };

    if !path.exists() {
        anyhow::bail!("profile not found: {} (tried {})", name, path.display());
    }

    let contents =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;

    match output {
        OutputFormat::Json => {
            let profile: AgentProfile = serde_yaml::from_str(&contents)
                .with_context(|| format!("parsing {}", path.display()))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&profile).context("serializing profile")?
            );
        }
        OutputFormat::Text => {
            println!("{}", contents);
        }
    }

    Ok(())
}

/// Validate a profile YAML file.
pub fn cmd_profile_validate(path: &str) -> Result<()> {
    let contents = std::fs::read_to_string(path).with_context(|| format!("reading {}", path))?;

    let profile: AgentProfile =
        serde_yaml::from_str(&contents).with_context(|| format!("parsing {}", path))?;

    // Basic validation
    if profile.name.is_empty() {
        anyhow::bail!("profile name is empty");
    }
    if profile.resource_limits.memory_bytes == 0 {
        anyhow::bail!("memory_bytes must be > 0");
    }
    if profile.resource_limits.max_pids == 0 {
        anyhow::bail!("max_pids must be > 0");
    }

    // Q4: Run full resource_limits validation from puzzled-types
    let rl_errors = profile.resource_limits.validate();
    if !rl_errors.is_empty() {
        anyhow::bail!(
            "resource limits validation failed:\n  {}",
            rl_errors.join("\n  ")
        );
    }

    println!("Profile '{}' is valid", profile.name);
    Ok(())
}

/// Interactively generate a new profile YAML file.
pub fn cmd_profile_init(
    output_path: Option<&str>,
    non_interactive: bool,
    cli_name: Option<&str>,
    cli_extends: Option<&str>,
    cli_network_mode: Option<&str>,
) -> Result<()> {
    use std::io::{BufRead, IsTerminal, Write};

    let interactive = !non_interactive && std::io::stdin().is_terminal();

    let prompt = |question: &str, default: &str| -> Result<String> {
        if interactive {
            eprint!("{} [{}]: ", question, default);
            std::io::stderr().flush()?;
            let mut input = String::new();
            std::io::stdin().lock().read_line(&mut input)?;
            let trimmed = input.trim();
            Ok(if trimmed.is_empty() {
                default.to_string()
            } else {
                trimmed.to_string()
            })
        } else {
            Ok(default.to_string())
        }
    };

    let name = cli_name
        .map(String::from)
        .map_or_else(|| prompt("Profile name", "my-agent"), Ok)?;
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        anyhow::bail!("profile name must be alphanumeric with hyphens/underscores");
    }

    let description = prompt("Description", &format!("Custom profile for {}", name))?;

    let extends_val = cli_extends
        .map(String::from)
        .map_or_else(|| prompt("Extend base profile (or 'none')", "standard"), Ok)?;
    let extends_val = if extends_val == "none" {
        None
    } else {
        Some(extends_val)
    };

    let write_dirs_str = prompt(
        "Write directories (comma-separated, absolute paths)",
        "/tmp,/workspace",
    )?;
    let write_dirs: Vec<&str> = write_dirs_str
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    for d in &write_dirs {
        if !d.starts_with('/') {
            anyhow::bail!("write directory must be absolute: {}", d);
        }
    }

    let net_mode = cli_network_mode.map(String::from).map_or_else(
        || {
            prompt(
                "Network mode (Blocked/Gated/Monitored/Unrestricted)",
                "Blocked",
            )
        },
        Ok,
    )?;
    if !["Blocked", "Gated", "Monitored", "Unrestricted"].contains(&net_mode.as_str()) {
        anyhow::bail!(
            "invalid network mode '{}': must be one of: Blocked, Gated, Monitored, Unrestricted",
            net_mode
        );
    }

    let mut allowed_domains = Vec::new();
    if net_mode == "Gated" {
        let domains_str = prompt("Allowed domains (comma-separated)", "github.com,pypi.org")?;
        allowed_domains = domains_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }

    let memory_mb: u64 = prompt("Memory limit (MB)", "512")?
        .parse()
        .context("invalid memory")?;
    let max_pids: u32 = prompt("Max PIDs", "64")?
        .parse()
        .context("invalid max_pids")?;
    let storage_mb: u64 = prompt("Storage quota (MB)", "1024")?
        .parse()
        .context("invalid storage")?;

    let network_mode: puzzled_types::NetworkMode = match net_mode.as_str() {
        "Blocked" => puzzled_types::NetworkMode::Blocked,
        "Gated" => puzzled_types::NetworkMode::Gated,
        "Monitored" => puzzled_types::NetworkMode::Monitored,
        "Unrestricted" => puzzled_types::NetworkMode::Unrestricted,
        _ => unreachable!(), // validated above
    };

    let profile = puzzled_types::AgentProfile {
        name: name.clone(),
        description,
        extends: extends_val,
        filesystem: puzzled_types::FilesystemRules {
            read_allowlist: vec![
                "/usr/bin".into(),
                "/usr/share".into(),
                "/usr/lib".into(),
                "/usr/lib64".into(),
                "/proc/self".into(),
                "/dev/null".into(),
                "/dev/urandom".into(),
                "/etc/localtime".into(),
            ],
            write_allowlist: write_dirs.iter().map(PathBuf::from).collect(),
            denylist: vec![
                "/etc/shadow".into(),
                "/etc/gshadow".into(),
                "/etc/ssh".into(),
            ],
            read_denylist: vec![],
            write_denylist: vec![],
        },
        exec_allowlist: vec![
            "/usr/bin/python3".into(),
            "/usr/bin/cat".into(),
            "/usr/bin/ls".into(),
        ],
        exec_denylist: vec![
            "nsenter".into(),
            "unshare".into(),
            "chroot".into(),
            "mount".into(),
            "strace".into(),
            "gdb".into(),
            "su".into(),
            "sudo".into(),
        ],
        capabilities: vec![],
        resource_limits: puzzled_types::ResourceLimits {
            memory_bytes: memory_mb * 1024 * 1024,
            cpu_shares: 100,
            io_weight: 100,
            max_pids,
            storage_quota_mb: storage_mb,
            inode_quota: 10000,
            ..Default::default()
        },
        network: puzzled_types::NetworkConfig {
            mode: network_mode,
            allowed_domains,
            data_residency: None,
            dlp_rules_path: None,
        },
        behavioral: puzzled_types::BehavioralConfig {
            max_deletions: 50,
            max_reads_per_minute: 1000,
            credential_access_alert: false,
            phantom_token_prefixes: vec![],
        },
        fail_mode: puzzled_types::FailMode::FailClosed,
        enforcement: Default::default(),
        seccomp_mode: puzzled_types::SeccompMode::Permissive,
        allow_symlinks: false,
        allow_exec_overlay: false,
        credentials: None,
    };

    let y = serde_yaml::to_string(&profile).context("serializing profile to YAML")?;

    if let Some(path) = output_path {
        if Path::new(path).exists() {
            anyhow::bail!("file already exists: {path}");
        }
        std::fs::write(path, &y).with_context(|| format!("writing {path}"))?;
        eprintln!("Profile written to {path}");
        eprintln!("Validate with: puzzlectl profile validate {path}");
    } else {
        print!("{y}");
    }
    Ok(())
}

/// Test a profile against a sample changeset.
pub fn cmd_profile_test(name: &str, changeset_path: &str, dir: &str) -> Result<()> {
    // V12: Validate profile name to prevent path traversal (same as G29 in cmd_profile_show)
    if !Path::new(name).exists() && (name.contains('/') || name.contains("..")) {
        anyhow::bail!(
            "V12: profile name must not contain path separators or '..' \
             (got '{}'). Use a plain profile name.",
            name
        );
    }
    // Load the profile
    let profile_path = if Path::new(name).exists() {
        PathBuf::from(name)
    } else {
        PathBuf::from(dir).join(format!("{}.yaml", name))
    };

    let profile_contents = std::fs::read_to_string(&profile_path)
        .with_context(|| format!("reading profile {}", profile_path.display()))?;
    let profile: AgentProfile = serde_yaml::from_str(&profile_contents)
        .with_context(|| format!("parsing profile {}", profile_path.display()))?;

    // Load the changeset
    let changeset_str = std::fs::read_to_string(changeset_path)
        .with_context(|| format!("reading changeset {}", changeset_path))?;
    let changes: Vec<FileChange> = serde_json::from_str(&changeset_str)
        .with_context(|| format!("parsing changeset {}", changeset_path))?;

    println!(
        "Testing profile '{}' against {} file changes...\n",
        profile.name,
        changes.len()
    );

    let mut pass_count = 0;
    let mut fail_count = 0;

    for change in &changes {
        let path_str = change.path.to_string_lossy();
        let mut blocked = false;
        let mut reason = String::new();

        // Check denylist
        // M28: Use Path::starts_with() for component-aware prefix matching
        // instead of string contains(), which could match partial path components
        // (e.g., "/etc/shadow" would incorrectly match "/etc/shadow-backup" with contains())
        for deny in &profile.filesystem.denylist {
            let path = std::path::Path::new(path_str.as_ref());
            let deny_path = std::path::Path::new(deny);
            if path.starts_with(deny_path) {
                blocked = true;
                reason = format!("matches denylist pattern '{}'", deny.display());
                break;
            }
        }

        // Check write allowlist (for modifications)
        if !blocked
            && matches!(
                change.kind,
                puzzled_types::FileChangeKind::Added | puzzled_types::FileChangeKind::Modified
            )
            && !profile.filesystem.write_allowlist.is_empty()
        {
            // M-ctl5: Use Path::starts_with for component-aware matching.
            // String::starts_with("/home/user") would incorrectly match "/home/username".
            let change_path = std::path::Path::new(path_str.as_ref());
            let allowed = profile
                .filesystem
                .write_allowlist
                .iter()
                .any(|p| change_path.starts_with(p));
            if !allowed {
                blocked = true;
                reason = "not in write allowlist".to_string();
            }
        }

        if blocked {
            println!("  FAIL  {} ({})", path_str, reason);
            fail_count += 1;
        } else {
            println!("  PASS  {}", path_str);
            pass_count += 1;
        }
    }

    println!("\nResults: {} passed, {} failed", pass_count, fail_count);

    if fail_count > 0 {
        anyhow::bail!(
            "{} file(s) would be rejected by profile '{}'",
            fail_count,
            profile.name
        );
    }

    Ok(())
}
