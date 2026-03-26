// SPDX-License-Identifier: Apache-2.0
//! Landlock rules JSON generation for the puzzle-init shim.
//!
//! Generates a JSON file consumed by the `puzzle-init` binary inside
//! the container. The shim reads the rules, builds a Landlock ruleset,
//! calls `landlock_restrict_self()` (irrevocable), then execs the real command.

use std::path::{Path, PathBuf};

use puzzled_types::AgentProfile;
use serde::{Deserialize, Serialize};

use crate::error::{PuzzledError, Result};

/// Landlock rules structure consumed by the puzzle-init shim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LandlockRules {
    /// Landlock ABI version to request (e.g., "V4").
    pub abi: String,
    /// Paths allowed for read access.
    pub read: Vec<String>,
    /// Paths allowed for write access (implies read).
    pub write: Vec<String>,
    /// Paths allowed for execution.
    pub exec: Vec<String>,
    /// Whether to allow LANDLOCK_ACCESS_FS_REFER (cross-directory renames).
    #[serde(default)]
    pub allow_refer: bool,
}

/// Generate Landlock rules JSON from an agent profile.
///
/// The rules translate the profile's filesystem allowlists into a format
/// that the `puzzle-init` shim can parse and apply via `landlock_restrict_self()`.
///
/// # Arguments
/// * `profile` - The agent profile containing filesystem rules
/// * `workspace_path` - The branch workspace directory (always writable)
pub fn generate_landlock_rules(
    profile: &AgentProfile,
    workspace_path: &Path,
) -> Result<LandlockRules> {
    // J81: Filter read paths against both the general denylist AND the read_denylist.
    let mut read_paths: Vec<String> = profile
        .filesystem
        .read_allowlist
        .iter()
        .filter(|p| !is_denylisted(p, &profile.filesystem.denylist))
        .filter(|p| !is_denylisted(p, &profile.filesystem.read_denylist))
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    // J81: Filter write paths against both the general denylist AND the write_denylist.
    let mut write_paths: Vec<String> = profile
        .filesystem
        .write_allowlist
        .iter()
        .filter(|p| !is_denylisted(p, &profile.filesystem.denylist))
        .filter(|p| !is_denylisted(p, &profile.filesystem.write_denylist))
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    // Always include the workspace directory as writable
    let workspace_str = workspace_path.to_string_lossy().to_string();
    if !write_paths.contains(&workspace_str) {
        write_paths.push(workspace_str);
    }

    let exec_paths: Vec<String> = profile.exec_allowlist.to_vec();

    // Standard read paths that agents commonly need
    let standard_read_paths = [
        "/usr",
        "/lib",
        "/lib64",
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
    ];
    // J81: Standard read paths must also be checked against read_denylist.
    for path in &standard_read_paths {
        let path_str = path.to_string();
        if !read_paths.contains(&path_str)
            && !is_denylisted_str(path, &profile.filesystem.denylist)
            && !is_denylisted_str(path, &profile.filesystem.read_denylist)
        {
            read_paths.push(path_str);
        }
    }

    Ok(LandlockRules {
        abi: "V4".to_string(),
        read: read_paths,
        write: write_paths,
        exec: exec_paths,
        allow_refer: profile.allow_symlinks,
    })
}

/// Write Landlock rules to a JSON file.
pub fn write_landlock_rules(rules: &LandlockRules, output_path: &Path) -> Result<PathBuf> {
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            PuzzledError::Sandbox(format!(
                "creating landlock rules directory {}: {}",
                parent.display(),
                e
            ))
        })?;
    }

    let json = serde_json::to_string_pretty(rules)
        .map_err(|e| PuzzledError::Sandbox(format!("serializing landlock rules: {}", e)))?;

    std::fs::write(output_path, &json).map_err(|e| {
        PuzzledError::Sandbox(format!(
            "writing landlock rules to {}: {}",
            output_path.display(),
            e
        ))
    })?;

    Ok(output_path.to_path_buf())
}

/// Check if a path is in the denylist.
///
/// K1: Canonicalize both the path and denylist entries before comparison
/// to prevent symlink-based bypass (matching pattern in landlock.rs).
/// Falls back to raw path if canonicalize fails.
fn is_denylisted(path: &Path, denylist: &[PathBuf]) -> bool {
    // K1: Canonicalize the path, fall back to raw path on failure
    let canonical_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    denylist.iter().any(|d| {
        // K1: Canonicalize each denylist entry, fall back to raw path on failure
        let canonical_d = std::fs::canonicalize(d).unwrap_or_else(|_| d.to_path_buf());
        canonical_path.starts_with(&canonical_d)
    })
}

/// Check if a string path is in the denylist.
///
/// K1: Canonicalize both the path and denylist entries before comparison
/// to prevent symlink-based bypass (matching pattern in landlock.rs).
/// Falls back to raw path if canonicalize fails.
fn is_denylisted_str(path: &str, denylist: &[PathBuf]) -> bool {
    let p = Path::new(path);
    // K1: Canonicalize the path, fall back to raw path on failure
    let canonical_p = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    denylist.iter().any(|d| {
        // K1: Canonicalize each denylist entry, fall back to raw path on failure
        let canonical_d = std::fs::canonicalize(d).unwrap_or_else(|_| d.to_path_buf());
        canonical_p.starts_with(&canonical_d)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{create_restricted_profile, create_test_profile};

    #[test]
    fn test_generate_rules_from_restricted_profile() {
        let profile = create_restricted_profile();
        let rules = generate_landlock_rules(&profile, Path::new("/workspace")).unwrap();

        assert_eq!(rules.abi, "V4");
        // Workspace is always included as writable
        assert!(rules.write.contains(&"/workspace".to_string()));
        assert!(!rules.allow_refer);
    }

    #[test]
    fn test_generate_rules_from_standard_profile() {
        let profile = create_test_profile("standard");
        let rules = generate_landlock_rules(&profile, Path::new("/workspace")).unwrap();

        // read_allowlist paths should be included (minus denylisted)
        assert!(rules.read.iter().any(|p| p.contains("/usr")));
        assert!(rules.read.iter().any(|p| p.contains("/tmp")));
        // /etc/shadow is in denylist, /root is in denylist
        // write_allowlist should include /tmp
        assert!(rules.write.iter().any(|p| p.contains("/tmp")));
        // Workspace always included
        assert!(rules.write.contains(&"/workspace".to_string()));
    }

    #[test]
    fn test_workspace_always_included() {
        let profile = create_restricted_profile();
        let rules = generate_landlock_rules(&profile, Path::new("/my/custom/workspace")).unwrap();

        assert!(rules.write.contains(&"/my/custom/workspace".to_string()));
    }

    #[test]
    fn test_schema_valid_json() {
        let profile = create_test_profile("test");
        let rules = generate_landlock_rules(&profile, Path::new("/workspace")).unwrap();

        let json = serde_json::to_string_pretty(&rules).unwrap();
        let parsed: LandlockRules = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.abi, "V4");
        assert_eq!(parsed.read.len(), rules.read.len());
        assert_eq!(parsed.write.len(), rules.write.len());
    }

    #[test]
    fn test_write_rules_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let output_path = dir.path().join("landlock.json");

        let profile = create_test_profile("test");
        let rules = generate_landlock_rules(&profile, Path::new("/workspace")).unwrap();

        let path = write_landlock_rules(&rules, &output_path).unwrap();
        assert!(path.exists());

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: LandlockRules = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed.abi, "V4");
    }

    #[test]
    fn test_denylisted_paths_excluded() {
        let mut profile = create_test_profile("test");
        profile.filesystem.read_allowlist =
            vec![PathBuf::from("/usr"), PathBuf::from("/etc/shadow")];
        profile.filesystem.denylist = vec![PathBuf::from("/etc/shadow")];

        let rules = generate_landlock_rules(&profile, Path::new("/workspace")).unwrap();

        assert!(rules.read.contains(&"/usr".to_string()));
        assert!(!rules.read.contains(&"/etc/shadow".to_string()));
    }

    #[test]
    fn test_exec_paths_from_profile() {
        let profile = create_test_profile("test");
        let rules = generate_landlock_rules(&profile, Path::new("/workspace")).unwrap();

        assert!(rules.exec.contains(&"/usr/bin/python3".to_string()));
        assert!(rules.exec.contains(&"/usr/bin/cat".to_string()));
    }

    #[test]
    fn test_allow_refer_from_profile() {
        let mut profile = create_test_profile("test");
        profile.allow_symlinks = true;

        let rules = generate_landlock_rules(&profile, Path::new("/workspace")).unwrap();
        assert!(rules.allow_refer);

        profile.allow_symlinks = false;
        let rules = generate_landlock_rules(&profile, Path::new("/workspace")).unwrap();
        assert!(!rules.allow_refer);
    }

    /// K1: Verify is_denylisted uses canonicalize for path comparison.
    #[test]
    fn test_k1_is_denylisted_uses_canonicalize() {
        let source = include_str!("landlock_rules.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // Verify is_denylisted uses std::fs::canonicalize
        assert!(
            prod_source.contains("std::fs::canonicalize(path)"),
            "K1: is_denylisted must canonicalize the path argument"
        );
        assert!(
            prod_source.contains("std::fs::canonicalize(d)"),
            "K1: is_denylisted must canonicalize denylist entries"
        );
        assert!(
            prod_source.contains("std::fs::canonicalize(p)"),
            "K1: is_denylisted_str must canonicalize the path argument"
        );
    }
}
