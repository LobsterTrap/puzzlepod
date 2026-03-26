// SPDX-License-Identifier: Apache-2.0
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedOutcome {
    Committed,
    Denied,
    RolledBack,
}

impl std::fmt::Display for ExpectedOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExpectedOutcome::Committed => write!(f, "committed"),
            ExpectedOutcome::Denied => write!(f, "denied"),
            ExpectedOutcome::RolledBack => write!(f, "rolled_back"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    WriteFile,
    DeleteFile,
    ExecCommand,
}

impl std::fmt::Display for ActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionType::WriteFile => write!(f, "write_file"),
            ActionType::DeleteFile => write!(f, "delete_file"),
            ActionType::ExecCommand => write!(f, "exec_command"),
        }
    }
}

/// N1: Resolve a relative path under `root`, rejecting any traversal that escapes the root.
fn resolve_safe_path(root: &Path, rel: &str) -> Result<PathBuf> {
    let canonical_root = std::fs::canonicalize(root)
        .with_context(|| format!("N1: cannot canonicalize root: {}", root.display()))?;
    let joined = canonical_root.join(rel);
    // Normalize the joined path by collapsing ".." components logically.
    // We cannot use fs::canonicalize because the target may not exist yet (e.g., WriteFile).
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        match component {
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::CurDir => {}
            _ => {
                normalized.push(component.as_os_str());
            }
        }
    }
    if !normalized.starts_with(&canonical_root) {
        anyhow::bail!(
            "N1: path traversal detected: '{}' escapes root '{}'",
            rel,
            root.display()
        );
    }
    Ok(normalized)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    #[serde(rename = "type")]
    pub action_type: ActionType,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl Action {
    pub fn display_target(&self) -> &str {
        if let Some(p) = &self.path {
            p.as_str()
        } else if let Some(c) = &self.command {
            c.as_str()
        } else {
            "<unknown>"
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self.action_type {
            ActionType::WriteFile => {
                anyhow::ensure!(self.path.is_some(), "write_file action requires 'path'");
                anyhow::ensure!(
                    self.content.is_some(),
                    "write_file action requires 'content'"
                );
            }
            ActionType::DeleteFile => {
                anyhow::ensure!(self.path.is_some(), "delete_file action requires 'path'");
            }
            ActionType::ExecCommand => {
                anyhow::ensure!(
                    self.command.is_some(),
                    "exec_command action requires 'command'"
                );
            }
        }
        Ok(())
    }

    /// Execute this action against a target directory (the sandbox root or overlay upper).
    pub fn execute(&self, root: &Path) -> Result<()> {
        match self.action_type {
            ActionType::WriteFile => {
                let raw = self.path.as_ref().unwrap();
                let rel = raw.strip_prefix('/').unwrap_or(raw);
                // N1: Validate path does not escape root via traversal (e.g., ../../etc/passwd)
                let path = resolve_safe_path(root, rel)?;
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)
                        .context(format!("mkdir -p {}", parent.display()))?;
                }
                std::fs::write(&path, self.content.as_ref().unwrap())
                    .context(format!("write {}", path.display()))?;
            }
            ActionType::DeleteFile => {
                let raw = self.path.as_ref().unwrap();
                let rel = raw.strip_prefix('/').unwrap_or(raw);
                // N1: Validate path does not escape root via traversal
                let path = resolve_safe_path(root, rel)?;
                if path.exists() {
                    std::fs::remove_file(&path).context(format!("delete {}", path.display()))?;
                }
            }
            ActionType::ExecCommand => {
                let cmd = self.command.as_ref().unwrap();
                // L61: Avoid shell injection — execute command directly without shell interpretation
                // V13: Whitespace-only splitting intentionally prevents shell injection (L61).
                // Arguments with spaces are not supported — use separate exec actions instead.
                let parts: Vec<&str> = cmd.split_whitespace().collect();
                if parts.is_empty() {
                    return Err(anyhow::anyhow!("L61: empty command in scenario action"));
                }
                let status = std::process::Command::new(parts[0])
                    .args(&parts[1..])
                    .current_dir(root)
                    .status()
                    .with_context(|| format!("failed to execute: {}", parts[0]))?;
                if !status.success() {
                    anyhow::bail!(
                        "command '{}' exited with status: {}",
                        cmd,
                        status.code().unwrap_or(-1)
                    );
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub profile: String,
    pub base_path: PathBuf,
    pub task: String,
    pub expected_outcome: ExpectedOutcome,
    #[serde(default)]
    pub expected_reason: Option<String>,
    pub actions: Vec<Action>,
}

impl Scenario {
    pub fn from_yaml(content: &str) -> Result<Self> {
        let scenario: Scenario =
            serde_yaml::from_str(content).context("failed to parse scenario YAML")?;
        scenario.validate()?;
        Ok(scenario)
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let content =
            std::fs::read_to_string(path).context(format!("failed to read {}", path.display()))?;
        Self::from_yaml(&content)
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(!self.name.is_empty(), "scenario name must not be empty");
        anyhow::ensure!(
            !self.profile.is_empty(),
            "scenario profile must not be empty"
        );
        anyhow::ensure!(!self.task.is_empty(), "scenario task must not be empty");
        anyhow::ensure!(
            !self.actions.is_empty(),
            "scenario must have at least one action"
        );
        for (i, action) in self.actions.iter().enumerate() {
            action
                .validate()
                .context(format!("invalid action at index {}", i))?;
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn slug(&self) -> String {
        self.name.to_lowercase().replace(' ', "_")
    }
}

/// Discover all `.yaml` scenario files in a directory.
pub fn discover_scenarios(dir: &Path) -> Result<Vec<(String, Scenario)>> {
    let pattern = format!("{}/*.yaml", dir.display());
    let mut scenarios = Vec::new();
    for entry in glob::glob(&pattern).context("invalid glob pattern")? {
        let path = entry.context("glob error")?;
        match Scenario::from_file(&path) {
            Ok(scenario) => {
                let stem = path
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                scenarios.push((stem, scenario));
            }
            Err(e) => {
                eprintln!("Warning: skipping {}: {}", path.display(), e);
            }
        }
    }
    scenarios.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(scenarios)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scenario() {
        let yaml = r#"
name: "Test Scenario"
description: "A test"
profile: standard
base_path: /tmp/test
task: "Do a thing"
expected_outcome: committed
actions:
  - type: write_file
    path: foo.txt
    description: "Write foo"
    content: "hello"
    tags: [safe]
  - type: delete_file
    path: old.txt
    description: "Remove old"
  - type: exec_command
    command: "echo hi"
    description: "Say hi"
"#;
        let scenario = Scenario::from_yaml(yaml).unwrap();
        assert_eq!(scenario.name, "Test Scenario");
        assert_eq!(scenario.actions.len(), 3);
        assert_eq!(scenario.expected_outcome, ExpectedOutcome::Committed);
        assert_eq!(scenario.slug(), "test_scenario");
    }

    #[test]
    fn test_validate_missing_path() {
        let yaml = r#"
name: "Bad"
profile: standard
base_path: /tmp
task: "x"
expected_outcome: denied
actions:
  - type: write_file
    content: "hello"
"#;
        let result = Scenario::from_yaml(yaml);
        assert!(result.is_err());
    }

    /// L61: Verify exec_command does NOT use shell interpretation (sh -c).
    /// Commands must be executed directly to prevent shell injection from YAML scenarios.
    #[test]
    fn test_l61_no_shell_injection_via_sh_c() {
        let source = include_str!("scenario.rs");
        // The execute() method must not spawn "sh" with "-c" — that enables shell injection
        // from user-supplied YAML command strings.
        let in_execute = source
            .split("pub fn execute")
            .nth(1)
            .expect("execute() method not found");
        // Scope to just the execute method body (up to the next pub fn or end of impl)
        let execute_body = in_execute.split("pub fn ").next().unwrap_or(in_execute);
        assert!(
            !execute_body.contains(r#"Command::new("sh")"#),
            "L61: execute() must not use Command::new(\"sh\") — shell injection risk"
        );
        assert!(
            !execute_body.contains(r#".arg("-c")"#),
            "L61: execute() must not use .arg(\"-c\") — shell injection risk"
        );
    }

    #[test]
    fn test_action_display_target() {
        let action = Action {
            action_type: ActionType::WriteFile,
            path: Some("src/main.py".to_string()),
            content: Some("code".to_string()),
            command: None,
            description: None,
            tags: vec![],
        };
        assert_eq!(action.display_target(), "src/main.py");
    }

    /// N1: Verify path traversal via ../../etc/passwd is rejected.
    #[test]
    fn test_n1_path_traversal_rejected() {
        let tmp = std::env::temp_dir().join("puzzlepod_n1_test");
        std::fs::create_dir_all(&tmp).unwrap();

        let action = Action {
            action_type: ActionType::WriteFile,
            path: Some("../../etc/passwd".to_string()),
            content: Some("malicious".to_string()),
            command: None,
            description: None,
            tags: vec![],
        };
        let result = action.execute(&tmp);
        assert!(result.is_err(), "N1: path traversal should be rejected");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("N1: path traversal"),
            "error should mention path traversal: {}",
            err_msg,
        );

        // Clean up
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// N1: Verify that safe relative paths within root are accepted.
    #[test]
    fn test_n1_safe_path_accepted() {
        let tmp = std::env::temp_dir().join("puzzlepod_n1_safe_test");
        std::fs::create_dir_all(&tmp).unwrap();

        let action = Action {
            action_type: ActionType::WriteFile,
            path: Some("subdir/file.txt".to_string()),
            content: Some("safe content".to_string()),
            command: None,
            description: None,
            tags: vec![],
        };
        let result = action.execute(&tmp);
        assert!(
            result.is_ok(),
            "N1: safe path should be accepted: {:?}",
            result.err()
        );

        // Clean up
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
