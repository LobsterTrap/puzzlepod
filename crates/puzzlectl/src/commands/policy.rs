// SPDX-License-Identifier: Apache-2.0
use anyhow::{Context, Result};
use puzzled_types::FileChange;
use std::path::Path;

use crate::cli::OutputFormat;
use crate::client;
use crate::output::output_action;

/// Handle the Policy Reload command (requires D-Bus).
pub async fn handle_reload(client: &client::PuzzledClient, output: OutputFormat) -> Result<()> {
    let (success, detail) = client.reload_policy().await?;
    if success {
        output_action(output, "reloaded", "", "", "Policies reloaded");
    } else {
        output_action(
            output,
            "failed",
            "",
            &detail,
            &format!("Policy reload failed: {}", detail),
        );
    }
    Ok(())
}

/// Test a policy against a sample changeset.
pub fn cmd_policy_test(changeset_path: &str, policy_dir: &str) -> Result<()> {
    // Load the changeset
    let changeset_str = std::fs::read_to_string(changeset_path)
        .with_context(|| format!("reading changeset {}", changeset_path))?;

    let changes: Vec<FileChange> = serde_json::from_str(&changeset_str)
        .with_context(|| format!("parsing changeset {}", changeset_path))?;

    // Create and load the policy engine
    let mut engine = regorus::Engine::new();

    let policy_path = Path::new(policy_dir);
    if !policy_path.exists() {
        anyhow::bail!("policy directory not found: {}", policy_dir);
    }

    let mut policy_count = 0;
    for entry in std::fs::read_dir(policy_path).context("reading policy directory")? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("rego") {
            let contents = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            engine
                .add_policy(path.display().to_string(), contents)
                .with_context(|| format!("loading policy {}", path.display()))?;
            policy_count += 1;
        }
    }

    println!("Loaded {} policy files from {}", policy_count, policy_dir);
    println!("Evaluating {} file changes...", changes.len());

    // Build and set input
    // T22: Include target, new_mode, and old_mode for full Rego rule coverage
    // (deny_suid_binary, deny_symlink_outside_workspace, etc.)
    let input = serde_json::json!({
        "changes": changes.iter().map(|c| {
            serde_json::json!({
                "path": c.path.to_string_lossy(),
                "kind": format!("{:?}", c.kind),
                "size": c.size,
                "checksum": &c.checksum,
                "target": c.target.as_deref().unwrap_or(""),
                "new_mode": c.new_mode,
            })
        }).collect::<Vec<_>>()
    });

    let input_str = serde_json::to_string(&input).context("serializing input")?;
    let input_value = regorus::Value::from_json_str(&input_str).context("parsing input value")?;
    engine.set_input(input_value);

    // Evaluate
    let allow = engine
        .eval_rule("data.puzzlepod.commit.allow".to_string())
        .context("evaluating allow rule")?;

    let allowed = matches!(allow, regorus::Value::Bool(true));

    if allowed {
        println!("\nResult: APPROVED");
        println!("The changeset passes all governance policies.");
    } else {
        println!("\nResult: REJECTED");

        // Get violations
        let violations = engine
            .eval_query("data.puzzlepod.commit.violations".to_string(), false)
            .context("evaluating violations")?;

        println!("\nViolations:");
        for result in &violations.result {
            for expr in &result.expressions {
                print_violations(&expr.value);
            }
        }
    }

    Ok(())
}

/// Sanitize a string for use as a Rego rule name (alphanumeric + underscores only).
pub fn sanitize_rule_name(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect()
}

/// Escape a string for embedding in a Rego double-quoted string literal.
fn escape_rego_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Escape regex metacharacters in user input, convert glob `*` to `.*`, and anchor.
fn escape_glob_to_regex(pattern: &str) -> String {
    let mut result = String::with_capacity(pattern.len() + 4);
    result.push('^');
    for ch in pattern.chars() {
        match ch {
            '*' => result.push_str(".*"),
            '.' | '+' | '?' | '^' | '$' | '{' | '}' | '(' | ')' | '|' | '[' | ']' => {
                result.push('\\');
                result.push(ch);
            }
            '\\' => result.push_str("\\\\"),
            _ => result.push(ch),
        }
    }
    result.push('$');
    result
}

/// Escape a file extension for use in a regex pattern (anchored at end).
fn escape_ext_to_regex(ext: &str) -> String {
    let mut result = String::with_capacity(ext.len() + 4);
    for ch in ext.chars() {
        match ch {
            '.' | '+' | '?' | '^' | '$' | '{' | '}' | '(' | ')' | '|' | '[' | ']' | '*' => {
                result.push('\\');
                result.push(ch);
            }
            '\\' => result.push_str("\\\\"),
            _ => result.push(ch),
        }
    }
    result.push('$');
    result
}

/// Add a governance rule from a template (generates Rego, no D-Bus required).
#[allow(clippy::too_many_arguments)]
pub fn cmd_policy_add_rule(
    deny_path: Option<&str>,
    max_file_size: Option<u64>,
    deny_extension: Option<&str>,
    max_files: Option<u32>,
    severity: &str,
    message: Option<&str>,
    policy_file: &str,
    dry_run: bool,
) -> Result<()> {
    // Validate severity
    if !["warning", "error", "critical"].contains(&severity) {
        anyhow::bail!(
            "invalid severity '{}': must be one of: warning, error, critical",
            severity
        );
    }

    // Require at least one rule type
    if deny_path.is_none()
        && max_file_size.is_none()
        && deny_extension.is_none()
        && max_files.is_none()
    {
        anyhow::bail!(
            "at least one rule type required: --deny-path, --max-file-size, --deny-extension, or --max-files"
        );
    }

    let mut rules = String::new();

    if let Some(pattern) = deny_path {
        let rule_name = sanitize_rule_name(pattern);
        let msg = escape_rego_string(message.unwrap_or("path matches denied pattern"));
        let regex = escape_rego_string(&escape_glob_to_regex(pattern));
        rules += &format!(
            r#"
violations[v] if {{
    some change in input.changes
    re_match("{regex}", change.path)
    v := {{
        "rule": "deny_path_{rule_name}",
        "message": sprintf("{msg}: %s", [change.path]),
        "severity": "{severity}",
    }}
}}
"#,
            regex = regex,
            rule_name = rule_name,
            msg = msg,
            severity = severity,
        );
    }

    if let Some(max_size) = max_file_size {
        let msg = escape_rego_string(message.unwrap_or("file exceeds maximum size"));
        rules += &format!(
            r#"
violations[v] if {{
    some change in input.changes
    change.size > {max_size}
    v := {{
        "rule": "max_file_size_{max_size}",
        "message": sprintf("{msg} ({max_size} bytes): %s (%d bytes)", [change.path, change.size]),
        "severity": "{severity}",
    }}
}}
"#,
            max_size = max_size,
            msg = msg,
            severity = severity,
        );
    }

    if let Some(extensions) = deny_extension {
        for ext in extensions
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            let rule_name = sanitize_rule_name(ext);
            let regex = escape_rego_string(&escape_ext_to_regex(ext));
            let msg = escape_rego_string(message.unwrap_or("file has denied extension"));
            let ext_escaped = escape_rego_string(ext);
            rules += &format!(
                r#"
violations[v] if {{
    some change in input.changes
    re_match("{regex}", lower(change.path))
    v := {{
        "rule": "deny_ext_{rule_name}",
        "message": sprintf("{msg} ({ext}): %s", [change.path]),
        "severity": "{severity}",
    }}
}}
"#,
                regex = regex,
                rule_name = rule_name,
                ext = ext_escaped,
                msg = msg,
                severity = severity,
            );
        }
    }

    if let Some(max) = max_files {
        let msg = escape_rego_string(message.unwrap_or("changeset exceeds maximum file count"));
        rules += &format!(
            r#"
violations[v] if {{
    count(input.changes) > {max}
    v := {{
        "rule": "max_files_{max}",
        "message": sprintf("{msg}: %d files (max {max})", [count(input.changes)]),
        "severity": "{severity}",
    }}
}}
"#,
            max = max,
            msg = msg,
            severity = severity,
        );
    }

    let header =
        "package puzzlepod.commit\n\nimport future.keywords.if\nimport future.keywords.in\n";
    let full_content = format!("{header}{rules}");

    if dry_run {
        print!("{full_content}");
    } else {
        let path = Path::new(policy_file);
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating directory {}", parent.display()))?;
            }
        }
        if path.exists() {
            // Append rules (skip header since file already has it)
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(path)
                .with_context(|| format!("opening {policy_file}"))?;
            write!(f, "{rules}")?;
        } else {
            std::fs::write(path, &full_content)
                .with_context(|| format!("writing {policy_file}"))?;
        }
        eprintln!("Rule(s) added to {policy_file}");
        eprintln!("Hint: reload with: puzzlectl policy reload");
    }
    Ok(())
}

/// Pretty-print violation objects from regorus output.
///
/// Converts the regorus Value to JSON for reliable parsing,
/// since regorus internal types are not publicly accessible.
fn print_violations(value: &regorus::Value) {
    // Convert to JSON string via regorus Display, then parse
    let json_str = value.to_json_str();
    match json_str {
        Ok(s) => {
            // The violations set comes as an object { violation_obj: true, ... }
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&s) {
                match json {
                    serde_json::Value::Object(map) => {
                        for (key, val) in &map {
                            if val == &serde_json::Value::Bool(true) {
                                // key is a JSON-encoded violation object
                                if let Ok(violation) =
                                    serde_json::from_str::<serde_json::Value>(key)
                                {
                                    let rule = violation
                                        .get("rule")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("unknown");
                                    let message = violation
                                        .get("message")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("(no message)");
                                    let severity = violation
                                        .get("severity")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("error");
                                    println!(
                                        "  [{}] {}: {}",
                                        severity.to_uppercase(),
                                        rule,
                                        message
                                    );
                                }
                            }
                        }
                    }
                    serde_json::Value::Array(arr) => {
                        for item in &arr {
                            let rule = item
                                .get("rule")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            let message = item
                                .get("message")
                                .and_then(|v| v.as_str())
                                .unwrap_or("(no message)");
                            let severity = item
                                .get("severity")
                                .and_then(|v| v.as_str())
                                .unwrap_or("error");
                            println!("  [{}] {}: {}", severity.to_uppercase(), rule, message);
                        }
                    }
                    _ => {
                        println!("  {}", s);
                    }
                }
            } else {
                println!("  {}", s);
            }
        }
        Err(e) => {
            eprintln!("  Error formatting violations: {}", e);
        }
    }
}
