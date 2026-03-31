// SPDX-License-Identifier: Apache-2.0
use anyhow::{Context, Result};
use puzzled_types::BranchId;

use crate::cli::OutputFormat;

// J42: Limit stdin reads for credentials to prevent unbounded memory allocation
pub const MAX_CREDENTIAL_SIZE: u64 = 65_536;

/// Output a JSON action result or a plain text message.
/// L-ctl2: Uses serde_json::to_string_pretty for JSON output consistency.
pub fn output_action(format: OutputFormat, status: &str, id: &str, reason: &str, text_msg: &str) {
    match format {
        OutputFormat::Json => {
            let mut obj = serde_json::json!({"status": status, "branch_id": id});
            if !reason.is_empty() {
                obj["reason"] = serde_json::Value::String(reason.to_string());
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&obj).unwrap_or_else(|_| obj.to_string())
            );
        }
        OutputFormat::Text => println!("{text_msg}"),
    }
}

/// Output a D-Bus result string as pretty JSON or plain text.
/// Handles the common pattern where the daemon returns a JSON string that needs
/// pretty-printing in JSON mode, or direct printing in text mode.
pub fn output_json_or_text(format: OutputFormat, json_str: &str, text_fn: impl FnOnce(&str)) {
    match format {
        OutputFormat::Json => {
            // Try to parse as JSON for pretty-printing; fall back to raw string
            let pretty = serde_json::from_str::<serde_json::Value>(json_str)
                .ok()
                .and_then(|v| serde_json::to_string_pretty(&v).ok())
                .unwrap_or_else(|| json_str.to_string());
            println!("{pretty}");
        }
        OutputFormat::Text => text_fn(json_str),
    }
}

pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// L11: UTF-8 safe truncation. Uses char_indices to find a valid boundary
/// instead of byte slicing, which could panic on multi-byte characters.
pub fn truncate(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        return s;
    }
    match s.char_indices().nth(max_len) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

/// L-ctl1: Filter branches JSON array by state.
/// Supported state filters: "active", "reviewing" (governance_review), "degraded", "all".
pub fn filter_branches_by_state(branches_json: &str, state_filter: &str) -> String {
    if state_filter == "all" {
        return branches_json.to_string();
    }

    let target_state = match state_filter {
        "active" => "active",
        "reviewing" => "governance_review",
        "degraded" => "degraded",
        other => other,
    };

    match serde_json::from_str::<Vec<serde_json::Value>>(branches_json) {
        Ok(branches) => {
            let filtered: Vec<&serde_json::Value> = branches
                .iter()
                .filter(|b| {
                    b.get("state")
                        .and_then(|v| v.as_str())
                        .map(|s| s == target_state)
                        .unwrap_or(false)
                })
                .collect();
            serde_json::to_string(&filtered).unwrap_or_else(|_| branches_json.to_string())
        }
        Err(_) => branches_json.to_string(),
    }
}

/// M-ctl2: Validate a branch ID before sending it over D-Bus.
/// Returns the validated BranchId, or a clear CLI error instead of a cryptic D-Bus error on invalid input.
pub fn validate_branch_id(id: &str) -> Result<BranchId> {
    BranchId::validated(id.to_string())
        .map_err(|e| anyhow::anyhow!("invalid branch ID '{}': {}", id, e))
}

/// Read a credential value from stdin with bounded size.
/// H62: Uses Zeroizing<String> so credential material is zeroized on drop.
/// J42: Limits stdin read to MAX_CREDENTIAL_SIZE to prevent unbounded allocation.
pub fn read_credential_stdin(context_msg: &str) -> Result<zeroize::Zeroizing<String>> {
    let mut value = zeroize::Zeroizing::new(String::new());
    std::io::Read::read_to_string(
        &mut std::io::Read::take(std::io::stdin(), MAX_CREDENTIAL_SIZE),
        &mut value,
    )
    .context(context_msg.to_string())?;
    Ok(zeroize::Zeroizing::new(value.trim_end().to_string()))
}
