// SPDX-License-Identifier: Apache-2.0
use crate::cli::OutputFormat;
use crate::client;
use anyhow::{Context, Result};

/// Handle audit commands that require D-Bus (List, Export).
pub async fn handle_dbus(
    action: crate::cli::AuditAction,
    client: &client::PuzzledClient,
    output: OutputFormat,
) -> Result<()> {
    match action {
        crate::cli::AuditAction::List {
            branch_id,
            event_type,
            since,
            limit,
        } => {
            let filter = serde_json::json!({
                "branch_id": branch_id,
                "event_type": event_type,
                "since": since,
                "limit": limit,
            });
            let result = client.query_audit_events(&filter.to_string()).await?;
            println!("{result}");
        }
        crate::cli::AuditAction::Export { format, file } => {
            let result = client.export_audit_events(&format).await?;
            if let Some(path) = file {
                std::fs::write(&path, &result).with_context(|| format!("writing to {}", path))?;
                match output {
                    OutputFormat::Json => {
                        println!(
                            "{}",
                            serde_json::json!({"status": "exported", "file": path})
                        );
                    }
                    OutputFormat::Text => println!("Exported to {}", path),
                }
            } else {
                println!("{result}");
            }
        }
        crate::cli::AuditAction::Verify { .. } => unreachable!(),
    }
    Ok(())
}

/// Verify an IMA manifest signature.
pub fn cmd_audit_verify(hash_or_path: &str) -> Result<()> {
    let path = if std::path::Path::new(hash_or_path).exists() {
        std::path::PathBuf::from(hash_or_path)
    } else {
        // Try to find the manifest by branch ID hash
        let manifest_dir = std::path::PathBuf::from("/var/lib/puzzled/branches/manifests");
        let candidate = manifest_dir.join(format!("{}.manifest.yaml", hash_or_path));
        if candidate.exists() {
            candidate
        } else {
            anyhow::bail!(
                "manifest not found: {} (tried path and /var/lib/puzzled/branches/manifests/)",
                hash_or_path
            );
        }
    };

    let contents =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;

    println!("Manifest: {}", path.display());
    println!("{}", contents);

    // T23: Signature verification is not yet implemented — fail explicitly
    // rather than silently succeeding and misleading the operator.
    eprintln!("WARNING: signature verification is not yet implemented.");
    eprintln!(
        "The manifest contents are displayed above but have NOT been cryptographically verified."
    );
    eprintln!(
        "Use puzzled's attestation bundle (puzzlectl attestation verify-bundle) for verified audit."
    );

    Ok(())
}
