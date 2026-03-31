// SPDX-License-Identifier: Apache-2.0
use crate::cli::OutputFormat;
use crate::client;
use crate::output::{output_action, output_json_or_text, read_credential_stdin};
use anyhow::Result;

pub async fn handle(
    action: crate::cli::CredentialAction,
    client: &client::PuzzledClient,
    output: OutputFormat,
) -> Result<()> {
    match action {
        crate::cli::CredentialAction::Store {
            name,
            credential_type,
            profiles,
            domains,
            inject,
        } => {
            let value = read_credential_stdin("reading credential value from stdin")?;

            let config_json = serde_json::json!({
                "inject": inject,
                "profiles": profiles,
                "domains": domains,
            })
            .to_string();

            // value_source is the literal credential value read from stdin;
            // the daemon handles multi-profile/domain association via config_json
            let success = client
                .store_credential(&name, &credential_type, &value, &config_json)
                .await?;
            match output {
                OutputFormat::Json => {
                    let result = serde_json::json!({
                        "status": if success { "stored" } else { "failed" },
                        "name": name,
                        "profiles": profiles,
                        "domains": domains,
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&result)
                            .unwrap_or_else(|_| result.to_string())
                    );
                }
                OutputFormat::Text => {
                    if success {
                        println!("Credential '{name}' stored");
                    } else {
                        println!("Failed to store credential '{name}'");
                    }
                }
            }
        }
        crate::cli::CredentialAction::Remove { name } => {
            let success = client.remove_credential(&name).await?;
            if success {
                output_action(
                    output,
                    "removed",
                    &name,
                    "",
                    &format!("Credential '{name}' removed"),
                );
            } else {
                output_action(
                    output,
                    "not_found",
                    &name,
                    "",
                    &format!("Credential '{name}' not found"),
                );
            }
        }
        crate::cli::CredentialAction::Rotate { name } => {
            let value = read_credential_stdin("reading new credential value from stdin")?;

            let success = client.rotate_credential(&name, &value).await?;
            if success {
                output_action(
                    output,
                    "rotated",
                    &name,
                    "",
                    &format!("Credential '{name}' rotated"),
                );
            } else {
                output_action(
                    output,
                    "not_found",
                    &name,
                    "",
                    &format!("Credential '{name}' not found"),
                );
            }
        }
        crate::cli::CredentialAction::List => {
            // List all credentials (empty profile = all)
            let result = client.list_credentials("").await?;
            output_json_or_text(output, &result, |s| {
                let parsed: Result<Vec<serde_json::Value>, _> = serde_json::from_str(s);
                match parsed {
                    Ok(creds) if creds.is_empty() => {
                        println!("No credentials stored");
                    }
                    Ok(creds) => {
                        for cred in &creds {
                            let name = cred.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                            let ctype = cred
                                .get("credential_type")
                                .and_then(|v| v.as_str())
                                .unwrap_or("?");
                            let domains =
                                cred.get("domains").and_then(|v| v.as_str()).unwrap_or("");
                            println!("  {name}  type={ctype}  domains={domains}");
                        }
                    }
                    Err(_) => println!("{s}"),
                }
            });
        }
        crate::cli::CredentialAction::Test { domain, profile } => {
            // Test credential injection by listing credentials for the profile
            // and checking if any match the domain
            let result = client.list_credentials(&profile).await?;
            let parsed: Result<Vec<serde_json::Value>, _> = serde_json::from_str(&result);
            match parsed {
                Ok(creds) => {
                    let matching: Vec<_> = creds
                        .iter()
                        .filter(|c| {
                            c.get("domains")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .split(',')
                                .any(|d| d.trim() == domain)
                        })
                        .collect();
                    match output {
                        OutputFormat::Json => {
                            let test_result = serde_json::json!({
                                "domain": domain,
                                "profile": profile,
                                "matched": !matching.is_empty(),
                                "credentials": matching.iter().map(|c| {
                                    c.get("name").and_then(|v| v.as_str()).unwrap_or("?")
                                }).collect::<Vec<_>>(),
                            });
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&test_result)
                                    .unwrap_or_else(|_| test_result.to_string())
                            );
                        }
                        OutputFormat::Text => {
                            if matching.is_empty() {
                                println!(
                                    "No credentials match domain '{domain}' for profile '{profile}'"
                                );
                            } else {
                                println!(
                                    "Found {} credential(s) for domain '{domain}' in profile '{profile}':",
                                    matching.len()
                                );
                                for cred in &matching {
                                    let name =
                                        cred.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                                    let inject =
                                        cred.get("inject").and_then(|v| v.as_str()).unwrap_or("?");
                                    println!("  {name} (inject: {inject})");
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    anyhow::bail!("Failed to parse credential list: {e}");
                }
            }
        }
        // §3.4 G21: Add credential with encryption
        crate::cli::CredentialAction::Add {
            name,
            from_env,
            from_file,
            passphrase,
            credential_type,
            profiles,
            domains,
        } => {
            // Read credential value from specified source
            let value = if let Some(ref env_var) = from_env {
                zeroize::Zeroizing::new(std::env::var(env_var).map_err(|e| {
                    anyhow::anyhow!("--from-env: env var '{}' not set: {}", env_var, e)
                })?)
            } else if let Some(ref file_path) = from_file {
                zeroize::Zeroizing::new(
                    std::fs::read_to_string(file_path)
                        .map_err(|e| {
                            anyhow::anyhow!("--from-file: reading '{}': {}", file_path, e)
                        })?
                        .trim_end()
                        .to_string(),
                )
            } else {
                read_credential_stdin("reading credential value from stdin")?
            };

            if value.is_empty() {
                anyhow::bail!("credential value is empty");
            }

            if passphrase {
                // Encrypt with Argon2id passphrase
                eprint!("Enter passphrase: ");
                // J42: Limit passphrase read
                let pass = read_credential_stdin("reading passphrase from stdin")?;

                if pass.is_empty() {
                    anyhow::bail!("passphrase is empty");
                }

                // Encrypt and save
                let encrypted = puzzle_proxy::credential_backends::encrypt_with_passphrase(
                    &name,
                    value.as_bytes(),
                    pass.as_bytes(),
                )
                .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))?;

                let secrets_dir = std::env::var("XDG_CONFIG_HOME")
                    .map(std::path::PathBuf::from)
                    .or_else(|_| {
                        std::env::var("HOME").map(|h| std::path::PathBuf::from(h).join(".config"))
                    })
                    .unwrap_or_else(|_| std::path::PathBuf::from("/etc"))
                    .join("puzzled/secrets");

                std::fs::create_dir_all(&secrets_dir)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&secrets_dir, std::fs::Permissions::from_mode(0o700))?;
                }

                let enc_path = secrets_dir.join(format!("{}.enc", name));
                std::fs::write(&enc_path, &encrypted)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&enc_path, std::fs::Permissions::from_mode(0o600))?;
                }

                output_action(
                    output,
                    "added",
                    &name,
                    "",
                    &format!(
                        "Credential '{}' encrypted with Argon2id at {}",
                        name,
                        enc_path.display()
                    ),
                );
            } else {
                // Default: store via D-Bus (systemd-creds or backend encryption)
                let config = serde_json::json!({
                    "profiles": profiles,
                    "domains": domains,
                    "inject": "header",
                });
                client
                    .store_credential(&name, &credential_type, &value, &config.to_string())
                    .await?;
                output_action(
                    output,
                    "added",
                    &name,
                    "",
                    &format!("Credential '{}' stored", name),
                );
            }
        }
        // §3.4 G21: Unlock passphrase-encrypted credential
        crate::cli::CredentialAction::Unlock { name } => {
            eprint!("Enter passphrase for '{}': ", name);
            // J42: Limit passphrase read
            let passphrase = read_credential_stdin("reading passphrase from stdin")?;

            if passphrase.is_empty() {
                anyhow::bail!("passphrase is empty");
            }

            let result = client.unlock_credential(&name, &passphrase).await?;
            if result {
                output_action(
                    output,
                    "unlocked",
                    &name,
                    "",
                    &format!("Credential '{}' unlocked", name),
                );
            } else {
                anyhow::bail!("failed to unlock credential '{}'", name);
            }
        }
    }
    Ok(())
}
