// SPDX-License-Identifier: Apache-2.0
use anyhow::{Context, Result};
use std::path::Path;

use crate::cli::{OutputFormat, ReportFormat};
use crate::compliance;
use crate::output::truncate;

// --- Compliance evidence generation (§3.2) ---
// Core logic is in compliance.rs; these are the CLI command handlers.

pub fn cmd_compliance_frameworks(output: OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json => {
            let frameworks: Vec<serde_json::Value> = compliance::FRAMEWORKS
                .iter()
                .map(|f| {
                    serde_json::json!({
                        "id": f.id,
                        "name": f.name,
                        "controls": f.controls.len(),
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&frameworks)?);
        }
        OutputFormat::Text => {
            println!("{:<15} {:<50} {:>8}", "ID", "NAME", "CONTROLS");
            println!("{}", "-".repeat(73));
            for f in compliance::FRAMEWORKS {
                println!("{:<15} {:<50} {:>8}", f.id, f.name, f.controls.len());
            }
        }
    }
    Ok(())
}

/// Generate a compliance report.
#[allow(clippy::too_many_arguments)]
pub fn cmd_compliance_report(
    frameworks: &[String],
    period: &str,
    output_path: Option<&str>,
    report_format: ReportFormat,
    audit_dir: &Path,
    profiles_dir: &Path,
    policies_dir: &Path,
    signing_key: &Path,
    output: OutputFormat,
) -> Result<()> {
    if frameworks.is_empty() {
        anyhow::bail!(
            "at least one --framework is required (eu-ai-act, soc2, iso27001, nist-ai-rmf)"
        );
    }

    let resolved: Vec<&compliance::FrameworkDef> = frameworks
        .iter()
        .map(|f| compliance::get_framework(f))
        .collect::<Result<Vec<_>>>()?;

    let period_secs = compliance::parse_period_secs(period)?;
    let load_result = compliance::load_audit_records(audit_dir, Some(period_secs))?;
    if load_result.parse_failures > 0 {
        eprintln!(
            "warning: {} of {} audit lines failed to parse",
            load_result.parse_failures, load_result.total_lines
        );
    }
    if load_result.timestamp_parse_failures > 0 {
        eprintln!(
            "warning: {} records had unparseable timestamps (included unfiltered)",
            load_result.timestamp_parse_failures
        );
    }
    let records = load_result.records;
    let event_counts = compliance::count_events_by_type(&records);
    let profile_result = compliance::load_profiles(profiles_dir);
    if profile_result.parse_failures > 0 {
        eprintln!(
            "warning: {} of {} profile files failed to parse",
            profile_result.parse_failures, profile_result.total_files
        );
    }
    let profiles = profile_result.profiles;

    match (report_format, output_path) {
        (ReportFormat::Dir, Some(dir)) => {
            // Full directory tree package generation
            let signing_key_opt = if signing_key.exists() {
                Some(signing_key)
            } else {
                None
            };
            compliance::generate_report_package(
                Path::new(dir),
                &resolved,
                &records,
                &event_counts,
                &profiles,
                profiles_dir,
                policies_dir,
                period,
                signing_key_opt,
            )?;

            match output {
                OutputFormat::Json => {
                    println!(
                        "{}",
                        serde_json::json!({"status": "generated", "output": dir})
                    );
                }
                OutputFormat::Text => {
                    println!("Compliance report generated in {}", dir);
                    for fw in &resolved {
                        let controls = compliance::evaluate_controls(fw, &event_counts, &profiles);
                        let evidenced = controls
                            .iter()
                            .filter(|c| c.status == compliance::EvidenceStatus::Evidenced)
                            .count();
                        let partial = controls
                            .iter()
                            .filter(|c| c.status == compliance::EvidenceStatus::PartiallyEvidenced)
                            .count();
                        let gaps = controls
                            .iter()
                            .filter(|c| c.status == compliance::EvidenceStatus::Gap)
                            .count();
                        println!(
                            "  {}: {}/{} evidenced, {} partial, {} gaps",
                            fw.id,
                            evidenced,
                            controls.len(),
                            partial,
                            gaps
                        );
                    }
                }
            }
        }
        (ReportFormat::Json, output_file) => {
            // Single JSON document — write to file or stdout
            let mut framework_results = serde_json::Map::new();
            for fw in &resolved {
                let controls = compliance::evaluate_controls(fw, &event_counts, &profiles);
                let evidenced = controls
                    .iter()
                    .filter(|c| c.status == compliance::EvidenceStatus::Evidenced)
                    .count();
                let partial = controls
                    .iter()
                    .filter(|c| c.status == compliance::EvidenceStatus::PartiallyEvidenced)
                    .count();
                let gaps = controls
                    .iter()
                    .filter(|c| c.status == compliance::EvidenceStatus::Gap)
                    .count();

                framework_results.insert(
                    fw.id.to_string(),
                    serde_json::json!({
                        "framework": fw.name,
                        "controls_total": controls.len(),
                        "controls_evidenced": evidenced,
                        "controls_partially_evidenced": partial,
                        "controls_gap": gaps,
                        "controls": controls,
                    }),
                );
            }

            let report = serde_json::json!({
                "report_version": env!("CARGO_PKG_VERSION"),
                "generated_at": compliance::chrono_now_rfc3339(),
                "period": period,
                "data_sources": {
                    "audit_events_count": records.len(),
                    "profiles_count": profiles.len(),
                },
                "event_distribution": event_counts,
                "frameworks": framework_results,
            });
            let json_str = serde_json::to_string_pretty(&report)?;

            if let Some(path) = output_file {
                std::fs::write(path, &json_str)
                    .with_context(|| format!("writing report to {}", path))?;
                match output {
                    OutputFormat::Json => {
                        println!(
                            "{}",
                            serde_json::json!({"status": "generated", "output": path})
                        );
                    }
                    OutputFormat::Text => {
                        println!("Compliance report written to {}", path);
                    }
                }
            } else {
                println!("{}", json_str);
            }
        }
        (ReportFormat::Dir, None) => {
            // --format=dir requires --output
            anyhow::bail!("--output is required when --format=dir (specify output directory)");
        }
    }

    Ok(())
}

/// Show compliance status for a framework.
pub fn cmd_compliance_status(
    framework_id: &str,
    period: Option<&str>,
    audit_dir: &Path,
    profiles_dir: &Path,
    output: OutputFormat,
) -> Result<()> {
    let fw = compliance::get_framework(framework_id)?;
    let since_secs = period.map(compliance::parse_period_secs).transpose()?;
    let load_result = compliance::load_audit_records(audit_dir, since_secs)?;
    if load_result.parse_failures > 0 {
        eprintln!(
            "warning: {} of {} audit lines failed to parse",
            load_result.parse_failures, load_result.total_lines
        );
    }
    let records = load_result.records;
    let event_counts = compliance::count_events_by_type(&records);
    let profile_result = compliance::load_profiles(profiles_dir);
    if profile_result.parse_failures > 0 {
        eprintln!(
            "warning: {} of {} profile files failed to parse",
            profile_result.parse_failures, profile_result.total_files
        );
    }
    let profiles = profile_result.profiles;
    let controls = compliance::evaluate_controls(fw, &event_counts, &profiles);
    let evidenced = controls
        .iter()
        .filter(|c| c.status == compliance::EvidenceStatus::Evidenced)
        .count();
    let partial = controls
        .iter()
        .filter(|c| c.status == compliance::EvidenceStatus::PartiallyEvidenced)
        .count();
    let gaps = controls
        .iter()
        .filter(|c| c.status == compliance::EvidenceStatus::Gap)
        .count();

    match output {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "framework": fw.id,
                    "name": fw.name,
                    "controls_total": controls.len(),
                    "controls_evidenced": evidenced,
                    "controls_partially_evidenced": partial,
                    "controls_gap": gaps,
                    "controls": controls,
                }))?
            );
        }
        OutputFormat::Text => {
            println!("{} ({})", fw.name, fw.id);
            println!(
                "Controls: {}/{} evidenced, {} partial, {} gaps\n",
                evidenced,
                controls.len(),
                partial,
                gaps
            );
            println!(
                "{:<12} {:<6} {:<40} {:>8}",
                "CONTROL", "STATUS", "TITLE", "EVENTS"
            );
            println!("{}", "-".repeat(70));
            for ctrl in &controls {
                let status = match ctrl.status {
                    compliance::EvidenceStatus::Evidenced => "OK",
                    compliance::EvidenceStatus::PartiallyEvidenced => "PAR",
                    compliance::EvidenceStatus::Gap => "GAP",
                };
                println!(
                    "{:<12} {:<6} {:<40} {:>8}",
                    ctrl.control_id,
                    status,
                    truncate(&ctrl.title, 40),
                    ctrl.total_events
                );
            }
        }
    }
    Ok(())
}

/// Identify evidence gaps for a framework.
pub fn cmd_compliance_gaps(
    framework_id: &str,
    period: Option<&str>,
    audit_dir: &Path,
    profiles_dir: &Path,
    output: OutputFormat,
) -> Result<()> {
    let fw = compliance::get_framework(framework_id)?;
    let since_secs = period.map(compliance::parse_period_secs).transpose()?;
    let load_result = compliance::load_audit_records(audit_dir, since_secs)?;
    if load_result.parse_failures > 0 {
        eprintln!(
            "warning: {} of {} audit lines failed to parse",
            load_result.parse_failures, load_result.total_lines
        );
    }
    let records = load_result.records;
    let event_counts = compliance::count_events_by_type(&records);
    let profile_result = compliance::load_profiles(profiles_dir);
    if profile_result.parse_failures > 0 {
        eprintln!(
            "warning: {} of {} profile files failed to parse",
            profile_result.parse_failures, profile_result.total_files
        );
    }
    let profiles = profile_result.profiles;
    let analysis = compliance::analyze_gaps(fw, &event_counts, &profiles, period);

    match output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&analysis)?);
        }
        OutputFormat::Text => {
            if analysis.gaps.is_empty() {
                println!(
                    "{}: No evidence gaps found (all {} controls evidenced)",
                    fw.id, analysis.summary.total_controls
                );
            } else {
                println!(
                    "{}: {} gap(s), {} partial, {} evidenced out of {} controls\n",
                    fw.id,
                    analysis.summary.gaps,
                    analysis.summary.partially_evidenced,
                    analysis.summary.evidenced,
                    analysis.summary.total_controls
                );
                for gap in &analysis.gaps {
                    println!(
                        "  {} ({}) — {}",
                        gap.criterion,
                        gap.status.label(),
                        gap.title
                    );
                    if let Some(reason) = &gap.reason {
                        println!("    Reason: {}", reason);
                    }
                    println!("    Recommendation: {}", gap.recommendation);
                }
            }
        }
    }
    Ok(())
}
