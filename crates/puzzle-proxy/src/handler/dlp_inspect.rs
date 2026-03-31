// SPDX-License-Identifier: Apache-2.0
//! §3.3: DLP content inspection on request and response bodies.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};
use puzzled_types::BranchId;

use crate::dlp::DlpEngine;

use super::util::send_audit;
use super::BoxBody;

/// §3.4 G25 / D-C3: Decompress response body for credential leak scanning.
/// Returns decompressed bytes, or Err with a rejection reason for unknown encodings.
/// Supports gzip and deflate via `flate2`. Unknown or unsupported encodings
/// (br, zstd, etc.) return Err so the caller can fail-closed per PRD.
pub(super) fn decompress_for_scanning(
    body: &[u8],
    content_encoding: &str,
) -> Result<Vec<u8>, String> {
    use std::io::Read;
    // 100 MB limit to prevent decompression bombs (zip bombs, gzip bombs).
    const MAX_DECOMPRESSED_SIZE: usize = 100 * 1024 * 1024;

    match content_encoding.trim().to_lowercase().as_str() {
        "gzip" | "x-gzip" => {
            let decoder = flate2::read::GzDecoder::new(body);
            let mut decompressed = Vec::new();
            decoder
                .take(MAX_DECOMPRESSED_SIZE as u64)
                .read_to_end(&mut decompressed)
                .map_err(|e| format!("gzip decompression failed: {}", e))?;
            Ok(decompressed)
        }
        "deflate" => {
            let decoder = flate2::read::DeflateDecoder::new(body);
            let mut decompressed = Vec::new();
            decoder
                .take(MAX_DECOMPRESSED_SIZE as u64)
                .read_to_end(&mut decompressed)
                .map_err(|e| format!("deflate decompression failed: {}", e))?;
            Ok(decompressed)
        }
        "identity" | "" => {
            // No compression — return as-is.
            Ok(body.to_vec())
        }
        other => {
            // br, zstd, or unknown — fail-closed per PRD §3.4.
            Err(format!(
                "unsupported Content-Encoding '{}' — blocking response (fail-closed)",
                other
            ))
        }
    }
}

/// DLP inspection on response body returned from upstream.
///
/// Scans the response body and either blocks or redacts sensitive content.
/// Takes ownership of the response and returns a (possibly modified) response.
#[allow(clippy::too_many_arguments)]
pub(super) async fn inspect_dlp_response(
    resp: Response<BoxBody>,
    dlp: &DlpEngine,
    branch_id: &BranchId,
    audit_sender: Option<&tokio::sync::mpsc::Sender<crate::ProxyAuditEvent>>,
    domain: &str,
    quarantine_sender: Option<&tokio::sync::mpsc::Sender<BranchId>>,
    max_inspection_body_size: usize,
    oversized_body_action: crate::dlp::OversizedAction,
) -> Response<BoxBody> {
    use http_body_util::BodyExt;

    let (parts, body) = resp.into_parts();

    // Collect body bytes from Full<Bytes> via BodyExt
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return Response::from_parts(parts, Full::new(Bytes::new()));
        }
    };

    if body_bytes.is_empty() {
        return Response::from_parts(parts, Full::new(body_bytes));
    }

    // Gap 30: Oversized body check on response DLP inspection
    if body_bytes.len() > max_inspection_body_size {
        match oversized_body_action {
            crate::dlp::OversizedAction::BlockAndAlert => {
                tracing::warn!(
                    branch = %branch_id,
                    body_size = body_bytes.len(),
                    limit = max_inspection_body_size,
                    "§3.3: oversized response body blocked (fail closed)"
                );
                return Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Full::new(Bytes::from(format!(
                        "Response body too large for DLP inspection (max {} bytes)\n",
                        max_inspection_body_size
                    ))))
                    .unwrap();
            }
            crate::dlp::OversizedAction::AllowAndLog => {
                tracing::info!(
                    branch = %branch_id,
                    body_size = body_bytes.len(),
                    limit = max_inspection_body_size,
                    "§3.3: oversized response body allowed without inspection (fail open)"
                );
                return Response::from_parts(parts, Full::new(body_bytes));
            }
        }
    }

    let result = dlp.inspect_response(&body_bytes);

    if !result.matches.is_empty() {
        for m in &result.matches {
            tracing::warn!(
                branch = %branch_id,
                rule = %m.rule_name,
                action = ?m.action,
                match_hash = %m.match_hash,
                "§3.3: DLP match in response body"
            );
        }
    }

    if !result.allowed {
        let action = result.most_severe_action();

        // Gap 28: Handle Quarantine action in response DLP
        if action == Some(crate::dlp::DlpAction::Quarantine) {
            tracing::error!(
                branch = %branch_id,
                "§3.3: DLP QUARANTINE on response — freezing branch"
            );
            if let Some(sender) = quarantine_sender {
                if sender.try_send(branch_id.clone()).is_err() {
                    tracing::error!(branch = %branch_id, "DLP-8: quarantine channel full — QUARANTINE NOT APPLIED");
                }
            }
            if let Some(sender) = audit_sender {
                for m in &result.matches {
                    send_audit(
                        sender,
                        crate::ProxyAuditEvent::DlpQuarantine {
                            branch_id: branch_id.clone(),
                            rule_name: m.rule_name.clone(),
                            domain: domain.to_string(),
                        },
                    );
                }
            }
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from(
                    "Agent quarantined: critical DLP violation in response\n",
                )))
                .unwrap();
        }

        // Gap 25: BlockAndReview emits audit event with requires_review detail
        if action == Some(crate::dlp::DlpAction::BlockAndReview) {
            tracing::warn!(
                branch = %branch_id,
                action = ?action,
                "§3.3: DLP blocked response — requires human review"
            );
            if let Some(sender) = audit_sender {
                for m in &result.matches {
                    send_audit(
                        sender,
                        crate::ProxyAuditEvent::DlpBlocked {
                            branch_id: branch_id.clone(),
                            rule_name: m.rule_name.clone(),
                            domain: format!("{} [requires_review]", domain),
                            match_hash: m.match_hash.clone(),
                        },
                    );
                }
            }
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from(
                    "Response blocked by DLP: sensitive content requires human review\n",
                )))
                .unwrap();
        }

        tracing::warn!(
            branch = %branch_id,
            action = ?action,
            "§3.3: DLP blocked response — sensitive content detected"
        );
        // Emit audit events for all matches in response block
        if let Some(sender) = audit_sender {
            for m in &result.matches {
                send_audit(
                    sender,
                    crate::ProxyAuditEvent::DlpBlocked {
                        branch_id: branch_id.clone(),
                        rule_name: m.rule_name.clone(),
                        domain: domain.to_string(),
                        match_hash: m.match_hash.clone(),
                    },
                );
            }
        }
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Full::new(Bytes::from(
                "Response blocked by DLP: sensitive content detected\n",
            )))
            .unwrap();
    }

    // Emit audit events for all LogAndAllow matches in responses
    if let Some(sender) = audit_sender {
        for m in &result.matches {
            send_audit(
                sender,
                crate::ProxyAuditEvent::DlpDetected {
                    branch_id: branch_id.clone(),
                    rule_name: m.rule_name.clone(),
                    domain: domain.to_string(),
                    match_hash: m.match_hash.clone(),
                },
            );
        }
    }

    // Apply redactions if needed
    if let Some(modified) = result.modified_body {
        tracing::info!(
            branch = %branch_id,
            "§3.3: DLP redacted content in response body"
        );
        if let Some(sender) = audit_sender {
            if let Some(m) = result
                .matches
                .iter()
                .find(|m| m.action == crate::dlp::DlpAction::RedactAndAllow)
            {
                send_audit(
                    sender,
                    crate::ProxyAuditEvent::DlpRedacted {
                        branch_id: branch_id.clone(),
                        rule_name: m.rule_name.clone(),
                        domain: domain.to_string(),
                    },
                );
            }
        }
        let modified_bytes = Bytes::from(modified);
        let mut resp = Response::from_parts(parts, Full::new(modified_bytes.clone()));
        // Update Content-Length to reflect redacted body size
        resp.headers_mut().insert(
            hyper::header::CONTENT_LENGTH,
            hyper::header::HeaderValue::from(modified_bytes.len()),
        );
        return resp;
    }

    Response::from_parts(parts, Full::new(body_bytes))
}

/// DLP inspection on a buffered request body (called from journal_request).
///
/// Returns `Ok(body)` (possibly redacted) if allowed, or `Err(Response)` if blocked.
/// If the most severe action is `Quarantine`, sends the branch ID on the quarantine channel.
#[allow(clippy::result_large_err)]
pub(super) fn inspect_dlp_body(
    body: &[u8],
    dlp: &DlpEngine,
    branch_id: &BranchId,
    quarantine_sender: Option<&tokio::sync::mpsc::Sender<BranchId>>,
    audit_sender: Option<&tokio::sync::mpsc::Sender<crate::ProxyAuditEvent>>,
    domain: &str,
) -> Result<Option<Vec<u8>>, Response<BoxBody>> {
    if body.is_empty() {
        return Ok(None);
    }

    let result = dlp.inspect(body);

    if !result.matches.is_empty() {
        for m in &result.matches {
            tracing::warn!(
                branch = %branch_id,
                rule = %m.rule_name,
                action = ?m.action,
                match_hash = %m.match_hash,
                "§3.3: DLP match in request body"
            );
        }
    }

    if !result.allowed {
        let most_severe = result.most_severe_action();
        // §3.3: Quarantine action — freeze branch via cgroup.freeze
        if most_severe == Some(crate::dlp::DlpAction::Quarantine) {
            tracing::error!(
                branch = %branch_id,
                "§3.3: DLP QUARANTINE — freezing branch"
            );
            if let Some(sender) = quarantine_sender {
                if sender.try_send(branch_id.clone()).is_err() {
                    tracing::error!(branch = %branch_id, "DLP-8: quarantine channel full — QUARANTINE NOT APPLIED");
                }
            }
            if let Some(sender) = audit_sender {
                for m in &result.matches {
                    send_audit(
                        sender,
                        crate::ProxyAuditEvent::DlpQuarantine {
                            branch_id: branch_id.clone(),
                            rule_name: m.rule_name.clone(),
                            domain: domain.to_string(),
                        },
                    );
                }
            }
            return Err(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from(
                    "Agent quarantined: critical DLP violation\n",
                )))
                .unwrap());
        }

        // Gap 25: BlockAndReview emits audit event with requires_review detail
        if most_severe == Some(crate::dlp::DlpAction::BlockAndReview) {
            tracing::warn!(
                branch = %branch_id,
                action = ?most_severe,
                "§3.3: DLP blocked request — requires human review"
            );
            if let Some(sender) = audit_sender {
                for m in &result.matches {
                    send_audit(
                        sender,
                        crate::ProxyAuditEvent::DlpBlocked {
                            branch_id: branch_id.clone(),
                            rule_name: m.rule_name.clone(),
                            domain: format!("{} [requires_review]", domain),
                            match_hash: m.match_hash.clone(),
                        },
                    );
                }
            }
            return Err(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from(
                    "Request blocked by DLP: sensitive content requires human review\n",
                )))
                .unwrap());
        }

        tracing::warn!(
            branch = %branch_id,
            action = ?most_severe,
            "§3.3: DLP blocked request — sensitive content in outbound body"
        );
        if let Some(sender) = audit_sender {
            for m in &result.matches {
                send_audit(
                    sender,
                    crate::ProxyAuditEvent::DlpBlocked {
                        branch_id: branch_id.clone(),
                        rule_name: m.rule_name.clone(),
                        domain: domain.to_string(),
                        match_hash: m.match_hash.clone(),
                    },
                );
            }
        }
        return Err(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Full::new(Bytes::from(
                "Request blocked by DLP: sensitive content in request body\n",
            )))
            .unwrap());
    }

    // Emit DlpDetected for LogAndAllow matches
    if !result.matches.is_empty() {
        if let Some(sender) = audit_sender {
            for m in &result.matches {
                if m.action == crate::dlp::DlpAction::LogAndAllow {
                    send_audit(
                        sender,
                        crate::ProxyAuditEvent::DlpDetected {
                            branch_id: branch_id.clone(),
                            rule_name: m.rule_name.clone(),
                            domain: domain.to_string(),
                            match_hash: m.match_hash.clone(),
                        },
                    );
                }
            }
        }
    }

    // Emit DlpRedacted for all matches when body was redacted
    if result.modified_body.is_some() {
        if let Some(sender) = audit_sender {
            for m in &result.matches {
                send_audit(
                    sender,
                    crate::ProxyAuditEvent::DlpRedacted {
                        branch_id: branch_id.clone(),
                        rule_name: m.rule_name.clone(),
                        domain: domain.to_string(),
                    },
                );
            }
        }
    }

    // Return redacted body if applicable
    Ok(result.modified_body)
}
