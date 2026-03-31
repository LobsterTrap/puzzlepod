// SPDX-License-Identifier: Apache-2.0
//! Journal side-effect requests for replay at commit time.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};

use super::dlp_inspect::inspect_dlp_body;
use super::forward::MAX_BODY_SIZE;
use super::util::chrono_now;
use super::BoxBody;
use super::ProxyRequestContext;

/// Journal a side-effect request for replay at commit time.
///
/// M17: Streams the request body chunk-by-chunk instead of using collect().
/// §3.3: After buffering, inspects the body with the DLP engine (if present).
#[allow(clippy::too_many_arguments)]
pub(super) async fn journal_request(
    req: Request<hyper::body::Incoming>,
    ctx: &ProxyRequestContext,
    injected_credential_value: Option<&str>,
    request_domain: &str,
) -> Result<Response<BoxBody>, hyper::Error> {
    use http_body_util::BodyExt;

    let branch_id = &ctx.branch_id;
    let journal = ctx.journal.clone();
    let dlp_engine = &ctx.dlp_engine;
    let max_inspection_body_size = ctx.max_inspection_body_size;
    let oversized_body_action = ctx.oversized_body_action;
    let quarantine_sender = &ctx.quarantine_sender;
    let audit_sender = ctx.audit_sender.as_ref();
    let method = req.method().clone();
    let mut uri = req.uri().clone();
    // §3.4: Redact credential headers AND URI before journaling to avoid persisting
    // real credential values to disk. Replay should re-inject from PTM.
    // Covers all injection methods: BearerHeader, BasicHeader (authorization),
    // CustomHeader (arbitrary header names), QueryParameter (URI query string).
    let mut headers = req.headers().clone();
    if let Some(cred_val) = injected_credential_value {
        // Remove any header whose value contains the real credential
        let headers_to_remove: Vec<hyper::header::HeaderName> = headers
            .iter()
            .filter(|(_, v)| v.to_str().is_ok_and(|s| s.contains(cred_val)))
            .map(|(k, _)| k.clone())
            .collect();
        for name in headers_to_remove {
            headers.remove(&name);
        }
        // Redact credential from URI query string (QueryParameter injection)
        if let Some(query) = uri.query() {
            if query.contains(cred_val)
                || query.contains(&urlencoding::encode(cred_val).to_string())
            {
                // Strip query string entirely — cannot partially redact and re-parse
                let redacted = if let Some(authority) = uri.authority() {
                    let scheme = uri.scheme_str().unwrap_or("https");
                    format!("{}://{}{}", scheme, authority, uri.path())
                } else {
                    uri.path().to_string()
                };
                if let Ok(new_uri) = redacted.parse() {
                    uri = new_uri;
                }
            }
        }
    }

    // Check Content-Length header for early rejection
    // U20: Multiple Content-Length headers are rejected by hyper (RFC 9112 §6.3) before reaching this code
    // V6: Malformed Content-Length in journal path — log and default to 0 (journal-only, not forwarding)
    if let Some(cl) = headers.get("content-length") {
        let cl_str = cl.to_str().unwrap_or("0");
        if !cl_str.bytes().all(|b| b.is_ascii_digit()) {
            tracing::warn!(
                branch = %branch_id,
                raw_value = %cl_str,
                "V6: malformed Content-Length in journal request, defaulting to 0"
            );
        }
        if let Ok(len) = cl_str.parse::<usize>() {
            if len > MAX_BODY_SIZE {
                tracing::warn!(
                    branch = %branch_id,
                    content_length = len,
                    "request body too large (rejected before reading)"
                );
                return Ok(Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(Full::new(Bytes::from(format!(
                        "Request body too large (max {} bytes)\n",
                        MAX_BODY_SIZE
                    ))))
                    .unwrap());
            }
        }
    }

    // M17: Stream body chunks instead of collecting all at once
    let mut body_parts = Vec::new();
    let mut total_size = 0usize;
    let mut body_stream = req.into_body();

    while let Some(frame_result) = body_stream.frame().await {
        match frame_result {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    total_size += data.len();
                    if total_size > MAX_BODY_SIZE {
                        tracing::warn!(
                            branch = %branch_id,
                            body_size = total_size,
                            "request body too large (exceeded limit while streaming)"
                        );
                        return Ok(Response::builder()
                            .status(StatusCode::PAYLOAD_TOO_LARGE)
                            .body(Full::new(Bytes::from(format!(
                                "Request body too large (max {} bytes)\n",
                                MAX_BODY_SIZE
                            ))))
                            .unwrap());
                    }
                    body_parts.push(data);
                }
            }
            Err(e) => return Err(e),
        }
    }

    let body: Vec<u8> = if body_parts.is_empty() {
        Vec::new()
    } else if body_parts.len() == 1 {
        body_parts
            .into_iter()
            .next()
            .expect("V24: guarded by body_parts len check")
            .to_vec()
    } else {
        let mut combined = Vec::with_capacity(total_size);
        for part in body_parts {
            combined.extend_from_slice(&part);
        }
        combined
    };

    // §3.4 defense-in-depth: Check that the buffered request body does NOT contain
    // the real credential value that was just injected into headers. An agent might
    // embed credentials in the body to exfiltrate them to an upstream service.
    // D-I2: Uses byte-string search instead of from_utf8 to detect credentials in
    // non-UTF-8 bodies (e.g., binary payloads with embedded credential bytes).
    if let Some(cred_val) = injected_credential_value {
        let cred_bytes = cred_val.as_bytes();
        if !body.is_empty()
            && !cred_bytes.is_empty()
            && body.windows(cred_bytes.len()).any(|w| w == cred_bytes)
        {
            tracing::warn!(
                branch = %branch_id,
                "§3.4: real credential value found in request body after injection — blocking"
            );
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from(
                    "Credential value detected in request body — blocked\n",
                )))
                .unwrap());
        }
    }

    // §3.3: DLP inspection on buffered request body
    let body = if let Some(ref dlp) = dlp_engine {
        // §3.3: Oversized body enforcement
        if body.len() > max_inspection_body_size {
            match oversized_body_action {
                crate::dlp::OversizedAction::BlockAndAlert => {
                    tracing::warn!(
                        branch = %branch_id,
                        body_size = body.len(),
                        limit = max_inspection_body_size,
                        "§3.3: oversized body blocked (fail closed)"
                    );
                    return Ok(Response::builder()
                        .status(StatusCode::PAYLOAD_TOO_LARGE)
                        .body(Full::new(Bytes::from(format!(
                            "Request body too large for DLP inspection (max {} bytes)\n",
                            max_inspection_body_size
                        ))))
                        .unwrap());
                }
                crate::dlp::OversizedAction::AllowAndLog => {
                    tracing::info!(
                        branch = %branch_id,
                        body_size = body.len(),
                        limit = max_inspection_body_size,
                        "§3.3: oversized body allowed without inspection (fail open)"
                    );
                    body // Skip DLP inspection
                }
            }
        } else {
            match inspect_dlp_body(
                &body,
                dlp,
                branch_id,
                quarantine_sender.as_ref(),
                audit_sender,
                request_domain,
            ) {
                Ok(Some(redacted)) => redacted,
                Ok(None) => body,
                Err(resp) => return Ok(resp),
            }
        }
    } else {
        body
    };

    // Serialize to journal
    let entry = crate::replay::JournalEntry {
        method: method.to_string(),
        uri: uri.to_string(),
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect(),
        body,
        timestamp: chrono_now(),
        safe_replay: false,
    };

    let mut journal = journal.lock().await;
    if let Err(e) = journal.append(entry).await {
        tracing::error!(
            branch = %branch_id,
            error = %e,
            "failed to journal network request"
        );
        return Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Full::new(Bytes::from("Journal write failed\n")))
            .unwrap());
    }

    tracing::info!(
        branch = %branch_id,
        method = %method,
        uri = %uri,
        "side-effect request journaled for replay at commit"
    );

    Ok(Response::builder()
        .status(StatusCode::ACCEPTED)
        .body(Full::new(Bytes::from(
            "Request journaled; will be replayed at commit\n",
        )))
        .unwrap())
}
