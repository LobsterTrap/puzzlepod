// SPDX-License-Identifier: Apache-2.0
//! Handle the intercepted (decrypted) HTTP stream between agent and upstream.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::credentials::InjectionMethod;

use super::credentials::inject_credential_into_header_vec;
use super::dlp_inspect::{decompress_for_scanning, inspect_dlp_body};
use super::forward::{MAX_BODY_SIZE, MAX_HEADER_SIZE};
use super::routing::HOP_BY_HOP_HEADERS;
use super::tls::TLS_SESSION_TIMEOUT;
use super::util::{
    chrono_now, decode_chunked_body, find_header_end, is_valid_http_header_name,
    is_valid_http_header_value, send_audit,
};
use super::{ProxyRequestContext, MAX_RESPONSE_BODY_BYTES};

/// Handle the intercepted (decrypted) HTTP stream between agent and upstream.
///
/// Reads a single HTTP/1.1 request from the agent side, routes it based on method,
/// and relays the response back through the TLS streams.
pub(super) async fn handle_intercepted_stream<A, U>(
    mut agent_tls: A,
    mut upstream_tls: U,
    domain: &str,
    _target_with_port: &str,
    ctx: &ProxyRequestContext,
) -> Result<(), String>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let branch_id = &ctx.branch_id;
    let journal = ctx.journal.clone();
    let dlp_engine = &ctx.dlp_engine;
    let max_inspection_body_size = ctx.max_inspection_body_size;
    let oversized_body_action = ctx.oversized_body_action;
    let quarantine_sender = &ctx.quarantine_sender;
    let audit_sender = &ctx.audit_sender;
    let phantom_token_manager = &ctx.phantom_token_manager;
    let agent_profile = &ctx.agent_profile;
    let credential_mode = ctx.credential_mode;

    // V4: 4KB buffer is a tradeoff — larger buffers waste stack space per connection,
    // smaller buffers increase syscall overhead. Slowloris is mitigated by TLS_SESSION_TIMEOUT.
    let mut tmp_buf = [0u8; 4096];
    // Track leftover bytes read beyond the current request (pipelining / keep-alive)
    let mut leftover: Vec<u8> = Vec::new();

    // D-I6: Session-level timeout to prevent indefinite keep-alive loops.
    let session_start = std::time::Instant::now();

    // HTTP/1.1 keep-alive loop: process multiple requests on the same TLS connection.
    // Break on: connection close (read returns 0), Connection: close header, or I/O error.
    loop {
        // D-I6: Check session timeout at the start of each iteration.
        if session_start.elapsed() > TLS_SESSION_TIMEOUT {
            tracing::info!(
                branch = %branch_id,
                domain = %domain,
                elapsed_secs = session_start.elapsed().as_secs(),
                "D-I6: TLS session timeout exceeded, closing keep-alive connection"
            );
            break;
        }
        // Read the HTTP request from the agent (decrypted)
        // We read into a buffer and parse the HTTP/1.1 request manually
        let mut request_buf = Vec::with_capacity(8192);

        // Prepend any leftover bytes from the previous iteration
        if !leftover.is_empty() {
            request_buf.extend_from_slice(&leftover);
            leftover.clear();
        }

        // Read until we have a complete HTTP request (headers end with \r\n\r\n)
        let header_end;
        loop {
            // Check if we already have a complete header set (from leftover data)
            if let Some(pos) = find_header_end(&request_buf) {
                header_end = pos;
                break;
            }

            let n = match agent_tls.read(&mut tmp_buf).await {
                Ok(0) => {
                    // Connection closed cleanly by the agent — not an error.
                    tracing::debug!(
                        branch = %branch_id,
                        domain = %domain,
                        "C4: agent closed TLS connection (keep-alive end)"
                    );
                    return Ok(());
                }
                Ok(n) => n,
                Err(e) => {
                    tracing::debug!(
                        branch = %branch_id,
                        error = %e,
                        "C4: I/O error reading from agent, closing intercepted connection"
                    );
                    return Err(format!("reading from agent: {}", e));
                }
            };
            request_buf.extend_from_slice(&tmp_buf[..n]);

            // D-M1: Use MAX_HEADER_SIZE (64KB) instead of MAX_BODY_SIZE (100MB)
            // to prevent excessive memory consumption from oversized headers.
            if request_buf.len() > MAX_HEADER_SIZE {
                return Err("request headers too large".to_string());
            }
        }

        // Parse the request line and headers
        let header_bytes = &request_buf[..header_end];
        let header_str = std::str::from_utf8(header_bytes)
            .map_err(|e| format!("invalid UTF-8 in headers: {}", e))?;

        let mut lines = header_str.split("\r\n");
        let request_line = lines.next().ok_or("empty request")?;
        let mut parts = request_line.split_whitespace();
        let method_str = parts.next().ok_or("no method in request line")?;
        // D-C1: path must be mutable for QueryParameter credential injection.
        let mut path = parts.next().ok_or("no path in request line")?.to_string();

        // Parse headers
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut content_length: usize = 0;
        let mut content_length_seen = false;
        let mut connection_close = false;
        let mut has_transfer_encoding = false;
        let mut has_content_encoding = false;
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                let name = name.trim().to_string();
                let value = value.trim().to_string();

                // D-C3: Validate header name and value per RFC 9110.
                // Skip headers with invalid characters to prevent injection attacks.
                if !is_valid_http_header_name(&name) {
                    tracing::warn!(
                        branch = %branch_id,
                        header_name = %name,
                        "D-C3: skipping header with invalid name characters"
                    );
                    continue;
                }
                if !is_valid_http_header_value(&value) {
                    tracing::warn!(
                        branch = %branch_id,
                        header_name = %name,
                        "D-C3: skipping header with invalid value characters (null/control bytes)"
                    );
                    continue;
                }

                if name.eq_ignore_ascii_case("content-length") {
                    // V5: Reject malformed Content-Length — unwrap_or(0) could enable request smuggling
                    let new_cl: usize = match value.parse() {
                        Ok(cl) => cl,
                        Err(_) => {
                            tracing::warn!(
                                branch = %branch_id,
                                raw_value = %value,
                                "V5: rejecting request with malformed Content-Length"
                            );
                            let error_body = "Malformed Content-Length header\n";
                            let error_response = format!(
                                "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                error_body.len(), error_body
                            );
                            if let Err(e) = agent_tls.write_all(error_response.as_bytes()).await {
                                tracing::debug!(error = %e, "V5: failed to write TLS error response to agent");
                            }
                            if let Err(e) = agent_tls.flush().await {
                                tracing::debug!(error = %e, "V5: failed to flush TLS error response to agent");
                            }
                            return Ok(());
                        }
                    };
                    // D-C2: RFC 9112 §8.6 — reject requests with conflicting Content-Length
                    // values to prevent request smuggling via CL desync.
                    if content_length_seen && new_cl != content_length {
                        tracing::warn!(
                            branch = %branch_id,
                            first_cl = content_length,
                            second_cl = new_cl,
                            "D-C2: rejecting request with conflicting Content-Length headers"
                        );
                        let error_body = "Conflicting Content-Length headers\n";
                        let error_response = format!(
                            "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            error_body.len(), error_body
                        );
                        if let Err(e) = agent_tls.write_all(error_response.as_bytes()).await {
                            tracing::debug!(error = %e, "L40: failed to write TLS error response to agent");
                        }
                        if let Err(e) = agent_tls.flush().await {
                            tracing::debug!(error = %e, "L40: failed to flush TLS error response to agent");
                        }
                        return Ok(());
                    }
                    content_length = new_cl;
                    content_length_seen = true;
                }
                if name.eq_ignore_ascii_case("connection") && value.eq_ignore_ascii_case("close") {
                    connection_close = true;
                }
                // C7: Detect Transfer-Encoding header (especially chunked)
                if name.eq_ignore_ascii_case("transfer-encoding") {
                    has_transfer_encoding = true;
                }
                // D-C1: Detect Content-Encoding header (gzip/deflate/br/zstd)
                if name.eq_ignore_ascii_case("content-encoding") {
                    has_content_encoding = true;
                }
                headers.push((name, value));
            }
        }

        // D-C1: Reject requests with Content-Encoding when DLP is active.
        // Compressed bodies bypass DLP pattern matching.
        if has_content_encoding && dlp_engine.is_some() {
            tracing::warn!(
                branch = %branch_id,
                domain = %domain,
                method = %method_str,
                "D-C1: rejecting request with Content-Encoding in TLS intercept (DLP bypass prevention)"
            );
            let body = "Content-Encoding blocked: DLP inspection is active\n";
            let error_response = format!(
                "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            if let Err(e) = agent_tls.write_all(error_response.as_bytes()).await {
                tracing::debug!(error = %e, "L40: failed to write TLS error response to agent");
            }
            if let Err(e) = agent_tls.flush().await {
                tracing::debug!(error = %e, "L40: failed to flush TLS error response to agent");
            }
            return Ok(());
        }

        // C7: Reject requests with Transfer-Encoding header to prevent request
        // smuggling. The TLS MITM parser does not implement chunked decoding,
        // so allowing it would let an attacker smuggle additional requests.
        if has_transfer_encoding {
            tracing::warn!(
                branch = %branch_id,
                domain = %domain,
                method = %method_str,
                "C7: rejecting request with Transfer-Encoding (request smuggling prevention)"
            );
            let body = "Transfer-Encoding is not supported by this proxy\n";
            let error_response = format!(
                "HTTP/1.1 501 Not Implemented\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            if let Err(e) = agent_tls.write_all(error_response.as_bytes()).await {
                tracing::debug!(error = %e, "L40: failed to write TLS error response to agent");
            }
            if let Err(e) = agent_tls.flush().await {
                tracing::debug!(error = %e, "L40: failed to flush TLS error response to agent");
            }
            return Ok(());
        }

        // Read the body if Content-Length indicates one
        // We may have already read some body bytes beyond the header end
        let body_start = header_end + 4; // skip \r\n\r\n
        let mut body = Vec::new();
        if content_length > 0 {
            if content_length > MAX_BODY_SIZE {
                return Err(format!(
                    "request body too large ({} bytes, max {})",
                    content_length, MAX_BODY_SIZE
                ));
            }
            // Copy any body bytes already in the buffer
            if body_start < request_buf.len() {
                body.extend_from_slice(&request_buf[body_start..]);
            }
            // Read remaining body bytes
            while body.len() < content_length {
                let n = agent_tls
                    .read(&mut tmp_buf)
                    .await
                    .map_err(|e| format!("reading request body from agent: {}", e))?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&tmp_buf[..n]);
            }
            // If we read more than content_length, stash the overflow as leftover
            if body.len() > content_length {
                leftover.extend_from_slice(&body[content_length..]);
                body.truncate(content_length);
            }
        } else if body_start < request_buf.len() {
            // No body expected but there are bytes after headers — leftover for next request
            leftover.extend_from_slice(&request_buf[body_start..]);
        }

        // T18: full_uri is intentionally constructed BEFORE credential injection.
        // This ensures credentials injected via QueryParameter do not leak into
        // logs or journal entries. Do not move this after injection.
        let full_uri = format!("https://{}{}", domain, &path);

        // U18: Capture the original path BEFORE credential injection for the T14
        // exfiltration check below. QueryParameter injection modifies `path` by
        // appending credentials to the query string, so checking `path` after
        // injection would false-positive on the proxy's own injected credential.
        let original_path = path.clone();

        tracing::info!(
            branch = %branch_id,
            method = %method_str,
            uri = %full_uri,
            body_len = body.len(),
            "C4: intercepted HTTP request"
        );

        // §3.4/C4: Credential injection on TLS-intercepted requests.
        // D-I3: Enforce Blocked credential mode — strip all auth headers.
        let mut injected_credential_value: Option<zeroize::Zeroizing<String>> = None;
        // N10: Track custom header name from credential injection for redaction in journal.
        let mut injected_custom_header_name: Option<String> = None;
        // N5: Track whether credential was injected as query parameter for URI redaction.
        let mut injected_via_query_param = false;
        if credential_mode == puzzled_types::CredentialMode::Blocked {
            let before_len = headers.len();
            headers.retain(|(name, _)| {
                let lower = name.to_lowercase();
                lower != "authorization" && lower != "proxy-authorization" && lower != "x-api-key"
            });
            if headers.len() < before_len {
                tracing::warn!(
                    branch = %branch_id,
                    stripped = before_len - headers.len(),
                    "D-I3/§3.4: credential mode=Blocked, stripped auth headers in TLS intercept path"
                );
            }
        } else if credential_mode == puzzled_types::CredentialMode::Phantom {
            if let Some(ref ptm) = phantom_token_manager {
                let mgr = ptm.read().await;
                // Check each header for phantom tokens, stripping auth scheme prefixes
                let mut inject_header_idx: Option<usize> = None;
                let mut inject_token: Option<String> = None;
                // Q5: Removed dead `_inject_auth_prefix` variable (was unused after D-C4 refactor)
                for (idx, (_name, value)) in headers.iter().enumerate() {
                    // D-C4: Strip "Bearer " or "Basic " prefix before checking,
                    // matching the non-TLS path in inject_credentials().
                    // H61: Use case-insensitive matching for auth scheme prefixes
                    let (_prefix, token_part) =
                        if value.len() >= 7 && value[..7].eq_ignore_ascii_case("Bearer ") {
                            (Some("Bearer "), &value[7..])
                        } else if value.len() >= 6 && value[..6].eq_ignore_ascii_case("Basic ") {
                            (Some("Basic "), &value[6..])
                        } else {
                            (None, value.as_str())
                        };
                    if mgr.is_phantom_token(token_part) {
                        inject_header_idx = Some(idx);
                        inject_token = Some(token_part.to_string());
                        break;
                    }
                }
                if let Some((idx, token)) = inject_header_idx.zip(inject_token) {
                    if let Some(resolved) = mgr.resolve(&token, Some(branch_id)).await {
                        // Domain scope check
                        let domain_ok = resolved
                            .target_domains
                            .iter()
                            .any(|d| crate::credentials::domain_matches(domain, d));
                        if domain_ok {
                            // Profile check
                            let profile_ok = match &agent_profile {
                                Some(prof) => resolved
                                    .allowed_profiles
                                    .iter()
                                    .any(|p| p == "*" || p == prof),
                                None => true,
                            };
                            if profile_ok {
                                // D-C1: Use helper that dispatches on InjectionMethod
                                injected_credential_value = inject_credential_into_header_vec(
                                    &mut headers,
                                    &mut path,
                                    &resolved,
                                    idx,
                                );
                                // N10: Capture custom header name for journal redaction.
                                if let InjectionMethod::CustomHeader { ref header_name } =
                                    resolved.injection
                                {
                                    injected_custom_header_name = Some(header_name.clone());
                                }
                                // N5: Track query parameter injection for URI redaction.
                                if matches!(
                                    resolved.injection,
                                    InjectionMethod::QueryParameter { .. }
                                ) {
                                    injected_via_query_param = true;
                                }
                                tracing::info!(
                                    branch = %branch_id,
                                    credential = %resolved.credential_name,
                                    "§3.4/C4: credential injected in TLS intercept path"
                                );
                                if let Some(ref sender) = audit_sender {
                                    send_audit(
                                        sender,
                                        crate::ProxyAuditEvent::CredentialInjected {
                                            branch_id: branch_id.clone(),
                                            credential_name: resolved.credential_name.clone(),
                                            domain: domain.to_string(),
                                        },
                                    );
                                    // §3.4 T2.1: Emit CredentialResolved for D-Bus signal
                                    send_audit(
                                        sender,
                                        crate::ProxyAuditEvent::CredentialResolved {
                                            branch_id: branch_id.clone(),
                                            credential_name: resolved.credential_name.clone(),
                                            domain: domain.to_string(),
                                        },
                                    );
                                }
                            } else {
                                tracing::warn!(
                                    branch = %branch_id,
                                    credential = %resolved.credential_name,
                                    "§3.4/C4: credential not authorized for this profile"
                                );
                                let error_body = "Credential not authorized for this profile\n";
                                let error_response = format!(
                                    "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    error_body.len(), error_body
                                );
                                if let Err(e) = agent_tls.write_all(error_response.as_bytes()).await
                                {
                                    tracing::debug!(error = %e, "L40: failed to write TLS error response to agent");
                                }
                                if let Err(e) = agent_tls.flush().await {
                                    tracing::debug!(error = %e, "L40: failed to flush TLS error response to agent");
                                }
                                return Ok(());
                            }
                        } else {
                            tracing::warn!(
                                branch = %branch_id,
                                credential = %resolved.credential_name,
                                "§3.4/C4: credential not authorized for domain '{}'", domain
                            );
                            let error_body = "Credential not authorized for this domain\n";
                            let error_response = format!(
                                "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                error_body.len(), error_body
                            );
                            if let Err(e) = agent_tls.write_all(error_response.as_bytes()).await {
                                tracing::debug!(error = %e, "L40: failed to write TLS error response to agent");
                            }
                            if let Err(e) = agent_tls.flush().await {
                                tracing::debug!(error = %e, "L40: failed to flush TLS error response to agent");
                            }
                            return Ok(());
                        }
                    } else {
                        tracing::warn!(
                            branch = %branch_id,
                            "§3.4/C4: invalid or expired phantom token in TLS intercept"
                        );
                        let error_body = "Invalid or expired phantom token\n";
                        let error_response = format!(
                            "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            error_body.len(), error_body
                        );
                        if let Err(e) = agent_tls.write_all(error_response.as_bytes()).await {
                            tracing::debug!(error = %e, "L40: failed to write TLS error response to agent");
                        }
                        if let Err(e) = agent_tls.flush().await {
                            tracing::debug!(error = %e, "L40: failed to flush TLS error response to agent");
                        }
                        return Ok(());
                    }
                }

                // D-C2: Strip any remaining phantom tokens from other headers.
                // If the agent sent phantom tokens in multiple headers (e.g., both
                // Authorization and X-Api-Key), only one was resolved above. Any
                // unresolved phantom tokens must be removed to prevent leaking the
                // phantom token prefix pattern to upstream.
                let resolved_idx = inject_header_idx; // the index we already resolved
                let mut indices_to_remove: Vec<usize> = Vec::new();
                for (idx, (_name, value)) in headers.iter().enumerate() {
                    if Some(idx) == resolved_idx {
                        continue; // already handled
                    }
                    // J43: Case-insensitive prefix matching per RFC 7235 §2.1
                    let token_part =
                        if value.len() >= 7 && value[..7].eq_ignore_ascii_case("bearer ") {
                            &value[7..]
                        } else if value.len() >= 6 && value[..6].eq_ignore_ascii_case("basic ") {
                            &value[6..]
                        } else {
                            value.as_str()
                        };
                    if mgr.is_phantom_token(token_part) {
                        tracing::warn!(
                            branch = %branch_id,
                            header_name = %_name,
                            "D-C2: stripping additional phantom token from header (not resolved, would leak to upstream)"
                        );
                        indices_to_remove.push(idx);
                    }
                }
                // Remove in reverse order to preserve indices
                for idx in indices_to_remove.into_iter().rev() {
                    headers.remove(idx);
                }

                // D-I2/M-4: If no phantom token was found, strip all credential-bearing
                // headers (defense-in-depth). The agent should only use phantom tokens;
                // any other auth header is fabricated or leaked. PRD §3.4.8 Step 5.
                if inject_header_idx.is_none() {
                    let before_len = headers.len();
                    headers.retain(|(name, _)| {
                        !name.eq_ignore_ascii_case("authorization")
                            && !name.eq_ignore_ascii_case("x-api-key")
                            && !name.eq_ignore_ascii_case("proxy-authorization")
                    });
                    if headers.len() < before_len {
                        tracing::warn!(
                            branch = %branch_id,
                            "D-I2/M-4/§3.4: stripped non-phantom credential headers in TLS intercept path"
                        );
                    }
                }
            }
        }

        // T14: URI credential exfiltration check in TLS intercept path.
        // Mirrors the G23 check in the non-TLS path — blocks agents from
        // embedding credentials in request path or query parameters.
        // U18: Check original_path (captured before injection) to avoid false-positive
        // when QueryParameter injection appended the credential to the query string.
        if let Some(ref cred_val) = injected_credential_value {
            if original_path.contains(cred_val.as_str()) {
                tracing::warn!(
                    branch = %branch_id,
                    "T14/§3.4: real credential value found in request URI after injection — blocking"
                );
                if let Some(ref sender) = audit_sender {
                    send_audit(
                        sender,
                        crate::ProxyAuditEvent::CredentialDenied {
                            branch_id: branch_id.clone(),
                            credential_name: "unknown".to_string(),
                            domain: domain.to_string(),
                            reason: "credential_exfiltration_in_uri".to_string(),
                        },
                    );
                }
                let error_body = "Credential value detected in request URI — blocked\n";
                let error_response = format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    error_body.len(),
                    error_body
                );
                if let Err(e) = agent_tls.write_all(error_response.as_bytes()).await {
                    tracing::debug!(error = %e, "failed to write TLS error response");
                }
                if let Err(e) = agent_tls.flush().await {
                    tracing::debug!(error = %e, "failed to flush TLS error response");
                }
                return Ok(());
            }
        }

        // D-I4: Credential body exfiltration check in TLS intercept path.
        // If a credential was injected, verify the request body does NOT contain it.
        // D-I2: Uses byte-string search instead of from_utf8 to detect credentials
        // in non-UTF-8 bodies (binary payloads with embedded credential bytes).
        if let Some(ref cred_val) = injected_credential_value {
            let cred_bytes = cred_val.as_bytes();
            if !body.is_empty()
                && !cred_bytes.is_empty()
                && body.windows(cred_bytes.len()).any(|w| w == cred_bytes)
            {
                tracing::warn!(
                    branch = %branch_id,
                    "D-I4/§3.4: real credential value found in request body after injection — blocking"
                );
                if let Some(ref sender) = audit_sender {
                    send_audit(
                        sender,
                        crate::ProxyAuditEvent::CredentialDenied {
                            branch_id: branch_id.clone(),
                            credential_name: "unknown".to_string(),
                            domain: domain.to_string(),
                            reason: "credential_exfiltration_in_body".to_string(),
                        },
                    );
                }
                let error_body = "Credential value detected in request body — blocked\n";
                let error_response = format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    error_body.len(),
                    error_body
                );
                if let Err(e) = agent_tls.write_all(error_response.as_bytes()).await {
                    tracing::debug!(error = %e, "L40: failed to write TLS error response to agent");
                }
                if let Err(e) = agent_tls.flush().await {
                    tracing::debug!(error = %e, "L40: failed to flush TLS error response to agent");
                }
                return Ok(());
            }
        }

        // Route based on method
        let method_upper = method_str.to_uppercase();
        let is_side_effect = matches!(method_upper.as_str(), "POST" | "PUT" | "DELETE" | "PATCH");

        // §3.3: DLP inspection on intercepted side-effect request bodies
        // D-C3: Compressed request bodies are blocked by D-C1 (Content-Encoding
        // rejection) when DLP is active, so only uncompressed bodies reach here.
        // Compressed *response* bodies are decompressed before DLP/credential
        // scanning below (see resp_content_encoding handling).
        if is_side_effect {
            if let Some(ref dlp) = dlp_engine {
                if body.len() > max_inspection_body_size {
                    match oversized_body_action {
                        crate::dlp::OversizedAction::BlockAndAlert => {
                            tracing::warn!(
                                branch = %branch_id,
                                body_size = body.len(),
                                limit = max_inspection_body_size,
                                "§3.3/C4: oversized body blocked in TLS intercept (fail closed)"
                            );
                            let error_body = format!(
                                "Request body too large for DLP inspection (max {} bytes)\n",
                                max_inspection_body_size
                            );
                            let error_response = format!(
                                "HTTP/1.1 413 Payload Too Large\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                error_body.len(),
                                error_body
                            );
                            if let Err(e) = agent_tls.write_all(error_response.as_bytes()).await {
                                tracing::debug!(error = %e, "L40: failed to write TLS error response to agent");
                            }
                            if let Err(e) = agent_tls.flush().await {
                                tracing::debug!(error = %e, "L40: failed to flush TLS error response to agent");
                            }
                            return Ok(());
                        }
                        crate::dlp::OversizedAction::AllowAndLog => {
                            tracing::warn!(
                                branch = %branch_id,
                                body_size = body.len(),
                                limit = max_inspection_body_size,
                                "§3.3/C4: oversized body allowed without DLP inspection in TLS intercept (fail open)"
                            );
                            // Skip DLP inspection, continue to journal
                        }
                    }
                } else {
                    match inspect_dlp_body(
                        &body,
                        dlp,
                        branch_id,
                        quarantine_sender.as_ref(),
                        audit_sender.as_ref(),
                        domain,
                    ) {
                        Ok(Some(redacted)) => {
                            body = redacted;
                        }
                        Ok(None) => {
                            // No redaction needed, continue with original body
                        }
                        Err(resp) => {
                            // L21: DLP blocked the request — use a fixed-size error
                            // message instead of collecting the (potentially large)
                            // response body unboundedly.
                            let status = resp.status();
                            let dlp_err_body = "DLP blocked request\n";
                            let error_response = format!(
                                "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                status.as_u16(),
                                status.canonical_reason().unwrap_or("Forbidden"),
                                dlp_err_body.len(),
                                dlp_err_body,
                            );
                            if let Err(e) = agent_tls.write_all(error_response.as_bytes()).await {
                                tracing::debug!(error = %e, "L40: failed to write TLS error response to agent");
                            }
                            if let Err(e) = agent_tls.flush().await {
                                tracing::debug!(error = %e, "L40: failed to flush TLS error response to agent");
                            }
                            return Ok(());
                        }
                    }
                }
            }
        }

        if is_side_effect {
            // D-I8: Redact credential headers before journaling to avoid writing
            // real credentials to disk in plaintext. Create a redacted copy of headers
            // for the journal entry while preserving original headers for the upstream request.
            // N10: Also redact custom header names from credential injection.
            let redacted_headers: Vec<(String, String)> = headers
                .iter()
                .map(|(name, value)| {
                    let lower_name = name.to_lowercase();
                    if lower_name == "authorization"
                        || lower_name == "x-api-key"
                        || lower_name == "proxy-authorization"
                        || injected_custom_header_name
                            .as_ref()
                            .is_some_and(|h| h.to_lowercase() == lower_name)
                    {
                        (name.clone(), "[REDACTED]".to_string())
                    } else {
                        (name.clone(), value.clone())
                    }
                })
                .collect();

            // N5: Redact query string from journal URI when credential was injected
            // as a query parameter, to avoid writing the credential to disk.
            let journal_uri = if injected_via_query_param {
                if let Some(qpos) = full_uri.find('?') {
                    format!("{}?REDACTED", &full_uri[..qpos])
                } else {
                    full_uri.clone()
                }
            } else {
                full_uri.clone()
            };

            // Journal the request for replay at commit time
            let entry = crate::replay::JournalEntry {
                method: method_str.to_string(),
                uri: journal_uri,
                headers: redacted_headers,
                body: body.clone(),
                timestamp: chrono_now(),
                safe_replay: false,
            };

            let mut journal_guard = journal.lock().await;
            if let Err(e) = journal_guard.append(entry).await {
                tracing::error!(
                    branch = %branch_id,
                    error = %e,
                    "C4: failed to journal intercepted request"
                );
                // C8: Send a 502 response back to the agent with correct Content-Length
                let error_body = "Journal write failed\r\n";
                let error_response = format!(
                    "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\n\r\n{}",
                    error_body.len(),
                    error_body
                );
                if let Err(e) = agent_tls.write_all(error_response.as_bytes()).await {
                    tracing::debug!(error = %e, "L40: failed to write TLS error response to agent");
                }
                return Err(format!("journal write failed: {}", e));
            }
            drop(journal_guard);

            tracing::info!(
                branch = %branch_id,
                method = %method_str,
                uri = %full_uri,
                "C4: side-effect request journaled"
            );

            // Return synthetic 200 OK — do NOT forward side-effect to upstream.
            // Side-effects are replayed at commit time, not executed immediately.
            // C8: Content-Length must match actual body size exactly.
            let synthetic_body = "Request journaled; will be replayed at commit\n";
            let synthetic_response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nX-PuzzlePod-Journaled: true\r\n\r\n{}",
                synthetic_body.len(),
                synthetic_body
            );
            agent_tls
                .write_all(synthetic_response.as_bytes())
                .await
                .map_err(|e| format!("writing synthetic response to agent: {}", e))?;
            agent_tls
                .flush()
                .await
                .map_err(|e| format!("flushing synthetic response: {}", e))?;

            tracing::info!(
                branch = %branch_id,
                method = %method_str,
                uri = %full_uri,
                "C4: side-effect request journaled — synthetic 200 OK returned (not forwarded to upstream)"
            );
        } else {
            // Forward the raw request bytes to upstream
            // H65: Validate path and method contain no CR/LF to prevent header injection
            // V17: Header value CR/LF validation is handled by D-C3 (is_valid_http_header_value) — defense is split but complete
            if method_str.contains('\r')
                || method_str.contains('\n')
                || path.contains('\r')
                || path.contains('\n')
            {
                return Err(
                    "H65: request line contains CR/LF characters — possible header injection"
                        .to_string(),
                );
            }
            // H64: Validate domain contains no CR/LF to prevent header injection
            if domain.contains('\r') || domain.contains('\n') {
                return Err(
                    "H64: domain contains CR/LF characters — possible header injection".to_string(),
                );
            }
            // Reconstruct the HTTP request to send to upstream
            let mut upstream_request = format!("{} {} HTTP/1.1\r\n", method_str, path);
            // Ensure Host header is present
            let has_host = headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("host"));
            if !has_host {
                upstream_request.push_str(&format!("Host: {}\r\n", domain));
            }
            for (name, value) in &headers {
                // Skip hop-by-hop headers
                let lower = name.to_lowercase();
                if HOP_BY_HOP_HEADERS.contains(&lower.as_str()) {
                    continue;
                }
                // §3.4.8 step 7: Strip Accept-Encoding to force uncompressed responses,
                // ensuring credential scanning can inspect response bodies reliably.
                if lower == "accept-encoding" {
                    continue;
                }
                upstream_request.push_str(&format!("{}: {}\r\n", name, value));
            }
            upstream_request.push_str("\r\n");

            // §3.4 G26: Detect Expect: 100-continue header
            let has_expect_continue = headers.iter().any(|(n, v)| {
                n.eq_ignore_ascii_case("expect") && v.trim().eq_ignore_ascii_case("100-continue")
            });

            upstream_tls
                .write_all(upstream_request.as_bytes())
                .await
                .map_err(|e| format!("writing request to upstream: {}", e))?;

            upstream_tls
                .flush()
                .await
                .map_err(|e| format!("flushing upstream: {}", e))?;

            // §3.4 G26: If Expect: 100-continue, wait for upstream's 100 Continue
            // response and relay it back to the agent before sending the body.
            if has_expect_continue && !body.is_empty() {
                use tokio::io::AsyncReadExt;
                let mut continue_buf = [0u8; 256];
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    upstream_tls.read(&mut continue_buf),
                )
                .await
                {
                    Ok(Ok(n)) if n > 0 => {
                        // Relay the 100 Continue (or other response) to agent
                        agent_tls
                            .write_all(&continue_buf[..n])
                            .await
                            .map_err(|e| format!("relaying 100-continue to agent: {}", e))?;
                        agent_tls
                            .flush()
                            .await
                            .map_err(|e| format!("flushing 100-continue: {}", e))?;
                    }
                    Ok(Ok(_)) => {
                        tracing::debug!(
                            branch = %branch_id,
                            "§3.4 G26: upstream closed connection during 100-continue"
                        );
                    }
                    Ok(Err(e)) => {
                        tracing::debug!(
                            branch = %branch_id,
                            error = %e,
                            "§3.4 G26: error reading 100-continue from upstream"
                        );
                    }
                    Err(_) => {
                        tracing::debug!(
                            branch = %branch_id,
                            "§3.4 G26: 100-continue timeout — sending body anyway"
                        );
                    }
                }
            }

            if !body.is_empty() {
                upstream_tls
                    .write_all(&body)
                    .await
                    .map_err(|e| format!("writing request body to upstream: {}", e))?;
            }

            upstream_tls
                .flush()
                .await
                .map_err(|e| format!("flushing upstream: {}", e))?;

            // D-I5: Read the response from upstream using Content-Length or EOF.
            // Previously this read until EOF, which blocks on HTTP/1.1 keep-alive
            // connections where the server does not close the connection after each response.
            let mut response_buf = Vec::new();

            // U21: Response header size is bounded by hyper's default limits (currently ~64KB)
            // Step 1: Read until response headers are complete (\r\n\r\n)
            let resp_header_end;
            loop {
                if let Some(pos) = find_header_end(&response_buf) {
                    resp_header_end = pos;
                    break;
                }
                let n = upstream_tls
                    .read(&mut tmp_buf)
                    .await
                    .map_err(|e| format!("reading response headers from upstream: {}", e))?;
                if n == 0 {
                    // Server closed before sending complete headers
                    if response_buf.is_empty() {
                        return Err("upstream closed connection without response".to_string());
                    }
                    // Treat whatever we have as the full response (incomplete headers)
                    resp_header_end = response_buf.len().saturating_sub(4);
                    break;
                }
                response_buf.extend_from_slice(&tmp_buf[..n]);
                if response_buf.len() > MAX_RESPONSE_BODY_BYTES {
                    tracing::warn!(
                        branch = %branch_id,
                        bytes = response_buf.len(),
                        "C4: response headers exceeded size limit, closing"
                    );
                    resp_header_end = response_buf.len().saturating_sub(4);
                    break;
                }
            }

            // Step 2: Parse response headers to extract Content-Length and Transfer-Encoding
            let resp_body_start = resp_header_end + 4;
            let mut resp_content_length: Option<usize> = None;
            let mut resp_is_chunked = false;
            let mut resp_content_encoding: Option<String> = None;
            if let Ok(header_str) = std::str::from_utf8(&response_buf[..resp_header_end]) {
                for line in header_str.split("\r\n") {
                    if let Some((name, value)) = line.split_once(':') {
                        if name.trim().eq_ignore_ascii_case("content-length") {
                            resp_content_length = value.trim().parse().ok();
                        }
                        // D-C1: Detect chunked Transfer-Encoding in upstream responses
                        if name.trim().eq_ignore_ascii_case("transfer-encoding")
                            && value.trim().eq_ignore_ascii_case("chunked")
                        {
                            resp_is_chunked = true;
                        }
                        // D-C3: Detect Content-Encoding for response decompression
                        if name.trim().eq_ignore_ascii_case("content-encoding") {
                            resp_content_encoding = Some(value.trim().to_lowercase());
                        }
                    }
                }
            }

            // Step 3: Read body bytes based on Content-Length, chunked encoding, or EOF
            if resp_is_chunked {
                // D-M2: Read chunked body with per-read timeout instead of fragile
                // terminal marker detection. The `decode_chunked_body()` parser after
                // this loop handles proper chunk boundary parsing.
                loop {
                    match tokio::time::timeout(
                        Duration::from_secs(30),
                        upstream_tls.read(&mut tmp_buf),
                    )
                    .await
                    {
                        Ok(Ok(0)) => break, // EOF — server closed
                        Ok(Ok(n)) => {
                            response_buf.extend_from_slice(&tmp_buf[..n]);
                            if response_buf.len() > MAX_RESPONSE_BODY_BYTES {
                                tracing::warn!(
                                    branch = %branch_id,
                                    bytes = response_buf.len(),
                                    "D-C1: chunked response exceeded size limit, closing"
                                );
                                break;
                            }
                            // Probe: try to decode what we have so far. If it succeeds,
                            // the chunked body is complete.
                            let body_so_far = &response_buf[resp_body_start..];
                            if decode_chunked_body(body_so_far).is_ok() {
                                break;
                            }
                        }
                        Ok(Err(e)) => {
                            return Err(format!("reading chunked response from upstream: {}", e));
                        }
                        Err(_) => {
                            tracing::warn!(
                                branch = %branch_id,
                                bytes = response_buf.len(),
                                "D-M2: per-read timeout (30s) while reading chunked response, treating as complete"
                            );
                            break;
                        }
                    }
                }

                // Decode the chunked body
                let raw_chunked_body = &response_buf[resp_body_start..];
                match decode_chunked_body(raw_chunked_body) {
                    Ok(decoded_body) => {
                        // Rebuild response: replace Transfer-Encoding: chunked with
                        // Content-Length: <decoded_length> and use decoded body.
                        let header_bytes = &response_buf[..resp_header_end];
                        if let Ok(header_str) = std::str::from_utf8(header_bytes) {
                            let mut new_response = Vec::new();
                            for line in header_str.split("\r\n") {
                                if let Some((name, _)) = line.split_once(':') {
                                    if name.trim().eq_ignore_ascii_case("transfer-encoding") {
                                        // Replace with Content-Length
                                        new_response.extend_from_slice(
                                            format!("Content-Length: {}", decoded_body.len())
                                                .as_bytes(),
                                        );
                                        new_response.extend_from_slice(b"\r\n");
                                        continue;
                                    }
                                }
                                new_response.extend_from_slice(line.as_bytes());
                                new_response.extend_from_slice(b"\r\n");
                            }
                            new_response.extend_from_slice(b"\r\n");
                            new_response.extend_from_slice(&decoded_body);
                            response_buf = new_response;
                        } else {
                            // Cannot re-parse headers — just truncate and append decoded body
                            response_buf.truncate(resp_body_start);
                            response_buf.extend_from_slice(&decoded_body);
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            branch = %branch_id,
                            error = %e,
                            "D-C1: failed to decode chunked response body, passing raw"
                        );
                        // Fall through with the raw response — DLP will inspect chunk framing
                        // but this is a best-effort fallback for malformed responses.
                    }
                }
            } else if let Some(cl) = resp_content_length {
                // Read exactly `cl` body bytes
                let already_read = response_buf.len().saturating_sub(resp_body_start);
                let remaining = cl.saturating_sub(already_read);
                if remaining > 0 && (already_read + remaining) <= MAX_RESPONSE_BODY_BYTES {
                    let mut bytes_left = remaining;
                    while bytes_left > 0 {
                        let n = upstream_tls
                            .read(&mut tmp_buf)
                            .await
                            .map_err(|e| format!("reading response body from upstream: {}", e))?;
                        if n == 0 {
                            break; // Server closed early
                        }
                        response_buf.extend_from_slice(&tmp_buf[..n]);
                        bytes_left = bytes_left.saturating_sub(n);
                    }
                }
            } else {
                // D-C2: No Content-Length or chunked encoding — fall back to reading
                // until EOF (HTTP/1.0 style) with a per-read timeout to prevent hangs
                // on keep-alive connections that never send EOF.
                tracing::warn!(
                    branch = %branch_id,
                    "D-C2: upstream response has no Content-Length or chunked encoding, reading until EOF with 30s timeout"
                );
                loop {
                    match tokio::time::timeout(
                        Duration::from_secs(30),
                        upstream_tls.read(&mut tmp_buf),
                    )
                    .await
                    {
                        Ok(Ok(0)) => break, // EOF
                        Ok(Ok(n)) => {
                            response_buf.extend_from_slice(&tmp_buf[..n]);
                            if response_buf.len() > MAX_RESPONSE_BODY_BYTES {
                                tracing::warn!(
                                    branch = %branch_id,
                                    bytes = response_buf.len(),
                                    "C4: response exceeded size limit, closing"
                                );
                                break;
                            }
                        }
                        Ok(Err(e)) => {
                            return Err(format!("reading from upstream: {}", e));
                        }
                        Err(_) => {
                            tracing::warn!(
                                branch = %branch_id,
                                bytes = response_buf.len(),
                                "D-C2: per-read timeout (30s) in EOF fallback path, treating response as complete"
                            );
                            break;
                        }
                    }
                }
            }

            // D-C3: Decompress response body for DLP + credential leak scanning.
            // We decompress into a separate buffer for inspection only; the original
            // compressed response is forwarded to the agent unchanged (the agent
            // expects the Content-Encoding it negotiated with the upstream).
            let decompressed_body: Option<Vec<u8>> = if resp_content_encoding
                .as_deref()
                .is_some_and(|e| !e.is_empty() && e != "identity")
            {
                if let Some(hdr_end) = find_header_end(&response_buf) {
                    let body_off = hdr_end + 4;
                    if body_off < response_buf.len() {
                        let raw_body = &response_buf[body_off..];
                        match decompress_for_scanning(
                            raw_body,
                            resp_content_encoding.as_deref().unwrap_or(""),
                        ) {
                            Ok(decompressed) => {
                                tracing::debug!(
                                    branch = %branch_id,
                                    encoding = resp_content_encoding.as_deref().unwrap_or(""),
                                    compressed_size = raw_body.len(),
                                    decompressed_size = decompressed.len(),
                                    "D-C3: decompressed response body for DLP/credential scanning"
                                );
                                Some(decompressed)
                            }
                            Err(reason) => {
                                // Fail-closed: unsupported or corrupt encoding blocks the response.
                                tracing::warn!(
                                    branch = %branch_id,
                                    reason = %reason,
                                    "D-C3: blocking response — cannot decompress for scanning"
                                );
                                let error_body =
                                    "Response blocked: unsupported Content-Encoding for DLP scanning\n";
                                let error_response = format!(
                                    "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    error_body.len(),
                                    error_body
                                );
                                if let Err(e) = agent_tls.write_all(error_response.as_bytes()).await
                                {
                                    tracing::debug!(
                                        error = %e,
                                        "D-C3: failed to write error response to agent"
                                    );
                                }
                                if let Err(e) = agent_tls.flush().await {
                                    tracing::debug!(error = %e, "D-C3: failed to flush error response to agent");
                                }
                                return Ok(());
                            }
                        }
                    } else {
                        None // No body to decompress
                    }
                } else {
                    None // Could not find header end
                }
            } else {
                None // Not compressed or identity encoding
            };

            // §3.3: DLP inspection on TLS-intercepted response body
            let response_to_send = if let Some(ref dlp) = dlp_engine {
                // Find the response body start (after headers)
                if let Some(body_offset) = find_header_end(&response_buf) {
                    let body_start = body_offset + 4; // skip \r\n\r\n
                    if body_start < response_buf.len() {
                        // D-C3: Use decompressed body for inspection if available.
                        let resp_body = if let Some(ref decompressed) = decompressed_body {
                            decompressed.as_slice()
                        } else {
                            &response_buf[body_start..]
                        };
                        if !resp_body.is_empty() && resp_body.len() > max_inspection_body_size {
                            // D-I1: Handle oversized response bodies in TLS intercept path
                            match oversized_body_action {
                                crate::dlp::OversizedAction::BlockAndAlert => {
                                    tracing::warn!(
                                        branch = %branch_id,
                                        body_size = resp_body.len(),
                                        limit = max_inspection_body_size,
                                        "§3.3/C4: oversized response body blocked in TLS intercept (fail closed)"
                                    );
                                    let error_body = "Response body too large for DLP inspection\n";
                                    let error_response = format!(
                                        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                        error_body.len(), error_body
                                    );
                                    error_response.into_bytes()
                                }
                                crate::dlp::OversizedAction::AllowAndLog => {
                                    tracing::warn!(
                                        branch = %branch_id,
                                        body_size = resp_body.len(),
                                        limit = max_inspection_body_size,
                                        "§3.3/C4: oversized response body allowed without DLP inspection in TLS intercept (fail open)"
                                    );
                                    response_buf
                                }
                            }
                        } else if !resp_body.is_empty() {
                            // Gap 29: Use inspect_response() for response bodies, not inspect()
                            let result = dlp.inspect_response(resp_body);
                            if !result.matches.is_empty() {
                                for m in &result.matches {
                                    tracing::warn!(
                                        branch = %branch_id,
                                        rule = %m.rule_name,
                                        action = ?m.action,
                                        "§3.3/C4: DLP match in TLS-intercepted response body"
                                    );
                                }
                            }
                            if !result.allowed {
                                tracing::warn!(
                                    branch = %branch_id,
                                    "§3.3/C4: DLP blocked response — sensitive content in TLS-intercepted response"
                                );
                                // Send quarantine signal if needed
                                if result.most_severe_action()
                                    == Some(crate::dlp::DlpAction::Quarantine)
                                {
                                    if let Some(ref qs) = quarantine_sender {
                                        if qs.try_send(branch_id.clone()).is_err() {
                                            tracing::error!(branch = %branch_id, "DLP-8: quarantine channel full — QUARANTINE NOT APPLIED");
                                        }
                                    }
                                }
                                let error_body =
                                    "Response blocked by DLP: sensitive content detected\n";
                                let error_response = format!(
                                    "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    error_body.len(),
                                    error_body
                                );
                                error_response.into_bytes()
                            } else if let Some(modified) = result.modified_body {
                                tracing::info!(
                                    branch = %branch_id,
                                    "§3.3/C4: DLP redacted content in TLS-intercepted response body"
                                );
                                // Rebuild response with redacted body and updated Content-Length.
                                // Scan header bytes for Content-Length and replace in-place.
                                let header_bytes = &response_buf[..body_offset];
                                let cl_pos = header_bytes.windows(16).position(|w| {
                                    w.len() >= 15
                                        && w[..15].eq_ignore_ascii_case(b"content-length:")
                                });
                                if let Some(pos) = cl_pos {
                                    // Find the end of the Content-Length line
                                    let line_end = header_bytes[pos..]
                                        .windows(2)
                                        .position(|w| w == b"\r\n")
                                        .map(|p| pos + p)
                                        .unwrap_or(body_offset);
                                    let new_cl_line = format!("Content-Length: {}", modified.len());
                                    let mut final_resp = Vec::with_capacity(
                                        pos + new_cl_line.len()
                                            + (body_offset - line_end)
                                            + 4
                                            + modified.len(),
                                    );
                                    final_resp.extend_from_slice(&response_buf[..pos]);
                                    final_resp.extend_from_slice(new_cl_line.as_bytes());
                                    final_resp
                                        .extend_from_slice(&response_buf[line_end..body_start]);
                                    final_resp.extend_from_slice(&modified);
                                    final_resp
                                } else {
                                    let mut new_resp = response_buf[..body_start].to_vec();
                                    new_resp.extend_from_slice(&modified);
                                    new_resp
                                }
                            } else {
                                response_buf
                            }
                        } else {
                            response_buf
                        }
                    } else {
                        response_buf
                    }
                } else {
                    response_buf
                }
            } else {
                response_buf
            };

            // §3.4/C4: Check response body for injected credential leakage.
            // A malicious upstream could echo back the real credential value,
            // allowing the agent to extract it from the response.
            // D-I2: The contains() check below may have false positives for short
            // credential values that happen to appear in response content. For a
            // security check, false positives (blocking legitimate responses) are
            // acceptable — they are strictly better than false negatives (leaking
            // credentials). Short credentials are uncommon in practice.
            // D-I3: Use byte-string search instead of from_utf8 to detect credentials
            // in non-UTF-8 response bodies (binary payloads, images, etc.).
            // D-C3: Also scan decompressed body when Content-Encoding was present.
            let response_to_send = if let Some(ref cred_val) = injected_credential_value {
                let cred_bytes = cred_val.as_bytes();
                if !cred_bytes.is_empty() {
                    // M-2: Scan response HEADERS for credential leakage (TLS path).
                    // The non-TLS path scans headers at M6; this adds parity for TLS.
                    let header_leaked = if let Some(header_end) = find_header_end(&response_to_send)
                    {
                        let header_section = &response_to_send[..header_end];
                        header_section
                            .windows(cred_bytes.len())
                            .any(|w| w == cred_bytes)
                    } else {
                        false
                    };
                    if header_leaked {
                        tracing::error!(
                            branch = %branch_id,
                            domain = %domain,
                            "M-2/§3.4: BLOCKED — response HEADER contains injected credential value"
                        );
                        if let Some(ref sender) = audit_sender {
                            send_audit(
                                sender,
                                crate::ProxyAuditEvent::CredentialDenied {
                                    branch_id: branch_id.clone(),
                                    credential_name: "unknown".to_string(),
                                    domain: domain.to_string(),
                                    reason: "credential_echo_in_response_header".to_string(),
                                },
                            );
                        }
                        let error_body = "Response blocked: credential leakage in header\n";
                        let error_response = format!(
                            "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            error_body.len(), error_body
                        );
                        error_response.into_bytes()
                    } else {
                        // Check the response body (after headers) for the credential value.
                        // D-C3: If we have a decompressed body, scan that instead of the
                        // raw (compressed) bytes so credentials hidden in compressed
                        // payloads are detected.
                        let scan_body: Option<&[u8]> =
                            if let Some(ref decompressed) = decompressed_body {
                                Some(decompressed.as_slice())
                            } else if let Some(body_offset) = find_header_end(&response_to_send) {
                                let start = body_offset + 4;
                                if start < response_to_send.len() {
                                    Some(&response_to_send[start..])
                                } else {
                                    None
                                }
                            } else {
                                None
                            };
                        if let Some(resp_body) = scan_body {
                            // F3: Check raw, Base64, URL-encoded, and HTML-entity variants
                            // (matching the non-TLS path's scan_response_for_credential_leak).
                            let cred_b64 = zeroize::Zeroizing::new(base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD,
                                cred_bytes,
                            ));
                            let cred_url = zeroize::Zeroizing::new(
                                urlencoding::encode(cred_val.as_str()).into_owned(),
                            );
                            let cred_html = zeroize::Zeroizing::new(
                                cred_val
                                    .bytes()
                                    .map(|b| format!("&#{};", b))
                                    .collect::<String>(),
                            );
                            let tls_leaked = (resp_body.len() >= cred_bytes.len()
                                && resp_body.windows(cred_bytes.len()).any(|w| w == cred_bytes))
                                || (resp_body.len() >= cred_b64.len()
                                    && resp_body
                                        .windows(cred_b64.len())
                                        .any(|w| w == cred_b64.as_bytes()))
                                || (resp_body.len() >= cred_url.len()
                                    && resp_body
                                        .windows(cred_url.len())
                                        .any(|w| w == cred_url.as_bytes()))
                                || (!cred_html.is_empty()
                                    && resp_body.len() >= cred_html.len()
                                    && resp_body
                                        .windows(cred_html.len())
                                        .any(|w| w == cred_html.as_bytes()));
                            if tls_leaked {
                                tracing::error!(
                                    branch = %branch_id,
                                    domain = %domain,
                                    "§3.4/C4: BLOCKED — response body contains injected credential value (upstream echo attack)"
                                );
                                if let Some(ref sender) = audit_sender {
                                    send_audit(
                                        sender,
                                        crate::ProxyAuditEvent::CredentialDenied {
                                            branch_id: branch_id.clone(),
                                            credential_name: "unknown".to_string(),
                                            domain: domain.to_string(),
                                            reason: "credential_echo_in_response".to_string(),
                                        },
                                    );
                                }
                                let error_body = "Response blocked: credential leakage detected\n";
                                let error_response = format!(
                                    "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    error_body.len(), error_body
                                );
                                error_response.into_bytes()
                            } else {
                                response_to_send
                            }
                        } else {
                            response_to_send
                        }
                    } // close M-2 header_leaked else
                } else {
                    response_to_send
                }
            } else {
                response_to_send
            };

            // Write response to agent
            agent_tls
                .write_all(&response_to_send)
                .await
                .map_err(|e| format!("writing response to agent: {}", e))?;

            agent_tls
                .flush()
                .await
                .map_err(|e| format!("flushing agent stream: {}", e))?;

            tracing::info!(
                branch = %branch_id,
                method = %method_str,
                uri = %full_uri,
                response_bytes = response_to_send.len(),
                "C4: TLS MITM interception complete"
            );
        }

        // D-I1: Zeroize the injected credential value in the headers vector.
        // The `resolved.auth_header_value` is zeroized via ResolvedCredential's Drop,
        // and `injected_credential_value` is wrapped in Zeroizing<String>, but the
        // clone placed into `headers[idx].1` is a plain String that must be explicitly
        // zeroized after the response has been sent.
        if let Some(ref _cred) = injected_credential_value {
            // inject_header_idx was set during phantom token scanning
            // Zeroize all auth-related headers in the vector to be safe
            // Q6: Also zeroize custom header credentials (e.g., X-Custom-Auth from N10 injection)
            for (_name, value) in headers.iter_mut() {
                use zeroize::Zeroize;
                let lower = _name.to_lowercase();
                if lower == "authorization"
                    || lower == "x-api-key"
                    || lower == "proxy-authorization"
                    || injected_custom_header_name
                        .as_ref()
                        .is_some_and(|h| h.to_lowercase() == lower)
                {
                    value.zeroize();
                }
            }
        }

        // If the agent sent Connection: close, stop processing further requests.
        if connection_close {
            tracing::debug!(
                branch = %branch_id,
                domain = %domain,
                "C4: Connection: close received, ending keep-alive loop"
            );
            break;
        }
    } // end keep-alive loop

    Ok(())
}
