// SPDX-License-Identifier: Apache-2.0
//! §3.4: Credential injection — resolve phantom tokens in request headers.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};
use puzzled_types::BranchId;
use tokio::sync::RwLock;

use crate::credentials::{InjectionMethod, PhantomTokenManager};

use super::util::send_audit;
use super::BoxBody;

/// Resolve phantom tokens in request Authorization/custom headers to real credentials.
///
/// Scans all header values for the phantom token prefix. When found, resolves the
/// surrogate to the real credential and replaces the header value. The agent never
/// sees the real secret — only the proxy holds the mapping.
///
/// Returns `Ok((request, Some(real_credential_value)))` when a phantom token is resolved,
/// or `Ok((request, None))` when no injection occurred.
/// Returns `Err(Response)` with 401 if a phantom token is invalid/expired, or
/// 403 if the token's domain scope doesn't match the request.
/// Also strips any non-phantom Authorization headers (defense-in-depth).
#[allow(clippy::result_large_err)]
pub(super) async fn inject_credentials(
    req: Request<hyper::body::Incoming>,
    ptm: &Arc<RwLock<PhantomTokenManager>>,
    host: Option<&str>,
    profile: Option<&str>,
    branch_id: &BranchId,
    audit_sender: Option<&tokio::sync::mpsc::Sender<crate::ProxyAuditEvent>>,
) -> Result<
    (
        Request<hyper::body::Incoming>,
        Option<zeroize::Zeroizing<String>>,
    ),
    Response<BoxBody>,
> {
    let mgr = ptm.read().await;

    // Check Authorization header for phantom tokens
    if let Some(auth_value) = req.headers().get("authorization") {
        if let Ok(auth_str) = auth_value.to_str() {
            // G14: Extract the token part using case-insensitive prefix matching
            // per RFC 7235 §2.1 — auth-scheme is case-insensitive.
            let token_part = if auth_str.len() >= 7 && auth_str[..7].eq_ignore_ascii_case("bearer ")
            {
                &auth_str[7..]
            } else if auth_str.len() >= 6 && auth_str[..6].eq_ignore_ascii_case("basic ") {
                &auth_str[6..]
            } else {
                auth_str
            };

            if mgr.is_phantom_token(token_part) {
                let resolved = mgr
                    .resolve(token_part, Some(branch_id))
                    .await
                    .ok_or_else(|| {
                        tracing::warn!(
                            branch = %branch_id,
                            "§3.4: invalid or expired phantom token — returning 401"
                        );
                        if let Some(sender) = audit_sender {
                            send_audit(
                                sender,
                                crate::ProxyAuditEvent::CredentialDenied {
                                    branch_id: branch_id.clone(),
                                    credential_name: "unknown".to_string(),
                                    domain: host.unwrap_or("unknown").to_string(),
                                    reason: "invalid_or_expired_phantom_token".to_string(),
                                },
                            );
                        }
                        Response::builder()
                            .status(StatusCode::UNAUTHORIZED)
                            .body(Full::new(Bytes::from("Invalid or expired phantom token\n")))
                            .unwrap()
                    })?;

                // Verify domain scope
                let domain_ok = match host {
                    Some(h) => resolved
                        .target_domains
                        .iter()
                        .any(|d| crate::credentials::domain_matches(h, d)),
                    None => false,
                };
                if !domain_ok {
                    tracing::warn!(
                        branch = %branch_id,
                        host = ?host,
                        credential = %resolved.credential_name,
                        "§3.4: phantom token domain mismatch — returning 403"
                    );
                    if let Some(sender) = audit_sender {
                        send_audit(
                            sender,
                            crate::ProxyAuditEvent::CredentialDenied {
                                branch_id: branch_id.clone(),
                                credential_name: resolved.credential_name.clone(),
                                domain: host.unwrap_or("unknown").to_string(),
                                reason: "domain_mismatch".to_string(),
                            },
                        );
                    }
                    return Err(Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(Full::new(Bytes::from(
                            "Credential not authorized for this domain\n",
                        )))
                        .unwrap());
                }

                // §3.4.4: Verify credential's allowed_profiles includes branch profile
                if let Some(prof) = profile {
                    let profile_ok = resolved
                        .allowed_profiles
                        .iter()
                        .any(|p| p == "*" || p == prof);
                    if !profile_ok {
                        tracing::warn!(
                            branch = %branch_id,
                            profile = prof,
                            credential = %resolved.credential_name,
                            "§3.4: credential not allowed for this profile — returning 403"
                        );
                        if let Some(sender) = audit_sender {
                            send_audit(
                                sender,
                                crate::ProxyAuditEvent::CredentialDenied {
                                    branch_id: branch_id.clone(),
                                    credential_name: resolved.credential_name.clone(),
                                    domain: host.unwrap_or("unknown").to_string(),
                                    reason: "profile_mismatch".to_string(),
                                },
                            );
                        }
                        return Err(Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(Full::new(Bytes::from(
                                "Credential not authorized for this profile\n",
                            )))
                            .unwrap());
                    }
                }

                tracing::info!(
                    branch = %branch_id,
                    credential = %resolved.credential_name,
                    "§3.4: phantom token resolved — injecting real credential"
                );
                if let Some(sender) = audit_sender {
                    let domain_str = host.unwrap_or("unknown").to_string();
                    send_audit(
                        sender,
                        crate::ProxyAuditEvent::CredentialInjected {
                            branch_id: branch_id.clone(),
                            credential_name: resolved.credential_name.clone(),
                            domain: domain_str.clone(),
                        },
                    );
                    // §3.4 T2.1: Emit CredentialResolved for D-Bus signal
                    send_audit(
                        sender,
                        crate::ProxyAuditEvent::CredentialResolved {
                            branch_id: branch_id.clone(),
                            credential_name: resolved.credential_name.clone(),
                            domain: domain_str,
                        },
                    );
                }

                let injected_value = resolved.auth_header_value.clone();
                let (mut parts, body) = req.into_parts();
                // H63: fail-closed — if injection fails, block the request
                // R3: generic error — do not leak internal error details
                if let Err(e) = inject_resolved_credential(&mut parts, &resolved) {
                    tracing::error!(error = %e, "H63: credential injection failed");
                    return Err(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Full::new(Bytes::from("Credential injection failed\n")))
                        .unwrap());
                }

                // M-5/G36: Dual phantom token stripping on Authorization path —
                // after resolving a phantom token from the Authorization header,
                // scan remaining headers for unresolved phantom tokens and strip them.
                // Without this, an agent sending both Authorization: Bearer pt_puzzled_foo
                // and X-Api-Key: pt_puzzled_bar would leak the X-Api-Key phantom to upstream.
                let phantom_prefix = mgr.phantom_prefix();
                let headers_to_remove: Vec<hyper::header::HeaderName> = parts
                    .headers
                    .iter()
                    .filter(|(n, v)| {
                        *n != "authorization"
                            && v.to_str().is_ok_and(|s| s.contains(phantom_prefix))
                    })
                    .map(|(n, _)| n.clone())
                    .collect();
                for h in &headers_to_remove {
                    tracing::warn!(
                        branch = %branch_id,
                        header = %h,
                        "M-5/G36: stripping unresolved phantom token from header (Authorization path)"
                    );
                    parts.headers.remove(h);
                }

                return Ok((Request::from_parts(parts, body), Some(injected_value)));
            } else {
                // §3.4: Strip non-phantom Authorization headers (defense-in-depth).
                // The agent should only use phantom tokens; any other auth header
                // is either fabricated or leaked.
                tracing::warn!(
                    branch = %branch_id,
                    "§3.4: stripping non-phantom Authorization header"
                );
                let (mut parts, body) = req.into_parts();
                parts.headers.remove("authorization");
                return Ok((Request::from_parts(parts, body), None));
            }
        }
    }

    // Also check for phantom tokens in custom headers (X-Api-Key, etc.)
    // Collect matching header name + token to avoid borrowing req while consuming it.
    let mut phantom_header: Option<(hyper::header::HeaderName, String)> = None;
    for (name, val) in req.headers().iter() {
        if name == "authorization" {
            continue; // Already handled above
        }
        if let Ok(val_str) = val.to_str() {
            if mgr.is_phantom_token(val_str) {
                phantom_header = Some((name.clone(), val_str.to_string()));
                break;
            }
        }
    }

    if let Some((name, token_str)) = phantom_header {
        let resolved = match mgr.resolve(&token_str, Some(branch_id)).await {
            Some(r) => r,
            None => {
                tracing::warn!(
                    branch = %branch_id,
                    header = %name,
                    "§3.4: invalid phantom token in custom header — returning 401"
                );
                if let Some(sender) = audit_sender {
                    send_audit(
                        sender,
                        crate::ProxyAuditEvent::CredentialDenied {
                            branch_id: branch_id.clone(),
                            credential_name: "unknown".to_string(),
                            domain: host.unwrap_or("unknown").to_string(),
                            reason: "invalid_or_expired_phantom_token".to_string(),
                        },
                    );
                }
                return Err(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Full::new(Bytes::from("Invalid or expired phantom token\n")))
                    .unwrap());
            }
        };

        let domain_ok = match host {
            Some(h) => resolved
                .target_domains
                .iter()
                .any(|d| crate::credentials::domain_matches(h, d)),
            None => false,
        };
        if !domain_ok {
            if let Some(sender) = audit_sender {
                send_audit(
                    sender,
                    crate::ProxyAuditEvent::CredentialDenied {
                        branch_id: branch_id.clone(),
                        credential_name: resolved.credential_name.clone(),
                        domain: host.unwrap_or("unknown").to_string(),
                        reason: "domain_mismatch".to_string(),
                    },
                );
            }
            return Err(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from(
                    "Credential not authorized for this domain\n",
                )))
                .unwrap());
        }

        // §3.4.4: Verify credential's allowed_profiles includes branch profile (defense-in-depth)
        if let Some(prof) = profile {
            let profile_ok = resolved
                .allowed_profiles
                .iter()
                .any(|p| p == "*" || p == prof);
            if !profile_ok {
                if let Some(sender) = audit_sender {
                    send_audit(
                        sender,
                        crate::ProxyAuditEvent::CredentialDenied {
                            branch_id: branch_id.clone(),
                            credential_name: resolved.credential_name.clone(),
                            domain: host.unwrap_or("unknown").to_string(),
                            reason: "profile_mismatch".to_string(),
                        },
                    );
                }
                return Err(Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Full::new(Bytes::from(
                        "Credential not authorized for this profile\n",
                    )))
                    .unwrap());
            }
        }

        tracing::info!(
            branch = %branch_id,
            credential = %resolved.credential_name,
            header = %name,
            "§3.4: phantom token in custom header resolved"
        );
        if let Some(sender) = audit_sender {
            let domain_str = host.unwrap_or("unknown").to_string();
            send_audit(
                sender,
                crate::ProxyAuditEvent::CredentialInjected {
                    branch_id: branch_id.clone(),
                    credential_name: resolved.credential_name.clone(),
                    domain: domain_str.clone(),
                },
            );
            // §3.4 T2.1: Emit CredentialResolved for D-Bus signal
            send_audit(
                sender,
                crate::ProxyAuditEvent::CredentialResolved {
                    branch_id: branch_id.clone(),
                    credential_name: resolved.credential_name.clone(),
                    domain: domain_str,
                },
            );
        }
        let injected_value = resolved.auth_header_value.clone();
        let (mut parts, body) = req.into_parts();
        // H63: fail-closed — if injection fails, block the request
        // R3: generic error — do not leak internal error details
        if let Err(e) = inject_resolved_credential(&mut parts, &resolved) {
            tracing::error!(error = %e, "H63: credential injection failed");
            return Err(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from("Credential injection failed\n")))
                .unwrap());
        }

        // §3.4 G34: URI credential leakage check — after injection, verify the
        // real credential value is not present in the request URI query parameters.
        if let Some(query) = parts.uri.query() {
            if query.contains(&*injected_value) {
                tracing::error!(
                    branch = %branch_id,
                    "§3.4 G34: BLOCKED — real credential value found in request URI query parameters"
                );
                return Err(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Full::new(Bytes::from(
                        "Credential leakage in URI detected\n",
                    )))
                    .unwrap());
            }
        }

        // §3.4 G36: Dual phantom token stripping — after resolving one phantom
        // token, scan remaining headers for unresolved phantom tokens and remove them.
        let phantom_prefix = mgr.phantom_prefix();
        let headers_to_remove: Vec<hyper::header::HeaderName> = parts
            .headers
            .iter()
            .filter(|(n, v)| {
                *n != "authorization"
                    && n.as_str() != name.as_str()
                    && v.to_str().is_ok_and(|s| s.contains(phantom_prefix))
            })
            .map(|(n, _)| n.clone())
            .collect();
        for h in headers_to_remove {
            tracing::warn!(
                branch = %branch_id,
                header = %h,
                "§3.4 G36: stripping unresolved phantom token from header"
            );
            parts.headers.remove(&h);
        }

        return Ok((Request::from_parts(parts, body), Some(injected_value)));
    }

    // M-4: When no phantom token is found in any header, strip all credential-bearing
    // headers as defense-in-depth (PRD §3.4.8 Step 5). The agent should only use
    // phantom tokens; any raw credential header is fabricated or leaked.
    let (mut parts, body) = req.into_parts();
    let mut stripped = false;
    for header_name in &["x-api-key", "proxy-authorization"] {
        if parts.headers.remove(*header_name).is_some() {
            tracing::warn!(
                branch = %branch_id,
                header = %header_name,
                "M-4/§3.4: stripping non-phantom credential header (no phantom token found)"
            );
            stripped = true;
        }
    }
    if stripped {
        return Ok((Request::from_parts(parts, body), None));
    }

    Ok((Request::from_parts(parts, body), None))
}

/// Inject a resolved credential into the request based on the injection method.
///
/// Modifies headers for Bearer/Basic/CustomHeader, rewrites the URI for QueryParameter,
/// and adds AWS SigV4 placeholder headers for AwsSigV4.
///
/// H63: Returns Err on injection failure (fail-closed) instead of silently continuing
/// which would forward the request unauthenticated.
pub(super) fn inject_resolved_credential(
    parts: &mut hyper::http::request::Parts,
    resolved: &crate::credentials::ResolvedCredential,
) -> Result<(), String> {
    match &resolved.injection {
        InjectionMethod::BearerHeader | InjectionMethod::BasicHeader => {
            match hyper::header::HeaderValue::from_str(&resolved.auth_header_value) {
                Ok(val) => {
                    parts.headers.insert("authorization", val);
                }
                Err(e) => {
                    // H63: Fail-closed — return error instead of silently continuing
                    let msg = format!(
                        "§3.4: credential injection failed — header value contains invalid characters: {}",
                        e
                    );
                    tracing::error!(
                        credential = %resolved.credential_name,
                        error = %e,
                        "H63: {}", msg
                    );
                    return Err(msg);
                }
            }
        }
        InjectionMethod::CustomHeader { header_name } => {
            match hyper::header::HeaderName::from_bytes(header_name.as_bytes()) {
                Ok(hname) => {
                    match hyper::header::HeaderValue::from_str(&resolved.auth_header_value) {
                        Ok(val) => {
                            parts.headers.insert(hname, val);
                        }
                        Err(e) => {
                            // H63: Fail-closed — return error instead of silently continuing
                            let msg = format!(
                                "§3.4: credential injection failed — header value contains invalid characters: {}",
                                e
                            );
                            tracing::error!(
                                credential = %resolved.credential_name,
                                header = %header_name,
                                error = %e,
                                "H63: {}", msg
                            );
                            return Err(msg);
                        }
                    }
                }
                Err(e) => {
                    // H63: Fail-closed — return error instead of silently continuing
                    let msg = format!(
                        "§3.4: credential injection failed — invalid header name: {}",
                        e
                    );
                    tracing::error!(
                        credential = %resolved.credential_name,
                        header = %header_name,
                        error = %e,
                        "H63: {}", msg
                    );
                    return Err(msg);
                }
            }
        }
        InjectionMethod::QueryParameter { param_name } => {
            // §3.4 C3: Append credential as a query parameter to the URI.
            let uri = &parts.uri;
            let path = uri.path();
            let existing_query = uri.query().unwrap_or("");
            // G13: URL-encode both param_name and value to prevent injection
            // attacks via crafted parameter names containing '&' or '='.
            let encoded_name = urlencoding::encode(param_name);
            let encoded_value = urlencoding::encode(&resolved.auth_header_value);
            let new_query = if existing_query.is_empty() {
                format!("{}={}", encoded_name, encoded_value)
            } else {
                format!("{}&{}={}", existing_query, encoded_name, encoded_value)
            };
            let new_uri_str = if let Some(authority) = uri.authority() {
                let scheme = uri.scheme_str().unwrap_or("https");
                format!("{}://{}{}?{}", scheme, authority, path, new_query)
            } else {
                format!("{}?{}", path, new_query)
            };
            if let Ok(new_uri) = new_uri_str.parse() {
                parts.uri = new_uri;
                tracing::debug!(
                    param = %param_name,
                    "§3.4: injected credential as query parameter"
                );
            } else {
                // J41: fail-closed on URI parse failure (consistent with H63 pattern)
                return Err(format!(
                    "J41: failed to parse rewritten URI for query parameter injection (param={})",
                    param_name
                ));
            }
        }
        InjectionMethod::AwsSigV4 => {
            // §3.4 C4: AWS SigV4 request signing stub.
            // Full SigV4 signing requires computing a canonical request hash, string-to-sign,
            // and HMAC-SHA256 signature using the credential's access key and secret key.
            // Do NOT inject the raw secret key — that would leak it in cleartext.
            // Phase 2: Implement proper SigV4 signing with the aws-sigv4 crate.
            tracing::warn!(
                credential = %resolved.credential_name,
                "§3.4: AWS SigV4 signing not yet implemented — request will not be authenticated (requires aws-sigv4 crate)"
            );
        }
    }
    Ok(()) // H63: explicit success return
}

/// §3.4: Scan a response body for the injected credential value.
/// If the upstream echoes back the real credential, block the response to prevent leakage.
///
/// DEVIATION (M-1): PRD §3.4.8 specifies "direct byte comparison from mlock'd secure
/// region (NOT Aho-Corasick)." This function takes `credential_value: &str` from a
/// `Zeroizing<String>` on the heap, rather than reading directly from the
/// `SecureCredentialStore`'s mlock'd `SecureRegion`. The `Zeroizing` wrapper ensures
/// cleanup on drop. Full refactor to use `CredentialManager::scan_bytes()` would
/// require threading the CredentialManager through the response pipeline — deferred
/// to a future iteration. The `scan_bytes()` method exists in `secure_memory.rs`
/// and is ready for integration when the pipeline refactor is done.
pub(super) async fn scan_response_for_credential_leak(
    resp: Response<BoxBody>,
    credential_value: &str,
    branch_id: &BranchId,
    domain: &str,
    audit_sender: Option<&tokio::sync::mpsc::Sender<crate::ProxyAuditEvent>>,
) -> Response<BoxBody> {
    use http_body_util::BodyExt;

    use super::dlp_inspect::decompress_for_scanning;
    use super::MAX_RESPONSE_BODY_BYTES;

    if credential_value.is_empty() {
        return resp;
    }
    // L20: Check Content-Length before collecting body to prevent OOM.
    // Credential scan is a secondary check — skip it for oversized bodies.
    let (parts, body) = resp.into_parts();
    if let Some(cl) = parts.headers.get(hyper::header::CONTENT_LENGTH) {
        if let Ok(cl_str) = cl.to_str() {
            if let Ok(cl_val) = cl_str.parse::<usize>() {
                if cl_val > MAX_RESPONSE_BODY_BYTES {
                    tracing::debug!(
                        branch = %branch_id,
                        domain = %domain,
                        content_length = cl_val,
                        limit = MAX_RESPONSE_BODY_BYTES,
                        "L20: skipping credential scan — Content-Length exceeds MAX_RESPONSE_BODY_BYTES"
                    );
                    return Response::from_parts(parts, body);
                }
            }
        }
    }
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return Response::from_parts(parts, Full::new(Bytes::new())),
    };
    // L20: Post-collect size check for cases where Content-Length was absent
    if body_bytes.len() > MAX_RESPONSE_BODY_BYTES {
        tracing::debug!(
            branch = %branch_id,
            domain = %domain,
            body_size = body_bytes.len(),
            "L20: skipping credential scan — collected body exceeds MAX_RESPONSE_BODY_BYTES"
        );
        return Response::from_parts(parts, Full::new(body_bytes));
    }
    // §3.4 G25: Skip binary Content-Types — credential scanning is not useful
    // for binary content and would produce false positives.
    if let Some(ct) = parts.headers.get(hyper::header::CONTENT_TYPE) {
        if let Ok(ct_str) = ct.to_str() {
            let ct_lower = ct_str.to_lowercase();
            if ct_lower.starts_with("image/")
                || ct_lower.starts_with("audio/")
                || ct_lower.starts_with("video/")
                || ct_lower == "application/octet-stream"
                || ct_lower.starts_with("application/zip")
                || ct_lower.starts_with("application/gzip")
            {
                tracing::debug!(
                    branch = %branch_id,
                    content_type = %ct_str,
                    "§3.4 G25: skipping credential scan for binary Content-Type"
                );
                return Response::from_parts(parts, Full::new(body_bytes));
            }
        }
    }

    // M6: Scan response HEADERS for credential leakage before scanning body.
    // An upstream could echo credentials in response headers (e.g.,
    // X-Received-Auth, X-Request-Id containing the auth value).
    let cred_bytes_for_headers = credential_value.as_bytes();
    if !cred_bytes_for_headers.is_empty() {
        for (name, value) in parts.headers.iter() {
            if let Ok(val_str) = value.to_str() {
                if val_str
                    .as_bytes()
                    .windows(cred_bytes_for_headers.len())
                    .any(|w| w == cred_bytes_for_headers)
                {
                    tracing::error!(
                        branch = %branch_id,
                        domain = %domain,
                        header = %name,
                        "§3.4 M6: BLOCKED — response header contains injected credential value"
                    );
                    if let Some(sender) = audit_sender {
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
                    return Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Full::new(Bytes::from(
                            "Response blocked: credential leakage detected in response header\n",
                        )))
                        .unwrap();
                }
            }
        }
    }

    // D-I3: Use byte-string search instead of from_utf8 to detect credentials
    // in non-UTF-8 response bodies.
    // §3.4 G25: Also check Base64, URL-encoded, and HTML-entity variants.
    let cred_bytes = credential_value.as_bytes();
    // F6: Wrap derived credential encodings in Zeroizing to prevent heap residue.
    let cred_base64 = zeroize::Zeroizing::new(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        cred_bytes,
    ));
    let cred_url_encoded =
        zeroize::Zeroizing::new(urlencoding::encode(credential_value).into_owned());
    // F1: Generate HTML-entity encoded variant (decimal form) for response scanning.
    let cred_html_entity = zeroize::Zeroizing::new(
        credential_value
            .bytes()
            .map(|b| format!("&#{};", b))
            .collect::<String>(),
    );

    // F2: Decompress response body if Content-Encoding is present (non-TLS path).
    let scan_bytes: std::borrow::Cow<'_, [u8]> = if let Some(ce) =
        parts.headers.get(hyper::header::CONTENT_ENCODING)
    {
        if let Ok(ce_str) = ce.to_str() {
            match decompress_for_scanning(&body_bytes, ce_str) {
                Ok(decompressed) => std::borrow::Cow::Owned(decompressed),
                Err(reason) => {
                    tracing::error!(
                        branch = %branch_id,
                        domain = %domain,
                        reason = %reason,
                        "F2: failed to decompress response for credential scan — blocking (fail-closed)"
                    );
                    return Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Full::new(Bytes::from(
                            "Response blocked: unsupported Content-Encoding\n",
                        )))
                        .unwrap();
                }
            }
        } else {
            std::borrow::Cow::Borrowed(body_bytes.as_ref())
        }
    } else {
        std::borrow::Cow::Borrowed(body_bytes.as_ref())
    };

    let leaked = !cred_bytes.is_empty()
        && scan_bytes.len() >= cred_bytes.len()
        && (scan_bytes
            .windows(cred_bytes.len())
            .any(|w| w == cred_bytes)
            || scan_bytes
                .windows(cred_base64.len())
                .any(|w| w == cred_base64.as_bytes())
            || scan_bytes
                .windows(cred_url_encoded.len())
                .any(|w| w == cred_url_encoded.as_bytes())
            || (!cred_html_entity.is_empty()
                && scan_bytes.len() >= cred_html_entity.len()
                && scan_bytes
                    .windows(cred_html_entity.len())
                    .any(|w| w == cred_html_entity.as_bytes())));

    if leaked {
        tracing::error!(
            branch = %branch_id,
            domain = %domain,
            "§3.4: BLOCKED — response body contains injected credential value (upstream echo attack)"
        );
        if let Some(sender) = audit_sender {
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
        return Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from(
                "Response blocked: credential leakage detected\n",
            )))
            .unwrap();
    }
    Response::from_parts(parts, Full::new(body_bytes))
}

/// D-C2: Inject a resolved credential into a raw header vector (TLS intercept path).
///
/// Dispatches based on `resolved.injection` to correctly handle each injection method,
/// matching the behavior of `inject_resolved_credential()` for the non-TLS path.
///
/// N4: The headers vec stores `(String, String)` — the credential value is temporarily
/// held as a plain `String` in the vec. The returned `Zeroizing<String>` is zeroized on
/// drop, and the header vec values are overwritten by `redacted_headers` construction
/// before the originals are dropped. However, the plain `String` in the vec may leave
/// residual bytes in freed heap memory. Changing the vec to `Vec<(String, Zeroizing<String>)>`
/// would require refactoring all header parsing in the TLS intercept path.
pub(super) fn inject_credential_into_header_vec(
    headers: &mut Vec<(String, String)>,
    path: &mut String,
    resolved: &crate::credentials::ResolvedCredential,
    phantom_header_idx: usize,
) -> Option<zeroize::Zeroizing<String>> {
    match &resolved.injection {
        InjectionMethod::BearerHeader => {
            // N4: credential value is briefly held as plain String in headers vec
            headers[phantom_header_idx] = (
                "authorization".to_string(),
                (*resolved.auth_header_value).clone(),
            );
            Some(resolved.auth_header_value.clone())
        }
        InjectionMethod::BasicHeader => {
            // N4: credential value is briefly held as plain String in headers vec
            headers[phantom_header_idx] = (
                "authorization".to_string(),
                (*resolved.auth_header_value).clone(),
            );
            Some(resolved.auth_header_value.clone())
        }
        InjectionMethod::CustomHeader { header_name } => {
            // N4: credential value is briefly held as plain String in headers vec
            // auth_header_value for CustomHeader is the raw value (no prefix)
            headers[phantom_header_idx] =
                (header_name.clone(), (*resolved.auth_header_value).clone());
            Some(resolved.auth_header_value.clone())
        }
        InjectionMethod::QueryParameter { param_name } => {
            // Remove the phantom token header — credential goes in query string, not header
            headers.remove(phantom_header_idx);
            let encoded_value = urlencoding::encode(&resolved.auth_header_value);
            // J40: URL-encode param_name in TLS intercept path (matches G13 non-TLS path)
            let encoded_name = urlencoding::encode(param_name);
            if path.contains('?') {
                path.push_str(&format!("&{}={}", encoded_name, encoded_value));
            } else {
                path.push_str(&format!("?{}={}", encoded_name, encoded_value));
            }
            tracing::debug!(
                param = %param_name,
                "D-C1/§3.4: injected credential as query parameter in TLS intercept path"
            );
            Some(resolved.auth_header_value.clone())
        }
        InjectionMethod::AwsSigV4 => {
            // AwsSigV4: Do NOT inject the raw secret — log warning per PRD 3.4.10 item 10
            headers.remove(phantom_header_idx);
            tracing::warn!(
                credential = %resolved.credential_name,
                "D-C1/§3.4: AWS SigV4 signing not supported in TLS intercept path — \
                 phantom token removed but request will not be authenticated"
            );
            None
        }
    }
}
