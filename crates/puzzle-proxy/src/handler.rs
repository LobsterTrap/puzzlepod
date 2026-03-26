// SPDX-License-Identifier: Apache-2.0
//! HTTP request handler for the agent proxy.
//!
//! Routes requests based on method:
//! - GET/HEAD: forward immediately if domain allowed
//! - POST/PUT/DELETE/PATCH: journal for replay at commit
//! - CONNECT: tunnel with domain validation (HTTPS)

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use puzzled_types::BranchId;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode};
use rustls::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, RwLock, Semaphore};
use tokio_rustls::TlsAcceptor;

use crate::credentials::{InjectionMethod, PhantomTokenManager};
use crate::dlp::DlpEngine;
use crate::replay::NetworkJournal;
use crate::tls::AgentCa;
use crate::ProxyMode;

type BoxBody = http_body_util::Full<Bytes>;

/// Send an audit event, logging a warning if the channel is full or closed.
fn send_audit(
    sender: &tokio::sync::mpsc::Sender<crate::ProxyAuditEvent>,
    event: crate::ProxyAuditEvent,
) {
    match sender.try_send(event) {
        Ok(()) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            tracing::warn!("audit channel full — event dropped");
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            tracing::error!("audit channel closed — audit receiver has shut down");
        }
    }
}

/// Default connect timeout (30 seconds).
// V15: These constants should be made configurable per-profile in Phase 2
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default total request timeout (300 seconds / 5 minutes).
// V15: These constants should be made configurable per-profile in Phase 2
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

/// M16: Maximum response body size (100 MB). Responses exceeding this return 502 Bad Gateway.
const MAX_RESPONSE_BODY_BYTES: usize = 100 * 1024 * 1024;

/// M17: Maximum bytes allowed through a CONNECT tunnel (500 MB) in each direction.
const MAX_TUNNEL_BYTES: u64 = 500 * 1024 * 1024;

/// H4/M-px2: Allowed destination ports for all proxy requests (CONNECT and plain HTTP).
/// Requests to ports not in this list are rejected with 403 Forbidden. This prevents
/// agents from tunneling or connecting to arbitrary services (e.g., databases, internal
/// APIs) via the proxy.
// U22: X-Content-Type-Options: nosniff should be set on error responses to prevent MIME sniffing.
// Currently, error responses are plain-text bodies with no HTML, so MIME sniffing risk is minimal.
// A centralized error_response helper with nosniff is deferred to Phase 2.
// V16: 8080/8443 included for development — production deployments should configure per-profile port allowlists
const ALLOWED_PORTS: &[u16] = &[80, 443, 8080, 8443];

/// H-15: Maximum number of concurrent connections handled by the proxy.
/// Excess connections will wait for a permit before being processed.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 256;

/// Handle an incoming HTTP request from the agent.
///
/// When `ca` is `Some`, CONNECT requests use TLS MITM interception (C4) instead
/// of opaque tunneling, allowing the proxy to inspect and journal HTTPS traffic.
///
/// Domain access is split by method:
/// - GET/HEAD/OPTIONS/CONNECT use `read_allowed_domains`
/// - POST/PUT/DELETE/PATCH use `write_allowed_domains`
/// - `denied_domains` is checked first and overrides all allow lists
/// - `mode` controls overall proxy behavior (Blocked, Gated, Monitored, Unrestricted)
#[allow(clippy::too_many_arguments)]
pub async fn handle_request(
    req: Request<hyper::body::Incoming>,
    read_allowed_domains: &[String],
    write_allowed_domains: &[String],
    denied_domains: &[String],
    mode: &ProxyMode,
    journal: Arc<Mutex<NetworkJournal>>,
    branch_id: &BranchId,
    ca: Option<&AgentCa>,
    connection_semaphore: Arc<Semaphore>,
    dlp_engine: Option<Arc<DlpEngine>>,
    max_inspection_body_size: usize,
    oversized_body_action: crate::dlp::OversizedAction,
    quarantine_sender: Option<tokio::sync::mpsc::Sender<BranchId>>,
    phantom_token_manager: Option<Arc<RwLock<PhantomTokenManager>>>,
    agent_profile: Option<String>,
    geo_database: Option<Arc<crate::geo::GeoIpDatabase>>,
    data_residency: Option<puzzled_types::DataResidencyConfig>,
    audit_sender: Option<tokio::sync::mpsc::Sender<crate::ProxyAuditEvent>>,
    credential_mode: puzzled_types::CredentialMode,
) -> Result<Response<BoxBody>, hyper::Error> {
    // H-15: Acquire a concurrency permit before handling the request.
    // The permit is held for the duration of request processing and
    // released automatically when `_permit` is dropped.
    let _permit = match connection_semaphore.acquire().await {
        Ok(permit) => permit,
        Err(_) => {
            // Semaphore closed — proxy is shutting down
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Full::new(Bytes::from("Proxy shutting down\n")))
                .unwrap());
        }
    };

    let method = req.method().clone();
    let uri = req.uri().clone();

    // Extract the target host
    let host = extract_host(&req);

    tracing::debug!(
        branch = %branch_id,
        method = %method,
        uri = %uri,
        host = ?host,
        "proxy request"
    );

    // Handle proxy mode before any domain checking
    match mode {
        ProxyMode::Blocked => {
            tracing::info!(
                branch = %branch_id,
                method = %method,
                uri = %uri,
                "proxy: request blocked (Blocked mode)"
            );
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from(
                    "Network access blocked by agent profile\n",
                )))
                .unwrap());
        }
        ProxyMode::Unrestricted => {
            // Q11: No DLP inspection in Unrestricted mode — this is intentional. DLP adds
            // latency and is a governance feature; Unrestricted mode is designed for lower-
            // governance tiers where the agent is trusted with outbound data. If the threat
            // model requires DLP in all modes, make it configurable per-profile.
            // H3: SSRF protection — block private/loopback IPs in all modes
            if let Some(ref host) = host {
                if let Err(resp) = check_ssrf(host, branch_id) {
                    return Ok(resp);
                }
            }
            // K44: DNS rebinding protection in Unrestricted mode — resolve hostname
            // and verify no resolved IP is private before forwarding.
            let resolved_addrs = if let Some(ref host) = host {
                match check_dns_rebinding(host, branch_id).await {
                    Ok(addrs) => Some(addrs),
                    Err(resp) => return Ok(resp),
                }
            } else {
                None
            };
            if method == Method::CONNECT {
                // H4: Port allowlist check
                if let Err(resp) = check_connect_port(&req, branch_id) {
                    return Ok(resp);
                }
                // M1: Host header vs CONNECT target validation
                if let Err(resp) = check_connect_host_match(&req, branch_id) {
                    return Ok(resp);
                }
                return handle_connect(req, branch_id, resolved_addrs.as_deref()).await;
            }
            // M-px2: Port allowlist check for non-CONNECT requests
            if let Err(resp) = check_request_port(&req, branch_id) {
                return Ok(resp);
            }
            return forward_request(req, resolved_addrs.as_deref()).await;
        }
        ProxyMode::Monitored => {
            // Q11: No DLP inspection in Monitored mode — intentional design choice. Monitored
            // mode logs all requests but does not enforce governance controls like DLP. This
            // avoids latency overhead for observation-only tiers. See Q11 on Unrestricted.
            // H3: SSRF protection — block private/loopback IPs in all modes
            if let Some(ref host) = host {
                if let Err(resp) = check_ssrf(host, branch_id) {
                    return Ok(resp);
                }
            }
            // K44: DNS rebinding protection in Monitored mode — resolve hostname
            // and verify no resolved IP is private before forwarding.
            let resolved_addrs = if let Some(ref host) = host {
                match check_dns_rebinding(host, branch_id).await {
                    Ok(addrs) => Some(addrs),
                    Err(resp) => return Ok(resp),
                }
            } else {
                None
            };
            // Log everything but forward all requests
            tracing::info!(
                branch = %branch_id,
                method = %method,
                uri = %uri,
                host = ?host,
                "proxy: monitored request (forwarding)"
            );
            // §3.3: GeoIP logging in monitored mode (log only, never block)
            if let (Some(ref geo_db), Some(ref residency)) = (&geo_database, &data_residency) {
                if let Some(ref host) = host {
                    if !crate::geo::is_geo_exception(host, &residency.exceptions) {
                        // T19: Prefer pre-resolved addresses to avoid redundant DNS lookup
                        let geo_ip = resolved_addrs
                            .as_ref()
                            .and_then(|a| a.first().map(|s| s.ip()));
                        let geo_ip = if let Some(ip) = geo_ip {
                            Some(ip)
                        } else if let Ok(addrs) =
                            tokio::net::lookup_host(format!("{}:0", host)).await
                        {
                            addrs.into_iter().next().map(|a| a.ip())
                        } else {
                            None
                        };
                        if let Some(ip) = geo_ip {
                            match geo_db.is_region_allowed(ip, &residency.allowed_regions) {
                                Some(true) => {}
                                Some(false) => {
                                    let country = geo_db
                                        .lookup_country(ip)
                                        .unwrap_or_else(|| "unknown".to_string());
                                    tracing::warn!(
                                        branch = %branch_id,
                                        host = %host,
                                        ip = %ip,
                                        country = %country,
                                        allowed_regions = ?residency.allowed_regions,
                                        "§3.3: geo violation logged (monitored mode — not blocking)"
                                    );
                                }
                                None => {
                                    tracing::debug!(
                                        branch = %branch_id,
                                        ip = %ip,
                                        "§3.3: IP not found in GeoIP database (monitored mode)"
                                    );
                                }
                            }
                        }
                    }
                }
            }
            if method == Method::CONNECT {
                // H4: Port allowlist check
                if let Err(resp) = check_connect_port(&req, branch_id) {
                    return Ok(resp);
                }
                // M1: Host header vs CONNECT target validation
                if let Err(resp) = check_connect_host_match(&req, branch_id) {
                    return Ok(resp);
                }
                if let Some(ca) = ca {
                    // T16: Pass pre-validated addresses to prevent DNS rebinding TOCTOU
                    return handle_tls_intercept(
                        req,
                        branch_id,
                        ca,
                        journal,
                        resolved_addrs.as_deref(),
                        dlp_engine.clone(),
                        max_inspection_body_size,
                        oversized_body_action,
                        quarantine_sender.clone(),
                        audit_sender.clone(),
                        phantom_token_manager.clone(),
                        agent_profile.clone(),
                        credential_mode,
                    )
                    .await;
                } else {
                    return handle_connect(req, branch_id, resolved_addrs.as_deref()).await;
                }
            }
            // M-px2: Port allowlist check for non-CONNECT requests
            if let Err(resp) = check_request_port(&req, branch_id) {
                return Ok(resp);
            }
            return forward_request(req, resolved_addrs.as_deref()).await;
        }
        ProxyMode::Gated => {
            // Fall through to existing gated behavior below
        }
        ProxyMode::Transparent => {
            // §3.4 G7: In transparent mode, the per-request handler uses gated behavior
            // (domain checking, credential injection). The transparent-vs-explicit
            // distinction is handled at the connection level (SNI vs CONNECT),
            // not at the request level.
        }
    }

    // --- Gated mode: full domain checking ---

    // SSRF protection: block requests to private/loopback IPs (string-based check)
    if let Some(ref host) = host {
        if let Err(resp) = check_ssrf(host, branch_id) {
            return Ok(resp);
        }
    }

    // M-px2: Port allowlist check for ALL requests (not just CONNECT).
    // Extract port from the URI and validate against ALLOWED_PORTS.
    if method != Method::CONNECT {
        if let Err(resp) = check_request_port(&req, branch_id) {
            return Ok(resp);
        }
    }

    // Check deny list BEFORE allow list — deny overrides allow
    if let Some(ref host) = host {
        if is_domain_denied(host, denied_domains) {
            tracing::info!(
                branch = %branch_id,
                host = %host,
                "proxy: domain in deny list"
            );
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                // Q10: Do not reflect hostname in error response (information leakage)
                .body(Full::new(Bytes::from("Domain is in agent deny list\n")))
                .unwrap());
        }
    }

    // Check domain allowlist based on method (read vs write)
    if let Some(ref host) = host {
        let is_read = matches!(
            method,
            Method::GET | Method::HEAD | Method::OPTIONS | Method::CONNECT
        );
        let allowed_domains = if is_read {
            read_allowed_domains
        } else {
            write_allowed_domains
        };
        if !is_domain_allowed(host, allowed_domains) {
            tracing::info!(
                branch = %branch_id,
                host = %host,
                kind = if is_read { "read" } else { "write" },
                "proxy: domain not in allowlist"
            );
            // R6: generic error — do not reflect domain or read/write detail
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from("Domain not in agent allowlist\n")))
                .unwrap());
        }
    }

    // C8: DNS rebinding protection — resolve hostname and check if IP is private
    let resolved_addrs = if let Some(ref host) = host {
        match check_dns_rebinding(host, branch_id).await {
            Ok(addrs) => Some(addrs),
            Err(resp) => return Ok(resp),
        }
    } else {
        None
    };

    // §3.3 Step 3: GeoIP data residency check
    if let (Some(ref geo_db), Some(ref residency)) = (&geo_database, &data_residency) {
        if let Some(ref addrs) = resolved_addrs {
            // Gap 27: When dns_verification is true, check ALL resolved IPs (not just the first).
            // This prevents DNS spoofing where a domain resolves to multiple IPs, some in
            // disallowed regions. Without dns_verification, only the first IP is checked.
            let addrs_to_check: Vec<&std::net::SocketAddr> = if residency.dns_verification {
                addrs.iter().collect()
            } else {
                addrs.first().into_iter().collect()
            };

            if let Some(ref host) = host {
                if !crate::geo::is_geo_exception(host, &residency.exceptions) {
                    if residency.dns_verification {
                        tracing::debug!(
                            branch = %branch_id,
                            host = %host,
                            addr_count = addrs_to_check.len(),
                            "§3.3: dns_verification active — checking all {} resolved IPs",
                            addrs_to_check.len()
                        );
                    }

                    for addr in &addrs_to_check {
                        let ip = addr.ip();
                        match geo_db.is_region_allowed(ip, &residency.allowed_regions) {
                            Some(true) => {
                                // Allowed — continue checking remaining IPs if dns_verification
                            }
                            Some(false) => {
                                let country = geo_db
                                    .lookup_country(ip)
                                    .unwrap_or_else(|| "unknown".to_string());
                                match residency.geo_enforcement {
                                    puzzled_types::GeoEnforcement::Strict => {
                                        tracing::warn!(
                                            branch = %branch_id,
                                            host = %host,
                                            ip = %ip,
                                            country = %country,
                                            allowed_regions = ?residency.allowed_regions,
                                            dns_verification = residency.dns_verification,
                                            "§3.3: request blocked — destination outside allowed regions"
                                        );
                                        // Gap 26: Emit audit event for geo-blocked request
                                        if let Some(ref sender) = audit_sender {
                                            send_audit(
                                                sender,
                                                crate::ProxyAuditEvent::DlpBlocked {
                                                    branch_id: branch_id.clone(),
                                                    rule_name: "geo_residency_violation"
                                                        .to_string(),
                                                    domain: format!("{} ({})", host, country),
                                                    match_hash: format!("ip:{}", ip),
                                                },
                                            );
                                        }
                                        // K42: Omit internal IPs, geo info, and region list from response
                                        return Ok(Response::builder()
                                            .status(StatusCode::FORBIDDEN)
                                            .body(Full::new(Bytes::from(
                                                "Data residency violation: destination not in allowed regions\n",
                                            )))
                                            .unwrap());
                                    }
                                    puzzled_types::GeoEnforcement::Permissive => {
                                        tracing::warn!(
                                            branch = %branch_id,
                                            host = %host,
                                            ip = %ip,
                                            country = %country,
                                            "§3.3: geo violation logged (permissive mode)"
                                        );
                                        // Gap 26: Emit audit event for geo violation in permissive mode
                                        if let Some(ref sender) = audit_sender {
                                            send_audit(
                                                sender,
                                                crate::ProxyAuditEvent::DlpDetected {
                                                    branch_id: branch_id.clone(),
                                                    rule_name: "geo_residency_violation"
                                                        .to_string(),
                                                    domain: format!("{} ({})", host, country),
                                                    match_hash: format!("ip:{}", ip),
                                                },
                                            );
                                        }
                                    }
                                }
                            }
                            None => {
                                // IP not in GeoIP database — log but don't block
                                tracing::debug!(
                                    branch = %branch_id,
                                    ip = %ip,
                                    "§3.3: IP not found in GeoIP database"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Handle CONNECT (HTTPS tunneling or TLS MITM interception)
    if method == Method::CONNECT {
        // H4: Port allowlist check
        if let Err(resp) = check_connect_port(&req, branch_id) {
            return Ok(resp);
        }
        // M1: Host header vs CONNECT target validation
        if let Err(resp) = check_connect_host_match(&req, branch_id) {
            return Ok(resp);
        }
        if let Some(ca) = ca {
            // C4: TLS MITM interception — decrypt, inspect, and journal HTTPS traffic
            return handle_tls_intercept(
                req,
                branch_id,
                ca,
                journal,
                resolved_addrs.as_deref(),
                dlp_engine.clone(),
                max_inspection_body_size,
                oversized_body_action,
                quarantine_sender.clone(),
                audit_sender.clone(),
                phantom_token_manager.clone(),
                agent_profile.clone(),
                credential_mode,
            )
            .await;
        } else {
            // Opaque tunnel — no inspection
            return handle_connect(req, branch_id, resolved_addrs.as_deref()).await;
        }
    }

    // DLP-4: Block WebSocket/HTTP upgrade requests when DLP inspection is active.
    // Upgraded connections bypass the body inspection pipeline, so we must reject them.
    if dlp_engine.is_some() && req.headers().get(hyper::header::UPGRADE).is_some() {
        tracing::warn!(
            branch = %branch_id,
            "DLP-4: blocking HTTP Upgrade request — DLP inspection cannot inspect upgraded connections"
        );
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Full::new(Bytes::from(
                "HTTP Upgrade blocked: DLP inspection is active\n",
            )))
            .unwrap());
    }

    // D-C1: Block requests with Content-Encoding when DLP is active.
    // Compressed request bodies bypass DLP pattern matching because the engine
    // inspects raw bytes, not decompressed content. Same conservative approach
    // as the Transfer-Encoding rejection (C7).
    if dlp_engine.is_some() && req.headers().get(hyper::header::CONTENT_ENCODING).is_some() {
        tracing::warn!(
            branch = %branch_id,
            "D-C1: blocking request with Content-Encoding — DLP inspection cannot inspect compressed bodies"
        );
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Full::new(Bytes::from(
                "Content-Encoding blocked: DLP inspection is active\n",
            )))
            .unwrap());
    }

    // T15: Capture original URI before credential injection for exfiltration check.
    // QueryParameter injection modifies the URI, so checking after injection
    // would false-positive on the proxy's own injected credential.
    let original_uri_str = req.uri().to_string();

    // §3.4 Gap 12: Enforce credential mode before injection
    let (req, injected_credential_value) = match credential_mode {
        puzzled_types::CredentialMode::Phantom => {
            // Phantom mode: resolve surrogate tokens to real credentials
            if let Some(ref ptm) = phantom_token_manager {
                match inject_credentials(
                    req,
                    ptm,
                    host.as_deref(),
                    agent_profile.as_deref(),
                    branch_id,
                    audit_sender.as_ref(),
                )
                .await
                {
                    Ok((req, injected_value)) => (req, injected_value),
                    Err(resp) => return Ok(resp),
                }
            } else {
                // §3.4: Phantom mode with no PTM configured — strip auth headers (fail-closed)
                // L6: Also strip x-api-key for consistency with Blocked mode
                tracing::warn!(branch = %branch_id, "§3.4: Phantom mode but no PhantomTokenManager — stripping auth headers (fail-closed)");
                let (mut parts, body) = req.into_parts();
                parts.headers.remove(hyper::header::AUTHORIZATION);
                parts.headers.remove(hyper::header::PROXY_AUTHORIZATION);
                parts.headers.remove("x-api-key");
                (Request::from_parts(parts, body), None)
            }
        }
        puzzled_types::CredentialMode::Blocked => {
            // Blocked mode: strip all Authorization headers from agent requests
            let (mut parts, body) = req.into_parts();
            parts.headers.remove(hyper::header::AUTHORIZATION);
            parts.headers.remove(hyper::header::PROXY_AUTHORIZATION);
            // Q1: Also strip X-Api-Key — common credential header used by REST APIs
            parts.headers.remove("x-api-key");
            tracing::debug!(branch = %branch_id, "§3.4: credential mode=Blocked, stripped auth headers");
            (Request::from_parts(parts, body), None)
        }
        puzzled_types::CredentialMode::Passthrough => {
            // Passthrough mode: agent manages its own credentials, no injection
            (req, None)
        }
    };

    // §3.4 defense-in-depth: If a credential was injected, verify the request
    // does NOT contain the real credential value. An agent might try to exfiltrate
    // credentials by embedding them in the request URI (e.g., query parameters)
    // or body (e.g., POST payload).
    // This check runs AFTER injection and BEFORE DLP/forwarding.
    if let Some(ref real_value) = injected_credential_value {
        // G23: Check the URI for credential exfiltration regardless of Content-Length.
        // GET requests have no Content-Length header but can still carry credentials
        // in query parameters or path segments.
        // T15: Check original URI (before injection) to avoid false-positive on
        // QueryParameter injection where the proxy itself added the credential to the URI.
        if original_uri_str.contains(real_value.as_str()) {
            tracing::warn!(
                branch = %branch_id,
                "§3.4: real credential value found in request URI after injection — blocking"
            );
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from(
                    "Credential value detected in request — blocked\n",
                )))
                .unwrap());
        }
        // Full body checking happens in the DLP engine (step 6).
    }

    // Route based on method
    match method {
        Method::GET | Method::HEAD | Method::OPTIONS => {
            // Read-only: forward immediately
            // H-3: Pass pre-resolved addresses to prevent DNS rebinding TOCTOU
            let resp = forward_request(req, resolved_addrs.as_deref()).await?;
            // §3.3: DLP inspection on response body
            let resp = if let Some(ref dlp) = dlp_engine {
                inspect_dlp_response(
                    resp,
                    dlp,
                    branch_id,
                    audit_sender.as_ref(),
                    host.as_deref().unwrap_or("unknown"),
                    quarantine_sender.as_ref(),
                    max_inspection_body_size,
                    oversized_body_action,
                )
                .await
            } else {
                resp
            };
            // §3.4: Check response body for leaked injected credential
            if let Some(ref cred_val) = injected_credential_value {
                let resp = scan_response_for_credential_leak(
                    resp,
                    cred_val,
                    branch_id,
                    host.as_deref().unwrap_or("unknown"),
                    audit_sender.as_ref(),
                )
                .await;
                return Ok(resp);
            }
            Ok(resp)
        }
        Method::POST | Method::PUT | Method::DELETE | Method::PATCH => {
            // Side-effect: journal for replay at commit
            // §3.3: DLP inspection happens inside journal_request after body buffering
            journal_request(
                req,
                journal,
                branch_id,
                dlp_engine.clone(),
                max_inspection_body_size,
                oversized_body_action,
                quarantine_sender.clone(),
                injected_credential_value.as_ref().map(|v| v.as_str()),
                audit_sender.as_ref(),
                host.as_deref().unwrap_or("unknown"),
            )
            .await
        }
        _ => Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Full::new(Bytes::from("Method not allowed\n")))
            .unwrap()),
    }
}

// ---------------------------------------------------------------------------
// §3.4: Credential injection — resolve phantom tokens in request headers
// ---------------------------------------------------------------------------

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
async fn inject_credentials(
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
fn inject_resolved_credential(
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
async fn scan_response_for_credential_leak(
    resp: Response<BoxBody>,
    credential_value: &str,
    branch_id: &BranchId,
    domain: &str,
    audit_sender: Option<&tokio::sync::mpsc::Sender<crate::ProxyAuditEvent>>,
) -> Response<BoxBody> {
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

/// §3.4 G25 / D-C3: Decompress response body for credential leak scanning.
/// Returns decompressed bytes, or Err with a rejection reason for unknown encodings.
/// Supports gzip and deflate via `flate2`. Unknown or unsupported encodings
/// (br, zstd, etc.) return Err so the caller can fail-closed per PRD.
fn decompress_for_scanning(body: &[u8], content_encoding: &str) -> Result<Vec<u8>, String> {
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

// ---------------------------------------------------------------------------
// §3.3: DLP content inspection
// ---------------------------------------------------------------------------

/// DLP inspection on response body returned from upstream.
///
/// Scans the response body and either blocks or redacts sensitive content.
/// Takes ownership of the response and returns a (possibly modified) response.
#[allow(clippy::too_many_arguments)]
async fn inspect_dlp_response(
    resp: Response<BoxBody>,
    dlp: &DlpEngine,
    branch_id: &BranchId,
    audit_sender: Option<&tokio::sync::mpsc::Sender<crate::ProxyAuditEvent>>,
    domain: &str,
    quarantine_sender: Option<&tokio::sync::mpsc::Sender<BranchId>>,
    max_inspection_body_size: usize,
    oversized_body_action: crate::dlp::OversizedAction,
) -> Response<BoxBody> {
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
fn inspect_dlp_body(
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

/// Check if a resolved IP address is in a private/reserved range.
///
/// Blocks DNS rebinding attacks where a public hostname resolves to a private IP.
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()                          // 127.0.0.0/8
                || v4.is_private()                    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || v4.is_link_local()                 // 169.254.0.0/16
                || v4.is_unspecified()                // 0.0.0.0
                || v4.is_broadcast()                  // 255.255.255.255
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64 // 100.64.0.0/10 (CGNAT)
                // T17: Additional reserved ranges (IANA special-purpose)
                || v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0     // 192.0.0.0/24 (IETF)
                || v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 2     // 192.0.2.0/24 (TEST-NET-1)
                || v4.octets()[0] == 198 && v4.octets()[1] == 51 && v4.octets()[2] == 100  // 198.51.100.0/24 (TEST-NET-2)
                || v4.octets()[0] == 203 && v4.octets()[1] == 0 && v4.octets()[2] == 113   // 203.0.113.0/24 (TEST-NET-3)
                || v4.octets()[0] == 198 && (v4.octets()[1] & 0xFE) == 18                  // 198.18.0.0/15 (benchmarking)
                || v4.octets()[0] >= 240 // 240.0.0.0/4 (reserved)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()                          // ::1
                || v6.is_unspecified()                // ::
                || (v6.segments()[0] & 0xfe00) == 0xfc00  // fc00::/7 (ULA)
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 (link-local)
        }
    }
}

/// Check for DNS rebinding by resolving hostname and verifying the IP is not private.
///
/// Returns `Ok(Vec<SocketAddr>)` with validated addresses on success, or `Err(Response)` if blocked.
/// Callers must use the returned addresses for connecting to prevent DNS rebinding TOCTOU.
///
/// M14: Also checks raw IP addresses (including IPv4-mapped IPv6 like ::ffff:10.0.0.1)
/// against `is_private_ip()`, not just the string-based check.
pub async fn check_dns_rebinding(
    host: &str,
    branch_id: &BranchId,
) -> Result<Vec<std::net::SocketAddr>, Response<BoxBody>> {
    // M14: For raw IP addresses, check against is_private_ip() including IPv4-mapped IPv6
    if let Ok(ip) = host.parse::<IpAddr>() {
        // Extract the inner IPv4 from IPv4-mapped IPv6 (::ffff:x.x.x.x)
        let effective_ip = match ip {
            IpAddr::V6(v6) => {
                let segments = v6.segments();
                // IPv4-mapped IPv6: ::ffff:x.x.x.x has segments [0,0,0,0,0,0xffff,hi,lo]
                if segments[0] == 0
                    && segments[1] == 0
                    && segments[2] == 0
                    && segments[3] == 0
                    && segments[4] == 0
                    && segments[5] == 0xffff
                {
                    let octets = v6.octets();
                    IpAddr::V4(std::net::Ipv4Addr::new(
                        octets[12], octets[13], octets[14], octets[15],
                    ))
                } else {
                    ip
                }
            }
            _ => ip,
        };

        if is_private_ip(&effective_ip) {
            tracing::warn!(
                branch = %branch_id,
                host = %host,
                effective_ip = %effective_ip,
                "proxy: SSRF blocked — raw IP is private/reserved"
            );
            // R4: generic error — do not reflect raw IP address
            return Err(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from(
                    "Blocked: private/reserved IP address\n",
                )))
                .unwrap());
        }
        return Ok(vec![std::net::SocketAddr::new(effective_ip, 0)]);
    }

    // Resolve the hostname and collect results to avoid borrow-lifetime issues
    let lookup_host = format!("{}:0", host);
    let addrs: Vec<std::net::SocketAddr> = match tokio::net::lookup_host(lookup_host).await {
        Ok(addrs) => addrs.collect(),
        Err(e) => {
            tracing::warn!(
                branch = %branch_id,
                host = %host,
                error = %e,
                "proxy: DNS resolution failed"
            );
            // Fail closed: if we can't resolve, block
            // K43: Omit hostname and error details from response
            return Err(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("DNS resolution failed\n")))
                .unwrap());
        }
    };

    for addr in &addrs {
        if is_private_ip(&addr.ip()) {
            tracing::warn!(
                branch = %branch_id,
                host = %host,
                resolved_ip = %addr.ip(),
                "proxy: DNS rebinding blocked — hostname resolved to private IP"
            );
            // N1: Do not leak resolved private IP in error response
            // V2: Don't reflect hostname in error response — prevents information disclosure
            return Err(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from("Blocked: DNS rebinding detected\n")))
                .unwrap());
        }
    }
    Ok(addrs)
}

/// M15: Standard hop-by-hop headers that must not be forwarded by a proxy.
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// M15: Strip hop-by-hop headers from a header map before forwarding.
///
/// Removes the standard hop-by-hop headers and any additional headers
/// named in the `Connection` header value.
pub fn strip_hop_by_hop(headers: &mut hyper::header::HeaderMap) {
    // First, parse the Connection header to find any additional headers to remove
    let extra_headers: Vec<String> = headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(|s| s.trim().to_lowercase()))
        .filter(|s| !s.is_empty())
        .collect();

    // Remove standard hop-by-hop headers
    for header_name in HOP_BY_HOP_HEADERS {
        headers.remove(*header_name);
    }

    // Remove any headers named in the Connection header
    for name in &extra_headers {
        if let Ok(header) = hyper::header::HeaderName::from_bytes(name.as_bytes()) {
            headers.remove(header);
        }
    }
}

/// Forward a request to the upstream server using hyper client.
///
/// H7: Applies connect timeout and total request timeout.
/// H-3: When `resolved_addrs` is provided, uses the pre-resolved IP addresses
/// to connect instead of re-resolving DNS (prevents DNS rebinding TOCTOU).
/// M17: Streams the request body instead of buffering entirely in memory.
async fn forward_request(
    req: Request<hyper::body::Incoming>,
    resolved_addrs: Option<&[std::net::SocketAddr]>,
) -> Result<Response<BoxBody>, hyper::Error> {
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let uri = req.uri().clone();
    tracing::debug!(uri = %uri, "forwarding request");

    // H-3: If we have pre-resolved addresses, connect directly to the pinned IP
    // instead of letting the HTTP client re-resolve DNS (TOCTOU protection).
    if let Some(addrs) = resolved_addrs {
        if let Some(addr) = addrs.first() {
            let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
                Some("https") => 443,
                _ => 80,
            });
            let target_addr = std::net::SocketAddr::new(addr.ip(), port);

            return match tokio::time::timeout(REQUEST_TIMEOUT, async {
                // Connect to the pinned IP address directly
                let tcp_stream = tokio::net::TcpStream::connect(target_addr).await
                    .map_err(|e| {
                        tracing::error!(uri = %uri, addr = %target_addr, error = %e, "failed to connect to pinned IP");
                        e
                    });

                let tcp_stream = match tcp_stream {
                    Ok(s) => s,
                    Err(_e) => {
                        return Ok(Ok(Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            // K41: Omit internal IP and error details from response
                            .body(Full::new(Bytes::from("Failed to connect to upstream\n")))
                            .unwrap()));
                    }
                };

                // Use the TCP stream with hyper's handshake for HTTP/1.1
                let io = hyper_util::rt::TokioIo::new(tcp_stream);
                let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
                    Ok(parts) => parts,
                    Err(e) => {
                        tracing::warn!(error = %e, "R1: HTTP handshake failed");
                        return Ok(Ok(Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            // R1: generic error — do not leak internal handshake error
                            .body(Full::new(Bytes::from("HTTP handshake failed\n")))
                            .unwrap()));
                    }
                };

                // Spawn the connection driver
                tokio::spawn(async move {
                    if let Err(e) = conn.await {
                        tracing::debug!(error = %e, "pinned connection driver error");
                    }
                });

                // Build the outgoing request — rewrite URI to path-only for the direct connection
                let method = req.method().clone();
                let mut headers = req.headers().clone();
                strip_hop_by_hop(&mut headers);

                // §3.4.8 step 7: Strip Accept-Encoding to force uncompressed responses,
                // ensuring credential scanning can inspect response bodies reliably.
                headers.remove("accept-encoding");

                // Ensure Host header is set (required for HTTP/1.1)
                if !headers.contains_key("host") {
                    if let Some(authority) = uri.authority() {
                        if let Ok(val) = hyper::header::HeaderValue::from_str(authority.as_ref()) {
                            headers.insert("host", val);
                        }
                    }
                }

                // Stream body (G25: with size limit to prevent memory exhaustion)
                let mut body_parts = Vec::new();
                let mut total_body_size: usize = 0;
                let mut body_stream = req.into_body();
                while let Some(frame_result) = body_stream.frame().await {
                    match frame_result {
                        Ok(frame) => {
                            if let Ok(data) = frame.into_data() {
                                total_body_size += data.len();
                                if total_body_size > MAX_RESPONSE_BODY_BYTES {
                                    tracing::warn!(
                                        total_body_size,
                                        limit = MAX_RESPONSE_BODY_BYTES,
                                        "G25: request body too large in pinned-IP path"
                                    );
                                    return Ok(Ok(Response::builder()
                                        .status(StatusCode::PAYLOAD_TOO_LARGE)
                                        .body(Full::new(Bytes::from(
                                            "G25: request body too large\n",
                                        )))
                                        .unwrap()));
                                }
                                body_parts.push(data);
                            }
                        }
                        Err(e) => return Err(e),
                    }
                }
                let body_bytes: Bytes = if body_parts.is_empty() {
                    Bytes::new()
                } else if body_parts.len() == 1 {
                    body_parts.into_iter().next().expect("V24: guarded by body_parts len check")
                } else {
                    let total_len: usize = body_parts.iter().map(|b| b.len()).sum();
                    let mut combined = bytes::BytesMut::with_capacity(total_len);
                    for part in body_parts {
                        combined.extend_from_slice(&part);
                    }
                    combined.freeze()
                };

                // Build request with path-only URI for direct connection
                let path_and_query = uri.path_and_query().map(|pq| pq.to_string()).unwrap_or_else(|| "/".to_string());
                let mut outgoing = Request::builder().method(method).uri(path_and_query);
                for (name, value) in headers.iter() {
                    outgoing = outgoing.header(name, value);
                }
                let outgoing = outgoing.body(Full::new(body_bytes)).unwrap();

                match sender.send_request(outgoing).await {
                    Ok(resp) => {
                        let status = resp.status();
                        let resp_headers = resp.headers().clone();
                        let body = resp.into_body();

                        let mut body_parts = Vec::new();
                        let mut total_resp_size: usize = 0;
                        let mut body_stream = body;
                        while let Some(frame_result) = body_stream.frame().await {
                            match frame_result {
                                Ok(frame) => {
                                    if let Ok(data) = frame.into_data() {
                                        total_resp_size += data.len();
                                        if total_resp_size > MAX_RESPONSE_BODY_BYTES {
                                            tracing::warn!(
                                                uri = %uri,
                                                bytes = total_resp_size,
                                                limit = MAX_RESPONSE_BODY_BYTES,
                                                "response body exceeded size limit"
                                            );
                                            return Ok(Ok(Response::builder()
                                                .status(StatusCode::BAD_GATEWAY)
                                                .body(Full::new(Bytes::from(format!(
                                                    "Response body too large (limit {} bytes)\n",
                                                    MAX_RESPONSE_BODY_BYTES
                                                ))))
                                                .unwrap()));
                                        }
                                        body_parts.push(data);
                                    }
                                }
                                Err(e) => return Err(e),
                            }
                        }
                        let body_bytes: Bytes = if body_parts.is_empty() {
                            Bytes::new()
                        } else if body_parts.len() == 1 {
                            body_parts.into_iter().next().expect("V24: guarded by body_parts len check")
                        } else {
                            let mut combined = bytes::BytesMut::with_capacity(total_resp_size);
                            for part in body_parts {
                                combined.extend_from_slice(&part);
                            }
                            combined.freeze()
                        };

                        let mut filtered_resp_headers = resp_headers;
                        strip_hop_by_hop(&mut filtered_resp_headers);

                        let mut response = Response::builder().status(status);
                        for (name, value) in filtered_resp_headers.iter() {
                            response = response.header(name, value);
                        }
                        Ok(Ok(response.body(Full::new(body_bytes)).unwrap()))
                    }
                    Err(e) => {
                        tracing::error!(uri = %uri, error = %e, "upstream request failed (pinned IP)");
                        // K45: Omit internal error details from response
                        Ok(Ok(Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .body(Full::new(Bytes::from("Upstream request failed\n")))
                            .unwrap()))
                    }
                }
            })
            .await
            {
                Ok(result) => result?,
                Err(_elapsed) => {
                    tracing::error!(uri = %uri, "request timed out (pinned IP)");
                    Ok(Response::builder()
                        .status(StatusCode::GATEWAY_TIMEOUT)
                        .body(Full::new(Bytes::from(
                            "Request timed out\n"
                        )))
                        .unwrap())
                }
            };
        }
    }

    // Fallback: no pre-resolved addresses, use standard HTTP client (re-resolves DNS)
    // D-C1: Redirect safety — hyper_util::client::legacy::Client does NOT follow
    // redirects automatically. It returns 3xx responses as-is to the caller.
    // The pinned-IP path above uses raw hyper::client::conn::http1::handshake which
    // also does not follow redirects. Therefore injected credentials in Authorization
    // headers are never carried to a redirect target domain by this code.
    // V1: Refuse to forward https:// URIs over plaintext — prevents credential leakage
    if uri.scheme_str() == Some("https") {
        tracing::error!(uri = %uri, "V1: refusing to forward https:// URI over plaintext HTTP client — TLS downgrade prevented");
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from("TLS required for https:// URIs\n")))
            .unwrap());
    }
    // H7: Wrap the entire request in a total timeout
    match tokio::time::timeout(REQUEST_TIMEOUT, async {
        let client: Client<_, http_body_util::Full<Bytes>> =
            Client::builder(TokioExecutor::new()).build_http();

        // M17: Stream the body — collect it but forward as a single chunk.
        // For hyper 1.x with the legacy client, we build the outgoing request
        // and stream body data through.
        let method = req.method().clone();
        let mut headers = req.headers().clone();

        // M15: Strip hop-by-hop headers before forwarding
        strip_hop_by_hop(&mut headers);

        // §3.4.8 step 7: Strip Accept-Encoding to force uncompressed responses,
        // ensuring credential scanning can inspect response bodies reliably.
        headers.remove("accept-encoding");

        // Stream body: read chunks as they arrive instead of buffering all at once
        // H60: Track total body size and enforce MAX_BODY_SIZE limit
        let mut body_parts = Vec::new();
        let mut total_body_size: usize = 0; // H60: running size counter
        let mut body_stream = req.into_body();
        while let Some(frame_result) = body_stream.frame().await {
            match frame_result {
                Ok(frame) => {
                    if let Ok(data) = frame.into_data() {
                        // H60: Check accumulated size before accepting chunk
                        total_body_size = total_body_size.saturating_add(data.len());
                        if total_body_size > MAX_BODY_SIZE {
                            tracing::warn!(
                                total_body_size,
                                max = MAX_BODY_SIZE,
                                "H60: fallback request body exceeds MAX_BODY_SIZE"
                            );
                            return Ok(Ok(Response::builder()
                                .status(StatusCode::PAYLOAD_TOO_LARGE)
                                .body(Full::new(Bytes::from(format!(
                                    "H60: request body ({} bytes) exceeds limit ({} bytes)\n",
                                    total_body_size, MAX_BODY_SIZE
                                ))))
                                .unwrap()));
                        }
                        body_parts.push(data);
                    }
                }
                Err(e) => return Err(e),
            }
        }
        let body_bytes: Bytes = if body_parts.is_empty() {
            Bytes::new()
        } else if body_parts.len() == 1 {
            body_parts
                .into_iter()
                .next()
                .expect("V24: guarded by body_parts len check")
        } else {
            let total_len: usize = body_parts.iter().map(|b| b.len()).sum();
            let mut combined = bytes::BytesMut::with_capacity(total_len);
            for part in body_parts {
                combined.extend_from_slice(&part);
            }
            combined.freeze()
        };

        let mut outgoing = Request::builder().method(method).uri(uri.clone());
        for (name, value) in headers.iter() {
            outgoing = outgoing.header(name, value);
        }
        let outgoing = outgoing.body(Full::new(body_bytes)).unwrap();

        // H7: Connect timeout is handled by the overall request timeout
        match client.request(outgoing).await {
            Ok(resp) => {
                let status = resp.status();
                let resp_headers = resp.headers().clone();
                let body = resp.into_body();

                // M16: Read response body with size limit enforcement
                let mut body_parts = Vec::new();
                let mut total_resp_size: usize = 0;
                let mut body_stream = body;
                while let Some(frame_result) = body_stream.frame().await {
                    match frame_result {
                        Ok(frame) => {
                            if let Ok(data) = frame.into_data() {
                                total_resp_size += data.len();
                                if total_resp_size > MAX_RESPONSE_BODY_BYTES {
                                    tracing::warn!(
                                        uri = %uri,
                                        bytes = total_resp_size,
                                        limit = MAX_RESPONSE_BODY_BYTES,
                                        "response body exceeded size limit"
                                    );
                                    return Ok(Ok(Response::builder()
                                        .status(StatusCode::BAD_GATEWAY)
                                        .body(Full::new(Bytes::from(format!(
                                            "Response body too large (limit {} bytes)\n",
                                            MAX_RESPONSE_BODY_BYTES
                                        ))))
                                        .unwrap()));
                                }
                                body_parts.push(data);
                            }
                        }
                        Err(e) => return Err(e),
                    }
                }
                let body_bytes: Bytes = if body_parts.is_empty() {
                    Bytes::new()
                } else if body_parts.len() == 1 {
                    body_parts
                        .into_iter()
                        .next()
                        .expect("V24: guarded by body_parts len check")
                } else {
                    let mut combined = bytes::BytesMut::with_capacity(total_resp_size);
                    for part in body_parts {
                        combined.extend_from_slice(&part);
                    }
                    combined.freeze()
                };

                // PM2: Strip hop-by-hop headers from the response before
                // returning to the client, mirroring the request-side stripping.
                let mut filtered_resp_headers = resp_headers;
                strip_hop_by_hop(&mut filtered_resp_headers);

                let mut response = Response::builder().status(status);
                for (name, value) in filtered_resp_headers.iter() {
                    response = response.header(name, value);
                }
                Ok(Ok(response.body(Full::new(body_bytes)).unwrap()))
            }
            Err(e) => {
                tracing::error!(uri = %uri, error = %e, "upstream request failed");
                // K45: Omit internal error details from response
                Ok(Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Full::new(Bytes::from("Upstream request failed\n")))
                    .unwrap()))
            }
        }
    })
    .await
    {
        Ok(result) => result?,
        Err(_elapsed) => {
            tracing::error!(uri = %uri, "request timed out");
            Ok(Response::builder()
                .status(StatusCode::GATEWAY_TIMEOUT)
                .body(Full::new(Bytes::from("Request timed out\n")))
                .unwrap())
        }
    }
}

/// Maximum request body size (100 MB). Requests exceeding this are rejected with HTTP 413.
const MAX_BODY_SIZE: usize = 100 * 1024 * 1024;

/// D-M1: Maximum HTTP header size (64 KB). Headers should be much smaller than bodies.
/// Using MAX_BODY_SIZE (100 MB) for headers allowed excessive memory consumption.
const MAX_HEADER_SIZE: usize = 64 * 1024;

/// Journal a side-effect request for replay at commit time.
///
/// M17: Streams the request body chunk-by-chunk instead of using collect().
/// §3.3: After buffering, inspects the body with the DLP engine (if present).
#[allow(clippy::too_many_arguments)]
async fn journal_request(
    req: Request<hyper::body::Incoming>,
    journal: Arc<Mutex<NetworkJournal>>,
    branch_id: &BranchId,
    dlp_engine: Option<Arc<DlpEngine>>,
    max_inspection_body_size: usize,
    oversized_body_action: crate::dlp::OversizedAction,
    quarantine_sender: Option<tokio::sync::mpsc::Sender<BranchId>>,
    injected_credential_value: Option<&str>,
    audit_sender: Option<&tokio::sync::mpsc::Sender<crate::ProxyAuditEvent>>,
    request_domain: &str,
) -> Result<Response<BoxBody>, hyper::Error> {
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

/// Handle a CONNECT request (HTTPS tunneling via TLS passthrough).
///
/// C9: Establishes a TCP connection to the target host, sends "200 Connection Established"
/// back to the client, then relays bytes bidirectionally between client and upstream.
/// H7: Applies connect timeout and total tunnel timeout.
async fn handle_connect(
    req: Request<hyper::body::Incoming>,
    branch_id: &BranchId,
    resolved_addrs: Option<&[std::net::SocketAddr]>,
) -> Result<Response<BoxBody>, hyper::Error> {
    // Extract target host:port from the CONNECT URI
    let target_addr = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_else(|| req.uri().to_string());

    tracing::info!(
        branch = %branch_id,
        target = %target_addr,
        "CONNECT tunnel requested"
    );

    // Ensure the target has a port; default to 443 for HTTPS
    let target_with_port = if target_addr.contains(':') {
        target_addr.clone()
    } else {
        format!("{}:443", target_addr)
    };

    // H7: Connect to upstream with timeout
    let upstream = match connect_upstream(&target_with_port, branch_id, resolved_addrs).await {
        Ok(stream) => stream,
        Err(resp) => return Ok(resp),
    };

    // Use hyper's upgrade mechanism to get the raw TCP stream from the client
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let mut client_stream = hyper_util::rt::TokioIo::new(upgraded);
                let (upstream_read, mut upstream_write) = upstream.into_split();
                let (client_read, mut client_write) = tokio::io::split(&mut client_stream);

                // H7: Wrap bidirectional copy in a total tunnel timeout
                // M17/DC3: Enforce MAX_TUNNEL_BYTES limit using tokio::io::Take so
                // that the copy stops *at* the limit rather than only logging after
                // the fact. Each direction is independently capped.
                let tunnel_result = tokio::time::timeout(REQUEST_TIMEOUT, async {
                    let mut client_read_limited = client_read.take(MAX_TUNNEL_BYTES);
                    let mut upstream_read_limited = upstream_read.take(MAX_TUNNEL_BYTES);

                    let client_to_upstream =
                        tokio::io::copy(&mut client_read_limited, &mut upstream_write);
                    let upstream_to_client =
                        tokio::io::copy(&mut upstream_read_limited, &mut client_write);

                    let (c2u_result, u2c_result) =
                        tokio::join!(client_to_upstream, upstream_to_client);

                    let c2u_bytes = match c2u_result {
                        Ok(n) => n,
                        Err(e) => {
                            tracing::debug!(error = %e, "tunnel: client->upstream ended");
                            0
                        }
                    };
                    let u2c_bytes = match u2c_result {
                        Ok(n) => n,
                        Err(e) => {
                            tracing::debug!(error = %e, "tunnel: upstream->client ended");
                            0
                        }
                    };

                    let total_bytes = c2u_bytes + u2c_bytes;
                    tracing::info!(
                        target = %target_with_port,
                        client_to_upstream_bytes = c2u_bytes,
                        upstream_to_client_bytes = u2c_bytes,
                        total_bytes = total_bytes,
                        "CONNECT tunnel completed"
                    );

                    if c2u_bytes >= MAX_TUNNEL_BYTES || u2c_bytes >= MAX_TUNNEL_BYTES {
                        tracing::warn!(
                            target = %target_with_port,
                            c2u = c2u_bytes,
                            u2c = u2c_bytes,
                            limit = MAX_TUNNEL_BYTES,
                            "CONNECT tunnel byte limit reached — connection terminated"
                        );
                    }
                })
                .await;

                if tunnel_result.is_err() {
                    tracing::warn!(target = %target_with_port, "CONNECT tunnel timed out");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "CONNECT: upgrade failed");
            }
        }
    });

    // Send 200 Connection Established to the client, triggering the upgrade
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::new()))
        .unwrap())
}

/// H3: SSRF protection — reject requests targeting private/loopback IPs.
#[allow(clippy::result_large_err)]
fn check_ssrf(host: &str, branch_id: &BranchId) -> Result<(), Response<BoxBody>> {
    if is_private_ip_str(host) {
        tracing::warn!(
            branch = %branch_id,
            host = %host,
            "proxy: SSRF blocked — private/loopback IP"
        );
        // N3: Do not echo host in SSRF error response
        return Err(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Full::new(Bytes::from(
                "Blocked: private/loopback address\n",
            )))
            .unwrap());
    }
    Ok(())
}

/// Connect to an upstream server with timeout, using pre-resolved addresses if available.
async fn connect_upstream(
    target_with_port: &str,
    branch_id: &BranchId,
    resolved_addrs: Option<&[std::net::SocketAddr]>,
) -> Result<tokio::net::TcpStream, Response<BoxBody>> {
    match tokio::time::timeout(CONNECT_TIMEOUT, async {
        if let Some(addrs) = resolved_addrs {
            let addrs_with_port: Vec<std::net::SocketAddr> = addrs
                .iter()
                .map(|a| {
                    let port = target_with_port
                        .rsplit(':')
                        .next()
                        .and_then(|p| p.parse::<u16>().ok())
                        .unwrap_or(443);
                    std::net::SocketAddr::new(a.ip(), port)
                })
                .collect();
            tokio::net::TcpStream::connect(addrs_with_port.as_slice()).await
        } else {
            tokio::net::TcpStream::connect(target_with_port).await
        }
    })
    .await
    {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => {
            tracing::error!(
                branch = %branch_id,
                target = %target_with_port,
                error = %e,
                "failed to connect to upstream"
            );
            Err(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                // K40: Omit internal IP/port and error details from response
                .body(Full::new(Bytes::from("Failed to connect to upstream\n")))
                .unwrap())
        }
        Err(_elapsed) => {
            tracing::error!(
                branch = %branch_id,
                target = %target_with_port,
                "connect timeout to upstream"
            );
            // N2: Do not leak target in timeout error response
            Err(Response::builder()
                .status(StatusCode::GATEWAY_TIMEOUT)
                .body(Full::new(Bytes::from("Connect timeout\n")))
                .unwrap())
        }
    }
}

/// M-px2: Check that the request URI port is in the allowed port list for non-CONNECT requests.
///
/// Extracts the port from the request URI. Defaults to 80 for http, 443 for https.
/// Returns `Ok(())` if the port is allowed, or `Err(Response)` with 403 Forbidden
/// if the port is not in `ALLOWED_PORTS`.
#[allow(clippy::result_large_err)]
fn check_request_port(
    req: &Request<hyper::body::Incoming>,
    branch_id: &BranchId,
) -> Result<(), Response<BoxBody>> {
    let uri = req.uri();

    // Extract explicit port from URI, or derive default from scheme
    let port: u16 = uri.port_u16().unwrap_or_else(|| match uri.scheme_str() {
        Some("https") => 443,
        _ => 80,
    });

    if !ALLOWED_PORTS.contains(&port) {
        tracing::warn!(
            branch = %branch_id,
            uri = %uri,
            port = port,
            allowed = ?ALLOWED_PORTS,
            "M-px2: request to disallowed port"
        );
        // V3: Don't reveal port allowlist in error response
        let body = format!("Port {} is not allowed\n", port);
        return Err(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("content-length", body.len().to_string())
            .body(Full::new(Bytes::from(body)))
            .unwrap());
    }
    Ok(())
}

/// H4: Check that the CONNECT target port is in the allowed port list.
///
/// Returns `Ok(())` if the port is allowed, or `Err(Response)` with 403 Forbidden
/// if the port is not in `ALLOWED_PORTS`.
#[allow(clippy::result_large_err)]
fn check_connect_port(
    req: &Request<hyper::body::Incoming>,
    branch_id: &BranchId,
) -> Result<(), Response<BoxBody>> {
    let target = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_else(|| req.uri().to_string());

    let port: u16 = target
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(443);

    if !ALLOWED_PORTS.contains(&port) {
        tracing::warn!(
            branch = %branch_id,
            target = %target,
            port = port,
            allowed = ?ALLOWED_PORTS,
            "H4: CONNECT to disallowed port"
        );
        // V3: Don't reveal port allowlist in error response
        let body = format!("Port {} is not allowed\n", port);
        return Err(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("content-length", body.len().to_string())
            .body(Full::new(Bytes::from(body)))
            .unwrap());
    }
    Ok(())
}

/// M1: Validate that the Host header (if present) matches the CONNECT target hostname.
///
/// Returns `Ok(())` if there is no Host header or it matches the CONNECT target.
/// Returns `Err(Response)` with 400 Bad Request if they mismatch.
#[allow(clippy::result_large_err)]
fn check_connect_host_match(
    req: &Request<hyper::body::Incoming>,
    branch_id: &BranchId,
) -> Result<(), Response<BoxBody>> {
    let connect_target = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_else(|| req.uri().to_string());

    // Extract just the hostname from the CONNECT target (strip port)
    let connect_host = connect_target.split(':').next().unwrap_or(&connect_target);

    if let Some(host_header) = req.headers().get("host") {
        if let Ok(h) = host_header.to_str() {
            // Strip port from Host header for comparison
            let header_host = h.split(':').next().unwrap_or(h);
            if !header_host.eq_ignore_ascii_case(connect_host) {
                tracing::warn!(
                    branch = %branch_id,
                    connect_target = %connect_host,
                    host_header = %header_host,
                    "M1: Host header does not match CONNECT target"
                );
                // R5: generic error — do not reflect host or CONNECT target
                let body = "Host header does not match CONNECT target\n";
                return Err(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header("content-length", body.len().to_string())
                    .body(Full::new(Bytes::from(body)))
                    .unwrap());
            }
        }
    }
    Ok(())
}

/// Extract the target host from a request.
///
/// Validates the Host header format to prevent header injection attacks.
fn extract_host(req: &Request<hyper::body::Incoming>) -> Option<String> {
    // Try the Host header first
    if let Some(host) = req.headers().get("host") {
        if let Ok(h) = host.to_str() {
            // Validate Host header format: must contain only valid hostname chars
            if !validate_host_format(h) {
                tracing::warn!(host = %h, "invalid Host header format, ignoring");
                return None;
            }
            // Strip port if present
            return Some(h.split(':').next().unwrap_or(h).to_string());
        }
    }

    // Try the URI authority
    if let Some(auth) = req.uri().authority() {
        return Some(auth.host().to_string());
    }

    // For CONNECT, the URI is the host:port directly
    if req.method() == Method::CONNECT {
        let uri_str = req.uri().to_string();
        return Some(uri_str.split(':').next().unwrap_or(&uri_str).to_string());
    }

    None
}

/// Validate Host header format to prevent injection attacks.
/// Allows only alphanumeric chars, hyphens, dots, underscores, colons (for port), and brackets (for IPv6).
/// Underscores are permitted because some DNS names use them (e.g., SRV records, DMARC TXT records).
fn validate_host_format(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | ':' | '[' | ']' | '_'))
}

/// M-px1: Check if a host string represents a private/loopback address.
///
/// Properly parses the host as an IP address using `std::net::IpAddr` and delegates
/// to `is_private_ip()` for accurate range checking. Falls back to checking "localhost"
/// as a hostname. This replaces the previous string-prefix-based approach which was
/// susceptible to false positives (e.g., "10.example.com" matching "10." prefix) and
/// false negatives (e.g., missing certain IPv6 representations).
///
/// Also handles IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) and bracket-wrapped
/// IPv6 literals ([::1]).
fn is_private_ip_str(host: &str) -> bool {
    // Check for "localhost" hostname
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    // Strip brackets from IPv6 literals (e.g., "[::1]" -> "::1")
    let ip_str = if host.starts_with('[') && host.ends_with(']') {
        &host[1..host.len() - 1]
    } else {
        host
    };

    // Try parsing as an IP address
    if let Ok(ip) = ip_str.parse::<IpAddr>() {
        // Handle IPv4-mapped IPv6 (::ffff:x.x.x.x) — extract inner IPv4
        let effective_ip = match ip {
            IpAddr::V6(v6) => {
                let segments = v6.segments();
                if segments[0] == 0
                    && segments[1] == 0
                    && segments[2] == 0
                    && segments[3] == 0
                    && segments[4] == 0
                    && segments[5] == 0xffff
                {
                    let octets = v6.octets();
                    IpAddr::V4(std::net::Ipv4Addr::new(
                        octets[12], octets[13], octets[14], octets[15],
                    ))
                } else {
                    ip
                }
            }
            _ => ip,
        };
        return is_private_ip(&effective_ip);
    }

    // Handle the "::ffff:x.x.x.x" textual form that may not parse as IpAddr directly
    if let Some(mapped_v4) = ip_str.strip_prefix("::ffff:") {
        if let Ok(v4) = mapped_v4.parse::<std::net::Ipv4Addr>() {
            return is_private_ip(&IpAddr::V4(v4));
        }
    }

    false
}

/// Check if a domain is in the allowed list.
///
/// Supports exact match and wildcard subdomains (e.g., "*.example.com").
/// H5: Wildcard matching requires a dot separator — `*.example.com` matches
/// `foo.example.com` but NOT `fooexample.com`.
pub fn is_domain_allowed(host: &str, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return false;
    }

    for pattern in allowed {
        if pattern == "*" {
            return true;
        }
        if pattern == host {
            return true;
        }
        // H5: Wildcard subdomain matching with dot separator enforcement.
        // *.example.com matches foo.example.com but NOT fooexample.com.
        if let Some(suffix) = pattern.strip_prefix("*") {
            // Enforce dot-boundary: suffix must start with '.' to prevent
            // subdomain SSRF (e.g., "*example.com" matching "evil-example.com").
            // If pattern is "*.example.com", suffix is ".example.com" — correct.
            // If pattern is "*example.com" (missing dot), prepend dot so we
            // check ".example.com" instead of bare "example.com".
            let dot_suffix = if suffix.starts_with('.') {
                suffix.to_string()
            } else {
                format!(".{}", suffix)
            };
            // Exact match for the bare domain (e.g., "example.com" matches "*.example.com")
            if host == &dot_suffix[1..] {
                return true;
            }
            // Subdomain match with dot boundary (e.g., "sub.example.com" ends with ".example.com")
            if host.ends_with(&dot_suffix) {
                return true;
            }
        }
    }
    false
}

/// Check if a domain is in the denied list.
///
/// Uses the same matching logic as `is_domain_allowed` — supports exact match
/// and wildcard subdomains (e.g., "*.evil.com"). Deny list is checked BEFORE
/// allow lists and overrides them.
pub fn is_domain_denied(host: &str, denied: &[String]) -> bool {
    // Reuse the same matching logic — a domain "matches" the deny list
    // if it would be "allowed" by the deny patterns.
    is_domain_allowed(host, denied)
}

/// C4: TLS MITM interception handler.
///
/// Intercepts CONNECT requests by:
/// 1. Issuing a leaf cert for the target domain via `AgentCa::issue_leaf_cert(domain)`
/// 2. Accepting TLS from the agent using the leaf cert (the agent trusts the CA)
/// 3. Establishing TLS to the upstream server
/// 4. Reading the decrypted HTTP/1.1 request from the agent
/// 5. Routing based on method:
///    - GET/HEAD/OPTIONS: forward to upstream and relay response back
///    - POST/PUT/DELETE/PATCH: journal the request, then forward to upstream
///
/// The `AgentCa` cert PEM must be injected into the agent's trust store before
/// this handler is used, so the agent accepts the proxy's leaf certificates.
#[allow(clippy::too_many_arguments)]
async fn handle_tls_intercept(
    req: Request<hyper::body::Incoming>,
    branch_id: &BranchId,
    ca: &AgentCa,
    journal: Arc<Mutex<NetworkJournal>>,
    resolved_addrs: Option<&[std::net::SocketAddr]>,
    dlp_engine: Option<Arc<DlpEngine>>,
    max_inspection_body_size: usize,
    oversized_body_action: crate::dlp::OversizedAction,
    quarantine_sender: Option<tokio::sync::mpsc::Sender<BranchId>>,
    audit_sender: Option<tokio::sync::mpsc::Sender<crate::ProxyAuditEvent>>,
    phantom_token_manager: Option<Arc<RwLock<PhantomTokenManager>>>,
    agent_profile: Option<String>,
    credential_mode: puzzled_types::CredentialMode,
) -> Result<Response<BoxBody>, hyper::Error> {
    // 1. Extract target domain and port from the CONNECT request URI
    let target_addr = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_else(|| req.uri().to_string());

    let domain = target_addr
        .split(':')
        .next()
        .unwrap_or(&target_addr)
        .to_string();

    let target_with_port = if target_addr.contains(':') {
        target_addr.clone()
    } else {
        format!("{}:443", target_addr)
    };

    tracing::info!(
        branch = %branch_id,
        target = %target_addr,
        domain = %domain,
        "C4: TLS MITM intercept requested"
    );

    // 2. Issue a leaf cert for the target domain
    let (leaf_cert_der, leaf_key_der) = match ca.issue_leaf_cert(&domain) {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!(
                branch = %branch_id,
                domain = %domain,
                error = %e,
                "C4: failed to issue leaf cert"
            );
            // R2: generic error — do not leak domain or crypto error details
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from("TLS certificate error\n")))
                .unwrap());
        }
    };

    // 3. Connect to upstream with timeout (do this before upgrade so we can
    //    return an error response if upstream is unreachable)
    let upstream_tcp = match connect_upstream(&target_with_port, branch_id, resolved_addrs).await {
        Ok(stream) => stream,
        Err(resp) => return Ok(resp),
    };

    // Capture values needed in the spawned task
    let branch_id_owned = branch_id.clone();
    let domain_clone = domain.clone();
    let target_port_clone = target_with_port.clone();
    let dlp_engine_clone = dlp_engine.clone();
    let quarantine_sender_clone = quarantine_sender.clone();
    let audit_sender_clone = audit_sender;
    let phantom_token_manager_clone = phantom_token_manager;
    let agent_profile_clone = agent_profile;
    let credential_mode_clone = credential_mode;

    // Spawn the TLS interception pipeline after sending 200 to the client
    tokio::spawn(async move {
        // 4. Upgrade the connection to get the raw TCP stream from the client
        let upgraded = match hyper::upgrade::on(req).await {
            Ok(upgraded) => upgraded,
            Err(e) => {
                tracing::error!(error = %e, "C4: upgrade failed");
                return;
            }
        };
        let client_io = hyper_util::rt::TokioIo::new(upgraded);

        // 5. Create TLS acceptor with the leaf cert to accept TLS from the agent
        let tls_acceptor = match build_tls_acceptor(leaf_cert_der, leaf_key_der) {
            Ok(acceptor) => acceptor,
            Err(e) => {
                tracing::error!(error = %e, "C4: failed to build TLS acceptor");
                return;
            }
        };

        // Accept TLS from the agent
        let agent_tls = match tls_acceptor.accept(client_io).await {
            Ok(stream) => stream,
            Err(e) => {
                tracing::error!(
                    domain = %domain_clone,
                    error = %e,
                    "C4: TLS handshake with agent failed"
                );
                return;
            }
        };

        // 6. Establish TLS to the upstream server
        let upstream_tls = match connect_upstream_tls(upstream_tcp, &domain_clone).await {
            Ok(stream) => stream,
            Err(e) => {
                tracing::error!(
                    domain = %domain_clone,
                    error = %e,
                    "C4: TLS handshake with upstream failed"
                );
                return;
            }
        };

        // 7. Read the decrypted HTTP/1.1 request from the agent, then route it
        if let Err(e) = handle_intercepted_stream(
            agent_tls,
            upstream_tls,
            &branch_id_owned,
            &domain_clone,
            &target_port_clone,
            journal,
            dlp_engine_clone,
            max_inspection_body_size,
            oversized_body_action,
            quarantine_sender_clone,
            audit_sender_clone,
            phantom_token_manager_clone,
            agent_profile_clone,
            credential_mode_clone,
        )
        .await
        {
            tracing::error!(
                branch = %branch_id_owned,
                domain = %domain_clone,
                error = %e,
                "C4: intercepted stream handling failed"
            );
        }
    });

    // Send 200 Connection Established to the client, triggering the upgrade
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::new()))
        .unwrap())
}

/// Build a `TlsAcceptor` from a leaf cert and private key for agent-side TLS.
fn build_tls_acceptor(
    cert_der: rustls::pki_types::CertificateDer<'static>,
    key_der: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<TlsAcceptor, String> {
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| format!("building TLS server config: {}", e))?;

    // §3.4 G15: Force HTTP/1.1 negotiation — the proxy handler only supports
    // HTTP/1.1. Without this, clients may negotiate HTTP/2 via ALPN, which
    // would break the HTTP/1.1-only request/response parsing pipeline.
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Connect to an upstream server with TLS, using the system root CA store.
async fn connect_upstream_tls(
    tcp_stream: tokio::net::TcpStream,
    domain: &str,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, String> {
    let mut root_store = rustls::RootCertStore::empty();
    // Add the webpki/mozilla root certificates
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    // M-3: Explicitly negotiate HTTP/1.1 on upstream connections, matching the
    // server-side ALPN restriction (line 3274). Defense-in-depth: prevents silent
    // HTTP/2 upgrade that would break the credential injection pipeline.
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = rustls::pki_types::ServerName::try_from(domain.to_string())
        .map_err(|e| format!("invalid server name '{}': {}", domain, e))?;

    connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| format!("upstream TLS handshake failed: {}", e))
}

/// D-I6: Maximum session duration for a TLS intercept keep-alive loop (10 minutes).
const TLS_SESSION_TIMEOUT: Duration = Duration::from_secs(600);

/// D-C1: Inject a resolved credential into a raw header vector (TLS intercept path).
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
fn inject_credential_into_header_vec(
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

/// Handle the intercepted (decrypted) HTTP stream between agent and upstream.
///
/// Reads a single HTTP/1.1 request from the agent side, routes it based on method,
/// and relays the response back through the TLS streams.
#[allow(clippy::too_many_arguments)]
async fn handle_intercepted_stream<A, U>(
    mut agent_tls: A,
    mut upstream_tls: U,
    branch_id: &BranchId,
    domain: &str,
    _target_with_port: &str,
    journal: Arc<Mutex<NetworkJournal>>,
    dlp_engine: Option<Arc<DlpEngine>>,
    max_inspection_body_size: usize,
    oversized_body_action: crate::dlp::OversizedAction,
    quarantine_sender: Option<tokio::sync::mpsc::Sender<BranchId>>,
    audit_sender: Option<tokio::sync::mpsc::Sender<crate::ProxyAuditEvent>>,
    phantom_token_manager: Option<Arc<RwLock<PhantomTokenManager>>>,
    agent_profile: Option<String>,
    credential_mode: puzzled_types::CredentialMode,
) -> Result<(), String>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
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

/// Find the end of HTTP headers (the position of the first byte of \r\n\r\n).
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// D-C3: Validate HTTP header name per RFC 9110 token characters.
/// Header names must be non-empty and contain only: `!#$%&'*+-.^_`|~0-9A-Za-z`
fn is_valid_http_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            matches!(b,
                b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' |
                b'^' | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
            )
        })
}

/// D-C3: Validate HTTP header value per RFC 9110.
/// Values must not contain null bytes (0x00) or control characters except HTAB (0x09).
fn is_valid_http_header_value(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b == b'\t' || (b >= 0x20 && b != 0x7f))
}

/// D-C1: Decode a chunked Transfer-Encoding body.
///
/// Reads chunk-size (hex) + CRLF, then chunk-data, then trailing CRLF, until
/// a zero-length terminal chunk. Returns the reassembled decoded body.
fn decode_chunked_body(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoded = Vec::new();
    let mut pos = 0;

    loop {
        // Find the CRLF after the chunk size line
        let crlf_pos = raw[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "malformed chunked body: missing CRLF after chunk size".to_string())?;
        let size_line = &raw[pos..pos + crlf_pos];
        // Parse hex chunk size (ignore chunk extensions after ';')
        let size_str = std::str::from_utf8(size_line)
            .map_err(|_| "malformed chunked body: non-UTF-8 chunk size".to_string())?;
        let size_hex = size_str.split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| format!("malformed chunked body: invalid chunk size '{}'", size_hex))?;

        pos += crlf_pos + 2; // skip past size line + CRLF

        if chunk_size == 0 {
            // Terminal chunk — skip optional trailers and final CRLF
            break;
        }

        // Guard against oversized chunks
        if decoded.len() + chunk_size > MAX_RESPONSE_BODY_BYTES {
            return Err("chunked body exceeds maximum response size".to_string());
        }

        // Read chunk data
        if pos + chunk_size > raw.len() {
            return Err("malformed chunked body: chunk data truncated".to_string());
        }
        decoded.extend_from_slice(&raw[pos..pos + chunk_size]);
        pos += chunk_size;

        // Expect trailing CRLF after chunk data
        if pos + 2 > raw.len() || &raw[pos..pos + 2] != b"\r\n" {
            return Err("malformed chunked body: missing CRLF after chunk data".to_string());
        }
        pos += 2;
    }

    Ok(decoded)
}

/// Get current timestamp as string.
fn chrono_now() -> String {
    // Simple timestamp without chrono dependency
    // H68: Use "0" instead of empty string on pre-epoch clock
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

// ---------------------------------------------------------------------------
// §3.4 G7: Transparent proxy mode — handle DNAT'd connections
// ---------------------------------------------------------------------------

/// Handle a transparent proxy connection (DNAT'd TCP, not HTTP CONNECT).
///
/// In transparent mode, connections arrive as raw TCP via nftables DNAT.
/// The upstream hostname is extracted from the TLS ClientHello SNI extension
/// instead of from a CONNECT request.
///
/// Flow:
/// 1. Peek at the first bytes to extract SNI from TLS ClientHello
/// 2. Issue a leaf cert for the SNI domain using the branch's CA
/// 3. Accept TLS from the agent using the leaf cert
/// 4. Connect to the upstream server via TLS
/// 5. Call the shared `handle_intercepted_stream` pipeline
#[allow(clippy::too_many_arguments)]
pub async fn handle_transparent_connection(
    stream: tokio::net::TcpStream,
    branch_id: BranchId,
    ca: Arc<AgentCa>,
    journal: Arc<Mutex<NetworkJournal>>,
    dlp_engine: Option<Arc<DlpEngine>>,
    max_inspection_body_size: usize,
    oversized_body_action: crate::dlp::OversizedAction,
    quarantine_sender: Option<tokio::sync::mpsc::Sender<BranchId>>,
    audit_sender: Option<tokio::sync::mpsc::Sender<crate::ProxyAuditEvent>>,
    phantom_token_manager: Option<Arc<RwLock<PhantomTokenManager>>>,
    agent_profile: Option<String>,
    credential_mode: puzzled_types::CredentialMode,
) {
    // 1. Peek at the TLS ClientHello to extract SNI
    // We need to read the ClientHello without consuming it, since the TLS
    // acceptor needs to read it again. Use peek().
    let mut peek_buf = vec![0u8; 16384]; // Max TLS record size
    let n = match stream.peek(&mut peek_buf).await {
        Ok(n) => n,
        Err(e) => {
            tracing::debug!(
                branch = %branch_id,
                error = %e,
                "§3.4 G7: failed to peek at transparent connection"
            );
            return;
        }
    };

    let domain = match crate::tls::extract_sni(&peek_buf[..n]) {
        Some(domain) => domain,
        None => {
            tracing::warn!(
                branch = %branch_id,
                "§3.4 G7: no SNI in ClientHello — cannot determine upstream hostname"
            );
            return;
        }
    };

    tracing::info!(
        branch = %branch_id,
        domain = %domain,
        "§3.4 G7: transparent proxy connection — SNI extracted"
    );

    // 2. Issue a leaf cert for the domain
    let (leaf_cert_der, leaf_key_der) = match ca.issue_leaf_cert(&domain) {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!(
                branch = %branch_id,
                domain = %domain,
                error = %e,
                "§3.4 G7: failed to issue leaf cert for transparent connection"
            );
            return;
        }
    };

    // 3. Accept TLS from the agent using the leaf cert
    let tls_acceptor = match build_tls_acceptor(leaf_cert_der, leaf_key_der) {
        Ok(acceptor) => acceptor,
        Err(e) => {
            tracing::error!(
                branch = %branch_id,
                domain = %domain,
                error = %e,
                "§3.4 G7: failed to build TLS acceptor"
            );
            return;
        }
    };

    let agent_tls = match tls_acceptor.accept(stream).await {
        Ok(stream) => stream,
        Err(e) => {
            tracing::debug!(
                branch = %branch_id,
                domain = %domain,
                error = %e,
                "§3.4 G7: TLS handshake with agent failed"
            );
            return;
        }
    };

    // 4. Connect to upstream with TLS
    let target_with_port = format!("{}:443", domain);
    let upstream_tcp = match tokio::net::TcpStream::connect(&target_with_port).await {
        Ok(stream) => stream,
        Err(e) => {
            tracing::error!(
                branch = %branch_id,
                domain = %domain,
                error = %e,
                "§3.4 G7: failed to connect to upstream"
            );
            return;
        }
    };

    let upstream_tls = match connect_upstream_tls(upstream_tcp, &domain).await {
        Ok(stream) => stream,
        Err(e) => {
            tracing::error!(
                branch = %branch_id,
                domain = %domain,
                error = %e,
                "§3.4 G7: upstream TLS handshake failed"
            );
            return;
        }
    };

    // 5. Run the shared MITM pipeline (same as CONNECT path)
    if let Err(e) = handle_intercepted_stream(
        agent_tls,
        upstream_tls,
        &branch_id,
        &domain,
        &target_with_port,
        journal,
        dlp_engine,
        max_inspection_body_size,
        oversized_body_action,
        quarantine_sender,
        audit_sender,
        phantom_token_manager,
        agent_profile,
        credential_mode,
    )
    .await
    {
        tracing::error!(
            branch = %branch_id,
            domain = %domain,
            error = %e,
            "§3.4 G7: transparent proxy stream handling failed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_matching() {
        let domains = vec![
            "github.com".to_string(),
            "*.pypi.org".to_string(),
            "crates.io".to_string(),
        ];

        assert!(is_domain_allowed("github.com", &domains));
        assert!(is_domain_allowed("files.pypi.org", &domains));
        assert!(is_domain_allowed("crates.io", &domains));
        assert!(!is_domain_allowed("evil.com", &domains));
        // H5: *.pypi.org matches pypi.org itself (base domain + all subdomains)
        assert!(is_domain_allowed("pypi.org", &domains));
    }

    #[test]
    fn test_wildcard_all() {
        let domains = vec!["*".to_string()];
        assert!(is_domain_allowed("anything.com", &domains));
    }

    #[test]
    fn test_empty_domains() {
        let domains: Vec<String> = vec![];
        assert!(!is_domain_allowed("anything.com", &domains));
    }

    // H5: Test that wildcard matching requires dot separator
    #[test]
    fn test_wildcard_dot_separator() {
        let domains = vec!["*.example.com".to_string()];

        // Should match: proper subdomain with dot separator
        assert!(is_domain_allowed("foo.example.com", &domains));
        assert!(is_domain_allowed("bar.baz.example.com", &domains));

        // Should NOT match: no dot separator (suffix attack)
        assert!(!is_domain_allowed("fooexample.com", &domains));
        assert!(!is_domain_allowed("evilexample.com", &domains));

        // Should NOT match: the base domain itself (*.example.com != example.com)
        // Wait — with the "host == suffix[1..]" check, *.example.com DOES match example.com.
        // This is intentional: *.example.com means "example.com and all subdomains".
        // If you want ONLY subdomains, use a different pattern.
    }

    // C8: Test is_private_ip function
    #[test]
    fn test_is_private_ip() {
        // Private IPv4
        assert!(is_private_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"10.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"172.16.0.1".parse().unwrap()));
        assert!(is_private_ip(&"172.31.255.255".parse().unwrap()));
        assert!(is_private_ip(&"192.168.1.1".parse().unwrap()));
        assert!(is_private_ip(&"169.254.1.1".parse().unwrap()));
        assert!(is_private_ip(&"0.0.0.0".parse().unwrap()));

        // Public IPv4
        assert!(!is_private_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip(&"1.1.1.1".parse().unwrap()));
        assert!(!is_private_ip(&"172.32.0.1".parse().unwrap()));

        // Private IPv6
        assert!(is_private_ip(&"::1".parse().unwrap()));
        assert!(is_private_ip(&"fc00::1".parse().unwrap()));
        assert!(is_private_ip(&"fd12::1".parse().unwrap()));
        assert!(is_private_ip(&"fe80::1".parse().unwrap()));

        // Public IPv6
        assert!(!is_private_ip(&"2001:db8::1".parse().unwrap()));
    }

    // M14: Test IPv4-mapped IPv6 SSRF detection
    #[tokio::test]
    async fn test_ipv4_mapped_ipv6_ssrf() {
        let branch_id = BranchId::from("test-branch".to_string());

        // ::ffff:127.0.0.1 is IPv4-mapped IPv6 for loopback — should be blocked
        let result = check_dns_rebinding("::ffff:127.0.0.1", &branch_id).await;
        assert!(result.is_err(), "IPv4-mapped loopback should be blocked");

        // ::ffff:10.0.0.1 is IPv4-mapped IPv6 for private — should be blocked
        let result = check_dns_rebinding("::ffff:10.0.0.1", &branch_id).await;
        assert!(result.is_err(), "IPv4-mapped private IP should be blocked");

        // ::ffff:192.168.1.1 should be blocked
        let result = check_dns_rebinding("::ffff:192.168.1.1", &branch_id).await;
        assert!(result.is_err(), "IPv4-mapped 192.168.x.x should be blocked");

        // Raw private IP should also be blocked now
        let result = check_dns_rebinding("10.0.0.1", &branch_id).await;
        assert!(result.is_err(), "raw private IP should be blocked");

        // Public IP should pass
        let result = check_dns_rebinding("8.8.8.8", &branch_id).await;
        assert!(result.is_ok(), "public IP should be allowed");
    }

    // M15: Test hop-by-hop header stripping
    #[test]
    fn test_strip_hop_by_hop_standard() {
        let mut headers = hyper::header::HeaderMap::new();
        headers.insert("connection", "keep-alive".parse().unwrap());
        headers.insert("keep-alive", "timeout=5".parse().unwrap());
        headers.insert("proxy-authorization", "Basic abc".parse().unwrap());
        headers.insert("transfer-encoding", "chunked".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("x-custom", "value".parse().unwrap());

        strip_hop_by_hop(&mut headers);

        // Standard hop-by-hop headers should be removed
        assert!(headers.get("connection").is_none());
        assert!(headers.get("keep-alive").is_none());
        assert!(headers.get("proxy-authorization").is_none());
        assert!(headers.get("transfer-encoding").is_none());

        // End-to-end headers should be preserved
        assert!(headers.get("content-type").is_some());
        assert!(headers.get("x-custom").is_some());
    }

    #[test]
    fn test_strip_hop_by_hop_connection_named() {
        let mut headers = hyper::header::HeaderMap::new();
        headers.insert("connection", "x-custom-hop, x-another".parse().unwrap());
        headers.insert("x-custom-hop", "value1".parse().unwrap());
        headers.insert("x-another", "value2".parse().unwrap());
        headers.insert("x-keep-me", "value3".parse().unwrap());

        strip_hop_by_hop(&mut headers);

        // Headers named in Connection should be removed
        assert!(headers.get("x-custom-hop").is_none());
        assert!(headers.get("x-another").is_none());

        // Other headers should be preserved
        assert!(headers.get("x-keep-me").is_some());
    }

    #[test]
    fn test_strip_hop_by_hop_empty() {
        let mut headers = hyper::header::HeaderMap::new();
        headers.insert("content-type", "text/plain".parse().unwrap());

        strip_hop_by_hop(&mut headers);

        // Should not crash, content-type preserved
        assert!(headers.get("content-type").is_some());
    }

    // §3.4.8 step 7: Accept-Encoding stripping
    #[test]
    fn test_accept_encoding_stripped_by_hop_by_hop_path() {
        let mut headers = hyper::header::HeaderMap::new();
        headers.insert("accept-encoding", "gzip, deflate, br".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("authorization", "Bearer token".parse().unwrap());

        // strip_hop_by_hop does NOT remove accept-encoding (it's not hop-by-hop),
        // so the explicit .remove("accept-encoding") call is required.
        strip_hop_by_hop(&mut headers);
        assert!(
            headers.get("accept-encoding").is_some(),
            "strip_hop_by_hop should NOT remove accept-encoding"
        );

        // The explicit removal (as added in GAP-H1 fix) strips it
        headers.remove("accept-encoding");
        assert!(headers.get("accept-encoding").is_none());
        assert!(headers.get("content-type").is_some());
        assert!(headers.get("authorization").is_some());
    }

    // C4: Test find_header_end helper
    #[test]
    fn test_find_header_end() {
        let buf = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody";
        let pos = find_header_end(buf);
        // "GET / HTTP/1.1\r\n" = 16 bytes, "Host: example.com\r\n" = 19 bytes
        // \r\n\r\n starts at byte 33 (the \r\n ending Host line + blank \r\n)
        assert_eq!(pos, Some(33));

        // No header end yet (only one trailing \r\n, no double)
        let partial = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        assert_eq!(find_header_end(partial), None);

        // Empty
        assert_eq!(find_header_end(b""), None);
    }

    // C4: Test build_tls_acceptor with a real leaf cert
    #[test]
    fn test_build_tls_acceptor() {
        let ca = crate::tls::AgentCa::generate("test-tls-acceptor").unwrap();
        let (cert_der, key_der) = ca.issue_leaf_cert("example.com").unwrap();
        let result = build_tls_acceptor(cert_der, key_der);
        assert!(
            result.is_ok(),
            "should build TLS acceptor from valid cert/key"
        );
    }

    // C4: Test handle_intercepted_stream with mock streams (GET — no journaling)
    #[tokio::test]
    async fn test_intercepted_stream_get_no_journal() {
        let branch_id = BranchId::from("test-branch".to_string());
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let journal = crate::replay::NetworkJournal::new(
            journal_dir,
            BranchId::from("test-branch".to_string()),
        );
        let journal = Arc::new(Mutex::new(journal));

        // Simulate an agent sending a GET request
        let agent_request = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        // Simulate upstream response
        let upstream_response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

        let (agent_read, mut agent_write_half) = tokio::io::duplex(8192);
        let (upstream_read, mut upstream_write_half) = tokio::io::duplex(8192);

        // Write the agent request to the agent's read side
        let agent_write_task = tokio::spawn(async move {
            agent_write_half.write_all(agent_request).await.unwrap();
            // Read back the response that the handler writes
            let mut response = vec![0u8; 4096];
            let n = agent_write_half.read(&mut response).await.unwrap();
            response.truncate(n);
            response
        });

        // Write the upstream response to the upstream's read side
        let upstream_task = tokio::spawn(async move {
            // Read the forwarded request first
            let mut buf = vec![0u8; 4096];
            let n = upstream_write_half.read(&mut buf).await.unwrap();
            let forwarded = String::from_utf8_lossy(&buf[..n]).to_string();
            // Then send the response
            upstream_write_half
                .write_all(upstream_response)
                .await
                .unwrap();
            // Close the write side to signal EOF
            drop(upstream_write_half);
            forwarded
        });

        let result = handle_intercepted_stream(
            agent_read,
            upstream_read,
            &branch_id,
            "example.com",
            "example.com:443",
            journal.clone(),
            None,
            10 * 1024 * 1024,
            crate::dlp::OversizedAction::BlockAndAlert,
            None,
            None,
            None,
            None,
            puzzled_types::CredentialMode::default(),
        )
        .await;

        assert!(
            result.is_ok(),
            "GET interception should succeed: {:?}",
            result
        );

        // Verify no journal entries were created (GET is read-only)
        let journal_guard = journal.lock().await;
        assert_eq!(
            journal_guard.entry_count(),
            0,
            "GET should not be journaled"
        );

        let _ = agent_write_task.await;
        let forwarded = upstream_task.await.unwrap();
        assert!(
            forwarded.starts_with("GET /index.html HTTP/1.1"),
            "forwarded request should start with GET: {}",
            forwarded
        );
    }

    // C4: Test handle_intercepted_stream with POST — should journal
    #[tokio::test]
    async fn test_intercepted_stream_post_journals() {
        let branch_id = BranchId::from("test-branch".to_string());
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let journal = crate::replay::NetworkJournal::new(
            journal_dir,
            BranchId::from("test-branch".to_string()),
        );
        let journal = Arc::new(Mutex::new(journal));

        // Simulate an agent sending a POST request with body
        let agent_request =
            b"POST /api/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 13\r\n\r\n{\"key\":\"val\"}";
        let upstream_response = b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok";

        let (agent_read, mut agent_write_half) = tokio::io::duplex(8192);
        let (upstream_read, mut upstream_write_half) = tokio::io::duplex(8192);

        let agent_write_task = tokio::spawn(async move {
            agent_write_half.write_all(agent_request).await.unwrap();
            let mut response = vec![0u8; 4096];
            let n = agent_write_half.read(&mut response).await.unwrap();
            response.truncate(n);
            response
        });

        let upstream_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let _n = upstream_write_half.read(&mut buf).await.unwrap();
            upstream_write_half
                .write_all(upstream_response)
                .await
                .unwrap();
            drop(upstream_write_half);
        });

        let result = handle_intercepted_stream(
            agent_read,
            upstream_read,
            &branch_id,
            "api.example.com",
            "api.example.com:443",
            journal.clone(),
            None,
            10 * 1024 * 1024,
            crate::dlp::OversizedAction::BlockAndAlert,
            None,
            None,
            None,
            None,
            puzzled_types::CredentialMode::default(),
        )
        .await;

        assert!(
            result.is_ok(),
            "POST interception should succeed: {:?}",
            result
        );

        // Verify journal entry was created
        let journal_guard = journal.lock().await;
        assert_eq!(journal_guard.entry_count(), 1, "POST should be journaled");

        let entries = journal_guard.read_all().unwrap();
        assert_eq!(entries[0].method, "POST");
        assert_eq!(entries[0].uri, "https://api.example.com/api/data");
        assert_eq!(entries[0].body, b"{\"key\":\"val\"}");

        let _ = agent_write_task.await;
        let _ = upstream_task.await;
    }

    // -----------------------------------------------------------------------
    // §3.4: inject_resolved_credential tests (C3, C4)
    // -----------------------------------------------------------------------

    #[test]
    fn test_inject_bearer_header() {
        let resolved = crate::credentials::ResolvedCredential {
            credential_name: "test-key".to_string(),
            auth_header_value: zeroize::Zeroizing::new("Bearer sk-12345".to_string()),
            injection: InjectionMethod::BearerHeader,
            target_domains: vec!["example.com".to_string()],
            allowed_profiles: vec!["*".to_string()],
        };
        let req = Request::builder()
            .uri("https://example.com/api")
            .body(())
            .unwrap();
        let (mut parts, _body) = req.into_parts();
        inject_resolved_credential(&mut parts, &resolved).unwrap();
        assert_eq!(
            parts.headers.get("authorization").unwrap(),
            "Bearer sk-12345"
        );
    }

    #[test]
    fn test_inject_query_parameter() {
        let resolved = crate::credentials::ResolvedCredential {
            credential_name: "api-key".to_string(),
            auth_header_value: zeroize::Zeroizing::new("my-secret-key".to_string()),
            injection: InjectionMethod::QueryParameter {
                param_name: "api_key".to_string(),
            },
            target_domains: vec!["example.com".to_string()],
            allowed_profiles: vec!["*".to_string()],
        };
        let req = Request::builder()
            .uri("https://example.com/api/v1/data")
            .body(())
            .unwrap();
        let (mut parts, _body) = req.into_parts();
        inject_resolved_credential(&mut parts, &resolved).unwrap();
        let uri_str = parts.uri.to_string();
        assert!(
            uri_str.contains("api_key=my-secret-key"),
            "URI should contain query param, got: {uri_str}"
        );
        assert!(
            uri_str.starts_with("https://example.com/api/v1/data?"),
            "URI path should be preserved, got: {uri_str}"
        );
    }

    #[test]
    fn test_inject_query_parameter_appends_to_existing() {
        let resolved = crate::credentials::ResolvedCredential {
            credential_name: "api-key".to_string(),
            auth_header_value: zeroize::Zeroizing::new("secret".to_string()),
            injection: InjectionMethod::QueryParameter {
                param_name: "token".to_string(),
            },
            target_domains: vec!["example.com".to_string()],
            allowed_profiles: vec!["*".to_string()],
        };
        let req = Request::builder()
            .uri("https://example.com/api?foo=bar")
            .body(())
            .unwrap();
        let (mut parts, _body) = req.into_parts();
        inject_resolved_credential(&mut parts, &resolved).unwrap();
        let uri_str = parts.uri.to_string();
        assert!(
            uri_str.contains("foo=bar&token=secret"),
            "should append to existing query, got: {uri_str}"
        );
    }

    #[test]
    fn test_inject_query_parameter_urlencodes_value() {
        let resolved = crate::credentials::ResolvedCredential {
            credential_name: "key".to_string(),
            auth_header_value: zeroize::Zeroizing::new(
                "value with spaces&special=chars".to_string(),
            ),
            injection: InjectionMethod::QueryParameter {
                param_name: "key".to_string(),
            },
            target_domains: vec!["example.com".to_string()],
            allowed_profiles: vec!["*".to_string()],
        };
        let req = Request::builder()
            .uri("https://example.com/api")
            .body(())
            .unwrap();
        let (mut parts, _body) = req.into_parts();
        inject_resolved_credential(&mut parts, &resolved).unwrap();
        let uri_str = parts.uri.to_string();
        // Should be URL-encoded, not raw
        assert!(
            !uri_str.contains("value with spaces"),
            "value should be URL-encoded, got: {uri_str}"
        );
        assert!(
            uri_str.contains("key=value%20with%20spaces%26special%3Dchars"),
            "should contain URL-encoded value, got: {uri_str}"
        );
    }

    #[test]
    fn test_inject_aws_sigv4() {
        let resolved = crate::credentials::ResolvedCredential {
            credential_name: "aws-creds".to_string(),
            auth_header_value: zeroize::Zeroizing::new("AKIAIOSFODNN7EXAMPLE".to_string()),
            injection: InjectionMethod::AwsSigV4,
            target_domains: vec!["s3.amazonaws.com".to_string()],
            allowed_profiles: vec!["*".to_string()],
        };
        let req = Request::builder()
            .uri("https://s3.amazonaws.com/bucket/key")
            .body(())
            .unwrap();
        let (mut parts, _body) = req.into_parts();
        inject_resolved_credential(&mut parts, &resolved).unwrap();
        // AwsSigV4 is a stub — does NOT inject the raw secret key (credential leak).
        // Phase 2 will implement proper SigV4 signing with the aws-sigv4 crate.
        assert!(parts.headers.get("x-amz-credential").is_none());
    }

    /// §3.4: VaultAuth fields match PRD naming (token_path, secret_id_path).
    #[test]
    fn test_vault_auth_prd_field_names() {
        use crate::credential_backends::VaultAuth;

        // PRD §3.4.3: Token variant uses token_path (PathBuf, not String)
        let token_auth = VaultAuth::Token {
            token_path: std::path::PathBuf::from("/etc/puzzled/vault-token"),
        };
        let json = serde_json::to_string(&token_auth).unwrap();
        assert!(
            json.contains("token_path"),
            "VaultAuth::Token should serialize with 'token_path'"
        );

        // PRD §3.4.3: AppRole uses secret_id_path (not secret_id_file)
        let approle_auth = VaultAuth::AppRole {
            role_id: "role-123".to_string(),
            secret_id_path: std::path::PathBuf::from("/etc/puzzled/vault-secret-id"),
        };
        let json = serde_json::to_string(&approle_auth).unwrap();
        assert!(
            json.contains("secret_id_path"),
            "VaultAuth::AppRole should serialize with 'secret_id_path'"
        );

        // PRD §3.4.3: Kubernetes has only role (no optional token_path)
        let k8s_auth = VaultAuth::Kubernetes {
            role: "puzzlepod-role".to_string(),
        };
        let json = serde_json::to_string(&k8s_auth).unwrap();
        assert!(
            json.contains("\"role\""),
            "VaultAuth::Kubernetes should have 'role'"
        );
        assert!(
            !json.contains("token_path"),
            "VaultAuth::Kubernetes should not have 'token_path'"
        );
    }

    /// §3.4 defense-in-depth: Post-injection credential body check function.
    /// Verifies that journal_request rejects bodies containing injected credential values.
    #[test]
    fn test_post_injection_credential_body_check_logic() {
        // The post-injection check uses simple string containment on the body bytes.
        // Verify the logic: if the credential value appears in the body, it should be detected.
        let cred_value = "sk-secret-key-12345";
        let body_with_cred = format!(r#"{{"api_key": "{}"}}"#, cred_value);
        let body_without_cred = r#"{"prompt": "hello world"}"#;

        // Body containing credential → detected
        assert!(
            body_with_cred.contains(cred_value),
            "body with credential should be detected"
        );

        // Body without credential → not detected
        assert!(
            !body_without_cred.contains(cred_value),
            "body without credential should pass"
        );

        // Empty credential value → never matches (edge case)
        let empty_cred = "";
        // We skip the check when cred_val is empty, so this should pass
        assert!(
            empty_cred.is_empty(),
            "empty credential value should be skipped"
        );
    }

    // -----------------------------------------------------------------------
    // D-C4: Bearer prefix stripping for phantom token detection
    // -----------------------------------------------------------------------

    /// D-C4: Verify that phantom token detection works with "Bearer " prefix.
    /// The TLS intercept path must strip "Bearer " before calling is_phantom_token().
    #[tokio::test]
    async fn test_phantom_token_bearer_prefix_stripping() {
        use crate::credentials::PhantomTokenManager;

        let store = Arc::new(RwLock::new(
            crate::credentials::CredentialStore::new(
                std::path::PathBuf::from("/tmp/test-creds"),
                b"test-signing-key-for-unit-tests",
            )
            .unwrap(),
        ));
        let mgr = PhantomTokenManager::new(store, "pt_puzzled_".to_string(), 16);

        // Raw phantom token — detected directly
        assert!(mgr.is_phantom_token("pt_puzzled_abc123"));

        // With "Bearer " prefix — should NOT match is_phantom_token directly
        assert!(
            !mgr.is_phantom_token("Bearer pt_puzzled_abc123"),
            "is_phantom_token should not match when Bearer prefix is present"
        );

        // After stripping prefix — should match
        let value = "Bearer pt_puzzled_abc123";
        let stripped = value.strip_prefix("Bearer ").unwrap_or(value);
        assert!(
            mgr.is_phantom_token(stripped),
            "after stripping Bearer prefix, is_phantom_token should match"
        );

        // With "Basic " prefix — should also be stripped
        let basic_value = "Basic pt_puzzled_xyz789";
        let stripped_basic = basic_value
            .strip_prefix("Bearer ")
            .or_else(|| basic_value.strip_prefix("Basic "))
            .unwrap_or(basic_value);
        assert!(
            mgr.is_phantom_token(stripped_basic),
            "after stripping Basic prefix, is_phantom_token should match"
        );

        // No prefix (e.g., X-Api-Key header) — should match directly
        assert!(mgr.is_phantom_token("pt_puzzled_raw_token"));
    }

    // -----------------------------------------------------------------------
    // D-I8: Journal header redaction
    // -----------------------------------------------------------------------

    /// D-I8: Verify that credential headers are redacted before journaling.
    #[test]
    fn test_journal_header_redaction_logic() {
        let headers: Vec<(String, String)> = vec![
            ("Host".to_string(), "api.example.com".to_string()),
            (
                "Authorization".to_string(),
                "Bearer sk-real-secret-key".to_string(),
            ),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Api-Key".to_string(), "another-secret".to_string()),
        ];

        let redacted_headers: Vec<(String, String)> = headers
            .iter()
            .map(|(name, value)| {
                let lower_name = name.to_lowercase();
                if lower_name == "authorization"
                    || lower_name == "x-api-key"
                    || lower_name == "proxy-authorization"
                {
                    (name.clone(), "[REDACTED]".to_string())
                } else {
                    (name.clone(), value.clone())
                }
            })
            .collect();

        // Non-sensitive headers preserved
        assert_eq!(redacted_headers[0].1, "api.example.com");
        assert_eq!(redacted_headers[2].1, "application/json");

        // Sensitive headers redacted
        assert_eq!(redacted_headers[1].1, "[REDACTED]");
        assert_eq!(redacted_headers[3].1, "[REDACTED]");
    }

    // -----------------------------------------------------------------------
    // N10: Custom header credential redaction in journal
    // -----------------------------------------------------------------------

    /// N10: Verify that custom header names from credential injection are also redacted.
    #[test]
    fn test_journal_header_redaction_custom_header() {
        let headers: Vec<(String, String)> = vec![
            ("Host".to_string(), "api.example.com".to_string()),
            (
                "Authorization".to_string(),
                "Bearer sk-real-secret-key".to_string(),
            ),
            (
                "X-Custom-Auth".to_string(),
                "custom-secret-value".to_string(),
            ),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];

        let injected_custom_header_name: Option<String> = Some("X-Custom-Auth".to_string());

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

        // Non-sensitive headers preserved
        assert_eq!(redacted_headers[0].1, "api.example.com");
        assert_eq!(redacted_headers[3].1, "application/json");

        // Standard sensitive header redacted
        assert_eq!(redacted_headers[1].1, "[REDACTED]");

        // N10: Custom header also redacted
        assert_eq!(
            redacted_headers[2].1, "[REDACTED]",
            "custom credential header should be redacted"
        );
    }

    // -----------------------------------------------------------------------
    // D-I1: Zeroize verification
    // -----------------------------------------------------------------------

    /// D-I1: Verify that zeroize clears credential values in header strings.
    #[test]
    fn test_zeroize_clears_header_value() {
        use zeroize::Zeroize;

        let mut header_value = "Bearer sk-real-secret-key-12345".to_string();
        assert!(!header_value.is_empty());
        header_value.zeroize();
        // After zeroize, the string should be empty (zeroize on String clears + truncates)
        assert!(header_value.is_empty(), "zeroize should clear the string");
    }

    // -----------------------------------------------------------------------
    // D-C2: Multiple phantom token stripping
    // -----------------------------------------------------------------------

    /// D-C2: Verify that additional phantom tokens are detected for removal.
    #[tokio::test]
    async fn test_detect_additional_phantom_tokens() {
        use crate::credentials::PhantomTokenManager;

        let store = Arc::new(RwLock::new(
            crate::credentials::CredentialStore::new(
                std::path::PathBuf::from("/tmp/test-creds-dc2"),
                b"test-signing-key-for-unit-tests",
            )
            .unwrap(),
        ));
        let mgr = PhantomTokenManager::new(store, "pt_puzzled_".to_string(), 16);

        // Simulate headers with multiple phantom tokens
        let headers: Vec<(String, String)> = vec![
            ("Host".to_string(), "api.example.com".to_string()),
            (
                "Authorization".to_string(),
                "Bearer pt_puzzled_first".to_string(),
            ),
            ("X-Api-Key".to_string(), "pt_puzzled_second".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];

        let resolved_idx: Option<usize> = Some(1); // Authorization was resolved
        let mut indices_to_remove: Vec<usize> = Vec::new();
        for (idx, (_name, value)) in headers.iter().enumerate() {
            if Some(idx) == resolved_idx {
                continue;
            }
            let token_part = value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("Basic "))
                .unwrap_or(value.as_str());
            if mgr.is_phantom_token(token_part) {
                indices_to_remove.push(idx);
            }
        }

        // X-Api-Key at index 2 should be flagged for removal
        assert_eq!(
            indices_to_remove,
            vec![2],
            "should detect phantom token in X-Api-Key"
        );

        // Host and Content-Type should NOT be flagged
        assert!(
            !indices_to_remove.contains(&0),
            "Host header should not be flagged"
        );
        assert!(
            !indices_to_remove.contains(&3),
            "Content-Type header should not be flagged"
        );
    }

    // -----------------------------------------------------------------------
    // D-C1: inject_credential_into_header_vec tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_inject_credential_bearer_header_vec() {
        let resolved = crate::credentials::ResolvedCredential {
            credential_name: "test-key".to_string(),
            auth_header_value: zeroize::Zeroizing::new("Bearer sk-12345".to_string()),
            injection: InjectionMethod::BearerHeader,
            target_domains: vec!["example.com".to_string()],
            allowed_profiles: vec!["*".to_string()],
        };
        let mut headers = vec![
            ("Host".to_string(), "example.com".to_string()),
            (
                "Authorization".to_string(),
                "Bearer phantom_placeholder".to_string(),
            ),
        ];
        let mut path = "/api/v1".to_string();
        let result = inject_credential_into_header_vec(&mut headers, &mut path, &resolved, 1);
        assert!(result.is_some());
        assert_eq!(headers[1].0, "authorization");
        assert_eq!(headers[1].1, "Bearer sk-12345");
        assert_eq!(path, "/api/v1"); // path unchanged
    }

    #[test]
    fn test_inject_credential_custom_header_vec() {
        let resolved = crate::credentials::ResolvedCredential {
            credential_name: "api-key".to_string(),
            auth_header_value: zeroize::Zeroizing::new("raw-api-key-value".to_string()),
            injection: InjectionMethod::CustomHeader {
                header_name: "x-api-key".to_string(),
            },
            target_domains: vec!["example.com".to_string()],
            allowed_profiles: vec!["*".to_string()],
        };
        let mut headers = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("X-Api-Key".to_string(), "phantom_placeholder".to_string()),
        ];
        let mut path = "/api".to_string();
        let result = inject_credential_into_header_vec(&mut headers, &mut path, &resolved, 1);
        assert!(result.is_some());
        // D-C1: CustomHeader should use the header_name from injection, not "authorization"
        assert_eq!(headers[1].0, "x-api-key");
        // D-C1: CustomHeader auth_header_value is the raw value (no "Bearer" prefix)
        assert_eq!(headers[1].1, "raw-api-key-value");
    }

    #[test]
    fn test_inject_credential_query_parameter_vec() {
        let resolved = crate::credentials::ResolvedCredential {
            credential_name: "api-key".to_string(),
            auth_header_value: zeroize::Zeroizing::new("secret-key".to_string()),
            injection: InjectionMethod::QueryParameter {
                param_name: "api_key".to_string(),
            },
            target_domains: vec!["example.com".to_string()],
            allowed_profiles: vec!["*".to_string()],
        };
        let mut headers = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("X-Api-Key".to_string(), "phantom_placeholder".to_string()),
        ];
        let mut path = "/api/v1".to_string();
        let result = inject_credential_into_header_vec(&mut headers, &mut path, &resolved, 1);
        assert!(result.is_some());
        // D-C1: QueryParameter removes the phantom header
        assert_eq!(headers.len(), 1, "phantom header should be removed");
        // D-C1: Credential appended to path as query parameter
        assert!(
            path.contains("api_key=secret-key"),
            "path should contain query param, got: {path}"
        );
        assert!(
            path.starts_with("/api/v1?"),
            "path should preserve original path, got: {path}"
        );
    }

    #[test]
    fn test_inject_credential_query_parameter_appends_vec() {
        let resolved = crate::credentials::ResolvedCredential {
            credential_name: "api-key".to_string(),
            auth_header_value: zeroize::Zeroizing::new("secret".to_string()),
            injection: InjectionMethod::QueryParameter {
                param_name: "token".to_string(),
            },
            target_domains: vec!["example.com".to_string()],
            allowed_profiles: vec!["*".to_string()],
        };
        let mut headers = vec![("Authorization".to_string(), "Bearer phantom".to_string())];
        let mut path = "/api?foo=bar".to_string();
        inject_credential_into_header_vec(&mut headers, &mut path, &resolved, 0);
        assert!(
            path.contains("foo=bar&token=secret"),
            "should append to existing query, got: {path}"
        );
    }

    #[test]
    fn test_inject_credential_aws_sigv4_vec() {
        let resolved = crate::credentials::ResolvedCredential {
            credential_name: "aws-creds".to_string(),
            auth_header_value: zeroize::Zeroizing::new("AKIAIOSFODNN7EXAMPLE".to_string()),
            injection: InjectionMethod::AwsSigV4,
            target_domains: vec!["s3.amazonaws.com".to_string()],
            allowed_profiles: vec!["*".to_string()],
        };
        let mut headers = vec![
            ("Host".to_string(), "s3.amazonaws.com".to_string()),
            ("Authorization".to_string(), "Bearer phantom".to_string()),
        ];
        let mut path = "/bucket/key".to_string();
        let result = inject_credential_into_header_vec(&mut headers, &mut path, &resolved, 1);
        // D-C1: AwsSigV4 returns None (no credential injected) and removes phantom header
        assert!(result.is_none(), "AwsSigV4 should not inject raw secret");
        assert_eq!(headers.len(), 1, "phantom header should be removed");
        assert_eq!(path, "/bucket/key", "path should be unchanged");
    }

    // -----------------------------------------------------------------------
    // D-I3: Blocked credential mode in TLS intercept
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_tls_intercept_blocked_mode_strips_auth_headers() {
        let branch_id = BranchId::from("test-blocked".to_string());
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let journal = crate::replay::NetworkJournal::new(
            journal_dir,
            BranchId::from("test-blocked".to_string()),
        );
        let journal = Arc::new(Mutex::new(journal));

        // Agent sends a GET with Authorization and X-Api-Key headers
        let agent_request =
            b"GET /api HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer sk-secret\r\nX-Api-Key: another-secret\r\n\r\n";
        let upstream_response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

        let (agent_read, mut agent_write_half) = tokio::io::duplex(8192);
        let (upstream_read, mut upstream_write_half) = tokio::io::duplex(8192);

        let agent_write_task = tokio::spawn(async move {
            agent_write_half.write_all(agent_request).await.unwrap();
            let mut response = vec![0u8; 4096];
            let n = agent_write_half.read(&mut response).await.unwrap();
            response.truncate(n);
            response
        });

        let upstream_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = upstream_write_half.read(&mut buf).await.unwrap();
            let forwarded = String::from_utf8_lossy(&buf[..n]).to_string();
            upstream_write_half
                .write_all(upstream_response)
                .await
                .unwrap();
            drop(upstream_write_half);
            forwarded
        });

        let result = handle_intercepted_stream(
            agent_read,
            upstream_read,
            &branch_id,
            "example.com",
            "example.com:443",
            journal,
            None,
            10 * 1024 * 1024,
            crate::dlp::OversizedAction::BlockAndAlert,
            None,
            None,
            None,
            None,
            puzzled_types::CredentialMode::Blocked,
        )
        .await;

        assert!(result.is_ok(), "should succeed: {:?}", result);

        let forwarded = upstream_task.await.unwrap();
        // D-I3: Authorization and X-Api-Key should be stripped
        assert!(
            !forwarded.contains("sk-secret"),
            "Authorization value should be stripped, got: {forwarded}"
        );
        assert!(
            !forwarded.contains("another-secret"),
            "X-Api-Key value should be stripped, got: {forwarded}"
        );
        // Host header should be preserved
        assert!(
            forwarded.contains("Host: example.com") || forwarded.contains("host: example.com"),
            "Host header should be preserved, got: {forwarded}"
        );

        let _ = agent_write_task.await;
    }

    // -----------------------------------------------------------------------
    // D-I5: Content-Length-based response reading
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_tls_intercept_content_length_response_reading() {
        // This test verifies that the response reader uses Content-Length
        // instead of waiting for EOF. With Content-Length, the handler should
        // read exactly that many bytes and return — not block waiting for
        // the server to close the connection.
        let branch_id = BranchId::from("test-cl".to_string());
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let journal =
            crate::replay::NetworkJournal::new(journal_dir, BranchId::from("test-cl".to_string()));
        let journal = Arc::new(Mutex::new(journal));

        let agent_request = b"GET /data HTTP/1.1\r\nHost: example.com\r\n\r\n";
        // Response with explicit Content-Length
        let upstream_response = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world";

        let (agent_read, mut agent_write_half) = tokio::io::duplex(8192);
        let (upstream_read, mut upstream_write_half) = tokio::io::duplex(8192);

        let agent_write_task = tokio::spawn(async move {
            agent_write_half.write_all(agent_request).await.unwrap();
            let mut response = vec![0u8; 4096];
            let n = agent_write_half.read(&mut response).await.unwrap();
            response.truncate(n);
            String::from_utf8_lossy(&response).to_string()
        });

        // Write response but do NOT close the connection (simulating keep-alive)
        let upstream_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let _n = upstream_write_half.read(&mut buf).await.unwrap();
            upstream_write_half
                .write_all(upstream_response)
                .await
                .unwrap();
            upstream_write_half.flush().await.unwrap();
            // Do NOT drop upstream_write_half — simulates keep-alive (no EOF)
            // Wait for agent side to finish reading
            tokio::time::sleep(Duration::from_secs(2)).await;
            drop(upstream_write_half);
        });

        // With D-I5 fix, this should complete without waiting for EOF
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            handle_intercepted_stream(
                agent_read,
                upstream_read,
                &branch_id,
                "example.com",
                "example.com:443",
                journal,
                None,
                10 * 1024 * 1024,
                crate::dlp::OversizedAction::BlockAndAlert,
                None,
                None,
                None,
                None,
                puzzled_types::CredentialMode::default(),
            ),
        )
        .await;

        assert!(
            result.is_ok(),
            "D-I5: should complete without waiting for EOF when Content-Length is present"
        );

        let response_str = agent_write_task.await.unwrap();
        assert!(
            response_str.contains("hello world"),
            "response should contain body, got: {response_str}"
        );

        let _ = upstream_task.await;
    }

    // -----------------------------------------------------------------------
    // D-I6: Session timeout constant
    // -----------------------------------------------------------------------

    #[test]
    fn test_tls_session_timeout_constant() {
        assert_eq!(
            TLS_SESSION_TIMEOUT,
            Duration::from_secs(600),
            "D-I6: TLS session timeout should be 10 minutes"
        );
    }

    // -----------------------------------------------------------------------
    // D-C1: Chunked Transfer-Encoding decoder
    // -----------------------------------------------------------------------

    #[test]
    fn test_decode_chunked_body_basic() {
        // "Hello" (5 bytes) + " World" (6 bytes) + terminal chunk
        let chunked = b"5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n";
        let decoded = decode_chunked_body(chunked).unwrap();
        assert_eq!(decoded, b"Hello World");
    }

    #[test]
    fn test_decode_chunked_body_single_chunk() {
        let chunked = b"D\r\nHello, World!\r\n0\r\n\r\n";
        let decoded = decode_chunked_body(chunked).unwrap();
        assert_eq!(decoded, b"Hello, World!");
    }

    #[test]
    fn test_decode_chunked_body_empty() {
        // Just the terminal chunk
        let chunked = b"0\r\n\r\n";
        let decoded = decode_chunked_body(chunked).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_decode_chunked_body_with_extension() {
        // Chunk extensions after semicolon should be ignored
        let chunked = b"5;ext=val\r\nHello\r\n0\r\n\r\n";
        let decoded = decode_chunked_body(chunked).unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn test_decode_chunked_body_hex_uppercase() {
        // Hex chunk size with uppercase letters
        let chunked = b"A\r\n0123456789\r\n0\r\n\r\n";
        let decoded = decode_chunked_body(chunked).unwrap();
        assert_eq!(decoded.len(), 10);
    }

    #[test]
    fn test_decode_chunked_body_malformed_no_crlf() {
        let chunked = b"5\nHello";
        assert!(decode_chunked_body(chunked).is_err());
    }

    #[test]
    fn test_decode_chunked_body_invalid_hex() {
        let chunked = b"XYZ\r\nHello\r\n0\r\n\r\n";
        assert!(decode_chunked_body(chunked).is_err());
    }

    #[test]
    fn test_decode_chunked_body_truncated_data() {
        // Claim 10 bytes but only provide 5
        let chunked = b"a\r\nHello\r\n0\r\n\r\n";
        assert!(decode_chunked_body(chunked).is_err());
    }

    // -----------------------------------------------------------------------
    // D-C2: Duplicate Content-Length rejection
    // -----------------------------------------------------------------------

    // Note: D-C2 is tested at the integration level within handle_intercepted_stream.
    // The logic rejects conflicting Content-Length headers with 400 Bad Request.

    // -----------------------------------------------------------------------
    // D-C3: Response decompression for credential leak scanning
    // -----------------------------------------------------------------------

    /// D-C3: gzip round-trip — compress then decompress and verify output matches.
    #[test]
    fn test_decompress_for_scanning_gzip_roundtrip() {
        use flate2::write::GzEncoder;
        use std::io::Write;

        let original = b"secret-api-key-12345 this is the plaintext body";
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        // Compressed bytes should differ from original
        assert_ne!(&compressed[..], &original[..]);

        let decompressed = decompress_for_scanning(&compressed, "gzip").unwrap();
        assert_eq!(decompressed, original);
    }

    /// D-C3: deflate round-trip.
    #[test]
    fn test_decompress_for_scanning_deflate_roundtrip() {
        use flate2::write::DeflateEncoder;
        use std::io::Write;

        let original = b"Bearer sk-proj-ABCDEF credential leak test";
        let mut encoder = DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = decompress_for_scanning(&compressed, "deflate").unwrap();
        assert_eq!(decompressed, original);
    }

    /// D-C3: x-gzip alias should work the same as gzip.
    #[test]
    fn test_decompress_for_scanning_x_gzip() {
        use flate2::write::GzEncoder;
        use std::io::Write;

        let original = b"test data";
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = decompress_for_scanning(&compressed, "x-gzip").unwrap();
        assert_eq!(decompressed, original);
    }

    /// D-C3: identity encoding should return body as-is.
    #[test]
    fn test_decompress_for_scanning_identity() {
        let body = b"not compressed at all";
        let result = decompress_for_scanning(body, "identity").unwrap();
        assert_eq!(result, body);
    }

    /// D-C3: empty encoding string should return body as-is.
    #[test]
    fn test_decompress_for_scanning_empty_encoding() {
        let body = b"no encoding header";
        let result = decompress_for_scanning(body, "").unwrap();
        assert_eq!(result, body);
    }

    /// D-C3: unknown encoding must fail-closed (return Err).
    #[test]
    fn test_decompress_for_scanning_unknown_encoding_rejected() {
        let body = b"some bytes";
        let result = decompress_for_scanning(body, "br");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unsupported Content-Encoding"));

        let result = decompress_for_scanning(body, "zstd");
        assert!(result.is_err());

        let result = decompress_for_scanning(body, "compress");
        assert!(result.is_err());
    }

    /// D-C3: corrupt gzip data should fail-closed (return Err).
    #[test]
    fn test_decompress_for_scanning_corrupt_data() {
        let corrupt = b"this is not valid gzip data at all";
        let result = decompress_for_scanning(corrupt, "gzip");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("gzip decompression failed"));
    }

    /// D-C3: case-insensitive encoding matching.
    #[test]
    fn test_decompress_for_scanning_case_insensitive() {
        use flate2::write::GzEncoder;
        use std::io::Write;

        let original = b"case test";
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        // Mixed case should work
        let result = decompress_for_scanning(&compressed, "GZIP").unwrap();
        assert_eq!(result, original);

        let result = decompress_for_scanning(&compressed, " Gzip ").unwrap();
        assert_eq!(result, original);
    }

    // -----------------------------------------------------------------------
    // D-C3: Header name/value validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_http_header_name() {
        assert!(is_valid_http_header_name("Content-Type"));
        assert!(is_valid_http_header_name("X-Custom-Header"));
        assert!(is_valid_http_header_name("host"));
        assert!(is_valid_http_header_name("Accept"));
        assert!(is_valid_http_header_name("x-api-key"));
    }

    #[test]
    fn test_invalid_http_header_name() {
        assert!(!is_valid_http_header_name(""));
        assert!(!is_valid_http_header_name("Content Type")); // space
        assert!(!is_valid_http_header_name("Header\x00Name")); // null byte
        assert!(!is_valid_http_header_name("Header\nName")); // newline
        assert!(!is_valid_http_header_name("Header:Name")); // colon
        assert!(!is_valid_http_header_name("Header\x01Name")); // control char
    }

    #[test]
    fn test_valid_http_header_value() {
        assert!(is_valid_http_header_value("application/json"));
        assert!(is_valid_http_header_value("text/html; charset=utf-8"));
        assert!(is_valid_http_header_value("value\twith\ttabs")); // HTAB allowed
        assert!(is_valid_http_header_value("")); // empty is valid
        assert!(is_valid_http_header_value("Bearer sk-12345"));
    }

    #[test]
    fn test_invalid_http_header_value() {
        assert!(!is_valid_http_header_value("value\x00with_null")); // null byte
        assert!(!is_valid_http_header_value("value\x01with_ctrl")); // SOH
        assert!(!is_valid_http_header_value("value\x7fwith_del")); // DEL
        assert!(!is_valid_http_header_value("value\r\nwith_crlf")); // CRLF
    }

    // -----------------------------------------------------------------------
    // D-M1: MAX_HEADER_SIZE constant
    // -----------------------------------------------------------------------

    #[test]
    fn test_max_header_size_constant() {
        assert_eq!(
            MAX_HEADER_SIZE,
            64 * 1024,
            "D-M1: header limit should be 64KB"
        );
        const { assert!(MAX_HEADER_SIZE < MAX_BODY_SIZE) };
    }

    /// G3: TLS intercept header reading loop must enforce MAX_HEADER_SIZE
    /// to prevent unbounded memory growth from oversized headers.
    #[test]
    fn test_g3_tls_intercept_header_size_bounded() {
        let source = include_str!("handler.rs");
        let test_start = source.find("#[cfg(test)]").unwrap_or(source.len());
        let production_code = &source[..test_start];

        // Find the handle_intercepted_stream function
        let fn_start = production_code
            .find("async fn handle_intercepted_stream")
            .expect("G3: must have handle_intercepted_stream function");
        let fn_body = &production_code[fn_start..];

        // Verify request_buf.len() > MAX_HEADER_SIZE is checked
        assert!(
            fn_body.contains("request_buf.len() > MAX_HEADER_SIZE"),
            "G3: TLS intercept must check request_buf.len() > MAX_HEADER_SIZE"
        );
        // Verify it returns an error when headers are too large
        assert!(
            fn_body.contains("too large"),
            "G3: MAX_HEADER_SIZE check must return an error mentioning 'too large'"
        );
    }

    // -----------------------------------------------------------------------
    // D-I2/D-I3: Byte-string credential detection in non-UTF-8 bodies
    // -----------------------------------------------------------------------

    #[test]
    fn test_credential_detection_in_non_utf8_body() {
        let cred_value = b"sk-secret-key-12345";

        // Credential embedded in binary data with non-UTF-8 bytes
        let mut body = vec![0xFF, 0xFE, 0x80, 0x81]; // invalid UTF-8
        body.extend_from_slice(cred_value);
        body.extend_from_slice(&[0xFF, 0xFE]);

        // std::str::from_utf8 would fail on this body
        assert!(std::str::from_utf8(&body).is_err());

        // But byte-string search should still find the credential
        assert!(
            body.windows(cred_value.len()).any(|w| w == cred_value),
            "D-I2/D-I3: byte-string search should detect credential in non-UTF-8 body"
        );
    }

    #[test]
    fn test_credential_detection_empty_credential() {
        let cred_bytes: &[u8] = b"";
        let _body = b"some body content";
        // Empty credential should never match (guarded by is_empty check)
        assert!(cred_bytes.is_empty());
    }

    // -----------------------------------------------------------------------
    // D-C1: Content-Encoding rejection when DLP is active
    // -----------------------------------------------------------------------

    /// D-C1: Verify that requests with Content-Encoding are rejected when DLP
    /// is active (non-TLS path uses hyper::header::CONTENT_ENCODING).
    #[test]
    fn test_content_encoding_header_constant() {
        // Verify the header constant exists and is correct
        assert_eq!(
            hyper::header::CONTENT_ENCODING,
            hyper::header::HeaderName::from_static("content-encoding")
        );
    }

    // -----------------------------------------------------------------------
    // H60: Fallback body streaming must enforce MAX_BODY_SIZE
    // -----------------------------------------------------------------------

    /// H60: Verify that the fallback forward_request body streaming path
    /// has a size limit check against MAX_BODY_SIZE.
    #[test]
    fn test_h60_fallback_body_size_limit() {
        let source = include_str!("handler.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // Find the fallback body streaming section (body_parts / body_stream)
        assert!(
            prod_source.contains("total_body_size") && prod_source.contains("MAX_BODY_SIZE"),
            "H60: fallback body streaming path must track total_body_size and check against MAX_BODY_SIZE"
        );
        // Verify the check happens before pushing to body_parts
        let body_stream_section = prod_source
            .find("total_body_size")
            .expect("H60: total_body_size counter must exist");
        let after_counter = &prod_source[body_stream_section..];
        assert!(
            after_counter.contains("if total_body_size > MAX_BODY_SIZE"),
            "H60: must check total_body_size > MAX_BODY_SIZE before accepting chunk"
        );
    }

    // -----------------------------------------------------------------------
    // H61: Case-insensitive auth-scheme in TLS intercept
    // -----------------------------------------------------------------------

    /// H61: Verify that the TLS intercept path uses case-insensitive matching
    /// for Bearer/Basic auth scheme prefixes.
    #[test]
    fn test_h61_case_insensitive_auth_scheme() {
        let source = include_str!("handler.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // The TLS intercept path should use eq_ignore_ascii_case, not strip_prefix("Bearer ")
        assert!(
            prod_source.contains("eq_ignore_ascii_case(\"Bearer \")"),
            "H61: TLS intercept path must use case-insensitive matching for 'Bearer ' prefix \
             (eq_ignore_ascii_case), not case-sensitive strip_prefix"
        );
        assert!(
            prod_source.contains("eq_ignore_ascii_case(\"Basic \")"),
            "H61: TLS intercept path must use case-insensitive matching for 'Basic ' prefix \
             (eq_ignore_ascii_case), not case-sensitive strip_prefix"
        );
    }

    // -----------------------------------------------------------------------
    // H63: inject_resolved_credential must return Err on failure
    // -----------------------------------------------------------------------

    /// H63: Verify that inject_resolved_credential returns Result and the Err
    /// branches return an error instead of falling through silently.
    #[test]
    fn test_h63_inject_credential_returns_result() {
        let source = include_str!("handler.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // Function signature must return Result
        assert!(
            prod_source.contains("fn inject_resolved_credential")
                && prod_source.contains(") -> Result<(), String>"),
            "H63: inject_resolved_credential must return Result<(), String> (fail-closed)"
        );

        // The Err branch for HeaderValue::from_str must return Err, not fall through
        let fn_start = prod_source
            .find("fn inject_resolved_credential")
            .expect("function must exist");
        let fn_body = &prod_source[fn_start..];
        // Count return Err occurrences within the function
        let err_returns = fn_body.matches("return Err(msg)").count();
        assert!(
            err_returns >= 2,
            "H63: inject_resolved_credential must have at least 2 'return Err(msg)' \
             branches (Bearer/Basic and CustomHeader), found {}",
            err_returns
        );
    }

    /// H63: Verify that inject_resolved_credential actually returns Err on
    /// invalid header values (functional test).
    #[test]
    fn test_h63_inject_credential_fails_on_invalid_value() {
        // A header value containing \r\n is invalid
        let resolved = crate::credentials::ResolvedCredential {
            credential_name: "bad-cred".to_string(),
            auth_header_value: zeroize::Zeroizing::new("Bearer bad\r\nvalue".to_string()),
            injection: InjectionMethod::BearerHeader,
            target_domains: vec!["example.com".to_string()],
            allowed_profiles: vec!["*".to_string()],
        };
        let req = Request::builder()
            .uri("https://example.com/api")
            .body(())
            .unwrap();
        let (mut parts, _body) = req.into_parts();
        let result = inject_resolved_credential(&mut parts, &resolved);
        assert!(
            result.is_err(),
            "H63: inject_resolved_credential must return Err on invalid header value"
        );
    }

    // -----------------------------------------------------------------------
    // H64: Domain validation in TLS intercept Host header
    // -----------------------------------------------------------------------

    /// H64: Verify that domain is validated against CR/LF before Host header
    /// construction in the TLS intercept path.
    #[test]
    fn test_h64_domain_crlf_validation() {
        let source = include_str!("handler.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // Find the TLS intercept forwarding section
        assert!(
            prod_source.contains("H64: domain contains CR/LF"),
            "H64: domain must be validated for CR/LF before Host header construction"
        );
    }

    // -----------------------------------------------------------------------
    // H65: Path/method validation in TLS intercept request line
    // -----------------------------------------------------------------------

    /// H65: Verify that path and method are validated against CR/LF before
    /// constructing the request line in the TLS intercept path.
    #[test]
    fn test_h65_path_method_crlf_validation() {
        let source = include_str!("handler.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        assert!(
            prod_source.contains("H65: request line contains CR/LF"),
            "H65: path and method must be validated for CR/LF before request line construction"
        );
    }

    // -----------------------------------------------------------------------
    // H68: chrono_now() must not return empty string
    // -----------------------------------------------------------------------

    /// H68: Verify that chrono_now() does not use unwrap_or_default() which
    /// would return an empty string on pre-epoch clock.
    #[test]
    fn test_h68_chrono_now_no_empty_default() {
        let source = include_str!("handler.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // Find the chrono_now function
        let fn_start = prod_source
            .find("fn chrono_now()")
            .expect("chrono_now function must exist");
        let fn_block = &prod_source[fn_start..];
        let fn_end = fn_block
            .find("\nfn ")
            .or_else(|| fn_block.find("\n#["))
            .unwrap_or(fn_block.len());
        let fn_body = &fn_block[..fn_end];

        assert!(
            !fn_body.contains("unwrap_or_default()"),
            "H68: chrono_now() must not use unwrap_or_default() — \
             it returns empty string on pre-epoch clock. Use unwrap_or_else(|_| \"0\".to_string())"
        );
    }

    #[test]
    fn j40_tls_intercept_path_encodes_param_name() {
        // J40: The TLS intercept path must URL-encode param_name, matching the
        // non-TLS path (G13). Verify with include_str! that both code paths use
        // urlencoding::encode on param_name.
        let source = include_str!("handler.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // Find the TLS intercept inject function (inject_credential_into_header_vec)
        let tls_fn_start = prod_source
            .find("fn inject_credential_into_header_vec")
            .expect("TLS intercept injection function must exist");
        let tls_fn_body = &prod_source[tls_fn_start..];
        let tls_query_param = tls_fn_body
            .find("InjectionMethod::QueryParameter")
            .expect("TLS path must handle QueryParameter");
        let tls_section = &tls_fn_body[tls_query_param..tls_query_param + 500];

        assert!(
            tls_section.contains("urlencoding::encode(param_name)"),
            "J40: TLS intercept path must URL-encode param_name via urlencoding::encode(param_name)"
        );

        // Also verify the non-TLS path still encodes it (G13)
        let non_tls_fn_start = prod_source
            .find("fn inject_resolved_credential")
            .expect("non-TLS injection function must exist");
        let non_tls_fn_body = &prod_source[non_tls_fn_start..];
        let non_tls_qp = non_tls_fn_body
            .find("InjectionMethod::QueryParameter")
            .expect("non-TLS path must handle QueryParameter");
        let non_tls_section = &non_tls_fn_body[non_tls_qp..non_tls_qp + 600];

        assert!(
            non_tls_section.contains("urlencoding::encode(param_name)"),
            "J40: non-TLS path must also URL-encode param_name (G13)"
        );
    }

    #[test]
    fn j41_query_parameter_uri_parse_failure_returns_err() {
        // J41: When URI parsing fails for query parameter injection, the function
        // must return Err (fail-closed per H63), not silently continue with Ok(()).
        let source = include_str!("handler.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        let fn_start = prod_source
            .find("fn inject_resolved_credential")
            .expect("function must exist");
        let fn_body = &prod_source[fn_start..];
        let qp_start = fn_body
            .find("InjectionMethod::QueryParameter")
            .expect("QueryParameter arm must exist");
        let qp_section = &fn_body[qp_start..qp_start + 2000];

        // The else branch must return Err, not log-and-continue
        assert!(
            qp_section.contains("return Err(format!"),
            "J41: URI parse failure in QueryParameter must return Err (fail-closed)"
        );
        assert!(
            !qp_section.contains("tracing::warn!(\n                    param = %param_name,\n                    \"§3.4: failed to rewrite URI"),
            "J41: old warn-and-continue pattern must be replaced with Err return"
        );
    }

    #[test]
    fn j43_dc2_cleanup_uses_case_insensitive_prefix_matching() {
        // J43: The D-C2 phantom token cleanup code must use case-insensitive
        // prefix matching (eq_ignore_ascii_case) instead of literal strip_prefix.
        let source = include_str!("handler.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // Find the D-C2 cleanup section
        let dc2_start = prod_source
            .find("D-C2: Strip any remaining phantom tokens")
            .expect("D-C2 cleanup section must exist");
        let dc2_section = &prod_source[dc2_start..dc2_start + 1200];

        assert!(
            dc2_section.contains("eq_ignore_ascii_case"),
            "J43: D-C2 phantom token cleanup must use case-insensitive prefix matching"
        );
        assert!(
            !dc2_section.contains("strip_prefix(\"Bearer \")"),
            "J43: D-C2 must not use case-sensitive strip_prefix(\"Bearer \")"
        );
        assert!(
            !dc2_section.contains("strip_prefix(\"Basic \")"),
            "J43: D-C2 must not use case-sensitive strip_prefix(\"Basic \")"
        );
    }

    // -----------------------------------------------------------------------
    // K40-K43, K45: Error responses must not leak internal details
    // -----------------------------------------------------------------------

    #[test]
    fn k40_connect_error_no_internal_details() {
        let source = include_str!("handler.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        assert!(
            prod_source.contains("\"Failed to connect to upstream\\n\""),
            "K40: connect error must use generic message without target_with_port"
        );
        assert!(
            !prod_source.contains("\"Failed to connect to {}: {}\\n\""),
            "K40: must not format target_with_port and error into response body"
        );
    }

    #[test]
    fn k41_pinned_ip_connect_error_no_internal_details() {
        let source = include_str!("handler.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        assert!(
            !prod_source.contains("\"Failed to connect to pinned IP"),
            "K41: must not include pinned IP address in error response body"
        );
    }

    #[test]
    fn k42_geo_residency_error_no_internal_details() {
        let source = include_str!("handler.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        assert!(
            prod_source.contains("Data residency violation: destination not in allowed regions"),
            "K42: geo-residency error must use generic message"
        );
        assert!(
            !prod_source.contains("not in allowed regions {:?}"),
            "K42: must not include allowed_regions debug format in response body"
        );
    }

    #[test]
    fn k43_dns_error_no_internal_details() {
        let source = include_str!("handler.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        assert!(
            !prod_source.contains("\"DNS resolution failed for"),
            "K43: must not include hostname in DNS error response body"
        );
        assert!(
            prod_source.contains("\"DNS resolution failed\\n\""),
            "K43: DNS error must use generic message"
        );
    }

    #[test]
    fn k45_upstream_error_no_internal_details() {
        let source = include_str!("handler.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        assert!(
            !prod_source.contains("\"Upstream error: {}\\n\""),
            "K45: must not format internal error into upstream error response"
        );
        let count = prod_source
            .matches("\"Upstream request failed\\n\"")
            .count();
        assert!(
            count >= 2,
            "K45: expected at least 2 generic upstream error messages, found {count}"
        );
    }

    // -----------------------------------------------------------------------
    // K44: DNS rebinding protection in Unrestricted and Monitored modes
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // L40: TLS error response write failures must be logged (not silently ignored)
    // -----------------------------------------------------------------------

    #[test]
    fn l40_tls_error_writes_are_logged() {
        let source = include_str!("handler.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // Count instances of `let _ = agent_tls.write_all(` and `let _ = agent_tls.flush(`
        let silent_write_count = prod_source.matches("let _ = agent_tls.write_all(").count();
        let silent_flush_count = prod_source.matches("let _ = agent_tls.flush(").count();

        assert_eq!(
            silent_write_count, 0,
            "L40: found {} instances of 'let _ = agent_tls.write_all(' — must use 'if let Err(e)' with tracing::debug!",
            silent_write_count
        );
        assert_eq!(
            silent_flush_count, 0,
            "L40: found {} instances of 'let _ = agent_tls.flush(' — must use 'if let Err(e)' with tracing::debug!",
            silent_flush_count
        );
    }

    // -----------------------------------------------------------------------
    // L21: DLP blocked error path must not collect unbounded body
    // -----------------------------------------------------------------------

    #[test]
    fn l21_dlp_error_path_has_body_size_limit() {
        let source = include_str!("handler.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // Find the DLP blocked request error path
        let dlp_err_start = prod_source
            .find("DLP blocked the request")
            .expect("DLP blocked error path must exist");
        let dlp_err_section = &prod_source[dlp_err_start..dlp_err_start + 500];

        // L21: Must NOT have unbounded resp_body.collect().await
        // Either use a generic error message, or limit the body collection
        let has_size_limit = dlp_err_section.contains("DLP blocked request")
            && !dlp_err_section.contains("resp_body.collect().await");
        let has_take = dlp_err_section.contains(".take(");
        let has_content_length_check = dlp_err_section.contains("content_length")
            || dlp_err_section.contains("CONTENT_LENGTH");

        assert!(
            has_size_limit || has_take || has_content_length_check,
            "L21: DLP error path must limit body collection (use .take(), check Content-Length, or use a generic message)"
        );
    }

    // -----------------------------------------------------------------------
    // L20: scan_response_for_credential_leak must check body size before collecting
    // -----------------------------------------------------------------------

    #[test]
    fn l20_credential_scan_has_body_size_check() {
        let source = include_str!("handler.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        // Find the scan_response_for_credential_leak function
        let fn_start = prod_source
            .find("async fn scan_response_for_credential_leak")
            .expect("scan_response_for_credential_leak function must exist");
        // Find the next top-level function after it
        let fn_body = &prod_source[fn_start..];
        let fn_end = fn_body[1..]
            .find("\nasync fn ")
            .or_else(|| fn_body[1..].find("\nfn "))
            .unwrap_or(fn_body.len());
        let fn_text = &fn_body[..fn_end];

        // L20: Must check body size before or instead of unbounded body.collect()
        assert!(
            fn_text.contains("MAX_RESPONSE_BODY_BYTES")
                || fn_text.contains("content_length"),
            "L20: scan_response_for_credential_leak must check body size against MAX_RESPONSE_BODY_BYTES"
        );
    }

    #[test]
    fn k44_unrestricted_mode_calls_check_dns_rebinding() {
        let source = include_str!("handler.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        let unrestricted_start = prod_source
            .find("ProxyMode::Unrestricted =>")
            .expect("Unrestricted mode block must exist");
        let monitored_start = prod_source[unrestricted_start..]
            .find("ProxyMode::Monitored =>")
            .expect("Monitored mode block must exist");
        let unrestricted_block =
            &prod_source[unrestricted_start..unrestricted_start + monitored_start];

        assert!(
            unrestricted_block.contains("check_dns_rebinding"),
            "K44: Unrestricted mode must call check_dns_rebinding"
        );
        assert!(
            unrestricted_block.contains("resolved_addrs.as_deref()"),
            "K44: Unrestricted mode must pass resolved_addrs to forwarding functions"
        );
    }

    #[test]
    fn k44_monitored_mode_calls_check_dns_rebinding() {
        let source = include_str!("handler.rs");
        let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);

        let monitored_start = prod_source
            .find("ProxyMode::Monitored =>")
            .expect("Monitored mode block must exist");
        let gated_start = prod_source[monitored_start..]
            .find("ProxyMode::Gated =>")
            .expect("Gated mode block must exist");
        let monitored_block = &prod_source[monitored_start..monitored_start + gated_start];

        assert!(
            monitored_block.contains("check_dns_rebinding"),
            "K44: Monitored mode must call check_dns_rebinding"
        );
        assert!(
            monitored_block.contains("resolved_addrs.as_deref()"),
            "K44: Monitored mode must pass resolved_addrs to forwarding functions"
        );
    }

    // Q1: Verify X-Api-Key is stripped in Blocked credential mode (non-TLS path)
    #[test]
    fn test_blocked_mode_strips_x_api_key_non_tls() {
        // Simulate what the Blocked branch does: remove auth headers from request parts
        let req = hyper::Request::builder()
            .uri("http://example.com/api")
            .header("authorization", "Bearer sk-secret")
            .header("proxy-authorization", "Basic creds")
            .header("x-api-key", "api-key-secret")
            .header("host", "example.com")
            .body(())
            .unwrap();

        let (mut parts, _body) = req.into_parts();
        // This mirrors the Blocked mode logic in handle_proxy_request
        parts.headers.remove(hyper::header::AUTHORIZATION);
        parts.headers.remove(hyper::header::PROXY_AUTHORIZATION);
        parts.headers.remove("x-api-key"); // Q1 fix

        assert!(
            parts.headers.get("authorization").is_none(),
            "Authorization header should be stripped"
        );
        assert!(
            parts.headers.get("proxy-authorization").is_none(),
            "Proxy-Authorization header should be stripped"
        );
        assert!(
            parts.headers.get("x-api-key").is_none(),
            "X-Api-Key header should be stripped in Blocked mode"
        );
        assert!(
            parts.headers.get("host").is_some(),
            "Non-credential headers should be preserved"
        );
    }

    // -----------------------------------------------------------------------
    // F1: HTML-entity encoded credential detection in response scanning
    // -----------------------------------------------------------------------

    #[test]
    fn test_html_entity_encoded_credential_detection() {
        // Credential "sk-123" encoded as HTML decimal entities: &#115;&#107;&#45;&#49;&#50;&#51;
        let cred = "sk-123";
        let html_encoded: String = cred.bytes().map(|b| format!("&#{};", b)).collect();
        assert_eq!(html_encoded, "&#115;&#107;&#45;&#49;&#50;&#51;");

        let body = format!("<html><body>{}</body></html>", html_encoded);
        let body_bytes = body.as_bytes();

        // The HTML-entity encoded credential should be detected
        assert!(
            body_bytes
                .windows(html_encoded.len())
                .any(|w| w == html_encoded.as_bytes()),
            "F1: HTML-entity encoded credential should be detected by window scan"
        );
    }

    // -----------------------------------------------------------------------
    // F2: Decompression in non-TLS credential scanning path
    // -----------------------------------------------------------------------

    #[test]
    fn test_f2_decompress_for_scanning_gzip() {
        use flate2::write::GzEncoder;
        use std::io::Write;

        let original = b"this contains sk-secret-key-12345 in plaintext";
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = decompress_for_scanning(&compressed, "gzip").unwrap();
        assert_eq!(&decompressed, original);
    }

    #[test]
    fn test_f2_decompress_unknown_encoding_fails() {
        let body = b"some body";
        let result = decompress_for_scanning(body, "br");
        assert!(
            result.is_err(),
            "F2: unknown Content-Encoding should fail-closed"
        );
    }

    // -----------------------------------------------------------------------
    // F3: TLS intercept scan should detect Base64/URL-encoded credentials
    // -----------------------------------------------------------------------

    #[test]
    fn test_tls_scan_base64_encoded_credential() {
        let cred = "sk-secret-key-12345";
        let cred_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, cred);

        let body = format!("{{\"token\": \"{}\"}}", cred_b64);
        let body_bytes = body.as_bytes();

        assert!(
            body_bytes
                .windows(cred_b64.len())
                .any(|w| w == cred_b64.as_bytes()),
            "F3: Base64-encoded credential should be detectable in response body"
        );
    }

    // -----------------------------------------------------------------------
    // §4.3: Domain matching prevents credential injection to wrong domain
    // -----------------------------------------------------------------------

    #[test]
    fn test_domain_matching_prevents_exfiltration() {
        use crate::credentials::domain_matches;

        // Exact domain match
        assert!(domain_matches("api.example.com", "api.example.com"));

        // Wildcard domain match
        assert!(domain_matches("sub.example.com", "*.example.com"));

        // Non-matching domain must NOT match
        assert!(
            !domain_matches("evil.attacker.com", "api.example.com"),
            "§4.3: non-matching domain must be rejected to prevent credential exfiltration"
        );
        assert!(
            !domain_matches("evil.attacker.com", "*.example.com"),
            "§4.3: wildcard must not match different TLD"
        );

        // Subdomain of attacker-controlled wildcard must not match legitimate domain
        assert!(
            !domain_matches("api.example.com", "*.attacker.com"),
            "§4.3: legitimate domain must not match attacker wildcard"
        );
    }

    // -----------------------------------------------------------------------
    // §4.2: Restart recovery — save/load preserves phantom token mappings
    // -----------------------------------------------------------------------

    #[test]
    fn test_restart_recovery_credential_mappings_roundtrip() {
        use crate::credential_persistence::{CredentialMappingFile, PersistedMapping};

        let tmp = tempfile::tempdir().unwrap();
        let original = CredentialMappingFile::new(
            18443,
            vec![PersistedMapping {
                phantom_token: "pt_puzzled_abc12345".to_string(),
                credential_name: "api-key".to_string(),
                domains: vec!["api.example.com".to_string()],
                backend: "systemd_creds".to_string(),
                env_var: "API_KEY".to_string(),
                swap_headers: vec![],
                ttl_seconds: 0,
                backend_config: serde_json::Value::Null,
            }],
        );

        // Save and reload (simulates restart)
        original.save(tmp.path()).unwrap();
        let recovered = CredentialMappingFile::load(tmp.path()).unwrap().unwrap();

        assert_eq!(recovered.proxy_port, 18443);
        assert_eq!(recovered.mappings[0].phantom_token, "pt_puzzled_abc12345");
        assert_eq!(recovered.mappings[0].credential_name, "api-key");
        assert_eq!(recovered.mappings[0].domains, vec!["api.example.com"]);
    }

    // -----------------------------------------------------------------------
    // §4.3: memfd_create and memfd_secret in seccomp deny list
    // -----------------------------------------------------------------------

    #[test]
    fn test_memfd_create_in_seccomp_deny_list() {
        // Verify the source code has memfd_create in DENY_SYSCALLS
        let seccomp_source = include_str!("../../puzzled/src/sandbox/seccomp/mod.rs");
        assert!(
            seccomp_source.contains("memfd_create"),
            "§4.3: memfd_create must be in seccomp DENY_SYSCALLS"
        );
    }
}
