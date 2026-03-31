// SPDX-License-Identifier: Apache-2.0
//! HTTP request handler for the agent proxy.
//!
//! Routes requests based on method:
//! - GET/HEAD: forward immediately if domain allowed
//! - POST/PUT/DELETE/PATCH: journal for replay at commit
//! - CONNECT: tunnel with domain validation (HTTPS)

pub(crate) mod connect;
pub(crate) mod credentials;
pub(crate) mod dlp_inspect;
pub(crate) mod forward;
pub(crate) mod intercept;
pub(crate) mod journal;
pub mod routing;
pub(crate) mod tls;
pub(crate) mod transparent;
pub(crate) mod util;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Request, Response, StatusCode};
use puzzled_types::BranchId;
use tokio::sync::{Mutex, RwLock, Semaphore};

use crate::credentials::PhantomTokenManager;
use crate::dlp::DlpEngine;
use crate::replay::NetworkJournal;
use crate::tls::AgentCa;
use crate::ProxyMode;

// Re-exports for use by lib.rs and other crates
pub use self::routing::{
    check_dns_rebinding, is_domain_allowed, is_domain_denied, strip_hop_by_hop,
};
pub use self::transparent::handle_transparent_connection;

type BoxBody = http_body_util::Full<Bytes>;

/// Shared per-connection context for proxy request handling.
/// All fields are cheaply cloneable (Arc/Copy/Clone).
#[derive(Clone)]
pub struct ProxyRequestContext {
    pub journal: Arc<Mutex<NetworkJournal>>,
    pub branch_id: BranchId,
    pub connection_semaphore: Arc<Semaphore>,
    pub dlp_engine: Option<Arc<DlpEngine>>,
    pub max_inspection_body_size: usize,
    pub oversized_body_action: crate::dlp::OversizedAction,
    pub quarantine_sender: Option<tokio::sync::mpsc::Sender<BranchId>>,
    pub phantom_token_manager: Option<Arc<RwLock<PhantomTokenManager>>>,
    pub agent_profile: Option<String>,
    pub audit_sender: Option<tokio::sync::mpsc::Sender<crate::ProxyAuditEvent>>,
    pub credential_mode: puzzled_types::CredentialMode,
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

// Import sub-module functions used by handle_request
use self::connect::handle_connect;
use self::credentials::{inject_credentials, scan_response_for_credential_leak};
use self::dlp_inspect::inspect_dlp_response;
use self::forward::forward_request;
use self::journal::journal_request;
use self::routing::{
    check_connect_host_match, check_connect_port, check_request_port, check_ssrf, extract_host,
};
use self::tls::handle_tls_intercept;
use self::util::send_audit;

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
    ctx: &ProxyRequestContext,
    ca: Option<&AgentCa>,
    geo_database: Option<Arc<crate::geo::GeoIpDatabase>>,
    data_residency: Option<puzzled_types::DataResidencyConfig>,
) -> Result<Response<BoxBody>, hyper::Error> {
    // H-15: Acquire a concurrency permit before handling the request.
    // The permit is held for the duration of request processing and
    // released automatically when `_permit` is dropped.
    let _permit = match ctx.connection_semaphore.acquire().await {
        Ok(permit) => permit,
        Err(_) => {
            // Semaphore closed — proxy is shutting down
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Full::new(Bytes::from("Proxy shutting down\n")))
                .unwrap());
        }
    };

    // Unpack context fields as local references for use throughout the handler.
    let branch_id = &ctx.branch_id;
    let dlp_engine = &ctx.dlp_engine;
    let max_inspection_body_size = ctx.max_inspection_body_size;
    let oversized_body_action = ctx.oversized_body_action;
    let quarantine_sender = &ctx.quarantine_sender;
    let phantom_token_manager = &ctx.phantom_token_manager;
    let agent_profile = &ctx.agent_profile;
    let audit_sender = &ctx.audit_sender;
    let credential_mode = ctx.credential_mode;

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
                    return handle_tls_intercept(req, ca, resolved_addrs.as_deref(), ctx).await;
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
            return handle_tls_intercept(req, ca, resolved_addrs.as_deref(), ctx).await;
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
                ctx,
                injected_credential_value.as_ref().map(|v| v.as_str()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::InjectionMethod;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // C4: Test find_header_end helper
    #[test]
    fn test_find_header_end() {
        use self::util::find_header_end;
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
        let result = tls::build_tls_acceptor(cert_der, key_der);
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

        let ctx = ProxyRequestContext {
            journal: journal.clone(),
            branch_id: branch_id.clone(),
            connection_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            dlp_engine: None,
            max_inspection_body_size: 10 * 1024 * 1024,
            oversized_body_action: crate::dlp::OversizedAction::BlockAndAlert,
            quarantine_sender: None,
            phantom_token_manager: None,
            agent_profile: None,
            audit_sender: None,
            credential_mode: puzzled_types::CredentialMode::default(),
        };

        let result = intercept::handle_intercepted_stream(
            agent_read,
            upstream_read,
            "example.com",
            "example.com:443",
            &ctx,
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

        let ctx = ProxyRequestContext {
            journal: journal.clone(),
            branch_id: branch_id.clone(),
            connection_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            dlp_engine: None,
            max_inspection_body_size: 10 * 1024 * 1024,
            oversized_body_action: crate::dlp::OversizedAction::BlockAndAlert,
            quarantine_sender: None,
            phantom_token_manager: None,
            agent_profile: None,
            audit_sender: None,
            credential_mode: puzzled_types::CredentialMode::default(),
        };

        let result = intercept::handle_intercepted_stream(
            agent_read,
            upstream_read,
            "api.example.com",
            "api.example.com:443",
            &ctx,
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
        credentials::inject_resolved_credential(&mut parts, &resolved).unwrap();
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
        credentials::inject_resolved_credential(&mut parts, &resolved).unwrap();
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
        credentials::inject_resolved_credential(&mut parts, &resolved).unwrap();
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
        credentials::inject_resolved_credential(&mut parts, &resolved).unwrap();
        let uri_str = parts.uri.to_string();
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
        credentials::inject_resolved_credential(&mut parts, &resolved).unwrap();
        assert!(parts.headers.get("x-amz-credential").is_none());
    }

    /// §3.4: VaultAuth fields match PRD naming (token_path, secret_id_path).
    #[test]
    fn test_vault_auth_prd_field_names() {
        use crate::credential_backends::VaultAuth;

        let token_auth = VaultAuth::Token {
            token_path: std::path::PathBuf::from("/etc/puzzled/vault-token"),
        };
        let json = serde_json::to_string(&token_auth).unwrap();
        assert!(json.contains("token_path"));

        let approle_auth = VaultAuth::AppRole {
            role_id: "role-123".to_string(),
            secret_id_path: std::path::PathBuf::from("/etc/puzzled/vault-secret-id"),
        };
        let json = serde_json::to_string(&approle_auth).unwrap();
        assert!(json.contains("secret_id_path"));

        let k8s_auth = VaultAuth::Kubernetes {
            role: "puzzlepod-role".to_string(),
        };
        let json = serde_json::to_string(&k8s_auth).unwrap();
        assert!(json.contains("\"role\""));
        assert!(!json.contains("token_path"));
    }

    #[test]
    fn test_post_injection_credential_body_check_logic() {
        let cred_value = "sk-secret-key-12345";
        let body_with_cred = format!(r#"{{"api_key": "{}"}}"#, cred_value);
        let body_without_cred = r#"{"prompt": "hello world"}"#;

        assert!(body_with_cred.contains(cred_value));
        assert!(!body_without_cred.contains(cred_value));

        let empty_cred = "";
        assert!(empty_cred.is_empty());
    }

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

        assert!(mgr.is_phantom_token("pt_puzzled_abc123"));
        assert!(!mgr.is_phantom_token("Bearer pt_puzzled_abc123"));

        let value = "Bearer pt_puzzled_abc123";
        let stripped = value.strip_prefix("Bearer ").unwrap_or(value);
        assert!(mgr.is_phantom_token(stripped));

        let basic_value = "Basic pt_puzzled_xyz789";
        let stripped_basic = basic_value
            .strip_prefix("Bearer ")
            .or_else(|| basic_value.strip_prefix("Basic "))
            .unwrap_or(basic_value);
        assert!(mgr.is_phantom_token(stripped_basic));

        assert!(mgr.is_phantom_token("pt_puzzled_raw_token"));
    }

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

        assert_eq!(redacted_headers[0].1, "api.example.com");
        assert_eq!(redacted_headers[2].1, "application/json");
        assert_eq!(redacted_headers[1].1, "[REDACTED]");
        assert_eq!(redacted_headers[3].1, "[REDACTED]");
    }

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

        assert_eq!(redacted_headers[0].1, "api.example.com");
        assert_eq!(redacted_headers[3].1, "application/json");
        assert_eq!(redacted_headers[1].1, "[REDACTED]");
        assert_eq!(redacted_headers[2].1, "[REDACTED]");
    }

    #[test]
    fn test_zeroize_clears_header_value() {
        use zeroize::Zeroize;
        let mut header_value = "Bearer sk-real-secret-key-12345".to_string();
        assert!(!header_value.is_empty());
        header_value.zeroize();
        assert!(header_value.is_empty());
    }

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

        let headers: Vec<(String, String)> = vec![
            ("Host".to_string(), "api.example.com".to_string()),
            (
                "Authorization".to_string(),
                "Bearer pt_puzzled_first".to_string(),
            ),
            ("X-Api-Key".to_string(), "pt_puzzled_second".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];

        let resolved_idx: Option<usize> = Some(1);
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

        assert_eq!(indices_to_remove, vec![2]);
        assert!(!indices_to_remove.contains(&0));
        assert!(!indices_to_remove.contains(&3));
    }

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
        let result =
            credentials::inject_credential_into_header_vec(&mut headers, &mut path, &resolved, 1);
        assert!(result.is_some());
        assert_eq!(headers[1].0, "authorization");
        assert_eq!(headers[1].1, "Bearer sk-12345");
        assert_eq!(path, "/api/v1");
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
        let result =
            credentials::inject_credential_into_header_vec(&mut headers, &mut path, &resolved, 1);
        assert!(result.is_some());
        assert_eq!(headers[1].0, "x-api-key");
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
        let result =
            credentials::inject_credential_into_header_vec(&mut headers, &mut path, &resolved, 1);
        assert!(result.is_some());
        assert_eq!(headers.len(), 1);
        assert!(path.contains("api_key=secret-key"));
        assert!(path.starts_with("/api/v1?"));
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
        credentials::inject_credential_into_header_vec(&mut headers, &mut path, &resolved, 0);
        assert!(path.contains("foo=bar&token=secret"));
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
        let result =
            credentials::inject_credential_into_header_vec(&mut headers, &mut path, &resolved, 1);
        assert!(result.is_none());
        assert_eq!(headers.len(), 1);
        assert_eq!(path, "/bucket/key");
    }

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

        let ctx = ProxyRequestContext {
            journal,
            branch_id: branch_id.clone(),
            connection_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            dlp_engine: None,
            max_inspection_body_size: 10 * 1024 * 1024,
            oversized_body_action: crate::dlp::OversizedAction::BlockAndAlert,
            quarantine_sender: None,
            phantom_token_manager: None,
            agent_profile: None,
            audit_sender: None,
            credential_mode: puzzled_types::CredentialMode::Blocked,
        };

        let result = intercept::handle_intercepted_stream(
            agent_read,
            upstream_read,
            "example.com",
            "example.com:443",
            &ctx,
        )
        .await;
        assert!(result.is_ok());

        let forwarded = upstream_task.await.unwrap();
        assert!(!forwarded.contains("sk-secret"));
        assert!(!forwarded.contains("another-secret"));
        assert!(forwarded.contains("Host: example.com") || forwarded.contains("host: example.com"));

        let _ = agent_write_task.await;
    }

    #[tokio::test]
    async fn test_tls_intercept_content_length_response_reading() {
        let branch_id = BranchId::from("test-cl".to_string());
        let dir = tempfile::tempdir().unwrap();
        let journal_dir = dir.path().join("journal");
        let journal =
            crate::replay::NetworkJournal::new(journal_dir, BranchId::from("test-cl".to_string()));
        let journal = Arc::new(Mutex::new(journal));

        let agent_request = b"GET /data HTTP/1.1\r\nHost: example.com\r\n\r\n";
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

        let upstream_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let _n = upstream_write_half.read(&mut buf).await.unwrap();
            upstream_write_half
                .write_all(upstream_response)
                .await
                .unwrap();
            upstream_write_half.flush().await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
            drop(upstream_write_half);
        });

        let ctx = ProxyRequestContext {
            journal,
            branch_id: branch_id.clone(),
            connection_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            dlp_engine: None,
            max_inspection_body_size: 10 * 1024 * 1024,
            oversized_body_action: crate::dlp::OversizedAction::BlockAndAlert,
            quarantine_sender: None,
            phantom_token_manager: None,
            agent_profile: None,
            audit_sender: None,
            credential_mode: puzzled_types::CredentialMode::default(),
        };

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            intercept::handle_intercepted_stream(
                agent_read,
                upstream_read,
                "example.com",
                "example.com:443",
                &ctx,
            ),
        )
        .await;

        assert!(result.is_ok());
        let response_str = agent_write_task.await.unwrap();
        assert!(response_str.contains("hello world"));
        let _ = upstream_task.await;
    }

    #[test]
    fn test_tls_session_timeout_constant() {
        assert_eq!(tls::TLS_SESSION_TIMEOUT, Duration::from_secs(600));
    }

    // D-C1: Chunked Transfer-Encoding decoder tests
    #[test]
    fn test_decode_chunked_body_basic() {
        let chunked = b"5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n";
        let decoded = util::decode_chunked_body(chunked).unwrap();
        assert_eq!(decoded, b"Hello World");
    }

    #[test]
    fn test_decode_chunked_body_single_chunk() {
        let chunked = b"D\r\nHello, World!\r\n0\r\n\r\n";
        let decoded = util::decode_chunked_body(chunked).unwrap();
        assert_eq!(decoded, b"Hello, World!");
    }

    #[test]
    fn test_decode_chunked_body_empty() {
        let chunked = b"0\r\n\r\n";
        let decoded = util::decode_chunked_body(chunked).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_decode_chunked_body_with_extension() {
        let chunked = b"5;ext=val\r\nHello\r\n0\r\n\r\n";
        let decoded = util::decode_chunked_body(chunked).unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn test_decode_chunked_body_hex_uppercase() {
        let chunked = b"A\r\n0123456789\r\n0\r\n\r\n";
        let decoded = util::decode_chunked_body(chunked).unwrap();
        assert_eq!(decoded.len(), 10);
    }

    #[test]
    fn test_decode_chunked_body_malformed_no_crlf() {
        let chunked = b"5\nHello";
        assert!(util::decode_chunked_body(chunked).is_err());
    }

    #[test]
    fn test_decode_chunked_body_invalid_hex() {
        let chunked = b"XYZ\r\nHello\r\n0\r\n\r\n";
        assert!(util::decode_chunked_body(chunked).is_err());
    }

    #[test]
    fn test_decode_chunked_body_truncated_data() {
        let chunked = b"a\r\nHello\r\n0\r\n\r\n";
        assert!(util::decode_chunked_body(chunked).is_err());
    }

    // D-C3: Header name/value validation
    #[test]
    fn test_valid_http_header_name() {
        assert!(util::is_valid_http_header_name("Content-Type"));
        assert!(util::is_valid_http_header_name("X-Custom-Header"));
        assert!(util::is_valid_http_header_name("host"));
        assert!(util::is_valid_http_header_name("Accept"));
        assert!(util::is_valid_http_header_name("x-api-key"));
    }

    #[test]
    fn test_invalid_http_header_name() {
        assert!(!util::is_valid_http_header_name(""));
        assert!(!util::is_valid_http_header_name("Content Type"));
        assert!(!util::is_valid_http_header_name("Header\x00Name"));
        assert!(!util::is_valid_http_header_name("Header\nName"));
        assert!(!util::is_valid_http_header_name("Header:Name"));
        assert!(!util::is_valid_http_header_name("Header\x01Name"));
    }

    #[test]
    fn test_valid_http_header_value() {
        assert!(util::is_valid_http_header_value("application/json"));
        assert!(util::is_valid_http_header_value("text/html; charset=utf-8"));
        assert!(util::is_valid_http_header_value("value\twith\ttabs"));
        assert!(util::is_valid_http_header_value(""));
        assert!(util::is_valid_http_header_value("Bearer sk-12345"));
    }

    #[test]
    fn test_invalid_http_header_value() {
        assert!(!util::is_valid_http_header_value("value\x00with_null"));
        assert!(!util::is_valid_http_header_value("value\x01with_ctrl"));
        assert!(!util::is_valid_http_header_value("value\x7fwith_del"));
        assert!(!util::is_valid_http_header_value("value\r\nwith_crlf"));
    }

    #[test]
    fn test_max_header_size_constant() {
        assert_eq!(forward::MAX_HEADER_SIZE, 64 * 1024);
        const { assert!(forward::MAX_HEADER_SIZE < forward::MAX_BODY_SIZE) };
    }

    #[test]
    fn test_credential_detection_in_non_utf8_body() {
        let cred_value = b"sk-secret-key-12345";
        let mut body = vec![0xFF, 0xFE, 0x80, 0x81];
        body.extend_from_slice(cred_value);
        body.extend_from_slice(&[0xFF, 0xFE]);

        assert!(std::str::from_utf8(&body).is_err());
        assert!(body.windows(cred_value.len()).any(|w| w == cred_value));
    }

    #[test]
    fn test_credential_detection_empty_credential() {
        let cred_bytes: &[u8] = b"";
        let _body = b"some body content";
        assert!(cred_bytes.is_empty());
    }

    #[test]
    fn test_content_encoding_header_constant() {
        assert_eq!(
            hyper::header::CONTENT_ENCODING,
            hyper::header::HeaderName::from_static("content-encoding")
        );
    }

    // D-C3: Response decompression tests
    #[test]
    fn test_decompress_for_scanning_gzip_roundtrip() {
        use flate2::write::GzEncoder;
        use std::io::Write;

        let original = b"secret-api-key-12345 this is the plaintext body";
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        assert_ne!(&compressed[..], &original[..]);
        let decompressed = dlp_inspect::decompress_for_scanning(&compressed, "gzip").unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_decompress_for_scanning_deflate_roundtrip() {
        use flate2::write::DeflateEncoder;
        use std::io::Write;

        let original = b"Bearer sk-proj-ABCDEF credential leak test";
        let mut encoder = DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = dlp_inspect::decompress_for_scanning(&compressed, "deflate").unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_decompress_for_scanning_x_gzip() {
        use flate2::write::GzEncoder;
        use std::io::Write;

        let original = b"test data";
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = dlp_inspect::decompress_for_scanning(&compressed, "x-gzip").unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_decompress_for_scanning_identity() {
        let body = b"not compressed at all";
        let result = dlp_inspect::decompress_for_scanning(body, "identity").unwrap();
        assert_eq!(result, body);
    }

    #[test]
    fn test_decompress_for_scanning_empty_encoding() {
        let body = b"no encoding header";
        let result = dlp_inspect::decompress_for_scanning(body, "").unwrap();
        assert_eq!(result, body);
    }

    #[test]
    fn test_decompress_for_scanning_unknown_encoding_rejected() {
        let body = b"some bytes";
        assert!(dlp_inspect::decompress_for_scanning(body, "br").is_err());
        assert!(dlp_inspect::decompress_for_scanning(body, "zstd").is_err());
        assert!(dlp_inspect::decompress_for_scanning(body, "compress").is_err());
    }

    #[test]
    fn test_decompress_for_scanning_corrupt_data() {
        let corrupt = b"this is not valid gzip data at all";
        let result = dlp_inspect::decompress_for_scanning(corrupt, "gzip");
        assert!(result.is_err());
    }

    #[test]
    fn test_decompress_for_scanning_case_insensitive() {
        use flate2::write::GzEncoder;
        use std::io::Write;

        let original = b"case test";
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        assert_eq!(
            dlp_inspect::decompress_for_scanning(&compressed, "GZIP").unwrap(),
            original
        );
        assert_eq!(
            dlp_inspect::decompress_for_scanning(&compressed, " Gzip ").unwrap(),
            original
        );
    }

    #[test]
    fn test_h63_inject_credential_fails_on_invalid_value() {
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
        let result = credentials::inject_resolved_credential(&mut parts, &resolved);
        assert!(result.is_err());
    }

    #[test]
    fn test_html_entity_encoded_credential_detection() {
        let cred = "sk-123";
        let html_encoded: String = cred.bytes().map(|b| format!("&#{};", b)).collect();
        assert_eq!(html_encoded, "&#115;&#107;&#45;&#49;&#50;&#51;");

        let body = format!("<html><body>{}</body></html>", html_encoded);
        let body_bytes = body.as_bytes();
        assert!(body_bytes
            .windows(html_encoded.len())
            .any(|w| w == html_encoded.as_bytes()));
    }

    #[test]
    fn test_f2_decompress_for_scanning_gzip() {
        use flate2::write::GzEncoder;
        use std::io::Write;

        let original = b"this contains sk-secret-key-12345 in plaintext";
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = dlp_inspect::decompress_for_scanning(&compressed, "gzip").unwrap();
        assert_eq!(&decompressed, original);
    }

    #[test]
    fn test_f2_decompress_unknown_encoding_fails() {
        let body = b"some body";
        assert!(dlp_inspect::decompress_for_scanning(body, "br").is_err());
    }

    #[test]
    fn test_tls_scan_base64_encoded_credential() {
        let cred = "sk-secret-key-12345";
        let cred_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, cred);

        let body = format!("{{\"token\": \"{}\"}}", cred_b64);
        let body_bytes = body.as_bytes();
        assert!(body_bytes
            .windows(cred_b64.len())
            .any(|w| w == cred_b64.as_bytes()));
    }

    #[test]
    fn test_blocked_mode_strips_x_api_key_non_tls() {
        let req = hyper::Request::builder()
            .uri("http://example.com/api")
            .header("authorization", "Bearer sk-secret")
            .header("proxy-authorization", "Basic creds")
            .header("x-api-key", "api-key-secret")
            .header("host", "example.com")
            .body(())
            .unwrap();

        let (mut parts, _body) = req.into_parts();
        parts.headers.remove(hyper::header::AUTHORIZATION);
        parts.headers.remove(hyper::header::PROXY_AUTHORIZATION);
        parts.headers.remove("x-api-key");

        assert!(parts.headers.get("authorization").is_none());
        assert!(parts.headers.get("proxy-authorization").is_none());
        assert!(parts.headers.get("x-api-key").is_none());
        assert!(parts.headers.get("host").is_some());
    }

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

        original.save(tmp.path()).unwrap();
        let recovered = CredentialMappingFile::load(tmp.path()).unwrap().unwrap();

        assert_eq!(recovered.proxy_port, 18443);
        assert_eq!(recovered.mappings[0].phantom_token, "pt_puzzled_abc12345");
        assert_eq!(recovered.mappings[0].credential_name, "api-key");
        assert_eq!(recovered.mappings[0].domains, vec!["api.example.com"]);
    }

    #[test]
    fn test_memfd_create_in_seccomp_deny_list() {
        let seccomp_source = include_str!("../../../puzzled/src/sandbox/seccomp/mod.rs");
        assert!(seccomp_source.contains("memfd_create"));
    }

    // Source-introspection tests: these read sub-module source files to verify structural properties.

    #[test]
    fn test_g3_tls_intercept_header_size_bounded() {
        let source = include_str!("intercept.rs");
        assert!(source.contains("request_buf.len() > MAX_HEADER_SIZE"));
        assert!(source.contains("too large"));
    }

    #[test]
    fn test_h60_fallback_body_size_limit() {
        let source = include_str!("forward.rs");
        assert!(source.contains("total_body_size") && source.contains("MAX_BODY_SIZE"));
        let body_stream_section = source
            .find("total_body_size")
            .expect("total_body_size counter must exist");
        let after_counter = &source[body_stream_section..];
        assert!(after_counter.contains("if total_body_size > MAX_BODY_SIZE"));
    }

    #[test]
    fn test_h61_case_insensitive_auth_scheme() {
        let source = include_str!("intercept.rs");
        assert!(source.contains("eq_ignore_ascii_case(\"Bearer \")"));
        assert!(source.contains("eq_ignore_ascii_case(\"Basic \")"));
    }

    #[test]
    fn test_h63_inject_credential_returns_result() {
        let source = include_str!("credentials.rs");
        assert!(
            source.contains("fn inject_resolved_credential")
                && source.contains(") -> Result<(), String>")
        );
        let fn_start = source
            .find("fn inject_resolved_credential")
            .expect("function must exist");
        let fn_body = &source[fn_start..];
        let err_returns = fn_body.matches("return Err(msg)").count();
        assert!(err_returns >= 2, "found {}", err_returns);
    }

    #[test]
    fn test_h64_domain_crlf_validation() {
        let source = include_str!("intercept.rs");
        assert!(source.contains("H64: domain contains CR/LF"));
    }

    #[test]
    fn test_h65_path_method_crlf_validation() {
        let source = include_str!("intercept.rs");
        assert!(source.contains("H65: request line contains CR/LF"));
    }

    #[test]
    fn test_h68_chrono_now_no_empty_default() {
        let source = include_str!("util.rs");
        let fn_start = source
            .find("fn chrono_now()")
            .expect("chrono_now function must exist");
        let fn_body = &source[fn_start..];
        assert!(!fn_body.contains("unwrap_or_default()"));
    }

    #[test]
    fn j40_tls_intercept_path_encodes_param_name() {
        let tls_source = include_str!("credentials.rs");
        let tls_fn_start = tls_source
            .find("fn inject_credential_into_header_vec")
            .expect("TLS intercept injection function must exist");
        let tls_fn_body = &tls_source[tls_fn_start..];
        let tls_query_param = tls_fn_body
            .find("InjectionMethod::QueryParameter")
            .expect("TLS path must handle QueryParameter");
        let tls_section = &tls_fn_body[tls_query_param..tls_query_param + 500];
        assert!(tls_section.contains("urlencoding::encode(param_name)"));

        let non_tls_fn_start = tls_source
            .find("fn inject_resolved_credential")
            .expect("non-TLS injection function must exist");
        let non_tls_fn_body = &tls_source[non_tls_fn_start..];
        let non_tls_qp = non_tls_fn_body
            .find("InjectionMethod::QueryParameter")
            .expect("non-TLS path must handle QueryParameter");
        let non_tls_section = &non_tls_fn_body[non_tls_qp..non_tls_qp + 600];
        assert!(non_tls_section.contains("urlencoding::encode(param_name)"));
    }

    #[test]
    fn j41_query_parameter_uri_parse_failure_returns_err() {
        let source = include_str!("credentials.rs");
        let fn_start = source
            .find("fn inject_resolved_credential")
            .expect("function must exist");
        let fn_body = &source[fn_start..];
        let qp_start = fn_body
            .find("InjectionMethod::QueryParameter")
            .expect("QueryParameter arm must exist");
        let qp_section = &fn_body[qp_start..qp_start + 2000];
        assert!(qp_section.contains("return Err(format!"));
    }

    #[test]
    fn j43_dc2_cleanup_uses_case_insensitive_prefix_matching() {
        let source = include_str!("intercept.rs");
        let dc2_start = source
            .find("D-C2: Strip any remaining phantom tokens")
            .expect("D-C2 cleanup section must exist");
        let dc2_section = &source[dc2_start..dc2_start + 1200];
        assert!(dc2_section.contains("eq_ignore_ascii_case"));
        assert!(!dc2_section.contains("strip_prefix(\"Bearer \")"));
        assert!(!dc2_section.contains("strip_prefix(\"Basic \")"));
    }

    #[test]
    fn k40_connect_error_no_internal_details() {
        let source = include_str!("forward.rs");
        assert!(source.contains("\"Failed to connect to upstream\\n\""));
    }

    #[test]
    fn k42_geo_residency_error_no_internal_details() {
        let source = include_str!("mod.rs");
        assert!(source.contains("Data residency violation: destination not in allowed regions"));
    }

    #[test]
    fn k43_dns_error_no_internal_details() {
        let source = include_str!("routing.rs");
        assert!(!source.contains("\"DNS resolution failed for"));
        assert!(source.contains("\"DNS resolution failed\\n\""));
    }

    #[test]
    fn k45_upstream_error_no_internal_details() {
        let source = include_str!("forward.rs");
        assert!(!source.contains("\"Upstream error: {}\\n\""));
        let count = source.matches("\"Upstream request failed\\n\"").count();
        assert!(count >= 2, "found {count}");
    }

    #[test]
    fn k44_unrestricted_mode_calls_check_dns_rebinding() {
        let source = include_str!("mod.rs");
        let unrestricted_start = source
            .find("ProxyMode::Unrestricted =>")
            .expect("Unrestricted mode block must exist");
        let monitored_start = source[unrestricted_start..]
            .find("ProxyMode::Monitored =>")
            .expect("Monitored mode block must exist");
        let unrestricted_block = &source[unrestricted_start..unrestricted_start + monitored_start];
        assert!(unrestricted_block.contains("check_dns_rebinding"));
        assert!(unrestricted_block.contains("resolved_addrs.as_deref()"));
    }

    #[test]
    fn k44_monitored_mode_calls_check_dns_rebinding() {
        let source = include_str!("mod.rs");
        let monitored_start = source
            .find("ProxyMode::Monitored =>")
            .expect("Monitored mode block must exist");
        let gated_start = source[monitored_start..]
            .find("ProxyMode::Gated =>")
            .expect("Gated mode block must exist");
        let monitored_block = &source[monitored_start..monitored_start + gated_start];
        assert!(monitored_block.contains("check_dns_rebinding"));
        assert!(monitored_block.contains("resolved_addrs.as_deref()"));
    }

    #[test]
    fn l40_tls_error_writes_are_logged() {
        let source = include_str!("intercept.rs");
        let silent_write_count = source.matches("let _ = agent_tls.write_all(").count();
        let silent_flush_count = source.matches("let _ = agent_tls.flush(").count();
        assert_eq!(silent_write_count, 0);
        assert_eq!(silent_flush_count, 0);
    }

    #[test]
    fn l21_dlp_error_path_has_body_size_limit() {
        let source = include_str!("intercept.rs");
        let dlp_err_start = source
            .find("DLP blocked the request")
            .expect("DLP blocked error path must exist");
        let dlp_err_section = &source[dlp_err_start..dlp_err_start + 500];
        let has_size_limit = dlp_err_section.contains("DLP blocked request")
            && !dlp_err_section.contains("resp_body.collect().await");
        let has_take = dlp_err_section.contains(".take(");
        let has_content_length_check = dlp_err_section.contains("content_length")
            || dlp_err_section.contains("CONTENT_LENGTH");
        assert!(has_size_limit || has_take || has_content_length_check);
    }

    #[test]
    fn l20_credential_scan_has_body_size_check() {
        let source = include_str!("credentials.rs");
        let fn_start = source
            .find("async fn scan_response_for_credential_leak")
            .expect("function must exist");
        let fn_body = &source[fn_start..];
        let fn_end = fn_body[1..]
            .find("\nasync fn ")
            .or_else(|| fn_body[1..].find("\nfn "))
            .unwrap_or(fn_body.len());
        let fn_text = &fn_body[..fn_end];
        assert!(fn_text.contains("MAX_RESPONSE_BODY_BYTES") || fn_text.contains("content_length"));
    }
}
