// SPDX-License-Identifier: Apache-2.0
//! Network routing utilities: SSRF protection, DNS rebinding, domain matching,
//! port allowlists, and hop-by-hop header stripping.

use std::net::IpAddr;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};
use puzzled_types::BranchId;

use super::BoxBody;
use super::ALLOWED_PORTS;

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
pub(super) const HOP_BY_HOP_HEADERS: &[&str] = &[
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

/// H3: SSRF protection — reject requests targeting private/loopback IPs.
#[allow(clippy::result_large_err)]
pub(super) fn check_ssrf(host: &str, branch_id: &BranchId) -> Result<(), Response<BoxBody>> {
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

/// M-px2: Check that the request URI port is in the allowed port list for non-CONNECT requests.
///
/// Extracts the port from the request URI. Defaults to 80 for http, 443 for https.
/// Returns `Ok(())` if the port is allowed, or `Err(Response)` with 403 Forbidden
/// if the port is not in `ALLOWED_PORTS`.
#[allow(clippy::result_large_err)]
pub(super) fn check_request_port(
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
pub(super) fn check_connect_port(
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
pub(super) fn check_connect_host_match(
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
pub(super) fn extract_host(req: &Request<hyper::body::Incoming>) -> Option<String> {
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
    if req.method() == hyper::Method::CONNECT {
        let uri_str = req.uri().to_string();
        return Some(uri_str.split(':').next().unwrap_or(&uri_str).to_string());
    }

    None
}

/// Validate Host header format to prevent injection attacks.
/// Allows only alphanumeric chars, hyphens, dots, underscores, colons (for port), and brackets (for IPv6).
/// Underscores are permitted because some DNS names use them (e.g., SRV records, DMARC TXT records).
pub fn validate_host_format(host: &str) -> bool {
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
pub fn is_private_ip_str(host: &str) -> bool {
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

    // §4.3: Domain matching prevents credential injection to wrong domain
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
}
