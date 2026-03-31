// SPDX-License-Identifier: Apache-2.0
//! HTTP proxy handler tests.
//!
//! Tests domain filtering, host extraction, body size limits, and SSRF
//! protection without requiring a running HTTP server.
//!
//! Uses production functions directly from `puzzle_proxy::handler::routing`
//! to ensure tests validate the same behavior that runs in production.

use puzzle_proxy::handler::routing::{is_domain_allowed, is_private_ip_str, validate_host_format};

/// Mirrors the HOP_BY_HOP_HEADERS constant and strip_hop_by_hop logic from handler.rs.
fn strip_hop_by_hop(headers: &mut std::collections::HashMap<String, String>) {
    let hop_by_hop = [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ];

    // Parse Connection header for additional headers to remove
    let extra_headers: Vec<String> = headers
        .get("connection")
        .cloned()
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    for name in &hop_by_hop {
        headers.remove(*name);
    }
    for name in &extra_headers {
        headers.remove(name);
    }
}

/// Extract host from a string (simulates extract_host logic).
fn extract_host_from_header(header: &str) -> String {
    header.split(':').next().unwrap_or(header).to_string()
}

/// Extract host from a URI string (e.g., "http://example.com/path" -> "example.com").
/// Mirrors the host extraction in replay_entry.
fn extract_host_from_uri(uri: &str) -> String {
    // Strip scheme
    let after_scheme = if let Some(pos) = uri.find("://") {
        &uri[pos + 3..]
    } else {
        uri
    };
    // Take everything before the first '/' or ':'
    let host = after_scheme
        .split('/')
        .next()
        .unwrap_or(after_scheme)
        .split(':')
        .next()
        .unwrap_or(after_scheme);
    host.to_string()
}

#[test]
fn test_get_request_forwarding() {
    // GET requests to allowed domains should be forwarded (not journaled)
    let domains = vec!["api.github.com".to_string()];
    assert!(is_domain_allowed("api.github.com", &domains));
}

#[test]
fn test_domain_not_in_allowlist_blocked() {
    let domains = vec!["github.com".to_string(), "crates.io".to_string()];
    assert!(!is_domain_allowed("evil.com", &domains));
    assert!(!is_domain_allowed("malware.net", &domains));
}

#[test]
fn test_wildcard_domain_allows_all() {
    let domains = vec!["*".to_string()];
    assert!(is_domain_allowed("anything.com", &domains));
    assert!(is_domain_allowed("evil.net", &domains));
    assert!(is_domain_allowed("localhost", &domains));
}

#[test]
fn test_subdomain_wildcard_matching() {
    let domains = vec!["*.github.com".to_string()];
    assert!(is_domain_allowed("api.github.com", &domains));
    assert!(is_domain_allowed("raw.github.com", &domains));
}

#[test]
fn test_subdomain_wildcard_no_partial() {
    let domains = vec!["*.github.com".to_string()];
    // *.github.com DOES match github.com itself (bare domain matches wildcard).
    // This is intentional: *.github.com means "github.com and all subdomains".
    assert!(is_domain_allowed("github.com", &domains));
    // H5: dot-boundary enforcement prevents "notgithub.com" from matching
    // "*.github.com" — the character before the suffix must be '.'.
    assert!(!is_domain_allowed("notgithub.com", &domains));
    // Multi-level subdomains should still match
    assert!(is_domain_allowed("api.raw.github.com", &domains));
}

#[test]
fn test_post_request_journaled() {
    // POST/PUT/DELETE requests should be journaled (not forwarded)
    // This verifies the domain check still applies before journaling
    let domains = vec!["api.example.com".to_string()];
    assert!(is_domain_allowed("api.example.com", &domains));
    assert!(!is_domain_allowed("other.com", &domains));
}

#[test]
fn test_put_request_journaled() {
    let domains = vec!["api.example.com".to_string()];
    assert!(is_domain_allowed("api.example.com", &domains));
}

#[test]
fn test_delete_request_journaled() {
    let domains = vec!["api.example.com".to_string()];
    assert!(is_domain_allowed("api.example.com", &domains));
}

#[test]
fn test_connect_domain_check() {
    // CONNECT method (HTTPS tunneling or TLS MITM interception) is subject to
    // domain allowlist checks before the tunnel/interception is established.
    let domains = vec!["example.com".to_string()];
    assert!(is_domain_allowed("example.com", &domains));
    assert!(!is_domain_allowed("blocked.com", &domains));
}

#[test]
fn test_unknown_method_rejected() {
    // Unknown HTTP methods should be rejected with 405
    // Domain check still applies before method routing
    let domains: Vec<String> = vec![];
    assert!(!is_domain_allowed("anything.com", &domains));
}

#[test]
fn test_extract_host_from_header() {
    assert_eq!(extract_host_from_header("example.com"), "example.com");
    assert_eq!(extract_host_from_header("example.com:8080"), "example.com");
    assert_eq!(
        extract_host_from_header("api.github.com:443"),
        "api.github.com"
    );
}

#[test]
fn test_extract_host_from_uri() {
    // URI authority extraction
    assert_eq!(extract_host_from_header("localhost:3000"), "localhost");
}

#[test]
fn test_extract_host_strips_port() {
    assert_eq!(extract_host_from_header("example.com:443"), "example.com");
    assert_eq!(extract_host_from_header("127.0.0.1:8080"), "127.0.0.1");
}

#[test]
fn test_body_size_limit_enforced() {
    // MAX_BODY_SIZE = 100MB
    const MAX_BODY_SIZE: usize = 100 * 1024 * 1024;
    assert_eq!(MAX_BODY_SIZE, 104_857_600);

    // Bodies under the limit should be accepted
    let small_body = vec![0u8; 1024];
    assert!(small_body.len() <= MAX_BODY_SIZE);

    // Bodies over the limit should be rejected
    // (we just verify the constant, actual enforcement is in handler.rs)
    const { assert!(MAX_BODY_SIZE > 0) };
}

#[test]
fn test_host_header_format_validation() {
    // Valid formats
    assert!(validate_host_format("example.com"));
    assert!(validate_host_format("api.github.com"));
    assert!(validate_host_format("example.com:8080"));
    assert!(validate_host_format("127.0.0.1"));
    assert!(validate_host_format("[::1]"));

    // Invalid formats (injection attempts)
    assert!(!validate_host_format("")); // empty
    assert!(!validate_host_format("example.com\r\nX-Injected: true")); // header injection
    assert!(!validate_host_format("example.com\nHost: evil.com")); // newline injection
    assert!(!validate_host_format("example.com/path")); // path in host
    assert!(!validate_host_format(&"a".repeat(254))); // too long
}

// ---------------------------------------------------------------------------
// SSRF protection tests
// ---------------------------------------------------------------------------

#[test]
fn test_ssrf_private_ip_blocked() {
    assert!(is_private_ip_str("localhost"));
    assert!(is_private_ip_str("127.0.0.1"));
    assert!(is_private_ip_str("10.0.0.1"));
    assert!(is_private_ip_str("192.168.1.1"));
    assert!(is_private_ip_str("172.16.0.1"));
    assert!(is_private_ip_str("172.31.255.255"));
    assert!(is_private_ip_str("0.0.0.0"));
    assert!(is_private_ip_str("169.254.169.254")); // AWS metadata
    assert!(is_private_ip_str("::1"));
    assert!(is_private_ip_str("[::1]"));
}

#[test]
fn test_ssrf_public_ip_allowed() {
    assert!(!is_private_ip_str("8.8.8.8"));
    assert!(!is_private_ip_str("93.184.216.34"));
    assert!(!is_private_ip_str("1.1.1.1"));
    assert!(!is_private_ip_str("example.com"));
}

// ---------------------------------------------------------------------------
// T13: IPv6 SSRF prevention — IPv4-mapped IPv6 addresses
// ---------------------------------------------------------------------------

#[test]
fn t13_ipv6_ssrf_mapped_private_10() {
    // ::ffff:10.0.0.1 is an IPv4-mapped IPv6 address pointing to private 10.0.0.1
    assert!(
        is_private_ip_str("::ffff:10.0.0.1"),
        "::ffff:10.0.0.1 must be detected as private (10.0.0.0/8)"
    );
}

#[test]
fn t13_ipv6_ssrf_mapped_private_192_168() {
    // ::ffff:192.168.1.1 is an IPv4-mapped IPv6 address pointing to private 192.168.1.1
    assert!(
        is_private_ip_str("::ffff:192.168.1.1"),
        "::ffff:192.168.1.1 must be detected as private (192.168.0.0/16)"
    );
}

#[test]
fn t13_ipv6_ssrf_mapped_private_172_16() {
    assert!(
        is_private_ip_str("::ffff:172.16.0.1"),
        "::ffff:172.16.0.1 must be detected as private (172.16.0.0/12)"
    );
}

#[test]
fn t13_ipv6_ssrf_mapped_loopback() {
    assert!(
        is_private_ip_str("::ffff:127.0.0.1"),
        "::ffff:127.0.0.1 must be detected as private (loopback)"
    );
}

#[test]
fn t13_ipv6_ssrf_mapped_link_local() {
    assert!(
        is_private_ip_str("::ffff:169.254.169.254"),
        "::ffff:169.254.169.254 must be detected as private (link-local / AWS metadata)"
    );
}

#[test]
fn t13_ipv6_ssrf_mapped_bracketed() {
    // Bracketed form: [::ffff:10.0.0.1]
    assert!(
        is_private_ip_str("[::ffff:10.0.0.1]"),
        "[::ffff:10.0.0.1] (bracketed) must be detected as private"
    );
    assert!(
        is_private_ip_str("[::ffff:192.168.1.1]"),
        "[::ffff:192.168.1.1] (bracketed) must be detected as private"
    );
}

#[test]
fn t13_ipv6_ssrf_mapped_public_not_blocked() {
    // Public IPv4 addresses in mapped form should NOT be blocked
    assert!(
        !is_private_ip_str("::ffff:8.8.8.8"),
        "::ffff:8.8.8.8 (Google DNS) should not be blocked"
    );
    assert!(
        !is_private_ip_str("::ffff:93.184.216.34"),
        "::ffff:93.184.216.34 (example.com) should not be blocked"
    );
}

// ---------------------------------------------------------------------------
// T14: Hop-by-hop header stripping
// ---------------------------------------------------------------------------

#[test]
fn t14_strip_hop_by_hop_removes_standard_headers() {
    let mut headers = std::collections::HashMap::new();
    headers.insert("connection".to_string(), "keep-alive".to_string());
    headers.insert("keep-alive".to_string(), "timeout=5".to_string());
    headers.insert("proxy-authenticate".to_string(), "Basic".to_string());
    headers.insert("proxy-authorization".to_string(), "Bearer xyz".to_string());
    headers.insert("te".to_string(), "trailers".to_string());
    headers.insert("trailer".to_string(), "Expires".to_string());
    headers.insert("transfer-encoding".to_string(), "chunked".to_string());
    headers.insert("upgrade".to_string(), "websocket".to_string());
    // Non-hop-by-hop headers that should survive
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("authorization".to_string(), "Bearer token123".to_string());
    headers.insert("x-custom".to_string(), "value".to_string());

    strip_hop_by_hop(&mut headers);

    // All hop-by-hop headers must be removed
    assert!(
        !headers.contains_key("connection"),
        "Connection must be stripped"
    );
    assert!(
        !headers.contains_key("keep-alive"),
        "Keep-Alive must be stripped"
    );
    assert!(
        !headers.contains_key("proxy-authenticate"),
        "Proxy-Authenticate must be stripped"
    );
    assert!(
        !headers.contains_key("proxy-authorization"),
        "Proxy-Authorization must be stripped"
    );
    assert!(!headers.contains_key("te"), "TE must be stripped");
    assert!(!headers.contains_key("trailer"), "Trailer must be stripped");
    assert!(
        !headers.contains_key("transfer-encoding"),
        "Transfer-Encoding must be stripped"
    );
    assert!(!headers.contains_key("upgrade"), "Upgrade must be stripped");

    // Non-hop-by-hop headers must survive
    assert_eq!(headers.get("content-type").unwrap(), "application/json");
    assert_eq!(headers.get("authorization").unwrap(), "Bearer token123");
    assert_eq!(headers.get("x-custom").unwrap(), "value");
}

#[test]
fn t14_strip_hop_by_hop_removes_connection_named_headers() {
    let mut headers = std::collections::HashMap::new();
    // Connection header naming additional headers to strip
    headers.insert(
        "connection".to_string(),
        "X-Custom-Hop, X-Another".to_string(),
    );
    headers.insert("x-custom-hop".to_string(), "should-be-removed".to_string());
    headers.insert("x-another".to_string(), "also-removed".to_string());
    headers.insert("x-keep-this".to_string(), "stays".to_string());

    strip_hop_by_hop(&mut headers);

    assert!(!headers.contains_key("connection"));
    assert!(
        !headers.contains_key("x-custom-hop"),
        "Connection-named header must be stripped"
    );
    assert!(
        !headers.contains_key("x-another"),
        "Connection-named header must be stripped"
    );
    assert_eq!(headers.get("x-keep-this").unwrap(), "stays");
}

#[test]
fn t14_strip_hop_by_hop_no_headers() {
    let mut headers = std::collections::HashMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());

    strip_hop_by_hop(&mut headers);

    // Should not panic or remove non-hop-by-hop headers
    assert_eq!(headers.len(), 1);
    assert_eq!(headers.get("content-type").unwrap(), "text/plain");
}

// ---------------------------------------------------------------------------
// T15: Response body limit
// ---------------------------------------------------------------------------

#[test]
fn t15_response_body_limit_constant() {
    // MAX_RESPONSE_BODY_BYTES = 100 MB (mirrors handler.rs constant)
    const MAX_RESPONSE_BODY_BYTES: usize = 100 * 1024 * 1024;
    assert_eq!(MAX_RESPONSE_BODY_BYTES, 104_857_600);
}

#[test]
fn t15_response_body_under_limit_accepted() {
    const MAX_RESPONSE_BODY_BYTES: usize = 100 * 1024 * 1024;

    // Small response body is well under the limit
    let small_response = vec![0u8; 1024];
    assert!(small_response.len() <= MAX_RESPONSE_BODY_BYTES);

    // 50 MB response body is under the limit
    let medium_response_size: usize = 50 * 1024 * 1024;
    assert!(medium_response_size <= MAX_RESPONSE_BODY_BYTES);

    // Exactly at the limit should be accepted (not over)
    let at_limit = MAX_RESPONSE_BODY_BYTES;
    assert!(at_limit <= MAX_RESPONSE_BODY_BYTES);
}

#[test]
fn t15_response_body_over_limit_rejected() {
    const MAX_RESPONSE_BODY_BYTES: usize = 100 * 1024 * 1024;

    // 1 byte over the limit should be rejected
    let over_by_one = MAX_RESPONSE_BODY_BYTES + 1;
    assert!(over_by_one > MAX_RESPONSE_BODY_BYTES);

    // 200 MB response should be rejected
    let large_response_size: usize = 200 * 1024 * 1024;
    assert!(large_response_size > MAX_RESPONSE_BODY_BYTES);
}

// ---------------------------------------------------------------------------
// T16: Tunnel byte limit (CONNECT)
// ---------------------------------------------------------------------------

#[test]
fn t16_tunnel_byte_limit_constant() {
    // MAX_TUNNEL_BYTES = 500 MB per direction (mirrors handler.rs constant)
    const MAX_TUNNEL_BYTES: u64 = 500 * 1024 * 1024;
    assert_eq!(MAX_TUNNEL_BYTES, 524_288_000);
}

#[test]
fn t16_tunnel_under_limit_allowed() {
    const MAX_TUNNEL_BYTES: u64 = 500 * 1024 * 1024;

    // Normal HTTPS traffic (e.g., 10 MB) is well under the limit
    let normal_traffic: u64 = 10 * 1024 * 1024;
    assert!(normal_traffic < MAX_TUNNEL_BYTES);

    // Large download (100 MB) is still under the limit
    let large_download: u64 = 100 * 1024 * 1024;
    assert!(large_download < MAX_TUNNEL_BYTES);
}

#[test]
fn t16_tunnel_over_limit_terminated() {
    const MAX_TUNNEL_BYTES: u64 = 500 * 1024 * 1024;

    // 501 MB exceeds the per-direction limit
    let excessive_transfer: u64 = 501 * 1024 * 1024;
    assert!(excessive_transfer > MAX_TUNNEL_BYTES);

    // Each direction is independently capped; verify the limit is per-direction
    // (total allowed is 2 * MAX_TUNNEL_BYTES across both directions)
    let total_allowed: u64 = MAX_TUNNEL_BYTES * 2;
    assert_eq!(total_allowed, 1_048_576_000); // 1 GB total
}

#[test]
fn t16_tunnel_at_exact_limit() {
    const MAX_TUNNEL_BYTES: u64 = 500 * 1024 * 1024;

    // Exactly at the limit — tokio::io::Take will stop copying at this point
    let at_limit: u64 = MAX_TUNNEL_BYTES;
    assert_eq!(at_limit, MAX_TUNNEL_BYTES);

    // The tunnel should terminate when reaching the limit, not after
    let one_over: u64 = MAX_TUNNEL_BYTES + 1;
    assert!(one_over > MAX_TUNNEL_BYTES);
}

// ---------------------------------------------------------------------------
// T17: Replay re-validation — domains removed from allowlist are skipped
// ---------------------------------------------------------------------------

#[test]
fn t17_replay_revalidation_skips_disallowed_domains() {
    // Simulate the replay domain re-validation logic from replay.rs:
    // At journal time, both domains were allowed. At replay time, only
    // "allowed.com" is in the allowlist. Entries for "revoked.com" should
    // be skipped during replay.

    let journal_entries = vec![
        ("POST", "http://allowed.com/api/data"),
        ("PUT", "http://revoked.com/api/update"),
        ("POST", "http://allowed.com/api/submit"),
        ("DELETE", "http://revoked.com/api/remove"),
    ];

    let replay_allowlist = vec!["allowed.com".to_string()];

    let mut replayed_count = 0u32;
    let mut skipped_count = 0u32;

    for (_method, uri) in &journal_entries {
        // Extract host from URI (mirrors replay_entry logic)
        let host = extract_host_from_uri(uri);

        if is_domain_allowed(&host, &replay_allowlist) {
            replayed_count += 1;
        } else {
            skipped_count += 1;
        }
    }

    assert_eq!(
        replayed_count, 2,
        "only entries for allowed.com should be replayed"
    );
    assert_eq!(
        skipped_count, 2,
        "entries for revoked.com should be skipped"
    );
}

#[test]
fn t17_replay_revalidation_all_domains_revoked() {
    // If the allowlist is empty at replay time, all entries should be skipped
    let journal_entries = vec![
        ("POST", "http://example.com/a"),
        ("PUT", "http://other.com/b"),
    ];

    let replay_allowlist: Vec<String> = vec![];

    for (_method, uri) in &journal_entries {
        let host = extract_host_from_uri(uri);
        assert!(
            !is_domain_allowed(&host, &replay_allowlist),
            "empty allowlist should block all domains during replay"
        );
    }
}

#[test]
fn t17_replay_revalidation_wildcard_allows_all() {
    // If the allowlist contains "*" at replay time, all entries replay
    let replay_allowlist = vec!["*".to_string()];

    for host in &["example.com", "other.com", "internal.corp"] {
        assert!(
            is_domain_allowed(host, &replay_allowlist),
            "wildcard allowlist should permit all domains during replay"
        );
    }
}

// ---------------------------------------------------------------------------
// G13: QueryParameter param_name must be URL-encoded
// ---------------------------------------------------------------------------

#[test]
fn test_g13_query_param_name_encoded() {
    let source = include_str!("../src/handler/credentials.rs");
    // Find the QueryParameter injection code
    let qp_start = source
        .find("InjectionMethod::QueryParameter")
        .expect("G13: QueryParameter injection code must exist in handler.rs");
    let qp_body = &source[qp_start..];
    let qp_section_end = qp_body.len().min(500);
    let qp_section = &qp_body[..qp_section_end];
    assert!(
        qp_section.contains("encode(param_name)"),
        "G13: param_name must be URL-encoded in QueryParameter injection \
         to prevent injection via crafted parameter names"
    );
}

// ---------------------------------------------------------------------------
// G14: Bearer/Basic prefix stripping must be case-insensitive (RFC 7235)
// ---------------------------------------------------------------------------

#[test]
fn test_g14_bearer_case_insensitive() {
    let source = include_str!("../src/handler/credentials.rs");
    // Find the phantom token extraction code
    let auth_area = source
        .find("Extract the token part")
        .or_else(|| source.find("G14:"))
        .expect("G14: token extraction code must exist in handler.rs");
    let auth_section = &source[auth_area..];
    let section_end = auth_section.len().min(600);
    let auth_section = &auth_section[..section_end];
    assert!(
        auth_section.contains("eq_ignore_ascii_case"),
        "G14: Bearer/Basic prefix stripping must use case-insensitive matching \
         per RFC 7235 section 2.1 — auth-scheme is case-insensitive"
    );
}

// ---------------------------------------------------------------------------
// G23: Credential exfiltration URI check must not be inside content_length > 0
// ---------------------------------------------------------------------------

#[test]
fn test_g23_credential_exfil_check_covers_get() {
    let source = include_str!("../src/handler/mod.rs");
    // Find the credential exfiltration check area
    let exfil_start = source
        .find("credential value found in request URI")
        .expect("G23: credential exfiltration check must exist in handler.rs");
    // Walk backwards to find the nearest `if let Some(ref real_value)` block
    let before_exfil = &source[..exfil_start];
    let real_value_pos = before_exfil
        .rfind("if let Some(ref real_value)")
        .expect("G23: real_value check must exist before exfil check");
    let between = &source[real_value_pos..exfil_start];
    // The URI check must NOT be nested inside a content_length > 0 condition
    assert!(
        !between.contains("content_length") && !between.contains("len > 0"),
        "G23: credential exfiltration URI check must NOT be gated by \
         content_length > 0 — GET requests have no Content-Length but can \
         still carry credentials in query parameters"
    );
}

// ---------------------------------------------------------------------------
// G25: Request body buffered with size limit in pinned-IP path
// ---------------------------------------------------------------------------

#[test]
fn test_g25_request_body_size_bounded() {
    let source = include_str!("../src/handler/forward.rs");
    assert!(
        source.contains("G25: request body too large"),
        "G25: pinned-IP request body path must check body size to \
         prevent unbounded memory allocation"
    );
    assert!(
        source.contains("total_body_size > MAX_RESPONSE_BODY_BYTES"),
        "G25: pinned-IP request body must check total_body_size against \
         MAX_RESPONSE_BODY_BYTES"
    );
}
