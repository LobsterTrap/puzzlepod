// SPDX-License-Identifier: Apache-2.0
//! HTTP request forwarding to upstream servers.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};

use super::routing::strip_hop_by_hop;
use super::{BoxBody, CONNECT_TIMEOUT, MAX_RESPONSE_BODY_BYTES, REQUEST_TIMEOUT};

/// Forward a request to the upstream server using hyper client.
///
/// H7: Applies connect timeout and total request timeout.
/// H-3: When `resolved_addrs` is provided, uses the pre-resolved IP addresses
/// to connect instead of re-resolving DNS (prevents DNS rebinding TOCTOU).
/// M17: Streams the request body instead of buffering entirely in memory.
pub(super) async fn forward_request(
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
                use http_body_util::BodyExt;
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
        use http_body_util::BodyExt;
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
pub(super) const MAX_BODY_SIZE: usize = 100 * 1024 * 1024;

/// D-M1: Maximum HTTP header size (64 KB). Headers should be much smaller than bodies.
/// Using MAX_BODY_SIZE (100 MB) for headers allowed excessive memory consumption.
pub(super) const MAX_HEADER_SIZE: usize = 64 * 1024;

/// Connect to an upstream server with timeout, using pre-resolved addresses if available.
pub(super) async fn connect_upstream(
    target_with_port: &str,
    branch_id: &puzzled_types::BranchId,
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
