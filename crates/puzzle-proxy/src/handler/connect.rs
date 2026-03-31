// SPDX-License-Identifier: Apache-2.0
//! CONNECT tunnel handler for HTTPS passthrough.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};
use puzzled_types::BranchId;
use tokio::io::AsyncReadExt;

use super::forward::connect_upstream;
use super::{BoxBody, MAX_TUNNEL_BYTES, REQUEST_TIMEOUT};

/// Handle a CONNECT request (HTTPS tunneling via TLS passthrough).
///
/// C9: Establishes a TCP connection to the target host, sends "200 Connection Established"
/// back to the client, then relays bytes bidirectionally between client and upstream.
/// H7: Applies connect timeout and total tunnel timeout.
pub(super) async fn handle_connect(
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
