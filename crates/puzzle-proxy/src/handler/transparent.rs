// SPDX-License-Identifier: Apache-2.0
//! §3.4 G7: Transparent proxy mode — handle DNAT'd connections.

use std::sync::Arc;

use crate::tls::AgentCa;

use super::intercept::handle_intercepted_stream;
use super::tls::{build_tls_acceptor, connect_upstream_tls};
use super::ProxyRequestContext;

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
    ca: Arc<AgentCa>,
    ctx: ProxyRequestContext,
) {
    let branch_id = &ctx.branch_id;
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
    if let Err(e) =
        handle_intercepted_stream(agent_tls, upstream_tls, &domain, &target_with_port, &ctx).await
    {
        tracing::error!(
            branch = %branch_id,
            domain = %domain,
            error = %e,
            "§3.4 G7: transparent proxy stream handling failed"
        );
    }
}
