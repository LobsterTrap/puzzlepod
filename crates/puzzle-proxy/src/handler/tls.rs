// SPDX-License-Identifier: Apache-2.0
//! TLS MITM interception: leaf cert issuance, TLS accept/connect.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::tls::AgentCa;

use super::forward::connect_upstream;
use super::intercept::handle_intercepted_stream;
use super::BoxBody;
use super::ProxyRequestContext;

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
pub(super) async fn handle_tls_intercept(
    req: Request<hyper::body::Incoming>,
    ca: &AgentCa,
    resolved_addrs: Option<&[std::net::SocketAddr]>,
    ctx: &ProxyRequestContext,
) -> Result<Response<BoxBody>, hyper::Error> {
    let branch_id = &ctx.branch_id;

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

    // Clone context for the spawned task
    let ctx = ctx.clone();
    let domain_clone = domain.clone();
    let target_port_clone = target_with_port.clone();

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
            &domain_clone,
            &target_port_clone,
            &ctx,
        )
        .await
        {
            tracing::error!(
                branch = %ctx.branch_id,
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
pub(super) fn build_tls_acceptor(
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
pub(super) async fn connect_upstream_tls(
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
pub(super) const TLS_SESSION_TIMEOUT: Duration = Duration::from_secs(600);
