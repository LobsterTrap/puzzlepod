// SPDX-License-Identifier: Apache-2.0
//! HTTP proxy for PuzzlePod network gating.
//!
//! Provides application-layer network control for agent sandboxes in Gated mode:
//! - GET/HEAD requests: forwarded immediately if domain is in allowlist
//! - POST/PUT/DELETE/PATCH requests: serialized to network journal for replay at commit
//! - CONNECT tunneling: allowed with domain check (for HTTPS)
//!
//! Runs in-process within puzzled (not a separate binary).

pub mod credential_backends;
pub mod credential_persistence;
pub mod credentials;
pub mod dlp;
pub mod geo;
pub mod handler;
pub mod replay;
pub mod secure_memory;
pub mod systemd_creds_backend;
pub mod tls;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use puzzled_types::BranchId;
use tokio::sync::{Mutex, RwLock};

use crate::credentials::PhantomTokenManager;
use crate::dlp::DlpEngine;
use crate::tls::AgentCa;

/// Audit events emitted from the proxy handler back to puzzled.
///
/// The proxy crate cannot depend on puzzled's AuditEvent type, so this
/// lightweight enum carries the information needed for puzzled to emit
/// the corresponding structured audit event.
#[derive(Debug, Clone)]
pub enum ProxyAuditEvent {
    /// §3.3: DLP blocked a request or response (event 2616).
    DlpBlocked {
        branch_id: BranchId,
        rule_name: String,
        domain: String,
        match_hash: String,
    },
    /// §3.3: DLP detected but allowed (LogAndAllow) (event 2617).
    DlpDetected {
        branch_id: BranchId,
        rule_name: String,
        domain: String,
        match_hash: String,
    },
    /// §3.3: DLP redacted content (event 2618).
    DlpRedacted {
        branch_id: BranchId,
        rule_name: String,
        domain: String,
    },
    /// §3.3: DLP quarantined branch (event 2619).
    DlpQuarantine {
        branch_id: BranchId,
        rule_name: String,
        domain: String,
    },
    /// §3.4: Credential injected (event 2626).
    CredentialInjected {
        branch_id: BranchId,
        credential_name: String,
        domain: String,
    },
    /// §3.4: Credential denied (event 2627).
    CredentialDenied {
        branch_id: BranchId,
        credential_name: String,
        domain: String,
        reason: String,
    },
    /// §3.4 G29: Credential resolve failed.
    CredentialResolveFailed {
        branch_id: BranchId,
        credential_name: String,
        reason: String,
    },
    /// §3.4 G29: Real credential value detected in response body.
    CredentialResponseLeak { branch_id: BranchId, domain: String },
    /// §3.4 G29: Phantom token stripped from request headers.
    PhantomTokenStripped {
        branch_id: BranchId,
        header_name: String,
    },
    /// §3.4 T2.1: Credential resolved — D-Bus signal data for CredentialResolved.
    CredentialResolved {
        branch_id: BranchId,
        credential_name: String,
        domain: String,
    },
    /// §3.4 T2.2: Credential proxy error — D-Bus signal data for CredentialProxyError.
    CredentialProxyError {
        branch_id: BranchId,
        error: String,
        domain: String,
    },
}

/// Proxy operating mode per PRD network gating specification.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ProxyMode {
    /// Block all outbound network requests (403 for everything).
    Blocked,
    /// Gated mode: check allow/deny domain lists (default, current behavior).
    #[default]
    Gated,
    /// Monitored mode: log all requests but forward everything.
    Monitored,
    /// Unrestricted mode: forward all requests without logging.
    Unrestricted,
    /// §3.4 G7: Transparent mode — connections arrive via DNAT, hostname
    /// extracted from TLS SNI (not CONNECT). Used for credential isolation
    /// where agents should not know they are going through a proxy.
    Transparent,
}

/// Configuration for the proxy server.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Listen address.
    pub listen_addr: SocketAddr,
    /// Allowed domains for read operations (GET/HEAD/OPTIONS).
    pub read_allowed_domains: Vec<String>,
    /// Allowed domains for write operations (POST/PUT/DELETE/PATCH).
    pub write_allowed_domains: Vec<String>,
    /// Denied domains — checked BEFORE allow lists. Deny overrides allow.
    pub denied_domains: Vec<String>,
    /// Proxy operating mode.
    pub mode: ProxyMode,
    /// Branch directory for network journal storage.
    pub branch_dir: PathBuf,
    /// Branch ID for this proxy instance.
    pub branch_id: BranchId,
    /// Optional per-agent CA for TLS MITM interception (C4).
    /// When `Some`, CONNECT requests use TLS interception instead of opaque tunneling.
    pub ca: Option<Arc<AgentCa>>,
    /// §3.3: Optional DLP engine for content inspection on request/response bodies.
    pub dlp_engine: Option<Arc<DlpEngine>>,
    /// §3.3: Maximum request body size to inspect (bytes). Bodies larger than this
    /// are handled per `oversized_body_action`. Default: 10MB.
    pub max_inspection_body_size: usize,
    /// §3.3: Action for oversized bodies exceeding `max_inspection_body_size`.
    pub oversized_body_action: crate::dlp::OversizedAction,
    /// §3.3/§3.4: Optional channel to signal quarantine (cgroup.freeze) for a branch.
    /// Sends the branch ID when a Quarantine DLP action is triggered.
    pub quarantine_sender: Option<tokio::sync::mpsc::Sender<BranchId>>,
    /// §3.4: Optional phantom token manager for credential injection.
    pub phantom_token_manager: Option<Arc<RwLock<PhantomTokenManager>>>,
    /// Agent profile name for credential lookup scoping.
    pub agent_profile: Option<String>,
    /// §3.3: Optional GeoIP database for data residency enforcement.
    pub geo_database: Option<Arc<crate::geo::GeoIpDatabase>>,
    /// §3.3: Data residency configuration (allowed regions, enforcement mode, exceptions).
    pub data_residency: Option<puzzled_types::DataResidencyConfig>,
    /// §3.3/§3.4: Audit event channel for DLP and credential events.
    /// Handler sends ProxyAuditEvents; puzzled receiver converts to AuditEvents.
    pub audit_sender: Option<tokio::sync::mpsc::Sender<ProxyAuditEvent>>,
    /// §3.4: Credential injection mode (Phantom/Passthrough/Blocked).
    pub credential_mode: puzzled_types::CredentialMode,
    /// §3.4 G7: Enable transparent proxy mode (DNAT + SNI-based routing).
    /// When true, the proxy accepts raw TCP connections and extracts the
    /// upstream hostname from TLS SNI instead of HTTP CONNECT.
    pub transparent_mode: bool,
}

/// Proxy server state.
pub struct ProxyServer {
    config: ProxyConfig,
    journal: Arc<Mutex<replay::NetworkJournal>>,
    /// H-15: Semaphore limiting concurrent connections to prevent resource exhaustion.
    connection_semaphore: Arc<tokio::sync::Semaphore>,
}

impl ProxyServer {
    /// Create a new proxy server.
    pub fn new(config: ProxyConfig) -> Self {
        let journal_dir = config.branch_dir.join("network_journal");
        let journal = replay::NetworkJournal::new(journal_dir, config.branch_id.clone());

        Self {
            config,
            journal: Arc::new(Mutex::new(journal)),
            connection_semaphore: Arc::new(tokio::sync::Semaphore::new(
                handler::MAX_CONCURRENT_CONNECTIONS,
            )),
        }
    }

    /// Start the proxy server.
    ///
    /// Returns when the server is shut down.
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use hyper::server::conn::http1;
        use hyper::service::service_fn;
        use hyper_util::rt::TokioIo;

        let listener = tokio::net::TcpListener::bind(&self.config.listen_addr).await?;

        tracing::info!(
            addr = %self.config.listen_addr,
            read_domains = self.config.read_allowed_domains.len(),
            write_domains = self.config.write_allowed_domains.len(),
            denied_domains = self.config.denied_domains.len(),
            mode = ?self.config.mode,
            "HTTP proxy started"
        );

        let transparent_mode = self.config.transparent_mode;

        // Construct shared context once — cloned per connection.
        let base_ctx = handler::ProxyRequestContext {
            journal: self.journal.clone(),
            branch_id: self.config.branch_id.clone(),
            connection_semaphore: self.connection_semaphore.clone(),
            dlp_engine: self.config.dlp_engine.clone(),
            max_inspection_body_size: self.config.max_inspection_body_size,
            oversized_body_action: self.config.oversized_body_action,
            quarantine_sender: self.config.quarantine_sender.clone(),
            phantom_token_manager: self.config.phantom_token_manager.clone(),
            agent_profile: self.config.agent_profile.clone(),
            audit_sender: self.config.audit_sender.clone(),
            credential_mode: self.config.credential_mode,
        };

        loop {
            let (stream, peer_addr) = listener.accept().await?;

            let ctx = base_ctx.clone();
            let ca = self.config.ca.clone();

            if transparent_mode {
                // §3.4 G7: Transparent mode — handle DNAT'd TLS connections.
                // Connections arrive as raw TCP; SNI is extracted from ClientHello.
                let ca = match ca {
                    Some(ca) => ca,
                    None => {
                        tracing::error!(
                            peer = %peer_addr,
                            "§3.4 G7: transparent mode requires a CA — dropping connection"
                        );
                        continue;
                    }
                };

                tokio::spawn(async move {
                    handler::handle_transparent_connection(stream, ca, ctx).await;
                });
            } else {
                // Explicit proxy mode — standard HTTP/1.1 with CONNECT tunneling.
                let io = TokioIo::new(stream);
                let read_allowed_domains = self.config.read_allowed_domains.clone();
                let write_allowed_domains = self.config.write_allowed_domains.clone();
                let denied_domains = self.config.denied_domains.clone();
                let mode = self.config.mode.clone();
                let geo_database = self.config.geo_database.clone();
                let data_residency = self.config.data_residency.clone();

                tokio::spawn(async move {
                    let service = service_fn(move |req| {
                        let read_domains = read_allowed_domains.clone();
                        let write_domains = write_allowed_domains.clone();
                        let denied = denied_domains.clone();
                        let mode = mode.clone();
                        let ctx = ctx.clone();
                        let ca = ca.clone();
                        let geo_db = geo_database.clone();
                        let data_res = data_residency.clone();
                        async move {
                            handler::handle_request(
                                req,
                                &read_domains,
                                &write_domains,
                                &denied,
                                &mode,
                                &ctx,
                                ca.as_deref(),
                                geo_db,
                                data_res,
                            )
                            .await
                        }
                    });

                    if let Err(e) = http1::Builder::new()
                        .preserve_header_case(true)
                        .serve_connection(io, service)
                        .with_upgrades()
                        .await
                    {
                        tracing::debug!(
                            peer = %peer_addr,
                            error = %e,
                            "proxy connection error"
                        );
                    }
                });
            }
        }
    }

    /// Get the network journal for replay at commit time.
    pub fn journal(&self) -> Arc<Mutex<replay::NetworkJournal>> {
        self.journal.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_mode_default() {
        let mode = ProxyMode::default();
        assert_eq!(mode, ProxyMode::Gated);
    }

    #[test]
    fn test_proxy_mode_equality() {
        assert_eq!(ProxyMode::Blocked, ProxyMode::Blocked);
        assert_eq!(ProxyMode::Gated, ProxyMode::Gated);
        assert_eq!(ProxyMode::Monitored, ProxyMode::Monitored);
        assert_eq!(ProxyMode::Unrestricted, ProxyMode::Unrestricted);

        assert_ne!(ProxyMode::Blocked, ProxyMode::Gated);
        assert_ne!(ProxyMode::Gated, ProxyMode::Monitored);
        assert_ne!(ProxyMode::Monitored, ProxyMode::Unrestricted);
        assert_ne!(ProxyMode::Unrestricted, ProxyMode::Blocked);
    }

    #[test]
    fn test_proxy_mode_debug() {
        let debug_blocked = format!("{:?}", ProxyMode::Blocked);
        let debug_gated = format!("{:?}", ProxyMode::Gated);
        let debug_monitored = format!("{:?}", ProxyMode::Monitored);
        let debug_unrestricted = format!("{:?}", ProxyMode::Unrestricted);

        assert!(debug_blocked.contains("Blocked"));
        assert!(debug_gated.contains("Gated"));
        assert!(debug_monitored.contains("Monitored"));
        assert!(debug_unrestricted.contains("Unrestricted"));
    }

    #[test]
    fn test_proxy_server_new() {
        let tmp = tempfile::tempdir().unwrap();
        let config = ProxyConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            read_allowed_domains: vec![],
            write_allowed_domains: vec![],
            denied_domains: vec![],
            mode: ProxyMode::Blocked,
            branch_dir: tmp.path().to_path_buf(),
            branch_id: BranchId::from("test".to_string()),
            ca: None,
            dlp_engine: None,
            max_inspection_body_size: 10 * 1024 * 1024,
            oversized_body_action: crate::dlp::OversizedAction::BlockAndAlert,
            quarantine_sender: None,
            phantom_token_manager: None,
            agent_profile: None,
            geo_database: None,
            data_residency: None,
            audit_sender: None,
            credential_mode: puzzled_types::CredentialMode::Phantom,
            transparent_mode: false,
        };

        let server = ProxyServer::new(config);
        let journal = server.journal();
        // journal() should return an Arc
        assert!(Arc::strong_count(&journal) >= 1);
    }
}
