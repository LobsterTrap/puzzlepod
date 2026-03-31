// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Credential injection (§3.4)
// ---------------------------------------------------------------------------

/// Credential injection configuration per profile (§3.4.10).
///
/// Matches the PRD §3.4.10 schema: `secrets` defines per-credential specs,
/// `proxy` configures the transparent DNAT proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialConfig {
    /// Per-credential specifications.
    #[serde(default)]
    pub secrets: Vec<CredentialSpec>,
    /// Proxy configuration for transparent credential injection.
    #[serde(default)]
    pub proxy: CredentialProxyConfig,
}

impl CredentialConfig {
    /// Derive (domain, credential_name, env_var, required) tuples from secrets for
    /// phantom token issuance. Each credential's first Env exposure is used.
    /// M-4: Includes the `required` field from `CredentialSpec`.
    pub fn credential_mappings(&self) -> Vec<(String, String, String, bool)> {
        let mut result = Vec::new();
        for spec in &self.secrets {
            let env_var = spec
                .expose
                .iter()
                .find_map(|e| match e {
                    CredentialExposure::Env { var, .. } => Some(var.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            for domain in &spec.domains {
                result.push((
                    domain.clone(),
                    spec.name.clone(),
                    env_var.clone(),
                    spec.required,
                ));
            }
        }
        result
    }

    /// Whether phantom token injection is enabled (secrets defined and proxy enabled).
    pub fn is_phantom_enabled(&self) -> bool {
        !self.secrets.is_empty() && self.proxy.enabled
    }
}

/// Credential injection mode (§3.4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialMode {
    /// Phantom tokens: agent sees surrogates, proxy injects real credentials.
    #[default]
    Phantom,
    /// Passthrough: agent manages its own credentials (no injection).
    Passthrough,
    /// Blocked: agent cannot use any credentials (all auth headers stripped).
    Blocked,
}

// ---------------------------------------------------------------------------
// §3.4 G16: Extended credential isolation types
// ---------------------------------------------------------------------------

/// Full credential specification per PRD §3.4.10.
///
/// Clone is derived because CredentialSpec is part of CredentialConfig which
/// is embedded in AgentProfile (Clone). This type contains credential
/// *configuration* (names, backends, domains), never real credential values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSpec {
    /// Unique credential name within the profile.
    pub name: String,
    /// Storage backend type.
    #[serde(default)]
    pub backend: CredentialBackendType,
    /// Backend-specific configuration (opaque JSON).
    #[serde(default)]
    pub backend_config: serde_json::Value,
    /// How to expose the credential to the agent (env var, file, etc.).
    #[serde(default)]
    pub expose: Vec<CredentialExposure>,
    /// Whether to issue a phantom token for this credential (default: true).
    #[serde(default = "default_true_val")]
    pub phantom_token: bool,
    /// Domains this credential should be injected for.
    #[serde(default)]
    pub domains: Vec<String>,
    /// Allow wildcard domain patterns (default: false).
    #[serde(default)]
    pub allow_wildcard_domains: bool,
    /// Credential TTL in seconds for rotation (default: 900 = 15 minutes).
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u64,
    /// Headers to scan for phantom token swapping.
    #[serde(default = "default_swap_headers")]
    pub swap_headers: Vec<String>,
    /// Maximum credential value size in bytes (default: 4096).
    #[serde(default = "default_max_credential_size")]
    pub max_credential_size: usize,
    /// Whether this credential is required for branch creation (default: true).
    #[serde(default = "default_true_val")]
    pub required: bool,
}

pub(crate) fn default_true_val() -> bool {
    true
}
fn default_ttl() -> u64 {
    900
}
fn default_swap_headers() -> Vec<String> {
    vec!["authorization".to_string(), "x-api-key".to_string()]
}
fn default_max_credential_size() -> usize {
    4096
}

/// How a credential is exposed to the agent process.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum CredentialExposure {
    /// Expose as an environment variable.
    Env {
        /// Environment variable name.
        var: String,
        /// Optional JSON field path to extract (for structured secrets).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        field: Option<String>,
    },
    /// Expose as a file mounted into the container.
    File {
        /// Path inside the container.
        path: std::path::PathBuf,
        /// File format.
        #[serde(default)]
        format: CredentialFormat,
    },
}

/// File format when exposing credentials as files.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialFormat {
    /// Raw value, no formatting.
    #[default]
    Raw,
    /// INI-style key=value.
    Ini,
    /// JSON object.
    Json,
    /// Shell-compatible KEY=VALUE.
    Dotenv,
}

/// Credential storage backend type.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialBackendType {
    /// AES-256-GCM encrypted local file (HKDF-derived key).
    #[default]
    EncryptedFile,
    /// systemd-creds encrypt/decrypt (PRD §3.4.9 default).
    SystemdCreds,
    /// Read from puzzled's own environment variables (CI/development).
    EnvPassthrough,
    /// HashiCorp Vault KV v2.
    Vault,
    /// OpenBAO (open-source Vault fork).
    Openbao,
    /// AWS STS temporary credentials.
    AwsSts,
}

/// Credential proxy configuration within a profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProxyConfig {
    /// Enable the credential proxy for this profile (default: true).
    /// Per PRD §3.4.10, the proxy is enabled by default when credentials
    /// are configured.
    #[serde(default = "default_true_val")]
    pub enabled: bool,
    /// Ports to intercept via DNAT (default: [80, 443]).
    #[serde(default = "default_proxy_ports")]
    pub ports: Vec<u16>,
    /// Path to the combined CA trust bundle inside the container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_trust_path: Option<std::path::PathBuf>,
    /// Domains that bypass the proxy (direct connection allowed).
    #[serde(default)]
    pub passthrough_domains: Vec<String>,
}

impl Default for CredentialProxyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: default_proxy_ports(),
            ca_trust_path: None,
            passthrough_domains: vec![],
        }
    }
}

fn default_proxy_ports() -> Vec<u16> {
    vec![80, 443]
}

/// Data residency configuration for geographic enforcement (§3.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataResidencyConfig {
    /// Allowed geographic regions (ISO 3166-1 alpha-2 codes or aliases: "EU", "EEA", "US", "APAC").
    pub allowed_regions: Vec<String>,
    /// Enforcement mode.
    #[serde(default)]
    pub geo_enforcement: GeoEnforcement,
    /// Verify that DNS-resolved IPs match the claimed geographic region.
    #[serde(default)]
    pub dns_verification: bool,
    /// Path to MaxMind GeoLite2-Country database (.mmdb).
    #[serde(default = "default_geo_database")]
    pub geo_database: String,
    /// Domain exceptions (allowed regardless of region).
    #[serde(default)]
    pub exceptions: Vec<GeoException>,
}

fn default_geo_database() -> String {
    "/usr/share/GeoIP/GeoLite2-Country.mmdb".to_string()
}

/// Geographic enforcement mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GeoEnforcement {
    #[default]
    Strict,
    Permissive,
}

/// Domain exception for data residency rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoException {
    pub domain: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
}
