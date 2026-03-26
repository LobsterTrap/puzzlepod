// SPDX-License-Identifier: Apache-2.0
//! TLS MITM proxy support for agent network inspection.
//!
//! C4: Provides per-agent CA certificate generation and on-the-fly leaf certificate
//! issuance for TLS interception. This allows the proxy to decrypt, inspect, and
//! journal HTTPS POST/PUT/DELETE/PATCH requests while passing through GET requests.
//!
//! Each agent branch gets its own ephemeral CA (valid 1 day). The CA cert PEM is
//! injected into the agent's trust store so it accepts the proxy's leaf certs.
//! Leaf certs are generated on-the-fly for each target domain (valid 1 hour).

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Per-agent Certificate Authority for TLS MITM interception.
///
/// Generated once per branch, used to sign leaf certificates for target domains.
///
/// `Debug` is implemented manually to avoid printing sensitive key material.
///
/// N8: Known limitation — `rcgen::KeyPair` does not implement `Zeroize` and does not
/// expose raw key bytes for manual zeroization. The private key material held by
/// `ca_key_pair` will persist in freed heap memory until overwritten by subsequent
/// allocations. Mitigations: (1) each AgentCa is ephemeral (valid 1 day, created per
/// branch), (2) the puzzled process runs in a confined SELinux domain (`puzzled_t`),
/// (3) `/proc/pid/mem` access is restricted by PID namespace isolation. A future
/// upstream contribution to `rcgen` adding `Zeroize` support would close this gap.
pub struct AgentCa {
    /// The CA certificate in DER format.
    ca_cert_der: Vec<u8>,
    /// The CA certificate in PEM format (cached for injection into agent trust store).
    ca_cert_pem: String,
    /// The CA certificate params (needed for signing leaf certs).
    ca_cert: rcgen::Certificate,
    /// The CA key pair.
    /// N8: Cannot be zeroized — see struct-level doc comment.
    ca_key_pair: KeyPair,
}

impl std::fmt::Debug for AgentCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentCa")
            .field("ca_cert_pem_len", &self.ca_cert_pem.len())
            .finish_non_exhaustive()
    }
}

impl AgentCa {
    /// Generate a new per-agent CA certificate.
    ///
    /// Creates a self-signed root CA with:
    /// - CN: "PuzzlePod Agent CA - {branch_id}"
    /// - Key usage: cert signing
    /// - Basic constraints: CA=true
    /// - Validity: 1 day
    pub fn generate(branch_id: &str) -> Result<Self, String> {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(
            DnType::CommonName,
            format!("PuzzlePod Agent CA - {}", branch_id),
        );
        params
            .distinguished_name
            .push(DnType::OrganizationName, "PuzzlePod");

        // V22: Constrain CA path length to 0 — prevents leaf keys from issuing further certs
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        // Validity: ~1 day (CA cert)
        // Q12: rcgen's date_time_ymd has day granularity — month() returns 1-12 and day()
        // returns 1-31, both always fit in u8, so the `as u8` casts are safe.
        use chrono::{Datelike, Utc};
        let now = Utc::now();
        let not_before = now - chrono::TimeDelta::hours(1); // small backdate for clock skew
        let not_after = now + chrono::TimeDelta::days(1);
        params.not_before = rcgen::date_time_ymd(
            not_before.year(),
            not_before.month() as u8, // safe: 1..=12
            not_before.day() as u8,   // safe: 1..=31
        );
        params.not_after = rcgen::date_time_ymd(
            not_after.year(),
            not_after.month() as u8, // safe: 1..=12
            not_after.day() as u8,   // safe: 1..=31
        );

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| format!("generating CA key pair: {}", e))?;

        let ca_cert = params
            .self_signed(&key_pair)
            .map_err(|e| format!("self-signing CA cert: {}", e))?;

        let ca_cert_der = ca_cert.der().to_vec();
        let ca_cert_pem = ca_cert.pem();

        Ok(Self {
            ca_cert_der,
            ca_cert_pem,
            ca_cert,
            ca_key_pair: key_pair,
        })
    }

    /// Issue a leaf certificate for the given domain, signed by this CA.
    ///
    /// The leaf cert has:
    /// - SAN: the target domain name
    /// - Extended key usage: server auth
    /// - Validity: ~1 day (Q8: rcgen uses day granularity, not hours)
    pub fn issue_leaf_cert(
        &self,
        domain: &str,
    ) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), String> {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, domain.to_string());

        params.subject_alt_names = vec![SanType::DnsName(
            domain
                .to_string()
                .try_into()
                .map_err(|e| format!("invalid domain for SAN: {:?}", e))?,
        )];

        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];

        // Q8: Validity: ~1 day. rcgen's date_time_ymd has day granularity (no hours/minutes),
        // so adding only 1 hour could produce a not_after on the same calendar day as not_before,
        // resulting in a zero-validity or already-expired cert. We add 2 days to ensure the cert
        // is valid for at least 1 full day regardless of when during the day it's issued.
        use chrono::{Datelike, Utc};
        let now = Utc::now();
        let not_before = now - chrono::TimeDelta::minutes(5);
        let not_after = now + chrono::TimeDelta::days(2);
        params.not_before = rcgen::date_time_ymd(
            not_before.year(),
            // Q12: month() returns 1-12, day() returns 1-31 — both always fit in u8
            not_before.month() as u8, // safe: 1..=12
            not_before.day() as u8,   // safe: 1..=31
        );
        params.not_after = rcgen::date_time_ymd(
            not_after.year(),
            not_after.month() as u8, // safe: 1..=12
            not_after.day() as u8,   // safe: 1..=31
        );

        // Not a CA
        params.is_ca = IsCa::NoCa;

        let leaf_key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| format!("generating leaf key pair: {}", e))?;

        let leaf_cert = params
            .signed_by(&leaf_key_pair, &self.ca_cert, &self.ca_key_pair)
            .map_err(|e| format!("signing leaf cert: {}", e))?;

        let cert_der = CertificateDer::from(leaf_cert.der().to_vec());
        let key_der = PrivateKeyDer::try_from(leaf_key_pair.serialize_der())
            .map_err(|e| format!("serializing leaf private key: {}", e))?;

        Ok((cert_der, key_der))
    }

    /// Return the CA certificate in PEM format for injection into the agent trust store.
    pub fn ca_cert_pem(&self) -> String {
        self.ca_cert_pem.clone()
    }

    /// Return the CA certificate in DER format.
    pub fn ca_cert_der(&self) -> &[u8] {
        &self.ca_cert_der
    }
}

// ---------------------------------------------------------------------------
// §3.4 G7: TLS SNI extraction for transparent proxy mode
// ---------------------------------------------------------------------------

/// Extract the Server Name Indication (SNI) hostname from a TLS ClientHello.
///
/// Parses the raw TLS record to find the `server_name` extension in the
/// ClientHello handshake message. Returns `None` if the data is not a valid
/// TLS ClientHello or does not contain an SNI extension.
///
/// This is used in transparent proxy mode where connections arrive via DNAT
/// (not CONNECT), so the upstream hostname must be extracted from the TLS
/// handshake itself.
pub fn extract_sni(buf: &[u8]) -> Option<String> {
    // Minimum TLS record: 5 (record header) + 4 (handshake header) + 2 (version)
    // + 32 (random) + 1 (session_id_len) = 44 bytes
    if buf.len() < 44 {
        return None;
    }

    // TLS record header
    let content_type = buf[0];
    if content_type != 0x16 {
        // Not a Handshake record
        return None;
    }
    // buf[1..3] = TLS version (ignore — may be TLS 1.0 in record layer)
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len {
        return None;
    }
    let record = &buf[5..5 + record_len];

    // Handshake header
    if record.is_empty() || record[0] != 0x01 {
        // Not ClientHello
        return None;
    }
    let handshake_len =
        ((record[1] as usize) << 16) | ((record[2] as usize) << 8) | (record[3] as usize);
    if record.len() < 4 + handshake_len {
        return None;
    }
    let hello = &record[4..4 + handshake_len];

    // ClientHello fields
    if hello.len() < 38 {
        return None;
    }
    // hello[0..2] = client version
    // hello[2..34] = random (32 bytes)
    let mut pos = 34;

    // Session ID
    if pos >= hello.len() {
        return None;
    }
    let session_id_len = hello[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher suites
    if pos + 2 > hello.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    // Compression methods
    if pos >= hello.len() {
        return None;
    }
    let compression_len = hello[pos] as usize;
    pos += 1 + compression_len;

    // Extensions
    if pos + 2 > hello.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len;
    if extensions_end > hello.len() {
        return None;
    }

    // Walk extensions looking for server_name (type 0x0000)
    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
        let ext_len = u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // Server Name extension
            return parse_server_name_extension(&hello[pos..pos + ext_len]);
        }

        pos += ext_len;
    }

    None
}

/// Parse the server_name extension data to extract the hostname.
fn parse_server_name_extension(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }
    // data[0..2] = server_name_list length
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return None;
    }

    let mut pos = 2;
    let end = 2 + list_len;

    while pos + 3 <= end {
        let name_type = data[pos];
        let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;

        if name_type == 0x00 {
            // host_name type
            if pos + name_len > end {
                return None;
            }
            return std::str::from_utf8(&data[pos..pos + name_len])
                .ok()
                .map(|s| s.to_string());
        }

        pos += name_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_ca_generate() {
        let ca = AgentCa::generate("test-branch-123").unwrap();

        // CA cert PEM should be non-empty and look like a PEM certificate
        let pem = ca.ca_cert_pem();
        assert!(
            pem.contains("BEGIN CERTIFICATE"),
            "PEM should contain BEGIN CERTIFICATE"
        );
        assert!(
            pem.contains("END CERTIFICATE"),
            "PEM should contain END CERTIFICATE"
        );

        // CA cert DER should be non-empty
        assert!(!ca.ca_cert_der().is_empty(), "DER should be non-empty");
    }

    #[test]
    fn test_issue_leaf_cert() {
        let ca = AgentCa::generate("test-branch-456").unwrap();

        let (cert_der, key_der) = ca.issue_leaf_cert("api.example.com").unwrap();

        // Leaf cert DER should be non-empty
        assert!(!cert_der.is_empty(), "leaf cert DER should be non-empty");

        // Leaf private key should be non-empty
        let key_bytes: &[u8] = key_der.secret_der();
        assert!(
            !key_bytes.is_empty(),
            "leaf private key should be non-empty"
        );
    }

    #[test]
    fn test_issue_leaf_cert_different_domains() {
        let ca = AgentCa::generate("test-branch-789").unwrap();

        let (cert1, _key1) = ca.issue_leaf_cert("api.example.com").unwrap();
        let (cert2, _key2) = ca.issue_leaf_cert("cdn.example.org").unwrap();

        // Different domains should produce different certs
        assert_ne!(
            cert1.as_ref(),
            cert2.as_ref(),
            "different domains should produce different certs"
        );
    }

    #[test]
    fn test_agent_ca_debug_impl() {
        let ca = AgentCa::generate("test-debug").unwrap();
        let debug = format!("{:?}", ca);
        // Debug should include ca_cert_pem_len but NOT print key material
        assert!(
            debug.contains("AgentCa"),
            "Debug should include struct name"
        );
        assert!(
            debug.contains("ca_cert_pem_len"),
            "Debug should include pem_len field"
        );
        assert!(
            !debug.contains("BEGIN"),
            "Debug should NOT print PEM certificate"
        );
    }

    #[test]
    fn test_issue_leaf_cert_localhost() {
        let ca = AgentCa::generate("test-localhost").unwrap();
        let result = ca.issue_leaf_cert("localhost");
        assert!(result.is_ok(), "should issue cert for localhost");
    }

    #[test]
    fn test_ca_cert_der_nonempty() {
        let ca = AgentCa::generate("test-der").unwrap();
        let der = ca.ca_cert_der();
        assert!(der.len() > 100, "DER cert should be at least 100 bytes");
    }

    #[test]
    fn test_ca_cert_pem_consistency() {
        let ca = AgentCa::generate("test-branch-pem").unwrap();

        // Multiple calls should return the same PEM
        let pem1 = ca.ca_cert_pem();
        let pem2 = ca.ca_cert_pem();
        assert_eq!(pem1, pem2, "ca_cert_pem should be consistent");
    }

    #[test]
    fn test_ca_key_encrypt_decrypt_roundtrip() {
        let ca = AgentCa::generate("test-persist").unwrap();
        let key_der = ca.ca_key_pair.serialize_der();

        let mut instance_secret = [0u8; 32];
        getrandom::getrandom(&mut instance_secret).unwrap();

        let encrypted = encrypt_ca_key("test-persist", &key_der, &instance_secret).unwrap();
        assert_eq!(&encrypted[0..4], ACKF_MAGIC);

        let decrypted = decrypt_ca_key("test-persist", &encrypted, &instance_secret).unwrap();
        assert_eq!(&*decrypted, &key_der);
    }

    #[test]
    fn test_ca_key_wrong_branch_fails() {
        let key_data = b"fake-key-material";
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).unwrap();

        let encrypted = encrypt_ca_key("branch-A", key_data, &secret).unwrap();
        // Decrypt with wrong branch_id should fail (different HKDF info)
        let result = decrypt_ca_key("branch-B", &encrypted, &secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_ca_key_wrong_secret_fails() {
        let key_data = b"fake-key-material";
        let mut secret1 = [0u8; 32];
        let mut secret2 = [0u8; 32];
        getrandom::getrandom(&mut secret1).unwrap();
        getrandom::getrandom(&mut secret2).unwrap();

        let encrypted = encrypt_ca_key("branch", key_data, &secret1).unwrap();
        let result = decrypt_ca_key("branch", &encrypted, &secret2);
        assert!(result.is_err());
    }

    // §3.4 G7: SNI extraction tests

    #[test]
    fn test_extract_sni_valid_client_hello() {
        // A minimal TLS 1.2 ClientHello with SNI "example.com"
        // This is a hand-crafted minimal ClientHello message.
        let sni_hostname = b"example.com";
        let client_hello = build_test_client_hello(sni_hostname);
        let result = extract_sni(&client_hello);
        assert_eq!(result.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_extract_sni_no_sni_extension() {
        // ClientHello with no extensions
        let client_hello = build_test_client_hello_no_sni();
        let result = extract_sni(&client_hello);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_sni_too_short() {
        assert!(extract_sni(&[]).is_none());
        assert!(extract_sni(&[0x16, 0x03, 0x01]).is_none());
    }

    #[test]
    fn test_extract_sni_not_handshake() {
        let mut buf = vec![0x17; 100]; // Application data, not handshake
        buf[0] = 0x17;
        assert!(extract_sni(&buf).is_none());
    }

    /// Build a minimal TLS ClientHello with SNI extension for testing.
    fn build_test_client_hello(hostname: &[u8]) -> Vec<u8> {
        let mut hello = Vec::new();

        // ClientHello body (inside handshake message)
        let mut hello_body = Vec::new();
        // Client version TLS 1.2
        hello_body.extend_from_slice(&[0x03, 0x03]);
        // Random (32 bytes)
        hello_body.extend_from_slice(&[0u8; 32]);
        // Session ID length = 0
        hello_body.push(0);
        // Cipher suites: length=2, one cipher suite
        hello_body.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]);
        // Compression methods: length=1, null
        hello_body.extend_from_slice(&[0x01, 0x00]);

        // Extensions
        let mut extensions = Vec::new();
        // SNI extension (type 0x0000)
        let mut sni_ext = Vec::new();
        // server_name_list length
        let sni_entry_len = 1 + 2 + hostname.len(); // type + len + name
        sni_ext.extend_from_slice(&(sni_entry_len as u16).to_be_bytes());
        sni_ext.push(0x00); // host_name type
        sni_ext.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(hostname);

        extensions.extend_from_slice(&[0x00, 0x00]); // ext type = server_name
        extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext);

        // Extensions total length
        hello_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello_body.extend_from_slice(&extensions);

        // Handshake header: type=ClientHello (0x01), length=3 bytes
        let hs_len = hello_body.len();
        hello.push(0x01); // ClientHello
        hello.push(((hs_len >> 16) & 0xff) as u8);
        hello.push(((hs_len >> 8) & 0xff) as u8);
        hello.push((hs_len & 0xff) as u8);
        hello.extend_from_slice(&hello_body);

        // TLS record header
        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record layer
        record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
        record.extend_from_slice(&hello);

        record
    }

    /// Build a minimal ClientHello with no extensions.
    fn build_test_client_hello_no_sni() -> Vec<u8> {
        let mut hello_body = Vec::new();
        hello_body.extend_from_slice(&[0x03, 0x03]); // version
        hello_body.extend_from_slice(&[0u8; 32]); // random
        hello_body.push(0); // session_id_len
        hello_body.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]); // cipher suites
        hello_body.extend_from_slice(&[0x01, 0x00]); // compression
                                                     // No extensions length field = no extensions

        let mut hello = Vec::new();
        let hs_len = hello_body.len();
        hello.push(0x01);
        hello.push(((hs_len >> 16) & 0xff) as u8);
        hello.push(((hs_len >> 8) & 0xff) as u8);
        hello.push((hs_len & 0xff) as u8);
        hello.extend_from_slice(&hello_body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
        record.extend_from_slice(&hello);

        record
    }
}

// ---------------------------------------------------------------------------
// §3.4 G13: CA key persistence (ACKF file format)
// ---------------------------------------------------------------------------

/// ACKF file format magic bytes.
pub const ACKF_MAGIC: &[u8; 4] = b"ACKF";
/// ACKF file format version.
pub const ACKF_VERSION: u16 = 0x0001;

/// Encrypt a CA key pair for persistence using AES-256-GCM.
///
/// The encryption key is derived via HKDF from the instance secret, with
/// `branch_id` in the info string for domain separation.
///
/// File format (ACKF):
/// - Magic: "ACKF" (4 bytes)
/// - Version: 0x0001 (2 bytes, big-endian)
/// - Key source: 1 byte (0x01 = instance_secret)
/// - HKDF salt: 16 bytes random
/// - AES-256-GCM nonce: 12 bytes random
/// - Ciphertext + 16-byte GCM tag
///
/// Total header: 4 + 2 + 1 + 16 + 12 = 35 bytes
pub fn encrypt_ca_key(
    branch_id: &str,
    key_pair_bytes: &[u8],
    instance_secret: &[u8; 32],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    use hkdf::Hkdf;
    use sha2::Sha256;

    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut salt).map_err(|e| format!("getrandom failed: {}", e))?;
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("getrandom failed: {}", e))?;

    // Derive AES key via HKDF
    let info = format!("puzzlepod-ca-key-v1:{}", branch_id);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), instance_secret);
    let mut aes_key = zeroize::Zeroizing::new([0u8; 32]);
    hkdf.expand(info.as_bytes(), &mut *aes_key)
        .map_err(|e| format!("HKDF expand failed: {}", e))?;

    // Build header
    let mut header = Vec::with_capacity(35);
    header.extend_from_slice(ACKF_MAGIC); // 4
    header.extend_from_slice(&ACKF_VERSION.to_be_bytes()); // 2
    header.push(0x01); // key source: instance_secret        // 1
    header.extend_from_slice(&salt); // 16
    header.extend_from_slice(&nonce_bytes); // 12

    // Encrypt with AAD = header bytes (integrity-protects magic, version, key source,
    // salt, and nonce against tampering — F4 hardening).
    let cipher =
        Aes256Gcm::new_from_slice(&*aes_key).map_err(|e| format!("AES key init: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: key_pair_bytes,
                aad: &header,
            },
        )
        .map_err(|e| format!("AES-GCM encrypt: {}", e))?;

    let mut output = header;
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt a CA key pair from an ACKF-formatted file.
pub fn decrypt_ca_key(
    branch_id: &str,
    data: &[u8],
    instance_secret: &[u8; 32],
) -> Result<zeroize::Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    use hkdf::Hkdf;
    use sha2::Sha256;

    if data.len() < 35 {
        return Err("ACKF file too short".into());
    }
    if &data[0..4] != ACKF_MAGIC {
        return Err("invalid ACKF magic".into());
    }
    let version = u16::from_be_bytes([data[4], data[5]]);
    if version != ACKF_VERSION {
        return Err(format!("unsupported ACKF version: {}", version).into());
    }

    let salt = &data[7..23];
    let nonce_bytes = &data[23..35];
    let ciphertext = &data[35..];

    // Derive key
    let info = format!("puzzlepod-ca-key-v1:{}", branch_id);
    let hkdf = Hkdf::<Sha256>::new(Some(salt), instance_secret);
    let mut aes_key = zeroize::Zeroizing::new([0u8; 32]);
    hkdf.expand(info.as_bytes(), &mut *aes_key)
        .map_err(|e| format!("HKDF expand failed: {}", e))?;

    // Decrypt with AAD = header bytes (F4: verify header integrity).
    let header = &data[0..35];
    let cipher =
        Aes256Gcm::new_from_slice(&*aes_key).map_err(|e| format!("AES key init: {}", e))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .map_err(|e| format!("AES-GCM decrypt: {}", e))?;

    Ok(zeroize::Zeroizing::new(plaintext))
}
