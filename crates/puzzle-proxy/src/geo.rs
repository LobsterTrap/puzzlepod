// SPDX-License-Identifier: Apache-2.0
//! GeoIP lookup for data residency enforcement (§3.3).

use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use std::path::Path;

/// GeoIP database reader wrapping MaxMind GeoLite2-Country.
pub struct GeoIpDatabase {
    reader: Reader<Vec<u8>>,
}

impl std::fmt::Debug for GeoIpDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoIpDatabase").finish()
    }
}

impl GeoIpDatabase {
    /// Load a MaxMind .mmdb database from disk.
    pub fn open(path: &Path) -> Result<Self, maxminddb::MaxMindDbError> {
        let reader = Reader::open_readfile(path)?;
        Ok(Self { reader })
    }

    /// Lookup the ISO country code for an IP address.
    /// Returns None if the IP is not found in the database.
    pub fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        let result = self.reader.lookup(ip).ok()?;
        let country: geoip2::Country = result.decode().ok()??;
        country.country.iso_code.map(|s: &str| s.to_string())
    }

    /// Check whether an IP's country is in the allowed regions list.
    /// Supports ISO 3166-1 alpha-2 codes and region aliases:
    /// "EU" (all EU member states), "EEA" (EU + IS/LI/NO), "US", "APAC".
    pub fn is_region_allowed(&self, ip: IpAddr, allowed_regions: &[String]) -> Option<bool> {
        let country = self.lookup_country(ip)?;
        Some(allowed_regions.iter().any(|region| {
            // Always try region alias expansion first (handles "EU", "EEA", "US", "APAC").
            // Fall back to direct ISO country code comparison for unrecognized aliases.
            is_country_in_region(&country, region) || region.eq_ignore_ascii_case(&country)
        }))
    }
}

/// EU member state ISO codes.
const EU_COUNTRIES: &[&str] = &[
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV",
    "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE",
];

/// EEA = EU + Iceland, Liechtenstein, Norway.
const EEA_EXTRA: &[&str] = &["IS", "LI", "NO"];

/// APAC region codes (major markets).
const APAC_COUNTRIES: &[&str] = &[
    "AU", "BD", "BN", "KH", "CN", "FJ", "HK", "IN", "ID", "JP", "KR", "LA", "MO", "MY", "MV", "MN",
    "MM", "NP", "NZ", "PK", "PH", "SG", "LK", "TW", "TH", "VN",
];

/// Check if a country code belongs to a named region alias.
fn is_country_in_region(country: &str, region: &str) -> bool {
    let upper = country.to_uppercase();
    match region.to_uppercase().as_str() {
        "EU" => EU_COUNTRIES.contains(&upper.as_str()),
        "EEA" => EU_COUNTRIES.contains(&upper.as_str()) || EEA_EXTRA.contains(&upper.as_str()),
        "US" => upper == "US",
        "APAC" => APAC_COUNTRIES.contains(&upper.as_str()),
        _ => false,
    }
}

/// Check if a domain is in the geo exception list.
pub fn is_geo_exception(domain: &str, exceptions: &[puzzled_types::GeoException]) -> bool {
    exceptions.iter().any(|exc| {
        // Check expiry
        if let Some(ref expires) = exc.expires {
            if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(expires) {
                if chrono::Utc::now() > exp {
                    return false; // Exception expired
                }
            }
        }
        crate::credentials::domain_matches(domain, &exc.domain)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eu_region_membership() {
        assert!(is_country_in_region("DE", "EU"));
        assert!(is_country_in_region("FR", "EU"));
        assert!(is_country_in_region("de", "eu")); // case insensitive
        assert!(!is_country_in_region("US", "EU"));
        assert!(!is_country_in_region("NO", "EU")); // Norway is EEA, not EU
    }

    #[test]
    fn test_eea_region_membership() {
        assert!(is_country_in_region("DE", "EEA"));
        assert!(is_country_in_region("NO", "EEA")); // EEA includes Norway
        assert!(is_country_in_region("IS", "EEA")); // Iceland
        assert!(!is_country_in_region("US", "EEA"));
    }

    #[test]
    fn test_us_region() {
        assert!(is_country_in_region("US", "US"));
        assert!(!is_country_in_region("CA", "US"));
    }

    #[test]
    fn test_apac_region() {
        assert!(is_country_in_region("JP", "APAC"));
        assert!(is_country_in_region("AU", "APAC"));
        assert!(!is_country_in_region("US", "APAC"));
    }

    #[test]
    fn test_direct_country_code() {
        // When a 2-letter code is in allowed_regions, it matches directly
        assert!(is_country_in_region("US", "US"));
    }

    #[test]
    fn test_geo_exception_matching() {
        let exceptions = vec![
            puzzled_types::GeoException {
                domain: "api.anthropic.com".to_string(),
                reason: "LLM API".to_string(),
                approved_by: None,
                expires: None,
            },
            puzzled_types::GeoException {
                domain: "*.openai.com".to_string(),
                reason: "LLM API".to_string(),
                approved_by: None,
                expires: Some("2099-01-01T00:00:00Z".to_string()),
            },
        ];
        assert!(is_geo_exception("api.anthropic.com", &exceptions));
        assert!(is_geo_exception("api.openai.com", &exceptions));
        assert!(!is_geo_exception("google.com", &exceptions));
    }

    #[test]
    fn test_geo_exception_expired() {
        let exceptions = vec![puzzled_types::GeoException {
            domain: "expired.example.com".to_string(),
            reason: "test".to_string(),
            approved_by: None,
            expires: Some("2020-01-01T00:00:00Z".to_string()), // Past date
        }];
        assert!(!is_geo_exception("expired.example.com", &exceptions));
    }
}
