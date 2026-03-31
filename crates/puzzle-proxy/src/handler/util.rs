// SPDX-License-Identifier: Apache-2.0
//! Utility functions shared across handler sub-modules.

/// Send an audit event, logging a warning if the channel is full or closed.
pub(super) fn send_audit(
    sender: &tokio::sync::mpsc::Sender<crate::ProxyAuditEvent>,
    event: crate::ProxyAuditEvent,
) {
    match sender.try_send(event) {
        Ok(()) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            tracing::warn!("audit channel full — event dropped");
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            tracing::error!("audit channel closed — audit receiver has shut down");
        }
    }
}

/// Find the end of HTTP headers (the position of the first byte of \r\n\r\n).
pub(super) fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// D-C3: Validate HTTP header name per RFC 9110 token characters.
/// Header names must be non-empty and contain only: `!#$%&'*+-.^_`|~0-9A-Za-z`
pub(super) fn is_valid_http_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            matches!(b,
                b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' |
                b'^' | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
            )
        })
}

/// D-C3: Validate HTTP header value per RFC 9110.
/// Values must not contain null bytes (0x00) or control characters except HTAB (0x09).
pub(super) fn is_valid_http_header_value(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b == b'\t' || (b >= 0x20 && b != 0x7f))
}

/// D-C1: Decode a chunked Transfer-Encoding body.
///
/// Reads chunk-size (hex) + CRLF, then chunk-data, then trailing CRLF, until
/// a zero-length terminal chunk. Returns the reassembled decoded body.
pub(super) fn decode_chunked_body(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoded = Vec::new();
    let mut pos = 0;

    loop {
        // Find the CRLF after the chunk size line
        let crlf_pos = raw[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "malformed chunked body: missing CRLF after chunk size".to_string())?;
        let size_line = &raw[pos..pos + crlf_pos];
        // Parse hex chunk size (ignore chunk extensions after ';')
        let size_str = std::str::from_utf8(size_line)
            .map_err(|_| "malformed chunked body: non-UTF-8 chunk size".to_string())?;
        let size_hex = size_str.split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| format!("malformed chunked body: invalid chunk size '{}'", size_hex))?;

        pos += crlf_pos + 2; // skip past size line + CRLF

        if chunk_size == 0 {
            // Terminal chunk — skip optional trailers and final CRLF
            break;
        }

        // Guard against oversized chunks
        if decoded.len() + chunk_size > super::MAX_RESPONSE_BODY_BYTES {
            return Err("chunked body exceeds maximum response size".to_string());
        }

        // Read chunk data
        if pos + chunk_size > raw.len() {
            return Err("malformed chunked body: chunk data truncated".to_string());
        }
        decoded.extend_from_slice(&raw[pos..pos + chunk_size]);
        pos += chunk_size;

        // Expect trailing CRLF after chunk data
        if pos + 2 > raw.len() || &raw[pos..pos + 2] != b"\r\n" {
            return Err("malformed chunked body: missing CRLF after chunk data".to_string());
        }
        pos += 2;
    }

    Ok(decoded)
}

/// Get current timestamp as string.
pub(super) fn chrono_now() -> String {
    // Simple timestamp without chrono dependency
    // H68: Use "0" instead of empty string on pre-epoch clock
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}
