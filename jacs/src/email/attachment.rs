//! JACS attachment operations for raw RFC 5322 email bytes.
//!
//! Implements add/get/remove operations for JACS signature MIME attachments.
//! The attachment filename is configurable -- callers pass their preferred
//! name via `_named` variants. Works entirely at the raw byte level.

use mail_parser::{MessageParser, MimeHeaders as _};

use super::error::EmailError;

/// Default name for the JACS signature attachment.
///
/// JACS is a generic library. Callers (e.g., HAI server, haisdk) may pass
/// their own preferred filename via the `_named` variants of attachment
/// functions.
pub const DEFAULT_JACS_SIGNATURE_FILENAME: &str = "jacs-signature.json";

/// Legacy constant alias -- points to the generic JACS default.
/// Use `DEFAULT_JACS_SIGNATURE_FILENAME` for new code.
pub const JACS_SIGNATURE_FILENAME: &str = DEFAULT_JACS_SIGNATURE_FILENAME;

/// Find the last occurrence of `needle` in `haystack` (byte-level rfind).
/// Returns the byte offset of the start of the match, or None.
pub(crate) fn rfind_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    (0..=haystack.len() - needle.len())
        .rev()
        .find(|&i| &haystack[i..i + needle.len()] == needle)
}

/// Add a JACS signature attachment with a custom filename to a raw RFC 5322 email.
///
/// - If the email is already `multipart/mixed`: insert a new MIME part before the closing boundary.
/// - If the email is `multipart/alternative` or single-part: wrap in a new `multipart/mixed` envelope.
///
/// Returns the new raw email bytes with the attachment included.
pub fn add_jacs_attachment_named(
    raw_email: &[u8],
    doc: &[u8],
    filename: &str,
) -> Result<Vec<u8>, EmailError> {
    add_jacs_attachment_inner(raw_email, doc, filename)
}

/// Add a JACS signature attachment with the default filename to a raw RFC 5322 email.
///
/// Uses `DEFAULT_JACS_SIGNATURE_FILENAME` (`jacs-signature.json`).
/// For a custom name, use [`add_jacs_attachment_named`].
pub fn add_jacs_attachment(raw_email: &[u8], doc: &[u8]) -> Result<Vec<u8>, EmailError> {
    add_jacs_attachment_inner(raw_email, doc, DEFAULT_JACS_SIGNATURE_FILENAME)
}

/// Inner implementation: add a JACS attachment with the given filename.
fn add_jacs_attachment_inner(
    raw_email: &[u8],
    doc: &[u8],
    filename: &str,
) -> Result<Vec<u8>, EmailError> {
    let message = MessageParser::default().parse(raw_email).ok_or_else(|| {
        EmailError::InvalidEmailFormat("Cannot parse email for attachment injection".into())
    })?;

    let content_type = message
        .content_type()
        .map(|ct| format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or("")));

    match content_type.as_deref() {
        Some("multipart/mixed") => {
            // Find the boundary
            let boundary = message
                .content_type()
                .and_then(|ct| ct.attribute("boundary"))
                .ok_or_else(|| {
                    EmailError::InvalidEmailFormat("multipart/mixed without boundary".into())
                })?
                .to_string();
            insert_part_before_closing_boundary_named(raw_email, &boundary, doc, filename)
        }
        Some(ct) if ct.starts_with("multipart/") => {
            // Wrap in multipart/mixed
            wrap_in_multipart_mixed_named(raw_email, doc, filename)
        }
        _ => {
            // Single-part email: wrap in multipart/mixed
            wrap_in_multipart_mixed_named(raw_email, doc, filename)
        }
    }
}

/// Extract a JACS signature attachment with a custom filename from a raw RFC 5322 email.
///
/// Returns the raw bytes of the attachment content (MIME-decoded).
pub fn get_jacs_attachment_named(raw_email: &[u8], filename: &str) -> Result<Vec<u8>, EmailError> {
    let message = MessageParser::default().parse(raw_email).ok_or_else(|| {
        EmailError::InvalidEmailFormat("Cannot parse email for attachment extraction".into())
    })?;

    for part in message.parts.iter() {
        let part_filename = part
            .attachment_name()
            .or_else(|| part.content_type().and_then(|ct| ct.attribute("name")));

        if let Some(name) = part_filename {
            if name == filename {
                return Ok(part.contents().to_vec());
            }
        }
    }

    Err(EmailError::MissingJacsSignature)
}

/// Extract the default JACS signature attachment from a raw RFC 5322 email.
///
/// Looks for `DEFAULT_JACS_SIGNATURE_FILENAME` (`jacs-signature.json`).
/// For a custom name, use [`get_jacs_attachment_named`].
pub fn get_jacs_attachment(raw_email: &[u8]) -> Result<Vec<u8>, EmailError> {
    get_jacs_attachment_named(raw_email, DEFAULT_JACS_SIGNATURE_FILENAME)
}

/// Remove a JACS attachment with a custom filename from a raw email.
///
/// Returns the email without the named JACS attachment. The result is valid RFC 5322.
pub fn remove_jacs_attachment_named(
    raw_email: &[u8],
    filename: &str,
) -> Result<Vec<u8>, EmailError> {
    let message = MessageParser::default().parse(raw_email).ok_or_else(|| {
        EmailError::InvalidEmailFormat("Cannot parse email for attachment removal".into())
    })?;

    // Find the JACS part to remove
    let mut jacs_part_idx = None;
    for (idx, part) in message.parts.iter().enumerate() {
        let part_filename = part
            .attachment_name()
            .or_else(|| part.content_type().and_then(|ct| ct.attribute("name")));
        if let Some(name) = part_filename {
            if name == filename {
                jacs_part_idx = Some(idx);
                break;
            }
        }
    }

    let part_idx = jacs_part_idx.ok_or(EmailError::MissingJacsSignature)?;
    let jacs_part = &message.parts[part_idx];

    // Get the raw byte offsets for this part
    let header_offset = jacs_part.raw_header_offset() as usize;
    let end_offset = jacs_part.raw_end_offset() as usize;

    // We need to remove this MIME part from the raw bytes.
    // The MIME part starts at header_offset and ends at end_offset.
    // We also need to remove the preceding boundary line.
    // Find the boundary for the parent multipart
    let boundary = message
        .content_type()
        .and_then(|ct| ct.attribute("boundary"))
        .map(|b| b.to_string());

    if let Some(boundary) = boundary {
        // Remove the MIME part including its boundary prefix.
        // Use raw byte search to avoid lossy UTF-8 conversion that can
        // shift byte positions with non-ASCII email content.
        let boundary_marker = format!("--{}", boundary);
        let before_part = &raw_email[..header_offset];

        if let Some(boundary_start) = rfind_bytes(before_part, boundary_marker.as_bytes()) {
            let mut result = Vec::new();
            result.extend_from_slice(&raw_email[..boundary_start]);
            result.extend_from_slice(&raw_email[end_offset..]);
            return Ok(result);
        }
    }

    // Fallback: remove by byte range
    let mut result = Vec::new();
    result.extend_from_slice(&raw_email[..header_offset]);
    result.extend_from_slice(&raw_email[end_offset..]);
    Ok(result)
}

/// Remove the default JACS signature attachment from a raw email.
///
/// Looks for `DEFAULT_JACS_SIGNATURE_FILENAME` (`jacs-signature.json`).
/// For a custom name, use [`remove_jacs_attachment_named`].
pub fn remove_jacs_attachment(raw_email: &[u8]) -> Result<Vec<u8>, EmailError> {
    remove_jacs_attachment_named(raw_email, DEFAULT_JACS_SIGNATURE_FILENAME)
}

/// Insert a JACS part before the closing boundary of a multipart/mixed email (named variant).
fn insert_part_before_closing_boundary_named(
    raw_email: &[u8],
    boundary: &str,
    doc: &[u8],
    filename: &str,
) -> Result<Vec<u8>, EmailError> {
    let closing = format!("--{}--", boundary);

    // Use raw byte search to avoid lossy UTF-8 conversion.
    let closing_pos = rfind_bytes(raw_email, closing.as_bytes()).ok_or_else(|| {
        EmailError::InvalidEmailFormat("Cannot find closing boundary in multipart/mixed".into())
    })?;

    let jacs_part = build_jacs_mime_part_named(boundary, doc, filename);

    let mut result = Vec::new();
    result.extend_from_slice(&raw_email[..closing_pos]);
    result.extend_from_slice(jacs_part.as_bytes());
    result.extend_from_slice(closing.as_bytes());
    // Preserve anything after closing boundary (e.g., trailing CRLF)
    let after_closing = closing_pos + closing.len();
    if after_closing < raw_email.len() {
        result.extend_from_slice(&raw_email[after_closing..]);
    } else {
        result.extend_from_slice(b"\r\n");
    }

    Ok(result)
}

/// Wrap a non-multipart/mixed email in a new multipart/mixed envelope (named variant).
fn wrap_in_multipart_mixed_named(
    raw_email: &[u8],
    doc: &[u8],
    filename: &str,
) -> Result<Vec<u8>, EmailError> {
    let boundary = generate_boundary();

    // Find the header/body boundary
    let header_end = find_header_body_boundary(raw_email);

    let headers = &raw_email[..header_end];
    let body_start = skip_blank_line(raw_email, header_end);
    let body = &raw_email[body_start..];

    // Build the original content type from the existing headers
    let message = MessageParser::default()
        .parse(raw_email)
        .ok_or_else(|| EmailError::InvalidEmailFormat("Cannot parse email for wrapping".into()))?;

    let original_ct = message
        .content_type()
        .map(|ct| {
            let mut s = format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or("plain"));
            if let Some(attrs) = ct.attributes() {
                for attr in attrs {
                    s.push_str(&format!("; {}={}", attr.name, attr.value));
                }
            }
            s
        })
        .unwrap_or_else(|| "text/plain; charset=utf-8".to_string());

    let original_cte = message
        .parts
        .first()
        .and_then(|p| p.content_transfer_encoding())
        .unwrap_or("7bit");

    // Rebuild headers, replacing Content-Type with multipart/mixed.
    // RFC 5322 headers are 7-bit ASCII; use byte-level line scanning to
    // avoid lossy UTF-8 conversion that could corrupt binary preamble data.
    let new_headers = rebuild_headers_for_multipart(headers, &boundary)?;

    // Build the wrapped email as raw bytes to preserve binary body content.
    let mut result: Vec<u8> = Vec::new();
    result.extend_from_slice(&new_headers);
    result.extend_from_slice(b"\r\n");

    // Original body as first part
    result.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    result.extend_from_slice(format!("Content-Type: {}\r\n", original_ct).as_bytes());
    result.extend_from_slice(format!("Content-Transfer-Encoding: {}\r\n", original_cte).as_bytes());
    result.extend_from_slice(b"\r\n");
    result.extend_from_slice(body);
    if !body.ends_with(b"\r\n") && !body.ends_with(b"\n") {
        result.extend_from_slice(b"\r\n");
    }

    // JACS signature as second part
    let jacs_part = build_jacs_mime_part_bytes_named(&boundary, doc, filename);
    result.extend_from_slice(&jacs_part);

    // Closing boundary
    result.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

    Ok(result)
}

/// Ensure a raw email is `multipart/mixed` (without adding a JACS attachment).
///
/// If the email is already `multipart/mixed`, returns it unchanged.
/// Otherwise wraps it in a new `multipart/mixed` envelope with the original
/// content as the sole part. The closing boundary is left in place so that
/// `add_jacs_attachment` can insert before it.
///
/// This is used by `sign_email` to compute MIME header hashes AFTER wrapping,
/// ensuring they match what verification sees.
pub(crate) fn ensure_multipart_mixed(raw_email: &[u8]) -> Result<Vec<u8>, EmailError> {
    let message = MessageParser::default()
        .parse(raw_email)
        .ok_or_else(|| EmailError::InvalidEmailFormat("Cannot parse email for wrapping".into()))?;

    let content_type = message
        .content_type()
        .map(|ct| format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or("")));

    if content_type.as_deref() == Some("multipart/mixed") {
        return Ok(raw_email.to_vec());
    }

    // Wrap in multipart/mixed (same logic as wrap_in_multipart_mixed but
    // without the JACS part).
    let boundary = generate_boundary();

    let header_end = find_header_body_boundary(raw_email);
    let headers = &raw_email[..header_end];
    let body_start = skip_blank_line(raw_email, header_end);
    let body = &raw_email[body_start..];

    let original_ct = message
        .content_type()
        .map(|ct| {
            let mut s = format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or("plain"));
            if let Some(attrs) = ct.attributes() {
                for attr in attrs {
                    s.push_str(&format!("; {}={}", attr.name, attr.value));
                }
            }
            s
        })
        .unwrap_or_else(|| "text/plain; charset=utf-8".to_string());

    let original_cte = message
        .parts
        .first()
        .and_then(|p| p.content_transfer_encoding())
        .unwrap_or("7bit");

    // Use byte-level header rebuilding (no lossy UTF-8 conversion).
    let new_headers = rebuild_headers_for_multipart(headers, &boundary)?;

    // Build result as raw bytes to preserve binary body content.
    let mut result: Vec<u8> = Vec::new();
    result.extend_from_slice(&new_headers);
    result.extend_from_slice(b"\r\n");

    // Original body as first (and only) part
    result.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    result.extend_from_slice(format!("Content-Type: {}\r\n", original_ct).as_bytes());
    result.extend_from_slice(format!("Content-Transfer-Encoding: {}\r\n", original_cte).as_bytes());
    result.extend_from_slice(b"\r\n");
    result.extend_from_slice(body);
    if !body.ends_with(b"\r\n") && !body.ends_with(b"\n") {
        result.extend_from_slice(b"\r\n");
    }

    // Closing boundary
    result.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

    Ok(result)
}

/// Rebuild email headers at the byte level, replacing Content-Type with
/// multipart/mixed and removing Content-Transfer-Encoding.
///
/// RFC 5322 headers are 7-bit ASCII, so byte-level scanning is safe and
/// avoids lossy UTF-8 conversion that could corrupt adjacent binary data.
fn rebuild_headers_for_multipart(headers: &[u8], boundary: &str) -> Result<Vec<u8>, EmailError> {
    let mut result = Vec::new();
    let mut replaced_ct = false;
    let mut skip_current = false;
    let mut pos = 0;

    while pos < headers.len() {
        // Find end of this line (LF)
        let line_end = headers[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| pos + i + 1)
            .unwrap_or(headers.len());
        let line = &headers[pos..line_end];

        // Strip trailing CRLF for inspection
        let trimmed = strip_line_ending(line);

        if trimmed.is_empty() {
            break;
        }

        // Continuation line: starts with SP or TAB (RFC 5322 folding)
        if trimmed[0] == b' ' || trimmed[0] == b'\t' {
            if !skip_current {
                result.extend_from_slice(trimmed);
                result.extend_from_slice(b"\r\n");
            }
            pos = line_end;
            continue;
        }

        // New header line -- reset skip flag
        skip_current = false;
        let lower: Vec<u8> = trimmed.iter().map(|b| b.to_ascii_lowercase()).collect();

        if lower.starts_with(b"content-type:") {
            skip_current = true;
            if !replaced_ct {
                result.extend_from_slice(
                    format!(
                        "Content-Type: multipart/mixed; boundary=\"{}\"\r\n",
                        boundary
                    )
                    .as_bytes(),
                );
                replaced_ct = true;
            }
            pos = line_end;
            continue;
        }
        if lower.starts_with(b"content-transfer-encoding:") {
            skip_current = true;
            pos = line_end;
            continue;
        }

        result.extend_from_slice(trimmed);
        result.extend_from_slice(b"\r\n");
        pos = line_end;
    }

    if !replaced_ct {
        result.extend_from_slice(
            format!(
                "Content-Type: multipart/mixed; boundary=\"{}\"\r\n",
                boundary
            )
            .as_bytes(),
        );
    }

    Ok(result)
}

/// Strip trailing CR/LF from a line.
fn strip_line_ending(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    if end > 0 && line[end - 1] == b'\n' {
        end -= 1;
    }
    if end > 0 && line[end - 1] == b'\r' {
        end -= 1;
    }
    &line[..end]
}

/// Build the MIME part for a JACS signature attachment with a custom filename as raw bytes.
fn build_jacs_mime_part_bytes_named(boundary: &str, doc: &[u8], filename: &str) -> Vec<u8> {
    let mut part = Vec::new();
    part.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    part.extend_from_slice(
        format!("Content-Type: application/json; name=\"{}\"\r\n", filename).as_bytes(),
    );
    part.extend_from_slice(
        format!(
            "Content-Disposition: attachment; filename=\"{}\"\r\n",
            filename
        )
        .as_bytes(),
    );
    part.extend_from_slice(b"Content-Transfer-Encoding: 7bit\r\n");
    part.extend_from_slice(b"\r\n");
    part.extend_from_slice(doc);
    part.extend_from_slice(b"\r\n");
    part
}

/// Build the MIME part for the JACS signature attachment (default name) as raw bytes.
fn build_jacs_mime_part_bytes(boundary: &str, doc: &[u8]) -> Vec<u8> {
    build_jacs_mime_part_bytes_named(boundary, doc, DEFAULT_JACS_SIGNATURE_FILENAME)
}

/// Build the MIME part for the JACS signature attachment (named variant, UTF-8 string).
fn build_jacs_mime_part_named(boundary: &str, doc: &[u8], filename: &str) -> String {
    let bytes = build_jacs_mime_part_bytes_named(boundary, doc, filename);
    // JACS documents are JSON (valid UTF-8), so this conversion is safe.
    String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// Generate a unique MIME boundary string.
fn generate_boundary() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let random: u64 = rng.random();
    format!("jacs_{:016x}", random)
}

// Use shared implementation from canonicalize module (DRY).
use super::canonicalize::find_header_body_boundary;

/// Skip the blank line separator after headers.
fn skip_blank_line(raw: &[u8], header_end: usize) -> usize {
    let mut pos = header_end;
    if pos < raw.len() && raw[pos] == b'\r' {
        pos += 1;
    }
    if pos < raw.len() && raw[pos] == b'\n' {
        pos += 1;
    }
    if pos < raw.len() && raw[pos] == b'\r' {
        pos += 1;
    }
    if pos < raw.len() && raw[pos] == b'\n' {
        pos += 1;
    }
    pos
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_text_email() -> Vec<u8> {
        b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <test@example.com>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello World\r\n".to_vec()
    }

    fn multipart_mixed_email() -> Vec<u8> {
        b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <test@example.com>\r\nContent-Type: multipart/mixed; boundary=\"testboundary\"\r\n\r\n--testboundary\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello World\r\n--testboundary--\r\n".to_vec()
    }

    fn multipart_alternative_email() -> Vec<u8> {
        b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <test@example.com>\r\nContent-Type: multipart/alternative; boundary=\"altbound\"\r\n\r\n--altbound\r\nContent-Type: text/plain\r\n\r\nPlain text\r\n--altbound\r\nContent-Type: text/html\r\n\r\n<p>HTML</p>\r\n--altbound--\r\n".to_vec()
    }

    #[test]
    fn add_jacs_attachment_to_multipart_mixed() {
        let email = multipart_mixed_email();
        let doc = br#"{"test":"doc"}"#;
        let result = add_jacs_attachment(&email, doc).unwrap();
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains(DEFAULT_JACS_SIGNATURE_FILENAME));
        assert!(result_str.contains(r#"{"test":"doc"}"#));
        // Should still be parseable
        assert!(MessageParser::default().parse(&result).is_some());
    }

    #[test]
    fn add_jacs_attachment_to_multipart_alternative() {
        let email = multipart_alternative_email();
        let doc = br#"{"test":"doc"}"#;
        let result = add_jacs_attachment(&email, doc).unwrap();
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains(DEFAULT_JACS_SIGNATURE_FILENAME));
        // Original content should be preserved
        assert!(result_str.contains("Plain text") || result_str.contains("<p>HTML</p>"));
    }

    #[test]
    fn add_jacs_attachment_to_single_part() {
        let email = simple_text_email();
        let doc = br#"{"test":"doc"}"#;
        let result = add_jacs_attachment(&email, doc).unwrap();
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains(DEFAULT_JACS_SIGNATURE_FILENAME));
        assert!(result_str.contains("multipart/mixed"));
        // Original body should be preserved
        assert!(result_str.contains("Hello World"));
    }

    #[test]
    fn get_jacs_attachment_extracts_signature() {
        let email = simple_text_email();
        let doc = br#"{"version":"1.0"}"#;
        let signed = add_jacs_attachment(&email, doc).unwrap();
        let extracted = get_jacs_attachment(&signed).unwrap();
        assert_eq!(extracted, doc);
    }

    #[test]
    fn get_jacs_attachment_returns_error_when_missing() {
        let email = simple_text_email();
        let result = get_jacs_attachment(&email);
        assert!(result.is_err());
        match result.unwrap_err() {
            EmailError::MissingJacsSignature => {}
            other => panic!("Expected MissingJacsSignature, got {:?}", other),
        }
    }

    #[test]
    fn remove_jacs_attachment_removes_signature() {
        let email = simple_text_email();
        let doc = br#"{"version":"1.0"}"#;
        let signed = add_jacs_attachment(&email, doc).unwrap();

        // Verify it's there
        assert!(get_jacs_attachment(&signed).is_ok());

        let unsigned = remove_jacs_attachment(&signed).unwrap();

        // Verify it's gone
        assert!(get_jacs_attachment(&unsigned).is_err());

        // Should still be parseable
        assert!(MessageParser::default().parse(&unsigned).is_some());
    }

    #[test]
    fn roundtrip_add_then_get() {
        let email = simple_text_email();
        let doc = br#"{"payload":"test","hash":"sha256:abc"}"#;
        let signed = add_jacs_attachment(&email, doc).unwrap();
        let extracted = get_jacs_attachment(&signed).unwrap();
        assert_eq!(extracted, doc);
    }

    #[test]
    fn wrap_preserves_folded_subject_header() {
        // Regression test for Issue 024: continuation lines after Content-Type
        // replacement were incorrectly skipped, truncating folded headers.
        let email = b"From: sender@example.com\r\nTo: recipient@example.com\r\nContent-Type: text/plain;\r\n charset=utf-8\r\nSubject: This is a very long subject line that\r\n wraps to the next line\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <test@example.com>\r\n\r\nBody text\r\n";
        let doc = br#"{"test":"doc"}"#;
        let result = add_jacs_attachment(email, doc).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        // The Subject continuation line must be preserved
        assert!(
            result_str.contains("wraps to the next line"),
            "Subject continuation line was truncated: {}",
            result_str
        );
        // Content-Type should be replaced with multipart/mixed
        assert!(result_str.contains("multipart/mixed"));
        // Content-Type continuation (charset=utf-8) should NOT be in outer headers
        // (it moves to the inner part)
        let outer_headers = result_str.split("\r\n\r\n").next().unwrap();
        assert!(
            !outer_headers.contains(" charset=utf-8"),
            "Content-Type continuation should not be in outer headers"
        );
    }

    #[test]
    fn roundtrip_add_then_remove_parseable() {
        let email = multipart_mixed_email();
        let doc = br#"{"version":"1.0"}"#;
        let signed = add_jacs_attachment(&email, doc).unwrap();
        let unsigned = remove_jacs_attachment(&signed).unwrap();
        // Result should be parseable by mail-parser
        let parsed = MessageParser::default().parse(&unsigned);
        assert!(parsed.is_some());
    }

    // =====================================================================
    // _named variant tests
    // =====================================================================

    #[test]
    fn add_jacs_attachment_named_custom_name() {
        let email = simple_text_email();
        let doc = br#"{"test":"custom"}"#;
        let result = add_jacs_attachment_named(&email, doc, "hai.ai.signature.jacs.json").unwrap();
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("hai.ai.signature.jacs.json"));
        assert!(result_str.contains(r#"{"test":"custom"}"#));
    }

    #[test]
    fn get_jacs_attachment_named_finds_custom() {
        let email = simple_text_email();
        let doc = br#"{"version":"2.0"}"#;
        let signed = add_jacs_attachment_named(&email, doc, "custom.jacs.json").unwrap();
        let extracted = get_jacs_attachment_named(&signed, "custom.jacs.json").unwrap();
        assert_eq!(extracted, doc);
    }

    #[test]
    fn get_jacs_attachment_named_misses_wrong_name() {
        let email = simple_text_email();
        let doc = br#"{"v":"1"}"#;
        let signed = add_jacs_attachment_named(&email, doc, "custom.jacs.json").unwrap();
        // Looking for default name should fail
        let result = get_jacs_attachment(&signed);
        assert!(result.is_err());
    }

    #[test]
    fn default_attachment_name_unchanged() {
        // Default functions still use jacs-signature.json
        let email = simple_text_email();
        let doc = br#"{"test":"default"}"#;
        let result = add_jacs_attachment(&email, doc).unwrap();
        let result_str = String::from_utf8_lossy(&result);
        assert!(
            result_str.contains("jacs-signature.json"),
            "Default should use jacs-signature.json, got: {}",
            result_str
        );
    }

    #[test]
    fn remove_jacs_attachment_named_removes_custom() {
        let email = simple_text_email();
        let doc = br#"{"v":"1"}"#;
        let signed = add_jacs_attachment_named(&email, doc, "hai.ai.signature.jacs.json").unwrap();
        assert!(get_jacs_attachment_named(&signed, "hai.ai.signature.jacs.json").is_ok());

        let unsigned = remove_jacs_attachment_named(&signed, "hai.ai.signature.jacs.json").unwrap();
        assert!(get_jacs_attachment_named(&unsigned, "hai.ai.signature.jacs.json").is_err());
        assert!(MessageParser::default().parse(&unsigned).is_some());
    }
}
