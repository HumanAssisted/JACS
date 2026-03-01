//! JACS attachment operations for raw RFC 5322 email bytes.
//!
//! Implements add/get/remove operations for the `jacs-signature.json`
//! MIME attachment. Works entirely at the raw byte level -- no
//! re-serialization libraries are used.

use mail_parser::{MessageParser, MimeHeaders as _};

use super::error::EmailError;

/// Name of the active JACS signature attachment.
const JACS_SIGNATURE_FILENAME: &str = "jacs-signature.json";

/// Add a `jacs-signature.json` attachment to a raw RFC 5322 email.
///
/// - If the email is already `multipart/mixed`: insert a new MIME part before the closing boundary.
/// - If the email is `multipart/alternative` or single-part: wrap in a new `multipart/mixed` envelope.
///
/// Returns the new raw email bytes with the attachment included.
pub fn add_jacs_attachment(raw_email: &[u8], doc: &[u8]) -> Result<Vec<u8>, EmailError> {
    let message = MessageParser::default()
        .parse(raw_email)
        .ok_or_else(|| EmailError::InvalidEmailFormat("Cannot parse email for attachment injection".into()))?;

    let content_type = message
        .content_type()
        .map(|ct| format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or("")));

    match content_type.as_deref() {
        Some("multipart/mixed") => {
            // Find the boundary
            let boundary = message
                .content_type()
                .and_then(|ct| ct.attribute("boundary"))
                .ok_or_else(|| EmailError::InvalidEmailFormat("multipart/mixed without boundary".into()))?
                .to_string();
            insert_part_before_closing_boundary(raw_email, &boundary, doc)
        }
        Some(ct) if ct.starts_with("multipart/") => {
            // Wrap in multipart/mixed
            wrap_in_multipart_mixed(raw_email, doc)
        }
        _ => {
            // Single-part email: wrap in multipart/mixed
            wrap_in_multipart_mixed(raw_email, doc)
        }
    }
}

/// Extract the `jacs-signature.json` attachment from a raw RFC 5322 email.
///
/// Returns the raw bytes of the attachment content (MIME-decoded).
pub fn get_jacs_attachment(raw_email: &[u8]) -> Result<Vec<u8>, EmailError> {
    let message = MessageParser::default()
        .parse(raw_email)
        .ok_or_else(|| EmailError::InvalidEmailFormat("Cannot parse email for attachment extraction".into()))?;

    for part in message.parts.iter() {
        let filename = part
            .attachment_name()
            .or_else(|| part.content_type().and_then(|ct| ct.attribute("name")));

        if let Some(name) = filename {
            if name == JACS_SIGNATURE_FILENAME {
                return Ok(part.contents().to_vec());
            }
        }
    }

    Err(EmailError::MissingJacsSignature)
}

/// Remove the `jacs-signature.json` MIME part from a raw email.
///
/// Returns the email without the JACS attachment. The result is valid RFC 5322.
pub fn remove_jacs_attachment(raw_email: &[u8]) -> Result<Vec<u8>, EmailError> {
    let message = MessageParser::default()
        .parse(raw_email)
        .ok_or_else(|| EmailError::InvalidEmailFormat("Cannot parse email for attachment removal".into()))?;

    // Find the JACS part to remove
    let mut jacs_part_idx = None;
    for (idx, part) in message.parts.iter().enumerate() {
        let filename = part
            .attachment_name()
            .or_else(|| part.content_type().and_then(|ct| ct.attribute("name")));
        if let Some(name) = filename {
            if name == JACS_SIGNATURE_FILENAME {
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
        // Remove the MIME part including its boundary prefix
        let boundary_marker = format!("--{}", boundary);
        let before_part = &raw_email[..header_offset];

        // Find the boundary line before this part
        let before_str = String::from_utf8_lossy(before_part);
        if let Some(boundary_start) = before_str.rfind(&boundary_marker) {
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

/// Insert a JACS part before the closing boundary of a multipart/mixed email.
fn insert_part_before_closing_boundary(
    raw_email: &[u8],
    boundary: &str,
    doc: &[u8],
) -> Result<Vec<u8>, EmailError> {
    let closing = format!("--{}--", boundary);
    let email_str = String::from_utf8_lossy(raw_email);

    let closing_pos = email_str.rfind(&closing).ok_or_else(|| {
        EmailError::InvalidEmailFormat("Cannot find closing boundary in multipart/mixed".into())
    })?;

    let jacs_part = build_jacs_mime_part(boundary, doc);

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

/// Wrap a non-multipart/mixed email in a new multipart/mixed envelope.
fn wrap_in_multipart_mixed(raw_email: &[u8], doc: &[u8]) -> Result<Vec<u8>, EmailError> {
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
    // Track whether the *current* header is one being removed so that only
    // its continuation lines are skipped (not continuations of other headers).
    let headers_str = String::from_utf8_lossy(headers);
    let mut new_headers = String::new();
    let mut replaced_ct = false;
    let mut skip_current = false;

    for line in headers_str.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        // Continuation line: starts with SP or TAB (RFC 5322 folding)
        if line.starts_with(' ') || line.starts_with('\t') {
            if skip_current {
                continue; // continuation of a removed header
            }
            new_headers.push_str(line);
            new_headers.push_str("\r\n");
            continue;
        }
        // New header line -- reset skip flag
        skip_current = false;
        let lower = line.to_lowercase();
        if lower.starts_with("content-type:") {
            skip_current = true;
            if !replaced_ct {
                new_headers.push_str(&format!(
                    "Content-Type: multipart/mixed; boundary=\"{}\"\r\n",
                    boundary
                ));
                replaced_ct = true;
            }
            continue;
        }
        if lower.starts_with("content-transfer-encoding:") {
            skip_current = true;
            continue;
        }
        new_headers.push_str(line);
        new_headers.push_str("\r\n");
    }

    if !replaced_ct {
        new_headers.push_str(&format!(
            "Content-Type: multipart/mixed; boundary=\"{}\"\r\n",
            boundary
        ));
    }

    // Build the wrapped email
    let mut result = String::new();
    result.push_str(&new_headers);
    result.push_str("\r\n");

    // Original body as first part
    result.push_str(&format!("--{}\r\n", boundary));
    result.push_str(&format!("Content-Type: {}\r\n", original_ct));
    result.push_str(&format!("Content-Transfer-Encoding: {}\r\n", original_cte));
    result.push_str("\r\n");
    result.push_str(&String::from_utf8_lossy(body));
    if !body.ends_with(b"\r\n") && !body.ends_with(b"\n") {
        result.push_str("\r\n");
    }

    // JACS signature as second part
    let jacs_part = build_jacs_mime_part(&boundary, doc);
    result.push_str(&jacs_part);

    // Closing boundary
    result.push_str(&format!("--{}--\r\n", boundary));

    Ok(result.into_bytes())
}

/// Build the MIME part for the JACS signature attachment.
fn build_jacs_mime_part(boundary: &str, doc: &[u8]) -> String {
    let mut part = String::new();
    part.push_str(&format!("--{}\r\n", boundary));
    part.push_str("Content-Type: application/json; name=\"jacs-signature.json\"\r\n");
    part.push_str(
        "Content-Disposition: attachment; filename=\"jacs-signature.json\"\r\n",
    );
    part.push_str("Content-Transfer-Encoding: 7bit\r\n");
    part.push_str("\r\n");
    part.push_str(&String::from_utf8_lossy(doc));
    part.push_str("\r\n");
    part
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
        assert!(result_str.contains("jacs-signature.json"));
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
        assert!(result_str.contains("jacs-signature.json"));
        // Original content should be preserved
        assert!(result_str.contains("Plain text") || result_str.contains("<p>HTML</p>"));
    }

    #[test]
    fn add_jacs_attachment_to_single_part() {
        let email = simple_text_email();
        let doc = br#"{"test":"doc"}"#;
        let result = add_jacs_attachment(&email, doc).unwrap();
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("jacs-signature.json"));
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
}
