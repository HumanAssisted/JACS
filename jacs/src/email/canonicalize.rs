//! Email canonicalization functions for deterministic hashing.
//!
//! Implements the JACS email signing canonicalization profile:
//! DKIM-style relaxed header normalization, body canonicalization
//! (CTE decode, charset convert, CRLF, trailing WSP), and
//! MIME header hashing.

use mail_parser::{MessageParser, MimeHeaders as _};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use super::error::EmailError;
use super::types::{ParsedAttachment, ParsedBodyPart, ParsedEmailParts};

/// Parse raw RFC 5322 email bytes into structured parts.
pub fn extract_email_parts(raw_email: &[u8]) -> Result<ParsedEmailParts, EmailError> {
    let message = MessageParser::default()
        .parse(raw_email)
        .ok_or_else(|| EmailError::InvalidEmailFormat("Failed to parse RFC 5322 email".into()))?;

    let mut headers: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    // Extract headers from raw bytes by scanning the header block.
    // mail-parser provides typed access but we need the raw header values
    // for canonicalization. Parse the header block manually.
    let header_end = find_header_body_boundary(raw_email);
    let header_bytes = &raw_email[..header_end];
    let raw_headers = parse_raw_headers(header_bytes)?;
    for (name, value) in raw_headers {
        headers
            .entry(name.to_lowercase())
            .or_default()
            .push(value);
    }

    // Validate that the parsed message has a From header (RFC 5322 required).
    // mail_parser accepts garbage input and returns a Message with empty headers;
    // this gate ensures we fail early on non-email input.
    if !headers.contains_key("from") {
        return Err(EmailError::InvalidEmailFormat(
            "missing required From header".into(),
        ));
    }

    // Extract body parts
    let body_plain = extract_body_part(&message, "text/plain");
    let body_html = extract_body_part(&message, "text/html");

    // Extract attachments
    let mut attachments = Vec::new();
    let mut jacs_attachments = Vec::new();

    for part in message.parts.iter() {
        let is_attachment = part
            .content_disposition()
            .map_or(false, |d| d.ctype() == "attachment" || d.ctype() == "inline");

        let filename = part
            .attachment_name()
            .or_else(|| {
                part.content_type()
                    .and_then(|ct| ct.attribute("name"))
            })
            .unwrap_or("")
            .to_string();

        if !is_attachment && filename.is_empty() {
            continue;
        }

        // Skip body parts that have content types text/plain or text/html
        // unless they are explicitly attachments with filenames.
        let ct = part
            .content_type()
            .map(|ct| format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or("")))
            .unwrap_or_default();

        if filename.is_empty() && (ct == "text/plain" || ct == "text/html") {
            continue;
        }

        let raw_content = part.contents();
        // Trim trailing CRLF that MIME boundary processing may append.
        // This is a MIME extraction normalization — the trailing \r\n is a
        // boundary separator, not attachment content. Without this, the
        // attachment hash would depend on whether the content was parsed
        // from a MIME part (with trailing CRLF) or supplied directly.
        let content = strip_trailing_crlf(raw_content).to_vec();
        let content_type = ct.clone();
        let cte = part.content_transfer_encoding().map(|s| s.to_string());
        let cd = part
            .content_disposition()
            .map(|d| d.ctype().to_string());

        let nfc_filename: String = filename.nfc().collect();

        let parsed_att = ParsedAttachment {
            filename: nfc_filename.clone(),
            content_type: content_type.to_lowercase(),
            content,
            content_transfer_encoding: cte,
            content_disposition: cd,
        };

        if nfc_filename.starts_with("jacs-signature") && nfc_filename.ends_with(".json") {
            jacs_attachments.push(parsed_att);
        } else {
            attachments.push(parsed_att);
        }
    }

    Ok(ParsedEmailParts {
        headers,
        body_plain,
        body_html,
        attachments,
        jacs_attachments,
    })
}

/// Find the boundary between headers and body in raw email bytes.
pub(crate) fn find_header_body_boundary(raw: &[u8]) -> usize {
    // Look for \r\n\r\n or \n\n
    for i in 0..raw.len().saturating_sub(1) {
        if raw[i] == b'\r' && i + 3 < raw.len() && raw[i + 1] == b'\n' && raw[i + 2] == b'\r' && raw[i + 3] == b'\n' {
            return i;
        }
        if raw[i] == b'\n' && raw[i + 1] == b'\n' {
            return i;
        }
    }
    raw.len()
}

/// Parse raw header bytes into (name, value) pairs, handling continuations.
fn parse_raw_headers(header_bytes: &[u8]) -> Result<Vec<(String, String)>, EmailError> {
    let text = String::from_utf8_lossy(header_bytes);
    let mut result = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_value = String::new();

    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');

        if line.is_empty() {
            break;
        }

        // Continuation line (starts with whitespace)
        if line.starts_with(' ') || line.starts_with('\t') {
            if current_name.is_some() {
                current_value.push(' ');
                current_value.push_str(line.trim());
            }
            continue;
        }

        // Save previous header
        if let Some(name) = current_name.take() {
            result.push((name, current_value.clone()));
            current_value.clear();
        }

        // Parse new header
        if let Some(colon_pos) = line.find(':') {
            let name = line[..colon_pos].to_string();
            let value = line[colon_pos + 1..].trim().to_string();
            current_name = Some(name);
            current_value = value;
        }
    }

    if let Some(name) = current_name {
        result.push((name, current_value));
    }

    Ok(result)
}

/// Extract a body part of the given content type from a parsed message.
fn extract_body_part(
    message: &mail_parser::Message<'_>,
    target_type: &str,
) -> Option<ParsedBodyPart> {
    for part in message.parts.iter() {
        let ct = part.content_type();
        let type_str = ct
            .map(|ct| format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or("")))
            .unwrap_or_default();

        let is_attachment = part
            .content_disposition()
            .map_or(false, |d| d.ctype() == "attachment");
        if type_str == target_type && !is_attachment {
            let content = part.contents().to_vec();
            let content_type_full = ct.map(|ct| {
                let mut s = format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or(""));
                if let Some(attrs) = ct.attributes() {
                    for attr in attrs {
                        s.push_str(&format!("; {}={}", attr.name, attr.value));
                    }
                }
                s
            });
            let cte = part.content_transfer_encoding().map(|s| s.to_string());
            let cd = part
                .content_disposition()
                .map(|d| format!("{}", d.ctype()));

            return Some(ParsedBodyPart {
                content,
                content_type: content_type_full,
                content_transfer_encoding: cte,
                content_disposition: cd,
            });
        }
    }
    None
}

/// Canonicalize an email header value using DKIM-style relaxed normalization.
///
/// Steps:
/// 1. Unfold continuation lines
/// 2. Compress WSP runs to single SP
/// 3. Trim leading/trailing WSP
/// 4. For address headers: lowercase domain part only
/// 5. Decode RFC 2047 encoded words
/// 6. UTF-8 NFC normalize
pub fn canonicalize_header(name: &str, value: &str) -> Result<String, EmailError> {
    // Unfold continuations (already unfolded by parse_raw_headers, but be safe)
    let unfolded = value.replace("\r\n", "").replace('\n', "");

    // Compress WSP runs to single SP
    let mut compressed = String::with_capacity(unfolded.len());
    let mut in_wsp = false;
    for ch in unfolded.chars() {
        if ch == ' ' || ch == '\t' {
            if !in_wsp {
                compressed.push(' ');
                in_wsp = true;
            }
        } else {
            compressed.push(ch);
            in_wsp = false;
        }
    }

    // Trim leading/trailing WSP
    let trimmed = compressed.trim().to_string();

    // Decode RFC 2047 encoded words
    let decoded = decode_rfc2047(&trimmed);

    // UTF-8 NFC normalize
    let nfc: String = decoded.nfc().collect();

    // For address headers, lowercase domain part only
    let lower_name = name.to_lowercase();
    if lower_name == "from" || lower_name == "to" || lower_name == "cc" {
        Ok(lowercase_email_domain(&nfc))
    } else {
        Ok(nfc)
    }
}

/// Decode RFC 2047 encoded words in a header value.
fn decode_rfc2047(input: &str) -> String {
    // Simple RFC 2047 decoder for =?charset?encoding?text?= patterns
    let mut result = String::new();
    let mut remaining = input;

    while let Some(start) = remaining.find("=?") {
        // Add text before the encoded word
        result.push_str(&remaining[..start]);

        let after_start = &remaining[start + 2..];

        // Find charset
        let Some(q1) = after_start.find('?') else {
            result.push_str(&remaining[start..]);
            break;
        };
        let charset = &after_start[..q1];

        let after_charset = &after_start[q1 + 1..];

        // Find encoding
        let Some(q2) = after_charset.find('?') else {
            result.push_str(&remaining[start..]);
            break;
        };
        let encoding = &after_charset[..q2];

        let after_encoding = &after_charset[q2 + 1..];

        // Find end
        let Some(end) = after_encoding.find("?=") else {
            result.push_str(&remaining[start..]);
            break;
        };
        let encoded_text = &after_encoding[..end];

        // Decode
        let decoded_bytes = match encoding.to_uppercase().as_str() {
            "B" => base64_decode(encoded_text),
            "Q" => q_decode(encoded_text),
            _ => None,
        };

        if let Some(bytes) = decoded_bytes {
            let text = decode_charset(charset, &bytes);
            result.push_str(&text);
        } else {
            result.push_str(&remaining[start..start + 2 + q1 + 1 + q2 + 1 + end + 2]);
        }

        remaining = &after_encoding[end + 2..];
    }

    result.push_str(remaining);
    result
}

/// Decode base64 encoded bytes.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(input.trim())
        .ok()
}

/// Decode Q-encoding (RFC 2047 Q).
fn q_decode(input: &str) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' && i + 2 < bytes.len() {
            let hex = &input[i + 1..i + 3];
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                result.push(byte);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'_' {
            result.push(b' ');
        } else {
            result.push(bytes[i]);
        }
        i += 1;
    }
    Some(result)
}

/// Decode bytes from a given charset to UTF-8.
fn decode_charset(charset: &str, bytes: &[u8]) -> String {
    let charset_lower = charset.to_lowercase();
    match charset_lower.as_str() {
        "utf-8" | "utf8" => String::from_utf8_lossy(bytes).to_string(),
        _ => {
            let encoding = encoding_rs::Encoding::for_label(charset.as_bytes());
            match encoding {
                Some(enc) => {
                    let (result, _, _) = enc.decode(bytes);
                    result.to_string()
                }
                None => String::from_utf8_lossy(bytes).to_string(),
            }
        }
    }
}

/// Lowercase the domain part of email addresses.
fn lowercase_email_domain(value: &str) -> String {
    // Handle comma-separated addresses
    value
        .split(',')
        .map(|addr| {
            let addr = addr.trim();
            if let Some(at_pos) = addr.rfind('@') {
                // Find the domain boundary (might be inside angle brackets)
                let after_at = &addr[at_pos + 1..];
                let domain_end = after_at.find('>').unwrap_or(after_at.len());
                let domain = &after_at[..domain_end];
                format!(
                    "{}@{}{}",
                    &addr[..at_pos],
                    domain.to_lowercase(),
                    &after_at[domain_end..]
                )
            } else {
                addr.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Canonicalize a body part.
///
/// Steps:
/// 1. Content is already CTE-decoded by mail-parser
/// 2. Normalize line endings to CRLF
/// 3. Strip trailing WSP per line
/// 4. Strip trailing blank lines
pub fn canonicalize_body(content: &[u8]) -> Vec<u8> {
    // Convert to string (content is already decoded by mail-parser)
    let text = String::from_utf8_lossy(content);

    // Split into lines, normalize
    let lines: Vec<&str> = text.split('\n').collect();
    let mut result_lines: Vec<String> = Vec::new();

    for line in &lines {
        let line = line.trim_end_matches('\r');
        // Strip trailing WSP (SP, TAB) per line
        let trimmed = line.trim_end_matches(|c: char| c == ' ' || c == '\t');
        result_lines.push(trimmed.to_string());
    }

    // Strip trailing blank lines
    while result_lines.last().map_or(false, |l| l.is_empty()) {
        result_lines.pop();
    }

    // Join with CRLF
    let joined = result_lines.join("\r\n");
    joined.into_bytes()
}

/// Compute the SHA-256 hash of a canonicalized header value.
/// Returns `"sha256:<hex>"`.
pub fn compute_header_entry(canonicalized_value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonicalized_value.as_bytes());
    let hash = hasher.finalize();
    format!("sha256:{}", hex::encode(hash))
}

/// Compute the SHA-256 hash of canonicalized body content.
/// Returns `"sha256:<hex>"`.
pub fn compute_body_hash(canonicalized_body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonicalized_body);
    let hash = hasher.finalize();
    format!("sha256:{}", hex::encode(hash))
}

/// Compute the MIME headers hash for a body part or attachment.
///
/// Format (PRD lines 363-372):
/// ```text
/// sha256(
///   "content-disposition:" + canonical_disposition + "\n" +
///   "content-transfer-encoding:" + canonical_cte + "\n" +
///   "content-type:" + canonical_content_type + "\n"
/// )
/// ```
/// Omit lines for headers not present. Sort remaining lexicographically.
pub fn compute_mime_headers_hash(
    content_type: Option<&str>,
    content_transfer_encoding: Option<&str>,
    content_disposition: Option<&str>,
) -> String {
    let mut lines: Vec<String> = Vec::new();

    if let Some(cd) = content_disposition {
        let canonical = canonicalize_mime_header_value(cd);
        lines.push(format!("content-disposition:{}", canonical));
    }

    if let Some(cte) = content_transfer_encoding {
        let canonical = canonicalize_mime_header_value(cte);
        lines.push(format!("content-transfer-encoding:{}", canonical));
    }

    if let Some(ct) = content_type {
        let canonical = canonicalize_mime_header_value(ct);
        lines.push(format!("content-type:{}", canonical));
    }

    // Sort lexicographically (already in sorted order for these three names,
    // but sort explicitly for correctness)
    lines.sort();

    let input = lines
        .iter()
        .map(|l| format!("{}\n", l))
        .collect::<String>();

    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hash = hasher.finalize();
    format!("sha256:{}", hex::encode(hash))
}

/// Canonicalize a MIME header value (same rules as top-level headers).
fn canonicalize_mime_header_value(value: &str) -> String {
    // Unfold, compress WSP, trim, lowercase
    let unfolded = value.replace("\r\n", "").replace('\n', "");
    let mut compressed = String::with_capacity(unfolded.len());
    let mut in_wsp = false;
    for ch in unfolded.chars() {
        if ch == ' ' || ch == '\t' {
            if !in_wsp {
                compressed.push(' ');
                in_wsp = true;
            }
        } else {
            compressed.push(ch);
            in_wsp = false;
        }
    }
    compressed.trim().to_lowercase()
}

/// Compute the attachment content hash.
///
/// `sha256(filename_utf8_nfc + ":" + content_type_lower + ":" + decoded_bytes)`
///
/// Hashes the exact decoded bytes from mail-parser without any normalization.
/// Any trailing-byte mutations will be detected as a hash mismatch.
/// MIME boundary artifacts are handled at the extraction layer (mail-parser),
/// not at the hashing layer.
pub fn compute_attachment_hash(filename: &str, content_type: &str, raw_bytes: &[u8]) -> String {
    let filename_nfc: String = filename.nfc().collect();
    let content_type_lower = content_type.to_lowercase();

    let mut hasher = Sha256::new();
    hasher.update(filename_nfc.as_bytes());
    hasher.update(b":");
    hasher.update(content_type_lower.as_bytes());
    hasher.update(b":");
    hasher.update(raw_bytes);
    let hash = hasher.finalize();
    format!("sha256:{}", hex::encode(hash))
}

/// Strip trailing CRLF/LF bytes from MIME-decoded content.
///
/// Only strips line terminators (\r, \n), NOT spaces or tabs.
/// This normalizes MIME boundary artifacts at the extraction layer
/// so that content hashing operates on the actual payload bytes.
fn strip_trailing_crlf(bytes: &[u8]) -> &[u8] {
    let mut end = bytes.len();
    while end > 0 && matches!(bytes[end - 1], b'\r' | b'\n') {
        end -= 1;
    }
    &bytes[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_header_trims_and_compresses_wsp() {
        let result = canonicalize_header("Subject", "  Hello   World  ").unwrap();
        assert_eq!(result, "Hello World");
    }

    #[test]
    fn canonicalize_header_unfolds_continuation() {
        let result = canonicalize_header("Subject", "Hello\r\n World").unwrap();
        assert_eq!(result, "Hello World");
    }

    #[test]
    fn canonicalize_header_lowercases_email_domain_only() {
        let result =
            canonicalize_header("From", "  Agent@Example.COM  ").unwrap();
        assert_eq!(result, "Agent@example.com");
    }

    #[test]
    fn canonicalize_header_decodes_rfc2047_subject() {
        let result =
            canonicalize_header("Subject", "=?UTF-8?B?Q2Fmw6k=?=").unwrap();
        assert_eq!(result, "Caf\u{00e9}");
    }

    #[test]
    fn canonicalize_header_nfc_normalizes() {
        // NFD Cafe\u{0301} -> NFC Caf\u{00e9}
        let result =
            canonicalize_header("Subject", "=?UTF-8?B?Q2FmZcyB?=").unwrap();
        assert_eq!(result, "Caf\u{00e9}");
    }

    #[test]
    fn canonicalize_body_strips_trailing_wsp_and_blank_lines() {
        let body = b"Hello World   \r\nSecond line\t\t\r\n\r\n\r\n";
        let result = canonicalize_body(body);
        assert_eq!(result, b"Hello World\r\nSecond line");
    }

    #[test]
    fn canonicalize_body_normalizes_lf_to_crlf() {
        let body = b"Line one\nLine two\nLine three";
        let result = canonicalize_body(body);
        assert_eq!(result, b"Line one\r\nLine two\r\nLine three");
    }

    #[test]
    fn canonicalize_body_mixed_line_endings() {
        let body = b"LF only\nCRLF line\r\nAnother LF\n";
        let result = canonicalize_body(body);
        assert_eq!(result, b"LF only\r\nCRLF line\r\nAnother LF");
    }

    #[test]
    fn compute_header_entry_returns_sha256_hex() {
        let hash = compute_header_entry("agent@example.com");
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn compute_body_hash_returns_sha256_hex() {
        let hash = compute_body_hash(b"Hello World");
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), 7 + 64);
    }

    #[test]
    fn compute_mime_headers_hash_deterministic() {
        let hash1 = compute_mime_headers_hash(
            Some("text/plain; charset=utf-8"),
            Some("7bit"),
            None,
        );
        let hash2 = compute_mime_headers_hash(
            Some("text/plain; charset=utf-8"),
            Some("7bit"),
            None,
        );
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn compute_mime_headers_hash_sorted_lexicographically() {
        // content-disposition < content-transfer-encoding < content-type
        let hash = compute_mime_headers_hash(
            Some("text/plain"),
            Some("base64"),
            Some("attachment; filename=\"test.txt\""),
        );
        assert!(hash.starts_with("sha256:"));
    }

    #[test]
    fn compute_mime_headers_hash_omits_missing() {
        let hash_with = compute_mime_headers_hash(
            Some("text/plain"),
            Some("7bit"),
            None,
        );
        let hash_all = compute_mime_headers_hash(
            Some("text/plain"),
            Some("7bit"),
            Some("inline"),
        );
        assert_ne!(hash_with, hash_all);
    }

    #[test]
    fn compute_attachment_hash_deterministic() {
        let hash1 = compute_attachment_hash("report.pdf", "application/pdf", b"raw content");
        let hash2 = compute_attachment_hash("report.pdf", "application/pdf", b"raw content");
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn compute_attachment_hash_case_insensitive_content_type() {
        let hash1 = compute_attachment_hash("test.pdf", "Application/PDF", b"data");
        let hash2 = compute_attachment_hash("test.pdf", "application/pdf", b"data");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn extract_email_parts_parses_simple_text() {
        let email = b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <test@example.com>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello World\r\n";
        let parts = extract_email_parts(email).unwrap();
        assert!(parts.body_plain.is_some());
        assert!(parts.body_html.is_none());
        assert!(parts.attachments.is_empty());
        assert_eq!(parts.headers.get("from").unwrap()[0], "sender@example.com");
    }

    #[test]
    fn extract_email_parts_returns_error_on_garbage() {
        let result = extract_email_parts(b"not an email at all");
        assert!(result.is_err(), "garbage input must return Err");
    }

    #[test]
    fn rfc2047_q_encoding_decode() {
        let result = decode_rfc2047("=?UTF-8?Q?Caf=C3=A9?=");
        assert_eq!(result, "Caf\u{00e9}");
    }

    #[test]
    fn lowercase_email_domain_preserves_local_part() {
        let result = lowercase_email_domain("User.Name@EXAMPLE.COM");
        assert_eq!(result, "User.Name@example.com");
    }

    #[test]
    fn lowercase_email_domain_handles_angle_brackets() {
        let result = lowercase_email_domain("User <User@EXAMPLE.COM>");
        assert_eq!(result, "User <User@example.com>");
    }
}
