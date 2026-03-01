//! Email signing implementation for the JACS email system.
//!
//! Provides `sign_email()` which takes raw RFC 5322 email bytes and an
//! `EmailSigner`, and returns the email with a `jacs-signature.json`
//! MIME attachment containing the JACS email signature document.

use base64::Engine;
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::attachment::{add_jacs_attachment, get_jacs_attachment, remove_jacs_attachment};
use super::canonicalize::{
    canonicalize_body, canonicalize_header, compute_attachment_hash, compute_body_hash,
    compute_header_entry, compute_mime_headers_hash, extract_email_parts,
};
use super::error::{check_email_size, EmailError};
use super::types::{
    AttachmentEntry, BodyPartEntry, EmailSignatureHeaders, EmailSignaturePayload,
    JacsEmailMetadata, JacsEmailSignature, JacsEmailSignatureDocument, SignedHeaderEntry,
};

/// Trait for signing email payloads.
///
/// This is the minimal interface required by `sign_email()`. Implementations
/// typically delegate to a JACS `Agent` or an `haisdk::JacsProvider`.
pub trait EmailSigner {
    /// Sign raw bytes and return the signature bytes.
    fn sign_bytes(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>>;

    /// Return the signer's JACS agent ID.
    fn jacs_id(&self) -> &str;

    /// Return the key identifier used for signing.
    fn key_id(&self) -> &str;

    /// Return the signing algorithm name (e.g., "ed25519").
    fn algorithm(&self) -> &str;
}

/// Sign a raw RFC 5322 email and attach a `jacs-signature.json` document.
///
/// This is the primary sender-side function. It:
/// 1. Parses and canonicalizes the email
/// 2. Computes hashes for headers, body parts, and attachments
/// 3. Builds the JACS email signature document
/// 4. Signs the canonical payload
/// 5. Attaches the signature as a MIME part
///
/// Returns the modified email bytes with the JACS attachment.
pub fn sign_email(
    raw_email: &[u8],
    signer: &dyn EmailSigner,
) -> Result<Vec<u8>, EmailError> {
    // Step 0: Size check
    check_email_size(raw_email)?;

    // Step 0b: Check for existing JACS signature (forwarding case)
    let (email_for_signing, parent_signature_hash) =
        prepare_for_forwarding(raw_email)?;

    // Step 1: Parse and canonicalize (from the prepared email)
    let parts = extract_email_parts(&email_for_signing)?;

    // Step 2: Build signed headers
    let headers = build_signed_headers(&parts)?;

    // Step 3: Build body part entries
    let body_plain = parts.body_plain.as_ref().map(|bp| {
        let canonical = canonicalize_body(&bp.content);
        let content_hash = compute_body_hash(&canonical);
        let mime_headers_hash = compute_mime_headers_hash(
            bp.content_type.as_deref(),
            bp.content_transfer_encoding.as_deref(),
            bp.content_disposition.as_deref(),
        );
        BodyPartEntry {
            content_hash,
            mime_headers_hash,
        }
    });

    let body_html = parts.body_html.as_ref().map(|bp| {
        let canonical = canonicalize_body(&bp.content);
        let content_hash = compute_body_hash(&canonical);
        let mime_headers_hash = compute_mime_headers_hash(
            bp.content_type.as_deref(),
            bp.content_transfer_encoding.as_deref(),
            bp.content_disposition.as_deref(),
        );
        BodyPartEntry {
            content_hash,
            mime_headers_hash,
        }
    });

    // Step 4: Build attachment entries (sorted by content_hash)
    // For forwarding, this includes the renamed jacs-signature-N.json files
    // as regular attachments (they appear in parts.attachments after renaming)
    let mut all_attachments = parts.attachments.clone();
    // Also include jacs_attachments (the renamed parent signatures) as regular attachments
    for jacs_att in &parts.jacs_attachments {
        all_attachments.push(jacs_att.clone());
    }

    let mut attachment_entries: Vec<AttachmentEntry> = all_attachments
        .iter()
        .map(|att| {
            let content_hash =
                compute_attachment_hash(&att.filename, &att.content_type, &att.content);
            let mime_headers_hash = compute_mime_headers_hash(
                Some(&att.content_type),
                att.content_transfer_encoding.as_deref(),
                att.content_disposition.as_deref(),
            );
            AttachmentEntry {
                content_hash,
                mime_headers_hash,
                filename: att.filename.clone(),
            }
        })
        .collect();
    attachment_entries.sort_by(|a, b| a.content_hash.cmp(&b.content_hash));

    // Step 5: Build payload
    let payload = EmailSignaturePayload {
        headers,
        body_plain,
        body_html,
        attachments: attachment_entries,
        parent_signature_hash,
    };

    // Step 6: Build the complete JACS email signature document
    let doc = build_jacs_email_document(&payload, signer)?;

    // Step 7: Serialize to JSON
    let doc_json = serde_json::to_string(&doc)
        .map_err(|e| EmailError::InvalidJacsDocument(format!("failed to serialize: {e}")))?;

    // Step 8: Attach via add_jacs_attachment (to the prepared email, not the original)
    add_jacs_attachment(&email_for_signing, doc_json.as_bytes())
}

/// Prepare an email for signing, handling the forwarding case.
///
/// If the email already has a `jacs-signature.json` attachment:
/// 1. Extract it and compute its SHA-256 hash (becomes parent_signature_hash)
/// 2. Remove the active `jacs-signature.json`
/// 3. Re-attach it as `jacs-signature-{N}.json` where N is the next index
///
/// Returns (prepared_email_bytes, parent_signature_hash_option).
fn prepare_for_forwarding(
    raw_email: &[u8],
) -> Result<(Vec<u8>, Option<String>), EmailError> {
    // Try to extract the existing jacs-signature.json
    let jacs_bytes = match get_jacs_attachment(raw_email) {
        Ok(bytes) => bytes,
        Err(EmailError::MissingJacsSignature) => {
            // No existing signature -- not a forward
            return Ok((raw_email.to_vec(), None));
        }
        Err(e) => return Err(e),
    };

    // Compute parent_signature_hash = sha256(normalized bytes of existing jacs-signature.json)
    // Strip trailing whitespace for consistency with verification-side hash computation
    let trimmed_jacs_bytes = strip_trailing_ws(&jacs_bytes);
    let parent_hash = {
        let mut hasher = Sha256::new();
        hasher.update(trimmed_jacs_bytes);
        format!("sha256:{}", hex::encode(hasher.finalize()))
    };

    // Count existing renamed JACS signatures to determine next index
    let parts = extract_email_parts(raw_email)?;

    // Count only the renamed ones (jacs-signature-N.json pattern),
    // not the active jacs-signature.json
    let renamed_count = parts
        .jacs_attachments
        .iter()
        .filter(|a| {
            a.filename.starts_with("jacs-signature-") && a.filename.ends_with(".json")
        })
        .count();

    let new_name = format!("jacs-signature-{}.json", renamed_count);

    // Remove the active jacs-signature.json
    let email_without_active = remove_jacs_attachment(raw_email)?;

    // Re-attach it with the new name
    let renamed_email = add_named_jacs_attachment(
        &email_without_active,
        &jacs_bytes,
        &new_name,
    )?;

    Ok((renamed_email, Some(parent_hash)))
}

/// Add a named JACS attachment to a raw RFC 5322 email.
/// Unlike `add_jacs_attachment`, this lets you specify a custom filename.
fn add_named_jacs_attachment(
    raw_email: &[u8],
    doc: &[u8],
    filename: &str,
) -> Result<Vec<u8>, EmailError> {
    use mail_parser::{MessageParser, MimeHeaders as _};

    let message = MessageParser::default()
        .parse(raw_email)
        .ok_or_else(|| {
            EmailError::InvalidEmailFormat(
                "Cannot parse email for named attachment injection".into(),
            )
        })?;

    let content_type = message
        .content_type()
        .map(|ct| format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or("")));

    let build_mime_part = |boundary: &str| -> String {
        let mut part = String::new();
        part.push_str(&format!("--{}\r\n", boundary));
        part.push_str(&format!(
            "Content-Type: application/json; name=\"{}\"\r\n",
            filename
        ));
        part.push_str(&format!(
            "Content-Disposition: attachment; filename=\"{}\"\r\n",
            filename
        ));
        part.push_str("Content-Transfer-Encoding: 7bit\r\n");
        part.push_str("\r\n");
        part.push_str(&String::from_utf8_lossy(doc));
        part.push_str("\r\n");
        part
    };

    match content_type.as_deref() {
        Some("multipart/mixed") => {
            let boundary = message
                .content_type()
                .and_then(|ct: &mail_parser::ContentType<'_>| ct.attribute("boundary"))
                .ok_or_else(|| {
                    EmailError::InvalidEmailFormat(
                        "multipart/mixed without boundary".into(),
                    )
                })?
                .to_string();

            let closing = format!("--{}--", boundary);
            let email_str = String::from_utf8_lossy(raw_email);
            let closing_pos = email_str.rfind(&closing).ok_or_else(|| {
                EmailError::InvalidEmailFormat(
                    "Cannot find closing boundary in multipart/mixed".into(),
                )
            })?;

            let part = build_mime_part(&boundary);
            let mut result = Vec::new();
            result.extend_from_slice(&raw_email[..closing_pos]);
            result.extend_from_slice(part.as_bytes());
            result.extend_from_slice(closing.as_bytes());
            let after_closing = closing_pos + closing.len();
            if after_closing < raw_email.len() {
                result.extend_from_slice(&raw_email[after_closing..]);
            } else {
                result.extend_from_slice(b"\r\n");
            }
            Ok(result)
        }
        _ => {
            // For non-multipart/mixed, wrap first then add
            // This is a rare edge case since forwarded emails will typically
            // already be multipart/mixed from the original signing
            add_jacs_attachment(raw_email, doc)
        }
    }
}

/// Build the signed header entries from parsed email parts.
///
/// Required headers: From, To, Subject, Date, Message-ID
/// Optional headers: CC, In-Reply-To, References
fn build_signed_headers(
    parts: &super::types::ParsedEmailParts,
) -> Result<EmailSignatureHeaders, EmailError> {
    let from = get_required_singleton_header(parts, "from")?;
    let to = get_required_singleton_header(parts, "to")?;
    let subject = get_required_singleton_header(parts, "subject")?;
    let date = get_required_singleton_header(parts, "date")?;
    let message_id = get_required_singleton_header(parts, "message-id")?;

    let cc = get_optional_header(parts, "cc")?;
    let in_reply_to = get_optional_header(parts, "in-reply-to")?;
    let references = get_optional_header(parts, "references")?;

    Ok(EmailSignatureHeaders {
        from: build_header_entry("from", &from)?,
        to: build_header_entry("to", &to)?,
        cc: cc
            .map(|v| build_header_entry("cc", &v))
            .transpose()?,
        subject: build_header_entry("subject", &subject)?,
        date: build_header_entry("date", &date)?,
        message_id: build_header_entry("message-id", &message_id)?,
        in_reply_to: in_reply_to
            .map(|v| build_header_entry("in-reply-to", &v))
            .transpose()?,
        references: references
            .map(|v| build_header_entry("references", &v))
            .transpose()?,
    })
}

/// Get a required singleton header value. Fails if absent or duplicated.
fn get_required_singleton_header(
    parts: &super::types::ParsedEmailParts,
    name: &str,
) -> Result<String, EmailError> {
    let values = parts.headers.get(name);
    match values {
        None => Err(EmailError::InvalidEmailFormat(format!(
            "required header '{}' is missing",
            name
        ))),
        Some(v) if v.is_empty() => Err(EmailError::InvalidEmailFormat(format!(
            "required header '{}' is missing",
            name
        ))),
        Some(v) if v.len() > 1 => Err(EmailError::InvalidEmailFormat(format!(
            "required header '{}' has {} values (ambiguous)",
            name,
            v.len()
        ))),
        Some(v) => Ok(v[0].clone()),
    }
}

/// Get an optional header value. Returns None if absent, fails if duplicated.
fn get_optional_header(
    parts: &super::types::ParsedEmailParts,
    name: &str,
) -> Result<Option<String>, EmailError> {
    let values = parts.headers.get(name);
    match values {
        None => Ok(None),
        Some(v) if v.is_empty() => Ok(None),
        Some(v) if v.len() > 1 => Err(EmailError::InvalidEmailFormat(format!(
            "optional header '{}' has {} values (ambiguous)",
            name,
            v.len()
        ))),
        Some(v) => Ok(Some(v[0].clone())),
    }
}

/// Build a `SignedHeaderEntry` from a header name and raw value.
fn build_header_entry(
    name: &str,
    value: &str,
) -> Result<SignedHeaderEntry, EmailError> {
    let canonical = canonicalize_header(name, value)?;
    let hash = compute_header_entry(&canonical);
    Ok(SignedHeaderEntry {
        value: canonical,
        hash,
    })
}

/// Build the complete JACS email signature document from a payload and signer.
///
/// This handles:
/// - RFC 8785 (JCS) canonicalization of the payload
/// - SHA-256 hash computation for metadata
/// - Cryptographic signing via the signer
/// - Document assembly with metadata and signature sections
pub fn build_jacs_email_document(
    payload: &EmailSignaturePayload,
    signer: &dyn EmailSigner,
) -> Result<JacsEmailSignatureDocument, EmailError> {
    // Canonicalize payload via RFC 8785 (JCS) - sorted keys, compact JSON
    let payload_json = serde_json::to_value(payload)
        .map_err(|e| EmailError::InvalidJacsDocument(format!("payload serialization: {e}")))?;
    let canonical_payload = canonical_json_sorted(&payload_json);

    // Compute metadata.hash = sha256(canonical_payload)
    let hash = {
        let mut hasher = Sha256::new();
        hasher.update(canonical_payload.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    };

    let now = Utc::now().to_rfc3339();

    // Sign the canonical payload bytes
    let sig_bytes = signer
        .sign_bytes(canonical_payload.as_bytes())
        .map_err(|e| {
            EmailError::SignatureVerificationFailed(format!("signing failed: {e}"))
        })?;
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);

    let metadata = JacsEmailMetadata {
        issuer: signer.jacs_id().to_string(),
        document_id: Uuid::new_v4().to_string(),
        created_at: now.clone(),
        hash,
    };

    let signature = JacsEmailSignature {
        key_id: signer.key_id().to_string(),
        algorithm: signer.algorithm().to_string(),
        signature: sig_b64,
        signed_at: now,
    };

    Ok(JacsEmailSignatureDocument {
        version: "1.0".to_string(),
        document_type: "email_signature".to_string(),
        payload: payload.clone(),
        metadata,
        signature,
    })
}

// Use shared strip_trailing_whitespace from canonicalize module (DRY).
use super::canonicalize::strip_trailing_whitespace as strip_trailing_ws;

/// Canonical JSON per RFC 8785 (JSON Canonicalization Scheme / JCS).
///
/// Uses the `serde_json_canonicalizer` crate for full compliance including:
/// - Sorted keys
/// - IEEE 754 number serialization
/// - Minimal Unicode escape handling
/// - No unnecessary whitespace
pub(crate) fn canonical_json_sorted(value: &serde_json::Value) -> String {
    serde_json_canonicalizer::to_string(value).unwrap_or_else(|_| "null".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test signer that produces deterministic signatures.
    struct TestSigner {
        id: String,
    }

    impl TestSigner {
        fn new(id: &str) -> Self {
            Self {
                id: id.to_string(),
            }
        }
    }

    impl EmailSigner for TestSigner {
        fn sign_bytes(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let mut result = b"sig:".to_vec();
            result.extend_from_slice(data);
            Ok(result)
        }

        fn jacs_id(&self) -> &str {
            &self.id
        }

        fn key_id(&self) -> &str {
            &self.id
        }

        fn algorithm(&self) -> &str {
            "ed25519"
        }
    }

    fn simple_text_email() -> Vec<u8> {
        b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <test@example.com>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello World\r\n".to_vec()
    }

    fn multipart_alternative_email() -> Vec<u8> {
        b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <test@example.com>\r\nContent-Type: multipart/alternative; boundary=\"altbound\"\r\n\r\n--altbound\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nPlain text body\r\n--altbound\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>HTML body</p>\r\n--altbound--\r\n".to_vec()
    }

    fn multipart_with_attachment_email() -> Vec<u8> {
        b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <test@example.com>\r\nContent-Type: multipart/mixed; boundary=\"mixbound\"\r\n\r\n--mixbound\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nBody text\r\n--mixbound\r\nContent-Type: application/pdf; name=\"report.pdf\"\r\nContent-Disposition: attachment; filename=\"report.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n--mixbound--\r\n".to_vec()
    }

    fn threaded_reply_email() -> Vec<u8> {
        b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Re: Test\r\nDate: Fri, 28 Feb 2026 13:00:00 +0000\r\nMessage-ID: <reply@example.com>\r\nIn-Reply-To: <original@example.com>\r\nReferences: <original@example.com> <thread@example.com>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nReply body\r\n".to_vec()
    }

    #[test]
    fn sign_email_simple_text_attaches_jacs_signature() {
        let email = simple_text_email();
        let signer = TestSigner::new("test-agent-id:v1");
        let signed = sign_email(&email, &signer).unwrap();
        let signed_str = String::from_utf8_lossy(&signed);
        assert!(signed_str.contains("jacs-signature.json"));
        // Should be parseable
        assert!(mail_parser::MessageParser::default().parse(&signed).is_some());
    }

    #[test]
    fn sign_email_multipart_alternative_includes_both_body_parts() {
        let email = multipart_alternative_email();
        let signer = TestSigner::new("test-agent-id:v1");
        let signed = sign_email(&email, &signer).unwrap();

        // Extract the JACS doc
        let doc_bytes = super::super::attachment::get_jacs_attachment(&signed).unwrap();
        let doc: JacsEmailSignatureDocument = serde_json::from_slice(&doc_bytes).unwrap();

        assert!(doc.payload.body_plain.is_some());
        assert!(doc.payload.body_html.is_some());
    }

    #[test]
    fn sign_email_with_attachments_includes_sorted_attachment_hashes() {
        let email = multipart_with_attachment_email();
        let signer = TestSigner::new("test-agent-id:v1");
        let signed = sign_email(&email, &signer).unwrap();

        let doc_bytes = super::super::attachment::get_jacs_attachment(&signed).unwrap();
        let doc: JacsEmailSignatureDocument = serde_json::from_slice(&doc_bytes).unwrap();

        assert!(!doc.payload.attachments.is_empty());
        assert_eq!(doc.payload.attachments[0].filename, "report.pdf");
        assert!(doc.payload.attachments[0].content_hash.starts_with("sha256:"));
    }

    #[test]
    fn sign_email_threaded_reply_includes_in_reply_to_and_references() {
        let email = threaded_reply_email();
        let signer = TestSigner::new("test-agent-id:v1");
        let signed = sign_email(&email, &signer).unwrap();

        let doc_bytes = super::super::attachment::get_jacs_attachment(&signed).unwrap();
        let doc: JacsEmailSignatureDocument = serde_json::from_slice(&doc_bytes).unwrap();

        assert!(doc.payload.headers.in_reply_to.is_some());
        assert!(doc.payload.headers.references.is_some());
    }

    #[test]
    fn sign_email_sets_parent_signature_hash_null() {
        let email = simple_text_email();
        let signer = TestSigner::new("test-agent-id:v1");
        let signed = sign_email(&email, &signer).unwrap();

        let doc_bytes = super::super::attachment::get_jacs_attachment(&signed).unwrap();
        let doc: JacsEmailSignatureDocument = serde_json::from_slice(&doc_bytes).unwrap();

        assert!(doc.payload.parent_signature_hash.is_none());
    }

    #[test]
    fn sign_email_document_has_valid_structure() {
        let email = simple_text_email();
        let signer = TestSigner::new("test-agent-id:v1");
        let signed = sign_email(&email, &signer).unwrap();

        let doc_bytes = super::super::attachment::get_jacs_attachment(&signed).unwrap();
        let doc: JacsEmailSignatureDocument = serde_json::from_slice(&doc_bytes).unwrap();

        assert_eq!(doc.version, "1.0");
        assert_eq!(doc.document_type, "email_signature");
        assert_eq!(doc.metadata.issuer, "test-agent-id:v1");
        assert!(doc.metadata.hash.starts_with("sha256:"));
        assert_eq!(doc.signature.algorithm, "ed25519");
        assert!(!doc.signature.signature.is_empty());
    }

    #[test]
    fn sign_roundtrip_hashes_are_valid_sha256() {
        let email = simple_text_email();
        let signer = TestSigner::new("test-agent-id:v1");
        let signed = sign_email(&email, &signer).unwrap();

        let doc_bytes = super::super::attachment::get_jacs_attachment(&signed).unwrap();
        let doc: JacsEmailSignatureDocument = serde_json::from_slice(&doc_bytes).unwrap();

        // All hashes should be "sha256:<64 hex chars>"
        let check_hash = |h: &str, label: &str| {
            assert!(
                h.starts_with("sha256:"),
                "{label} hash doesn't start with sha256:"
            );
            assert_eq!(
                h.len(),
                7 + 64,
                "{label} hash has wrong length: {}",
                h.len()
            );
        };

        check_hash(&doc.payload.headers.from.hash, "from");
        check_hash(&doc.payload.headers.to.hash, "to");
        check_hash(&doc.payload.headers.subject.hash, "subject");
        check_hash(&doc.payload.headers.date.hash, "date");
        check_hash(&doc.payload.headers.message_id.hash, "message_id");
        check_hash(&doc.metadata.hash, "metadata");

        if let Some(bp) = &doc.payload.body_plain {
            check_hash(&bp.content_hash, "body_plain.content");
            check_hash(&bp.mime_headers_hash, "body_plain.mime");
        }
    }

    #[test]
    fn sign_multipart_has_both_body_hashes() {
        let email = multipart_alternative_email();
        let signer = TestSigner::new("test-agent-id:v1");
        let signed = sign_email(&email, &signer).unwrap();

        let doc_bytes = super::super::attachment::get_jacs_attachment(&signed).unwrap();
        let doc: JacsEmailSignatureDocument = serde_json::from_slice(&doc_bytes).unwrap();

        let plain = doc.payload.body_plain.as_ref().unwrap();
        let html = doc.payload.body_html.as_ref().unwrap();

        assert!(plain.content_hash.starts_with("sha256:"));
        assert!(plain.mime_headers_hash.starts_with("sha256:"));
        assert!(html.content_hash.starts_with("sha256:"));
        assert!(html.mime_headers_hash.starts_with("sha256:"));
    }
}
