//! Email signing implementation for the JACS email system.
//!
//! Provides `sign_email()` which takes raw RFC 5322 email bytes and any
//! [`JacsSigner`] implementor, and returns the email with a JACS signature
//! MIME attachment containing a real JACS document.
//!
//! The attachment filename is configurable via `sign_email_named()`. The
//! default `sign_email()` uses `DEFAULT_JACS_SIGNATURE_FILENAME`.
//!
//! All cryptographic operations are delegated to the [`JacsSigner`] via
//! [`JacsSigner::sign_message()`]. The email module only handles hash
//! computation and MIME operations.

use sha2::{Digest, Sha256};

use super::attachment::{
    DEFAULT_JACS_SIGNATURE_FILENAME, add_jacs_attachment, add_jacs_attachment_named,
    ensure_multipart_mixed, get_jacs_attachment_named, remove_jacs_attachment_named, rfind_bytes,
};
use super::canonicalize::{
    canonicalize_body, canonicalize_header, compute_attachment_hash, compute_body_hash,
    compute_header_entry, compute_mime_headers_hash, extract_email_parts,
};
use super::error::{EmailError, check_email_size};
use super::types::{
    AttachmentEntry, BodyPartEntry, EmailSignatureHeaders, EmailSignaturePayload, ParsedEmailParts,
    SignedHeaderEntry,
};

use super::JacsSigner;

/// Sign a raw RFC 5322 email with a custom attachment filename.
///
/// Same as [`sign_email`] but the caller specifies the JACS attachment
/// filename. Use this when you need a branded attachment name (e.g.,
/// `"hai.ai.signature.jacs.json"`) instead of the JACS default.
pub fn sign_email_named(
    raw_email: &[u8],
    signer: &impl JacsSigner,
    filename: &str,
) -> Result<Vec<u8>, EmailError> {
    sign_email_inner(raw_email, signer, filename)
}

/// Sign a raw RFC 5322 email and attach a JACS signature document.
///
/// This is the primary sender-side function. It:
/// 1. Parses and canonicalizes the email
/// 2. Computes hashes for headers, body parts, and attachments
/// 3. Creates a real JACS document containing the hash payload via the signer
/// 4. Attaches the signed JACS document as a MIME part
///
/// Uses `DEFAULT_JACS_SIGNATURE_FILENAME` (`jacs-signature.json`).
/// For a custom name, use [`sign_email_named`].
///
/// Accepts any type implementing [`JacsSigner`], including `SimpleAgent`.
///
/// Returns the modified email bytes with the JACS attachment.
pub fn sign_email(raw_email: &[u8], signer: &impl JacsSigner) -> Result<Vec<u8>, EmailError> {
    sign_email_inner(raw_email, signer, DEFAULT_JACS_SIGNATURE_FILENAME)
}

/// Inner implementation of email signing with configurable filename.
fn sign_email_inner(
    raw_email: &[u8],
    signer: &impl JacsSigner,
    filename: &str,
) -> Result<Vec<u8>, EmailError> {
    // Step 0: Size check
    check_email_size(raw_email)?;

    // Step 0b: Check for existing JACS signature (forwarding case)
    let (email_for_signing, parent_signature_hash) = prepare_for_forwarding(raw_email, filename)?;

    // Step 0c: Ensure the email is multipart/mixed BEFORE parsing.
    // This guarantees that the MIME headers hashed during signing match what
    // verification will see (verification parses the wrapped email sans JACS).
    let wrapped_email = ensure_multipart_mixed(&email_for_signing)?;

    // Step 1: Parse and canonicalize (from the wrapped email)
    let parts = extract_email_parts(&wrapped_email)?;

    // Step 2-5: Build the attachment-mode payload.
    let payload = build_email_signature_payload(&parts, parent_signature_hash, true, true, false)?;

    // Step 6: Create a real JACS document containing the email hash payload
    let jacs_doc_json = build_jacs_email_document(&payload, signer)?;

    // Step 7: Attach via add_jacs_attachment_named (to the wrapped email)
    add_jacs_attachment_named(&wrapped_email, jacs_doc_json.as_bytes(), filename)
}

/// Build the HTML-inline email signature payload.
///
/// Inline transport signs the same header scope as attachment mode, plus the
/// text body and user attachments. Generated HTML and inline signature
/// artifacts are excluded because they are added after the signed content is
/// authored.
pub fn build_html_inline_email_signature_payload(
    raw_email: &[u8],
) -> Result<EmailSignaturePayload, EmailError> {
    check_email_size(raw_email)?;
    let parts = extract_email_parts(raw_email)?;
    build_email_signature_payload(&parts, None, false, false, true)
}

fn build_email_signature_payload(
    parts: &ParsedEmailParts,
    parent_signature_hash: Option<String>,
    include_body_html: bool,
    include_jacs_attachments: bool,
    exclude_inline_logo: bool,
) -> Result<EmailSignaturePayload, EmailError> {
    let headers = build_signed_headers(parts)?;
    let body_plain = parts.body_plain.as_ref().map(build_body_part_entry);
    let body_html = if include_body_html {
        parts.body_html.as_ref().map(build_body_part_entry)
    } else {
        None
    };
    let attachments =
        build_attachment_entries(parts, include_jacs_attachments, exclude_inline_logo);

    Ok(EmailSignaturePayload {
        headers,
        body_plain,
        body_html,
        attachments,
        parent_signature_hash,
    })
}

fn build_body_part_entry(bp: &super::types::ParsedBodyPart) -> BodyPartEntry {
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
}

fn build_attachment_entries(
    parts: &ParsedEmailParts,
    include_jacs_attachments: bool,
    exclude_inline_logo: bool,
) -> Vec<AttachmentEntry> {
    let mut all_attachments: Vec<_> = parts
        .attachments
        .iter()
        .filter(|att| {
            !(exclude_inline_logo && super::transport::is_inline_logo_attachment_artifact(att))
        })
        .cloned()
        .collect();

    if include_jacs_attachments {
        all_attachments.extend(parts.jacs_attachments.iter().cloned());
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
    attachment_entries
}

/// Prepare an email for signing, handling the forwarding case.
///
/// If the email already has an active JACS signature attachment:
/// 1. Extract it and compute its SHA-256 hash (becomes parent_signature_hash)
/// 2. Remove the active attachment
/// 3. Re-attach it with a numbered name for the forwarding chain
///
/// `active_filename` is the filename to look for as the active signature
/// (e.g., `"jacs-signature.json"` or a branded name).
///
/// Returns (prepared_email_bytes, parent_signature_hash_option).
fn prepare_for_forwarding(
    raw_email: &[u8],
    active_filename: &str,
) -> Result<(Vec<u8>, Option<String>), EmailError> {
    // Try to extract the existing JACS signature attachment
    let jacs_bytes = match get_jacs_attachment_named(raw_email, active_filename) {
        Ok(bytes) => bytes,
        Err(EmailError::MissingJacsSignature) => {
            // No existing signature -- not a forward
            return Ok((raw_email.to_vec(), None));
        }
        Err(e) => return Err(e),
    };

    // Compute parent_signature_hash = sha256(exact bytes of existing JACS signature)
    let parent_hash = {
        let mut hasher = Sha256::new();
        hasher.update(&jacs_bytes);
        format!("sha256:{}", hex::encode(hasher.finalize()))
    };

    // Count existing renamed JACS signatures to determine next index
    let parts = extract_email_parts(raw_email)?;

    // Count existing renamed JACS signatures (exclude the active one).
    // jacs_attachments already filters to *.jacs.json and jacs-signature*.json;
    // we just exclude the active filename itself to count only renamed/chain entries.
    let renamed_count = parts
        .jacs_attachments
        .iter()
        .filter(|a| a.filename != active_filename)
        .count();

    // Derive the renamed filename from the active name's base pattern
    let new_name = derive_forwarding_name(active_filename, renamed_count);

    // Remove the active JACS signature attachment
    let email_without_active = remove_jacs_attachment_named(raw_email, active_filename)?;

    // Re-attach it with the new name
    let renamed_email = add_named_jacs_attachment(&email_without_active, &jacs_bytes, &new_name)?;

    Ok((renamed_email, Some(parent_hash)))
}

/// Derive a forwarding chain filename from the active filename.
///
/// For `"custom.jacs.json"` → `"custom.0.jacs.json"`, etc.
/// For `"jacs-signature.json"` → `"jacs-signature-0.json"`, etc.
fn derive_forwarding_name(active_filename: &str, index: usize) -> String {
    if active_filename.ends_with(".jacs.json") {
        let base = active_filename.trim_end_matches(".jacs.json");
        format!("{}.{}.jacs.json", base, index)
    } else if active_filename.ends_with(".json") {
        let base = active_filename.trim_end_matches(".json");
        format!("{}-{}.json", base, index)
    } else {
        format!("{}.{}", active_filename, index)
    }
}

/// Add a named JACS attachment to a raw RFC 5322 email.
/// Unlike `add_jacs_attachment`, this lets you specify a custom filename.
fn add_named_jacs_attachment(
    raw_email: &[u8],
    doc: &[u8],
    filename: &str,
) -> Result<Vec<u8>, EmailError> {
    use mail_parser::{MessageParser, MimeHeaders as _};

    let message = MessageParser::default().parse(raw_email).ok_or_else(|| {
        EmailError::InvalidEmailFormat("Cannot parse email for named attachment injection".into())
    })?;

    let content_type = message
        .content_type()
        .map(|ct| format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or("")));

    let build_mime_part_bytes = |boundary: &str| -> Vec<u8> {
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
    };

    match content_type.as_deref() {
        Some("multipart/mixed") => {
            let boundary = message
                .content_type()
                .and_then(|ct: &mail_parser::ContentType<'_>| ct.attribute("boundary"))
                .ok_or_else(|| {
                    EmailError::InvalidEmailFormat("multipart/mixed without boundary".into())
                })?
                .to_string();

            let closing = format!("--{}--", boundary);
            // Use raw byte search to avoid lossy UTF-8 conversion.
            let closing_pos = rfind_bytes(raw_email, closing.as_bytes()).ok_or_else(|| {
                EmailError::InvalidEmailFormat(
                    "Cannot find closing boundary in multipart/mixed".into(),
                )
            })?;

            let part = build_mime_part_bytes(&boundary);
            let mut result = Vec::new();
            result.extend_from_slice(&raw_email[..closing_pos]);
            result.extend_from_slice(&part);
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
        cc: cc.map(|v| build_header_entry("cc", &v)).transpose()?,
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
fn build_header_entry(name: &str, value: &str) -> Result<SignedHeaderEntry, EmailError> {
    let canonical = canonicalize_header(name, value)?;
    let hash = compute_header_entry(&canonical);
    Ok(SignedHeaderEntry {
        value: canonical,
        hash,
    })
}

/// Build a real JACS document containing the email signature payload.
///
/// Uses [`JacsSigner::sign_message()`] to create a proper JACS document
/// with standard JACS signing, hashing, and identity binding. The email
/// hash payload becomes the `content` field of the JACS document.
///
/// Returns the raw JSON string of the signed JACS document.
pub(crate) fn build_jacs_email_document(
    payload: &EmailSignaturePayload,
    signer: &impl JacsSigner,
) -> Result<String, EmailError> {
    // Convert the payload to a serde_json::Value for sign_message
    let payload_value = serde_json::to_value(payload)
        .map_err(|e| EmailError::InvalidJacsDocument(format!("payload serialization: {e}")))?;

    // Use the JacsSigner to create and sign a real JACS document.
    // sign_message() preserves the legacy signed-message type label:
    //   { "jacsType": "message", "jacsLevel": "raw", "content": <payload> }
    // then calls create_document_and_load() which handles schema validation,
    // canonical hashing, and cryptographic signing through the agent's identity.
    let signed_doc = signer.sign_message(&payload_value).map_err(|e| {
        EmailError::SignatureVerificationFailed(format!("JACS document signing failed: {e}"))
    })?;

    Ok(signed_doc.raw)
}

/// Canonical JSON per RFC 8785 (JSON Canonicalization Scheme / JCS).
///
/// Uses the `serde_json_canonicalizer` crate for full compliance including:
/// - Sorted keys
/// - IEEE 754 number serialization
/// - Minimal Unicode escape handling
/// - No unnecessary whitespace
pub fn canonicalize_json_rfc8785(value: &serde_json::Value) -> String {
    serde_json_canonicalizer::to_string(value).unwrap_or_else(|_| "null".to_string())
}

// =============================================================================
// YAML/HTML email signing wrappers
// =============================================================================

/// Sign a raw RFC 5322 email and attach the JACS signature as a YAML document.
///
/// Same as [`sign_email`] but the JACS signature attachment is converted to YAML
/// for human-readable viewing. The attachment filename defaults to
/// `jacs-signature.yaml`.
pub fn sign_email_yaml(
    raw_email: &[u8],
    signer: &impl super::JacsSigner,
) -> Result<Vec<u8>, EmailError> {
    sign_email_yaml_named(raw_email, signer, "jacs-signature.yaml")
}

/// Sign a raw RFC 5322 email and attach the JACS signature as a YAML document
/// with a custom attachment filename.
pub fn sign_email_yaml_named(
    raw_email: &[u8],
    signer: &impl super::JacsSigner,
    filename: &str,
) -> Result<Vec<u8>, EmailError> {
    // First sign normally to get the JACS document JSON
    let signed_email = sign_email_inner(raw_email, signer, "jacs-signature.json")?;

    // Extract the JSON JACS document from the signed email
    let json_bytes = super::attachment::get_jacs_attachment(&signed_email)?;
    let json_str = std::str::from_utf8(&json_bytes)
        .map_err(|e| EmailError::InvalidJacsDocument(format!("not UTF-8: {}", e)))?;

    // Convert to YAML
    let yaml_str = crate::convert::jacs_to_yaml(json_str)
        .map_err(|e| EmailError::InvalidJacsDocument(format!("YAML conversion: {}", e)))?;

    // Remove the JSON attachment and add the YAML one
    let without_json = super::attachment::remove_jacs_attachment(&signed_email)?;
    add_jacs_attachment_named(&without_json, yaml_str.as_bytes(), filename)
}

/// Sign a raw RFC 5322 email and attach the JACS signature as an HTML document.
///
/// Same as [`sign_email`] but the JACS signature attachment is rendered as a
/// self-contained HTML page with embedded JSON for lossless extraction.
/// The attachment filename defaults to `jacs-signature.html`.
pub fn sign_email_html(
    raw_email: &[u8],
    signer: &impl super::JacsSigner,
) -> Result<Vec<u8>, EmailError> {
    sign_email_html_named(raw_email, signer, "jacs-signature.html")
}

/// Sign a raw RFC 5322 email and attach the JACS signature as an HTML document
/// with a custom attachment filename.
pub fn sign_email_html_named(
    raw_email: &[u8],
    signer: &impl super::JacsSigner,
    filename: &str,
) -> Result<Vec<u8>, EmailError> {
    // First sign normally to get the JACS document JSON
    let signed_email = sign_email_inner(raw_email, signer, "jacs-signature.json")?;

    // Extract the JSON JACS document from the signed email
    let json_bytes = super::attachment::get_jacs_attachment(&signed_email)?;
    let json_str = std::str::from_utf8(&json_bytes)
        .map_err(|e| EmailError::InvalidJacsDocument(format!("not UTF-8: {}", e)))?;

    // Convert to HTML
    let html_str = crate::convert::jacs_to_html(json_str)
        .map_err(|e| EmailError::InvalidJacsDocument(format!("HTML conversion: {}", e)))?;

    // Remove the JSON attachment and add the HTML one
    let without_json = super::attachment::remove_jacs_attachment(&signed_email)?;
    add_jacs_attachment_named(&without_json, html_str.as_bytes(), filename)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simple::SimpleAgent;

    use crate::email::EMAIL_TEST_MUTEX;
    use serial_test::serial;

    /// Create a test SimpleAgent and set the env vars needed for signing.
    ///
    /// MUST be called while holding `EMAIL_TEST_MUTEX`.
    fn create_test_agent() -> (
        SimpleAgent,
        tempfile::TempDir,
        crate::email::EmailTestEnvGuard,
    ) {
        use crate::simple::CreateAgentParams;

        let tmp = tempfile::tempdir().expect("create temp dir");
        let tmp_root = tmp.path().canonicalize().expect("canonical temp dir");
        let tmp_path = tmp_root.to_string_lossy().to_string();

        let params = CreateAgentParams::builder()
            .name("email-sign-test-agent")
            .password("TestEmail!2026")
            .algorithm("ring-Ed25519")
            .domain("test.example.com")
            .description("Test agent for email signing")
            .data_directory(&format!("{}/jacs_data", tmp_path))
            .key_directory(&format!("{}/jacs_keys", tmp_path))
            .config_path(&format!("{}/jacs.config.json", tmp_path))
            .build();

        let (agent, _info) = SimpleAgent::create_with_params(params).expect("create test agent");

        // Set env vars needed by the keystore at signing time and restore on drop.
        let env_guard = crate::email::EmailTestEnvGuard::set(&[
            ("JACS_PRIVATE_KEY_PASSWORD", "TestEmail!2026".to_string()),
            ("JACS_KEY_DIRECTORY", format!("{}/jacs_keys", tmp_path)),
            (
                "JACS_AGENT_PRIVATE_KEY_FILENAME",
                "jacs.private.pem.enc".to_string(),
            ),
            (
                "JACS_AGENT_PUBLIC_KEY_FILENAME",
                "jacs.public.pem".to_string(),
            ),
        ]);

        (agent, tmp, env_guard)
    }

    /// Extract the email signature payload from a signed email's JACS document.
    fn extract_payload(signed_email: &[u8]) -> EmailSignaturePayload {
        let doc_bytes = super::super::attachment::get_jacs_attachment(signed_email).unwrap();
        let doc_str = std::str::from_utf8(&doc_bytes).unwrap();
        let jacs_doc: serde_json::Value = serde_json::from_str(doc_str).unwrap();
        let content = &jacs_doc["content"];
        serde_json::from_value(content.clone()).unwrap()
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

    fn html_inline_with_user_attachment_email() -> Vec<u8> {
        b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Inline Test\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <inline-test@example.com>\r\nContent-Type: multipart/mixed; boundary=\"mixbound\"\r\n\r\n--mixbound\r\nContent-Type: multipart/alternative; boundary=\"altbound\"\r\n\r\n--altbound\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nBody text\r\n--altbound\r\nContent-Type: multipart/related; boundary=\"relbound\"\r\n\r\n--relbound\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<!doctype html><html data-hai-template-version=\"v1\"><body><p>Body text</p><img src=\"cid:hai-jacs-logo@hai.ai\"><script type=\"application/jacs+json\" data-hai-jacs-envelope=\"v1\">header</script><footer data-hai-verify-footer=\"v1\">footer</footer></body></html>\r\n--relbound\r\nContent-Type: image/png\r\nContent-ID: <hai-jacs-logo@hai.ai>\r\nContent-Disposition: inline; filename=\"hai-jacs-logo.png\"\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0KGgo=\r\n--relbound--\r\n--altbound--\r\n--mixbound\r\nContent-Type: text/plain; name=\"notes.txt\"\r\nContent-Disposition: attachment; filename=\"notes.txt\"\r\nContent-Transfer-Encoding: base64\r\n\r\nTm90ZXMK\r\n--mixbound--\r\n".to_vec()
    }

    fn threaded_reply_email() -> Vec<u8> {
        b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Re: Test\r\nDate: Fri, 28 Feb 2026 13:00:00 +0000\r\nMessage-ID: <reply@example.com>\r\nIn-Reply-To: <original@example.com>\r\nReferences: <original@example.com> <thread@example.com>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nReply body\r\n".to_vec()
    }
    #[test]
    #[serial(jacs_env)]
    fn sign_email_simple_text_attaches_jacs_signature() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent();
        let email = simple_text_email();
        let signed = sign_email(&email, &agent).unwrap();
        let signed_str = String::from_utf8_lossy(&signed);
        assert!(signed_str.contains("jacs-signature.json"));
        assert!(
            mail_parser::MessageParser::default()
                .parse(&signed)
                .is_some()
        );
    }
    #[test]
    #[serial(jacs_env)]
    fn sign_email_produces_valid_jacs_document() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent();
        let email = simple_text_email();
        let signed = sign_email(&email, &agent).unwrap();

        let doc_bytes = super::super::attachment::get_jacs_attachment(&signed).unwrap();
        let doc_str = std::str::from_utf8(&doc_bytes).unwrap();

        let result = agent.verify(doc_str).unwrap();
        assert!(
            result.valid,
            "JACS document should be valid: {:?}",
            result.errors
        );
    }
    #[test]
    #[serial(jacs_env)]
    fn sign_email_multipart_alternative_includes_both_body_parts() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent();
        let email = multipart_alternative_email();
        let signed = sign_email(&email, &agent).unwrap();

        let payload = extract_payload(&signed);
        assert!(payload.body_plain.is_some());
        assert!(payload.body_html.is_some());
    }
    #[test]
    #[serial(jacs_env)]
    fn sign_email_with_attachments_includes_sorted_attachment_hashes() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent();
        let email = multipart_with_attachment_email();
        let signed = sign_email(&email, &agent).unwrap();

        let payload = extract_payload(&signed);
        assert!(!payload.attachments.is_empty());
        assert_eq!(payload.attachments[0].filename, "report.pdf");
        assert!(payload.attachments[0].content_hash.starts_with("sha256:"));
    }

    #[test]
    fn html_inline_payload_excludes_generated_html_and_logo_artifact() {
        let raw = include_bytes!("../../tests/fixtures/email/html_inline/03_generated_html.eml");

        let payload = build_html_inline_email_signature_payload(raw).unwrap();

        assert!(payload.body_plain.is_some());
        assert!(payload.body_html.is_none());
        assert!(payload.attachments.is_empty());
    }

    #[test]
    fn html_inline_payload_keeps_user_attachments() {
        let email = html_inline_with_user_attachment_email();

        let payload = build_html_inline_email_signature_payload(&email).unwrap();

        assert_eq!(payload.attachments.len(), 1);
        assert_eq!(payload.attachments[0].filename, "notes.txt");
    }

    #[test]
    fn html_inline_payload_ignores_generated_html_edits_but_not_text_edits() {
        let raw = include_str!("../../tests/fixtures/email/html_inline/03_generated_html.eml");
        let original = build_html_inline_email_signature_payload(raw.as_bytes()).unwrap();
        let html_edit = raw.replace(
            "<p>Hello from a signed HAI agent.</p>",
            "<p>Hello from a changed HTML body.</p>",
        );
        let text_edit = raw.replace(
            "Hello from a signed HAI agent.\n\n--hai-inline-alt-03",
            "Hello from changed text.\n\n--hai-inline-alt-03",
        );

        let html_payload = build_html_inline_email_signature_payload(html_edit.as_bytes()).unwrap();
        let text_payload = build_html_inline_email_signature_payload(text_edit.as_bytes()).unwrap();

        assert_eq!(
            original.body_plain.as_ref().unwrap().content_hash,
            html_payload.body_plain.as_ref().unwrap().content_hash
        );
        assert_ne!(
            original.body_plain.as_ref().unwrap().content_hash,
            text_payload.body_plain.as_ref().unwrap().content_hash
        );
        assert!(html_payload.body_html.is_none());
    }

    #[test]
    fn html_inline_payload_keeps_current_signed_header_scope() {
        let raw = b"From: sender@example.com\r\nTo: recipient@example.com\r\nCc: reviewer@example.com\r\nSubject: Header Scope\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <header-scope@example.com>\r\nIn-Reply-To: <parent@example.com>\r\nReferences: <root@example.com> <parent@example.com>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nBody text\r\n";

        let payload = build_html_inline_email_signature_payload(raw).unwrap();

        assert_eq!(payload.headers.from.value, "sender@example.com");
        assert_eq!(payload.headers.to.value, "recipient@example.com");
        assert_eq!(payload.headers.subject.value, "Header Scope");
        assert_eq!(
            payload.headers.date.value,
            "Fri, 28 Feb 2026 12:00:00 +0000"
        );
        assert_eq!(
            payload.headers.message_id.value,
            "<header-scope@example.com>"
        );
        assert_eq!(
            payload.headers.cc.as_ref().unwrap().value,
            "reviewer@example.com"
        );
        assert_eq!(
            payload.headers.in_reply_to.as_ref().unwrap().value,
            "<parent@example.com>"
        );
        assert_eq!(
            payload.headers.references.as_ref().unwrap().value,
            "<root@example.com> <parent@example.com>"
        );
    }

    #[test]
    #[serial(jacs_env)]
    fn sign_email_threaded_reply_includes_in_reply_to_and_references() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent();
        let email = threaded_reply_email();
        let signed = sign_email(&email, &agent).unwrap();

        let payload = extract_payload(&signed);
        assert!(payload.headers.in_reply_to.is_some());
        assert!(payload.headers.references.is_some());
    }
    #[test]
    #[serial(jacs_env)]
    fn sign_email_sets_parent_signature_hash_null() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent();
        let email = simple_text_email();
        let signed = sign_email(&email, &agent).unwrap();

        let payload = extract_payload(&signed);
        assert!(payload.parent_signature_hash.is_none());
    }
    #[test]
    #[serial(jacs_env)]
    fn sign_email_document_has_jacs_fields() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent();
        let email = simple_text_email();
        let signed = sign_email(&email, &agent).unwrap();

        let doc_bytes = super::super::attachment::get_jacs_attachment(&signed).unwrap();
        let doc_str = std::str::from_utf8(&doc_bytes).unwrap();
        let jacs_doc: serde_json::Value = serde_json::from_str(doc_str).unwrap();

        assert!(jacs_doc.get("jacsId").is_some(), "should have jacsId");
        assert!(
            jacs_doc.get("jacsVersion").is_some(),
            "should have jacsVersion"
        );
        assert!(
            jacs_doc.get("jacsSignature").is_some(),
            "should have jacsSignature"
        );
        assert!(
            jacs_doc.get("jacsSha256").is_some(),
            "should have jacsSha256"
        );
        assert!(
            jacs_doc.get("content").is_some(),
            "should have content field"
        );
        assert_eq!(jacs_doc["jacsType"].as_str(), Some("message"));
    }
    #[test]
    #[serial(jacs_env)]
    fn sign_roundtrip_hashes_are_valid_sha256() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent();
        let email = simple_text_email();
        let signed = sign_email(&email, &agent).unwrap();

        let payload = extract_payload(&signed);

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

        check_hash(&payload.headers.from.hash, "from");
        check_hash(&payload.headers.to.hash, "to");
        check_hash(&payload.headers.subject.hash, "subject");
        check_hash(&payload.headers.date.hash, "date");
        check_hash(&payload.headers.message_id.hash, "message_id");

        if let Some(bp) = &payload.body_plain {
            check_hash(&bp.content_hash, "body_plain.content");
            check_hash(&bp.mime_headers_hash, "body_plain.mime");
        }
    }
    #[test]
    #[serial(jacs_env)]
    fn sign_multipart_has_both_body_hashes() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent();
        let email = multipart_alternative_email();
        let signed = sign_email(&email, &agent).unwrap();

        let payload = extract_payload(&signed);

        let plain = payload.body_plain.as_ref().unwrap();
        let html = payload.body_html.as_ref().unwrap();

        assert!(plain.content_hash.starts_with("sha256:"));
        assert!(plain.mime_headers_hash.starts_with("sha256:"));
        assert!(html.content_hash.starts_with("sha256:"));
        assert!(html.mime_headers_hash.starts_with("sha256:"));
    }

    // =========================================================================
    // YAML/HTML email signing wrapper tests (conversion-related)
    //
    // These tests exercise the YAML/HTML format conversion integration with
    // the email signing system. Run with:
    //   cargo test -p jacs --features attestation -- sign_email_yaml
    //   cargo test -p jacs --features attestation -- sign_email_html
    // =========================================================================

    #[test]
    #[serial(jacs_env)]
    fn sign_email_yaml_attaches_yaml_signature() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent();
        let email = simple_text_email();
        let signed = sign_email_yaml(&email, &agent).unwrap();
        let signed_str = String::from_utf8_lossy(&signed);

        // Should have YAML attachment, not JSON
        assert!(
            signed_str.contains("jacs-signature.yaml"),
            "Should have jacs-signature.yaml attachment"
        );
        // Should be parseable
        assert!(
            mail_parser::MessageParser::default()
                .parse(&signed)
                .is_some()
        );
    }

    #[test]
    #[serial(jacs_env)]
    fn sign_email_yaml_round_trips_to_verifiable_json() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent();
        let email = simple_text_email();
        let signed = sign_email_yaml(&email, &agent).unwrap();

        // Extract the YAML attachment
        let yaml_bytes =
            super::super::attachment::get_jacs_attachment_named(&signed, "jacs-signature.yaml")
                .unwrap();
        let yaml_str = std::str::from_utf8(&yaml_bytes).unwrap();

        // Convert back to JSON
        let json_str = crate::convert::yaml_to_jacs(yaml_str).unwrap();

        // Verify the reconstituted JSON
        let result = agent.verify(&json_str).unwrap();
        assert!(
            result.valid,
            "YAML attachment should round-trip to verifiable JSON: {:?}",
            result.errors
        );
    }

    #[test]
    #[serial(jacs_env)]
    fn sign_email_html_attaches_html_signature() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent();
        let email = simple_text_email();
        let signed = sign_email_html(&email, &agent).unwrap();
        let signed_str = String::from_utf8_lossy(&signed);

        // Should have HTML attachment, not JSON
        assert!(
            signed_str.contains("jacs-signature.html"),
            "Should have jacs-signature.html attachment"
        );
        // Should be parseable
        assert!(
            mail_parser::MessageParser::default()
                .parse(&signed)
                .is_some()
        );
    }

    #[test]
    #[serial(jacs_env)]
    fn sign_email_html_contains_embedded_json_that_verifies() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent();
        let email = simple_text_email();
        let signed = sign_email_html(&email, &agent).unwrap();

        // Extract the HTML attachment
        let html_bytes =
            super::super::attachment::get_jacs_attachment_named(&signed, "jacs-signature.html")
                .unwrap();
        let html_str = std::str::from_utf8(&html_bytes).unwrap();

        // Extract JSON from HTML
        let json_str = crate::convert::html_to_jacs(html_str).unwrap();

        // Verify the extracted JSON
        let result = agent.verify(&json_str).unwrap();
        assert!(
            result.valid,
            "HTML attachment should contain verifiable JSON: {:?}",
            result.errors
        );
    }
}
