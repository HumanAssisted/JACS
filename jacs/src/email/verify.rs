//! Email verification implementation for the JACS email system.
//!
//! Provides `verify_email_document()` for JACS signature validation and
//! `verify_email_content()` for comparing trusted hashes against actual
//! email content.

use sha2::{Digest, Sha256};

use super::attachment::{
    DEFAULT_JACS_SIGNATURE_FILENAME, get_jacs_attachment_named, remove_jacs_attachment_named,
};
use super::canonicalize::{
    canonicalize_body, canonicalize_header, compute_attachment_hash, compute_body_hash,
    compute_header_entry, compute_mime_headers_hash, extract_email_parts,
};
use super::error::{EmailError, check_email_size};
use super::result::{EmailVerificationReason, SignedEmailVerificationResult, VerificationMode};
use super::transport::{
    SignedEmailTransport, detect_signed_email_transport, extract_inline_logo_part,
    extract_jacs_header_from_logo_png, extract_topmost_inline_jacs_envelope,
    html_bodies_equivalent, strip_inline_signature_artifacts_from_html,
};
use super::types::{
    ChainEntry, ContentVerificationResult, FieldResult, FieldStatus, JacsEmailSignatureDocument,
    ParsedEmailParts, SignedHeaderEntry,
};

/// Normalize an algorithm name to its canonical form.
///
/// Lowercases, strips "ring-" prefix and "-sha256"/"-sha384"/"-sha512" suffixes.
/// Examples:
/// - `"Ring-Ed25519"` → `"ed25519"`
/// - `"PQ2025"` → `"pq2025"`
pub fn normalize_algorithm(algorithm: &str) -> String {
    let mut s = algorithm.to_lowercase();
    if let Some(rest) = s.strip_prefix("ring-") {
        s = rest.to_string();
    }
    for suffix in &["-sha256", "-sha384", "-sha512"] {
        if let Some(rest) = s.strip_suffix(suffix) {
            s = rest.to_string();
            break;
        }
    }
    s
}

/// Extract and verify the JACS email signature document from a raw email,
/// looking for a custom attachment filename.
///
/// Same as [`verify_email_document`] but accepts a custom JACS attachment
/// filename. Use this when the email uses a branded attachment name
/// instead of the JACS default.
pub fn verify_email_document_named(
    raw_email: &[u8],
    verifier: &impl super::JacsSigner,
    public_key: &[u8],
    filename: &str,
) -> Result<(JacsEmailSignatureDocument, ParsedEmailParts), EmailError> {
    check_email_size(raw_email)?;

    let jacs_bytes = get_jacs_attachment_named(raw_email, filename)?;
    let email_without_jacs = remove_jacs_attachment_named(raw_email, filename)?;

    let jacs_str = std::str::from_utf8(&jacs_bytes).map_err(|e| {
        EmailError::InvalidJacsDocument(format!("attachment is not valid UTF-8: {e}"))
    })?;

    // Auto-detect format from filename extension and convert to JSON if needed.
    // YAML attachments are converted via yaml_to_jacs, HTML via html_to_jacs.
    // JSON attachments (or unrecognized extensions) are used as-is.
    let jacs_json = if filename.ends_with(".yaml") || filename.ends_with(".yml") {
        crate::convert::yaml_to_jacs(jacs_str).map_err(|e| {
            EmailError::InvalidJacsDocument(format!("YAML to JSON conversion failed: {e}"))
        })?
    } else if filename.ends_with(".html") || filename.ends_with(".htm") {
        crate::convert::html_to_jacs(jacs_str).map_err(|e| {
            EmailError::InvalidJacsDocument(format!("HTML to JSON extraction failed: {e}"))
        })?
    } else {
        jacs_str.to_string()
    };

    let doc = verify_jacs_email_document_json(&jacs_json, verifier, public_key)?;
    let parts = extract_email_parts(&email_without_jacs)?;
    Ok((doc, parts))
}

/// Extract and verify the JACS email signature document from a raw email.
///
/// Uses the default attachment filename ([`DEFAULT_JACS_SIGNATURE_FILENAME`]).
/// For a custom filename, use [`verify_email_document_named`].
pub fn verify_email_document(
    raw_email: &[u8],
    verifier: &impl super::JacsSigner,
    public_key: &[u8],
) -> Result<(JacsEmailSignatureDocument, ParsedEmailParts), EmailError> {
    verify_email_document_named(
        raw_email,
        verifier,
        public_key,
        DEFAULT_JACS_SIGNATURE_FILENAME,
    )
}

pub fn verify_html_inline_email_document(
    raw_email: &[u8],
    verifier: &impl super::JacsSigner,
    public_key: &[u8],
) -> Result<(JacsEmailSignatureDocument, ParsedEmailParts), EmailError> {
    check_email_size(raw_email)?;

    let envelope = extract_topmost_inline_jacs_envelope(raw_email)?;
    let envelope_value: serde_json::Value = serde_json::from_str(&envelope).map_err(|e| {
        EmailError::InvalidJacsDocument(format!("failed to parse inline JACS envelope: {e}"))
    })?;
    let jacs_envelope = envelope_value.get("jacsEnvelope").ok_or_else(|| {
        EmailError::InvalidJacsDocument("inline JACS envelope missing jacsEnvelope".to_string())
    })?;
    let jacs_json = serde_json::to_string(jacs_envelope).map_err(|e| {
        EmailError::InvalidJacsDocument(format!("failed to serialize inline JACS envelope: {e}"))
    })?;

    let doc = verify_jacs_email_document_json(&jacs_json, verifier, public_key)?;
    let parts = extract_email_parts(raw_email)?;
    Ok((doc, parts))
}

fn verify_jacs_email_document_json(
    jacs_json: &str,
    verifier: &impl super::JacsSigner,
    public_key: &[u8],
) -> Result<JacsEmailSignatureDocument, EmailError> {
    let result = verifier
        .verify_with_key(jacs_json, public_key.to_vec())
        .map_err(|e| {
            EmailError::SignatureVerificationFailed(format!(
                "JACS document verification failed: {e}"
            ))
        })?;

    if !result.valid {
        return Err(EmailError::SignatureVerificationFailed(format!(
            "JACS document signature is invalid: {:?}",
            result.errors
        )));
    }

    let jacs_value: serde_json::Value = serde_json::from_str(jacs_json).map_err(|e| {
        EmailError::InvalidJacsDocument(format!("failed to parse JACS document: {e}"))
    })?;

    let content = jacs_value.get("content").ok_or_else(|| {
        EmailError::InvalidJacsDocument("JACS document missing 'content' field".to_string())
    })?;

    let payload: super::types::EmailSignaturePayload = serde_json::from_value(content.clone())
        .map_err(|e| {
            EmailError::InvalidJacsDocument(format!(
                "failed to parse email payload from JACS document: {e}"
            ))
        })?;

    let signer_id = jacs_value
        .get("jacsSignature")
        .and_then(|sig| sig.get("agentID"))
        .and_then(|id| id.as_str())
        .unwrap_or("")
        .to_string();

    let document_id = jacs_value
        .get("jacsId")
        .and_then(|id| id.as_str())
        .unwrap_or("")
        .to_string();

    let created_at = jacs_value
        .get("jacsSignature")
        .and_then(|sig| sig.get("date"))
        .and_then(|d| d.as_str())
        .unwrap_or("")
        .to_string();

    let hash = jacs_value
        .get("jacsSha256")
        .and_then(|h| h.as_str())
        .unwrap_or("")
        .to_string();

    Ok(JacsEmailSignatureDocument {
        version: "2.0".to_string(),
        document_type: "email_signature".to_string(),
        payload,
        metadata: super::types::JacsEmailMetadata {
            issuer: signer_id,
            document_id,
            created_at: created_at.clone(),
            hash,
        },
        signature: super::types::JacsEmailSignature {
            key_id: String::new(),
            algorithm: String::new(),
            signature: String::new(),
            signed_at: created_at,
        },
    })
}

/// Verify a JACS-signed email with a custom attachment filename.
///
/// Same as [`verify_email`] but accepts a custom JACS attachment filename.
pub fn verify_email_named(
    raw_eml: &[u8],
    verifier: &impl super::JacsSigner,
    public_key: &[u8],
    filename: &str,
) -> Result<ContentVerificationResult, EmailError> {
    let (doc, parts) = verify_email_document_named(raw_eml, verifier, public_key, filename)?;
    Ok(verify_email_content(&doc, &parts))
}

/// Verify a JACS-signed email in a single call.
///
/// Uses the default attachment filename ([`DEFAULT_JACS_SIGNATURE_FILENAME`]).
/// For a custom filename, use [`verify_email_named`].
pub fn verify_email(
    raw_eml: &[u8],
    verifier: &impl super::JacsSigner,
    public_key: &[u8],
) -> Result<ContentVerificationResult, EmailError> {
    verify_email_named(
        raw_eml,
        verifier,
        public_key,
        DEFAULT_JACS_SIGNATURE_FILENAME,
    )
}

/// Detect the signed email transport and verify it through one entrypoint.
///
/// Attachment-backed messages delegate to the existing verifier. HTML-inline
/// verification is added incrementally by the inline transport tasks.
pub fn verify_signed_email(
    raw_eml: &[u8],
    verifier: &impl super::JacsSigner,
    public_key: &[u8],
    _mode: VerificationMode,
) -> Result<SignedEmailVerificationResult, EmailError> {
    match detect_signed_email_transport(raw_eml)? {
        SignedEmailTransport::AttachmentJacs => {
            let result = verify_email(raw_eml, verifier, public_key)?;
            if result.valid {
                Ok(SignedEmailVerificationResult::verified(
                    SignedEmailTransport::AttachmentJacs,
                ))
            } else {
                Ok(SignedEmailVerificationResult::failed(
                    SignedEmailTransport::AttachmentJacs,
                    EmailVerificationReason::CanonicalPreimageHashMismatch,
                ))
            }
        }
        SignedEmailTransport::HtmlInline => {
            let envelope = match extract_topmost_inline_jacs_envelope(raw_eml) {
                Ok(envelope) => envelope,
                Err(_) => {
                    return Ok(SignedEmailVerificationResult::failed(
                        SignedEmailTransport::HtmlInline,
                        EmailVerificationReason::MissingInlineJacsEnvelope,
                    ));
                }
            };
            let expected_logo_header = match expected_logo_header_from_inline_envelope(&envelope) {
                Some(header) => header,
                None => {
                    return Ok(SignedEmailVerificationResult::failed(
                        SignedEmailTransport::HtmlInline,
                        EmailVerificationReason::MissingInlineJacsEnvelope,
                    ));
                }
            };

            let logo = match extract_inline_logo_part(raw_eml) {
                Ok(logo) => logo,
                Err(_) => {
                    return Ok(SignedEmailVerificationResult::non_crypto_transport_failure(
                        _mode,
                        SignedEmailTransport::HtmlInline,
                        EmailVerificationReason::MissingSignedLogo,
                    ));
                }
            };

            let actual_logo_header = match extract_jacs_header_from_logo_png(&logo.content) {
                Ok(Some(header)) => header,
                Ok(None) | Err(_) => {
                    return Ok(SignedEmailVerificationResult::non_crypto_transport_failure(
                        _mode,
                        SignedEmailTransport::HtmlInline,
                        EmailVerificationReason::LogoSignatureExtractFailed,
                    ));
                }
            };

            if actual_logo_header != expected_logo_header {
                return Ok(SignedEmailVerificationResult::failed(
                    SignedEmailTransport::HtmlInline,
                    EmailVerificationReason::LogoSignatureMismatch,
                ));
            }

            let (doc, parts) = verify_html_inline_email_document(raw_eml, verifier, public_key)?;
            let content_result = verify_html_inline_email_content(&doc, &parts);
            if !content_result.valid {
                return Ok(SignedEmailVerificationResult::failed(
                    SignedEmailTransport::HtmlInline,
                    EmailVerificationReason::CanonicalPreimageHashMismatch,
                ));
            }

            if !html_inline_presentation_equivalent(&parts) {
                return Ok(SignedEmailVerificationResult::non_crypto_transport_failure(
                    _mode,
                    SignedEmailTransport::HtmlInline,
                    EmailVerificationReason::HtmlEquivalenceFailed,
                ));
            }

            Ok(SignedEmailVerificationResult::verified(
                SignedEmailTransport::HtmlInline,
            ))
        }
    }
}

fn expected_logo_header_from_inline_envelope(envelope: &str) -> Option<String> {
    let trimmed = envelope.trim();
    if trimmed.is_empty() {
        return None;
    }

    serde_json::from_str::<serde_json::Value>(trimmed)
        .ok()
        .and_then(|value| {
            value
                .get("compactHeader")
                .and_then(|header| header.as_str())
                .map(str::to_string)
        })
        .or_else(|| Some(trimmed.to_string()))
}

fn html_inline_presentation_equivalent(parts: &ParsedEmailParts) -> bool {
    let Some(text_part) = parts.body_plain.as_ref() else {
        return false;
    };
    let Some(html_part) = parts.body_html.as_ref() else {
        return false;
    };

    let text_body = String::from_utf8_lossy(&text_part.content);
    let user_text = user_text_from_inline_text_body(&text_body);
    let expected_html = render_expected_html_inline_body_without_artifacts(&user_text);
    let received_html = String::from_utf8_lossy(&html_part.content);
    let received_without_artifacts = strip_inline_signature_artifacts_from_html(&received_html);

    html_bodies_equivalent(expected_html.trim(), received_without_artifacts.trim())
}

fn user_text_from_inline_text_body(text_body: &str) -> String {
    let trimmed = text_body.trim_end_matches(['\r', '\n']);
    for separator in ["\r\n\r\n", "\n\n"] {
        if let Some((head, tail)) = trimmed.rsplit_once(separator) {
            if tail.starts_with("This email is sent from an AI agent. Verify at ") {
                return head.to_string();
            }
        }
    }
    trimmed.to_string()
}

fn render_expected_html_inline_body_without_artifacts(plain_text: &str) -> String {
    let normalized = plain_text.replace("\r\n", "\n").replace('\r', "\n");
    let body = escape_html_text(&normalized).replace('\n', "<br>");

    format!(
        r#"<html data-hai-template-version="v1"><body><main data-hai-message-body="v1">{body}</main></body></html>"#
    )
}

fn escape_html_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Verify a JACS-signed email whose signature attachment is in YAML format.
///
/// Looks for a `jacs-signature.yaml` attachment, converts it to JSON via
/// [`crate::convert::yaml_to_jacs`], and delegates to the standard
/// verification pipeline.
///
/// For a custom attachment filename, use [`verify_email_yaml_named`].
pub fn verify_email_yaml(
    raw_eml: &[u8],
    verifier: &impl super::JacsSigner,
    public_key: &[u8],
) -> Result<ContentVerificationResult, EmailError> {
    verify_email_yaml_named(raw_eml, verifier, public_key, "jacs-signature.yaml")
}

/// Verify a JACS-signed email whose YAML signature attachment has a custom filename.
///
/// Same as [`verify_email_yaml`] but accepts a custom attachment filename.
pub fn verify_email_yaml_named(
    raw_eml: &[u8],
    verifier: &impl super::JacsSigner,
    public_key: &[u8],
    filename: &str,
) -> Result<ContentVerificationResult, EmailError> {
    // verify_email_document_named already handles YAML auto-detection by extension
    let (doc, parts) = verify_email_document_named(raw_eml, verifier, public_key, filename)?;
    Ok(verify_email_content(&doc, &parts))
}

/// Verify a JACS-signed email whose signature attachment is in HTML format.
///
/// Looks for a `jacs-signature.html` attachment, extracts the embedded JSON
/// via [`crate::convert::html_to_jacs`], and delegates to the standard
/// verification pipeline.
///
/// For a custom attachment filename, use [`verify_email_html_named`].
pub fn verify_email_html(
    raw_eml: &[u8],
    verifier: &impl super::JacsSigner,
    public_key: &[u8],
) -> Result<ContentVerificationResult, EmailError> {
    verify_email_html_named(raw_eml, verifier, public_key, "jacs-signature.html")
}

/// Verify a JACS-signed email whose HTML signature attachment has a custom filename.
///
/// Same as [`verify_email_html`] but accepts a custom attachment filename.
pub fn verify_email_html_named(
    raw_eml: &[u8],
    verifier: &impl super::JacsSigner,
    public_key: &[u8],
    filename: &str,
) -> Result<ContentVerificationResult, EmailError> {
    // verify_email_document_named already handles HTML auto-detection by extension
    let (doc, parts) = verify_email_document_named(raw_eml, verifier, public_key, filename)?;
    Ok(verify_email_content(&doc, &parts))
}

/// Compare trusted JACS document hashes against actual email content.
///
/// This is the second step of two-step verification. Use `verify_email()`
/// for the simple one-call API. Use this when you need access to the
/// intermediate `JacsEmailSignatureDocument` (e.g., to inspect metadata
/// or issuer before content comparison).
///
/// For each field in the JACS document:
/// - Headers: recompute hash of canonicalized value, compare to stored hash
/// - Body parts: recompute content_hash
/// - Attachments: recompute hashes and compare sorted lists
///
/// Special cases:
/// - Message-ID always returns `Unverifiable`
/// - Missing body parts return `Unverifiable` (not `Fail`)
/// - Address header mismatches get case-insensitive fallback (returns `Modified`)
pub fn verify_email_content(
    doc: &JacsEmailSignatureDocument,
    parts: &ParsedEmailParts,
) -> ContentVerificationResult {
    let mut field_results = Vec::new();

    // Verify headers
    verify_header_field(
        "headers.from",
        &doc.payload.headers.from,
        parts.headers.get("from"),
        true,
        &mut field_results,
    );
    verify_header_field(
        "headers.to",
        &doc.payload.headers.to,
        parts.headers.get("to"),
        true,
        &mut field_results,
    );
    if let Some(ref cc) = doc.payload.headers.cc {
        verify_header_field(
            "headers.cc",
            cc,
            parts.headers.get("cc"),
            true,
            &mut field_results,
        );
    }
    verify_header_field(
        "headers.subject",
        &doc.payload.headers.subject,
        parts.headers.get("subject"),
        false,
        &mut field_results,
    );
    verify_header_field(
        "headers.date",
        &doc.payload.headers.date,
        parts.headers.get("date"),
        false,
        &mut field_results,
    );

    // Message-ID is always Unverifiable
    field_results.push(FieldResult {
        field: "headers.message_id".to_string(),
        status: FieldStatus::Unverifiable,
        original_hash: Some(doc.payload.headers.message_id.hash.clone()),
        current_hash: None,
        original_value: Some(doc.payload.headers.message_id.value.clone()),
        current_value: parts
            .headers
            .get("message-id")
            .and_then(|v| v.first())
            .cloned(),
    });

    if let Some(ref irt) = doc.payload.headers.in_reply_to {
        verify_header_field(
            "headers.in_reply_to",
            irt,
            parts.headers.get("in-reply-to"),
            false,
            &mut field_results,
        );
    }
    if let Some(ref refs) = doc.payload.headers.references {
        verify_header_field(
            "headers.references",
            refs,
            parts.headers.get("references"),
            false,
            &mut field_results,
        );
    }

    // Verify body parts
    verify_body_part(
        "body_plain",
        doc.payload.body_plain.as_ref(),
        parts.body_plain.as_ref(),
        &mut field_results,
    );
    verify_body_part(
        "body_html",
        doc.payload.body_html.as_ref(),
        parts.body_html.as_ref(),
        &mut field_results,
    );

    // Verify attachments
    // For forwarded emails, the renamed signature files appear as
    // regular attachments in the current email (parts.jacs_attachments) and
    // should be included when comparing against the signed attachment list.
    let mut all_current_attachments = parts.attachments.clone();
    for jacs_att in &parts.jacs_attachments {
        all_current_attachments.push(jacs_att.clone());
    }

    verify_attachments(
        &doc.payload.attachments,
        &all_current_attachments,
        &mut field_results,
    );

    // valid = true only if no Fail results
    let fields_valid = !field_results.iter().any(|r| r.status == FieldStatus::Fail);

    // Build chain from the current signer
    let is_forwarded = doc.payload.parent_signature_hash.is_some();
    let mut chain = vec![ChainEntry {
        signer: doc.payload.headers.from.value.clone(),
        jacs_id: doc.metadata.issuer.clone(),
        valid: fields_valid,
        forwarded: is_forwarded,
    }];

    // If parent_signature_hash exists, build the parent chain entries
    if let Some(ref parent_hash) = doc.payload.parent_signature_hash {
        build_parent_chain(parent_hash, parts, &mut chain);
    }

    // Overall validity: fields must pass AND all chain entries must be valid.
    // Parent chain entries are initially valid=false at the JACS level because
    // we lack the parent signers' public keys. The haisdk/HAI API layer must
    // verify parent signatures and upgrade chain entries before trusting the
    // chain. Until then, a forwarded email with unverified parents is invalid.
    let chain_valid = chain.iter().all(|entry| entry.valid);
    let valid = fields_valid && chain_valid;

    ContentVerificationResult {
        valid,
        field_results,
        chain,
    }
}

/// Verify content for HTML-inline signed email.
///
/// Inline transport signs user-authored content, not transport artifacts. This
/// wrapper removes the inline logo MIME artifact before delegating to the
/// existing content verifier so user attachments remain covered.
pub fn verify_html_inline_email_content(
    doc: &JacsEmailSignatureDocument,
    parts: &ParsedEmailParts,
) -> ContentVerificationResult {
    let mut parts_without_artifacts = parts.clone();
    parts_without_artifacts
        .attachments
        .retain(|att| !super::transport::is_inline_logo_attachment_artifact(att));
    verify_email_content(doc, &parts_without_artifacts)
}

/// Build the parent chain by walking parent_signature_hash links.
///
/// This resolves parent signatures from the JACS attachments in the email.
/// At the JACS library level, we can validate the document structure and hash
/// chain but NOT the cryptographic signatures (since we don't have the parent
/// signers' public keys -- that's done at the haisdk layer).
///
/// Supports both real JACS documents (v2, with `content` and `jacsSignature`
/// fields) and legacy `JacsEmailSignatureDocument` (v1).
fn build_parent_chain(parent_hash: &str, parts: &ParsedEmailParts, chain: &mut Vec<ChainEntry>) {
    // Search for the parent document among JACS attachments
    for jacs_att in &parts.jacs_attachments {
        // Compute sha256 of the exact attachment bytes (no trimming)
        let att_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&jacs_att.content);
            format!("sha256:{}", hex::encode(hasher.finalize()))
        };

        if att_hash == parent_hash {
            // Found the parent document -- try to parse it.
            // First attempt: real JACS document (new format with `content` field).
            if let Some((payload, signer_id)) = try_parse_jacs_document(&jacs_att.content) {
                let is_forwarded = payload.parent_signature_hash.is_some();
                chain.push(ChainEntry {
                    signer: payload.headers.from.value.clone(),
                    jacs_id: signer_id,
                    valid: false,
                    forwarded: is_forwarded,
                });

                // Recurse if this parent also has a parent
                if let Some(ref grandparent_hash) = payload.parent_signature_hash {
                    build_parent_chain(grandparent_hash, parts, chain);
                }
                return;
            }

            // Fallback: legacy JacsEmailSignatureDocument format (v1).
            if let Ok(parent_doc) =
                serde_json::from_slice::<JacsEmailSignatureDocument>(&jacs_att.content)
            {
                let is_forwarded = parent_doc.payload.parent_signature_hash.is_some();
                chain.push(ChainEntry {
                    signer: parent_doc.payload.headers.from.value.clone(),
                    jacs_id: parent_doc.metadata.issuer.clone(),
                    valid: false,
                    forwarded: is_forwarded,
                });

                if let Some(ref grandparent_hash) = parent_doc.payload.parent_signature_hash {
                    build_parent_chain(grandparent_hash, parts, chain);
                }
                return;
            }

            // Could not parse the parent document in either format
            return;
        }
    }
}

/// Try to parse raw bytes as a real JACS document (new format).
///
/// Returns the extracted `EmailSignaturePayload` and signer ID on success.
fn try_parse_jacs_document(raw: &[u8]) -> Option<(super::types::EmailSignaturePayload, String)> {
    let value: serde_json::Value = serde_json::from_slice(raw).ok()?;

    // Real JACS documents have a `content` field containing the payload
    let content = value.get("content")?;
    let payload: super::types::EmailSignaturePayload =
        serde_json::from_value(content.clone()).ok()?;

    let signer_id = value
        .get("jacsSignature")
        .and_then(|sig| sig.get("agentID"))
        .and_then(|id| id.as_str())
        .unwrap_or("")
        .to_string();

    Some((payload, signer_id))
}

/// Verify a single header field.
fn verify_header_field(
    field_name: &str,
    stored: &SignedHeaderEntry,
    current_values: Option<&Vec<String>>,
    is_address_header: bool,
    results: &mut Vec<FieldResult>,
) {
    let current_value = current_values.and_then(|v| v.first()).cloned();

    let Some(ref current_raw) = current_value else {
        // Header is missing from current email
        results.push(FieldResult {
            field: field_name.to_string(),
            status: FieldStatus::Fail,
            original_hash: Some(stored.hash.clone()),
            current_hash: None,
            original_value: Some(stored.value.clone()),
            current_value: None,
        });
        return;
    };

    // Determine the header name from the field_name for canonicalization
    let header_name = field_name
        .strip_prefix("headers.")
        .unwrap_or(field_name)
        .replace('_', "-");

    let canonical = match canonicalize_header(&header_name, current_raw) {
        Ok(c) => c,
        Err(_) => {
            results.push(FieldResult {
                field: field_name.to_string(),
                status: FieldStatus::Fail,
                original_hash: Some(stored.hash.clone()),
                current_hash: None,
                original_value: Some(stored.value.clone()),
                current_value: Some(current_raw.clone()),
            });
            return;
        }
    };

    let current_hash = compute_header_entry(&canonical);

    if current_hash == stored.hash {
        results.push(FieldResult {
            field: field_name.to_string(),
            status: FieldStatus::Pass,
            original_hash: Some(stored.hash.clone()),
            current_hash: Some(current_hash),
            original_value: Some(stored.value.clone()),
            current_value: Some(canonical),
        });
    } else if is_address_header {
        // Case-insensitive fallback for address headers
        if addresses_match_case_insensitive(&stored.value, &canonical) {
            results.push(FieldResult {
                field: field_name.to_string(),
                status: FieldStatus::Modified,
                original_hash: Some(stored.hash.clone()),
                current_hash: Some(current_hash),
                original_value: Some(stored.value.clone()),
                current_value: Some(canonical),
            });
        } else {
            results.push(FieldResult {
                field: field_name.to_string(),
                status: FieldStatus::Fail,
                original_hash: Some(stored.hash.clone()),
                current_hash: Some(current_hash),
                original_value: Some(stored.value.clone()),
                current_value: Some(canonical),
            });
        }
    } else {
        results.push(FieldResult {
            field: field_name.to_string(),
            status: FieldStatus::Fail,
            original_hash: Some(stored.hash.clone()),
            current_hash: Some(current_hash),
            original_value: Some(stored.value.clone()),
            current_value: Some(canonical),
        });
    }
}

/// Check if two address-header values match case-insensitively.
///
/// Uses RFC 5322 mailbox parsing: extracts the addr-spec from angle brackets
/// (e.g., `"Display Name" <user@example.com>` → `user@example.com`) and
/// compares the addr-spec portions case-insensitively.
fn addresses_match_case_insensitive(a: &str, b: &str) -> bool {
    let mut a_addrs = extract_addr_specs(a);
    let mut b_addrs = extract_addr_specs(b);
    a_addrs.sort();
    b_addrs.sort();
    a_addrs == b_addrs
}

/// Extract addr-spec values from an RFC 5322 address-list header value.
///
/// Uses `mail_parser` to parse a synthetic `From:` header, which handles
/// RFC 5322 mailbox formats including:
/// - `user@example.com` (bare addr-spec)
/// - `<user@example.com>` (angle-addr without display name)
/// - `"Display Name" <user@example.com>` (name-addr with display name)
/// - `User <user@example.com>, Other <other@example.com>` (comma-separated list)
/// - `(comment) user@example.com` (comments in addresses)
/// - `"quoted.local"@example.com` (quoted local parts)
///
/// Returns lowercased addr-specs.
fn extract_addr_specs(header_value: &str) -> Vec<String> {
    // Build a minimal RFC 5322 message so mail_parser can parse the address.
    let synthetic = format!("From: {}\r\n\r\n", header_value);
    let message = mail_parser::MessageParser::default().parse(synthetic.as_bytes());

    if let Some(msg) = message {
        if let Some(from) = msg.from() {
            return from
                .iter()
                .filter_map(|addr| addr.address().map(|a| a.to_lowercase()))
                .collect();
        }
    }

    // Fallback: if mail_parser couldn't extract addresses, try manual extraction
    header_value
        .split(',')
        .filter_map(|addr| {
            let trimmed = addr.trim();
            if trimmed.is_empty() {
                return None;
            }
            if let Some(start) = trimmed.rfind('<') {
                if let Some(end) = trimmed[start..].find('>') {
                    let spec = &trimmed[start + 1..start + end];
                    let spec = spec.trim();
                    if !spec.is_empty() {
                        return Some(spec.to_lowercase());
                    }
                }
            }
            Some(trimmed.to_lowercase())
        })
        .collect()
}

/// Verify a body part (text/plain or text/html).
fn verify_body_part(
    field_name: &str,
    stored: Option<&super::types::BodyPartEntry>,
    current: Option<&super::types::ParsedBodyPart>,
    results: &mut Vec<FieldResult>,
) {
    match (stored, current) {
        (Some(stored_entry), Some(current_part)) => {
            let canonical = canonicalize_body(&current_part.content);
            let current_content_hash = compute_body_hash(&canonical);
            let current_mime_hash = compute_mime_headers_hash(
                current_part.content_type.as_deref(),
                current_part.content_transfer_encoding.as_deref(),
                current_part.content_disposition.as_deref(),
            );

            let content_match = current_content_hash == stored_entry.content_hash;
            let mime_match = current_mime_hash == stored_entry.mime_headers_hash;

            let status = if content_match && mime_match {
                FieldStatus::Pass
            } else {
                FieldStatus::Fail
            };

            results.push(FieldResult {
                field: field_name.to_string(),
                status,
                original_hash: Some(stored_entry.content_hash.clone()),
                current_hash: Some(current_content_hash),
                original_value: None,
                current_value: None,
            });
        }
        (Some(stored_entry), None) => {
            // Body part was stripped -- Unverifiable, not Fail
            results.push(FieldResult {
                field: field_name.to_string(),
                status: FieldStatus::Unverifiable,
                original_hash: Some(stored_entry.content_hash.clone()),
                current_hash: None,
                original_value: None,
                current_value: None,
            });
        }
        (None, Some(_)) => {
            // Body part exists but wasn't in the signed document -- unexpected
            // This is not a failure of the signed content, just extra content
        }
        (None, None) => {
            // Neither signed nor present -- nothing to verify
        }
    }
}

/// Verify attachments by comparing sorted lists.
fn verify_attachments(
    stored: &[super::types::AttachmentEntry],
    current: &[super::types::ParsedAttachment],
    results: &mut Vec<FieldResult>,
) {
    // Compute current attachment hashes, sorted by content_hash
    let mut current_entries: Vec<(String, String, String)> = current
        .iter()
        .map(|att| {
            let content_hash =
                compute_attachment_hash(&att.filename, &att.content_type, &att.content);
            let mime_hash = compute_mime_headers_hash(
                Some(&att.content_type),
                att.content_transfer_encoding.as_deref(),
                att.content_disposition.as_deref(),
            );
            (content_hash, mime_hash, att.filename.clone())
        })
        .collect();
    current_entries.sort_by(|a, b| a.0.cmp(&b.0));

    // Check count mismatch
    if stored.len() != current_entries.len() {
        results.push(FieldResult {
            field: "attachments".to_string(),
            status: FieldStatus::Fail,
            original_hash: None,
            current_hash: None,
            original_value: Some(format!("{} attachments", stored.len())),
            current_value: Some(format!("{} attachments", current_entries.len())),
        });
        return;
    }

    // Compare each attachment
    for (i, (stored_att, (current_hash, current_mime, current_name))) in
        stored.iter().zip(current_entries.iter()).enumerate()
    {
        let content_match = stored_att.content_hash == *current_hash;
        let mime_match = stored_att.mime_headers_hash == *current_mime;

        let status = if content_match && mime_match {
            FieldStatus::Pass
        } else {
            FieldStatus::Fail
        };

        results.push(FieldResult {
            field: format!("attachments[{}]", i),
            status,
            original_hash: Some(stored_att.content_hash.clone()),
            current_hash: Some(current_hash.clone()),
            original_value: Some(stored_att.filename.clone()),
            current_value: Some(current_name.clone()),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::email::canonicalize::extract_email_parts;
    use crate::email::sign::{
        build_html_inline_email_signature_payload, sign_email, sign_email_named,
    };
    use crate::email::transport::remove_inline_signature_artifacts;
    use crate::email::types::*;
    use crate::simple::SimpleAgent;

    use crate::email::EMAIL_TEST_MUTEX;
    use serial_test::serial;

    /// Create a test SimpleAgent and configure env vars for signing.
    ///
    /// MUST be called while holding `EMAIL_TEST_MUTEX`.
    fn create_test_agent(
        name: &str,
    ) -> (
        SimpleAgent,
        tempfile::TempDir,
        crate::email::EmailTestEnvGuard,
    ) {
        use crate::simple::CreateAgentParams;

        let tmp = tempfile::tempdir().expect("create temp dir");
        let tmp_root = tmp.path().canonicalize().expect("canonical temp dir");
        let tmp_path = tmp_root.to_string_lossy().to_string();

        let params = CreateAgentParams::builder()
            .name(name)
            .password("TestEmail!2026")
            .algorithm("ring-Ed25519")
            .domain("test.example.com")
            .description("Test agent for email verification")
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

    /// Extract the email signature payload from a signed email's JACS attachment.
    fn extract_payload(signed_email: &[u8]) -> EmailSignaturePayload {
        let doc_bytes = crate::email::attachment::get_jacs_attachment(signed_email).unwrap();
        let doc_str = std::str::from_utf8(&doc_bytes).unwrap();
        let jacs_doc: serde_json::Value = serde_json::from_str(doc_str).unwrap();
        let content = &jacs_doc["content"];
        serde_json::from_value(content.clone()).unwrap()
    }

    fn simple_text_email() -> Vec<u8> {
        b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <test@example.com>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello World\r\n".to_vec()
    }

    /// Helper: get the public key bytes for a test agent.
    fn get_pubkey(agent: &SimpleAgent) -> Vec<u8> {
        agent
            .get_public_key()
            .expect("get_public_key should succeed")
    }

    // -- verify_email_document tests --
    #[test]
    #[serial(jacs_env)]
    fn verify_email_document_valid_signature() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-valid-sig");
        let pubkey = get_pubkey(&agent);
        let email = simple_text_email();
        let signed = sign_email(&email, &agent).unwrap();

        let (doc, parts) = verify_email_document(&signed, &agent, &pubkey).unwrap();

        assert_eq!(doc.document_type, "email_signature");
        assert!(parts.body_plain.is_some());
    }
    #[test]
    #[serial(jacs_env)]
    fn verify_email_document_missing_jacs_attachment() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-missing");
        let pubkey = get_pubkey(&agent);
        let email = simple_text_email();
        let result = verify_email_document(&email, &agent, &pubkey);
        assert!(result.is_err());
        match result.unwrap_err() {
            EmailError::MissingJacsSignature => {}
            other => panic!("Expected MissingJacsSignature, got {:?}", other),
        }
    }
    #[test]
    #[serial(jacs_env)]
    fn verify_email_document_tampered_content() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-tamper");
        let pubkey = get_pubkey(&agent);
        let email = simple_text_email();
        let signed = sign_email(&email, &agent).unwrap();

        let doc_bytes = crate::email::attachment::get_jacs_attachment(&signed).unwrap();
        let doc_str = std::str::from_utf8(&doc_bytes).unwrap();
        let mut jacs_doc: serde_json::Value = serde_json::from_str(doc_str).unwrap();
        jacs_doc["content"]["headers"]["from"]["hash"] = serde_json::json!(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        );
        let tampered_json = serde_json::to_string(&jacs_doc).unwrap();

        let email_without = crate::email::attachment::remove_jacs_attachment(&signed).unwrap();
        let tampered_email =
            crate::email::attachment::add_jacs_attachment(&email_without, tampered_json.as_bytes())
                .unwrap();

        let result = verify_email_document(&tampered_email, &agent, &pubkey);
        assert!(
            result.is_err(),
            "Tampered JACS document should fail verification"
        );
    }

    // -- verify_email_content tests --
    #[test]
    #[serial(jacs_env)]
    fn verify_email_content_all_pass() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-content-pass");
        let pubkey = get_pubkey(&agent);
        let email = simple_text_email();
        let signed = sign_email(&email, &agent).unwrap();

        let (doc, parts) = verify_email_document(&signed, &agent, &pubkey).unwrap();
        let result = verify_email_content(&doc, &parts);

        assert!(
            result.valid,
            "valid is false, field_results: {:?}",
            result.field_results
        );
        let from_result = result
            .field_results
            .iter()
            .find(|r| r.field == "headers.from")
            .unwrap();
        assert_eq!(from_result.status, FieldStatus::Pass);
        let subject_result = result
            .field_results
            .iter()
            .find(|r| r.field == "headers.subject")
            .unwrap();
        assert_eq!(subject_result.status, FieldStatus::Pass);
    }
    #[test]
    #[serial(jacs_env)]
    fn verify_email_content_tampered_from() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-tamper-from");
        let pubkey = get_pubkey(&agent);
        let email = simple_text_email();
        let signed = sign_email(&email, &agent).unwrap();

        let (doc, mut parts) = verify_email_document(&signed, &agent, &pubkey).unwrap();
        parts
            .headers
            .insert("from".to_string(), vec!["attacker@evil.com".to_string()]);

        let result = verify_email_content(&doc, &parts);
        assert!(!result.valid);
        let from_result = result
            .field_results
            .iter()
            .find(|r| r.field == "headers.from")
            .unwrap();
        assert_eq!(from_result.status, FieldStatus::Fail);
    }
    #[test]
    #[serial(jacs_env)]
    fn verify_email_content_tampered_body() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-tamper-body");
        let pubkey = get_pubkey(&agent);
        let email = simple_text_email();
        let signed = sign_email(&email, &agent).unwrap();

        let (doc, mut parts) = verify_email_document(&signed, &agent, &pubkey).unwrap();
        if let Some(ref mut bp) = parts.body_plain {
            bp.content = b"Tampered body content".to_vec();
        }

        let result = verify_email_content(&doc, &parts);
        assert!(!result.valid);
        let body_result = result
            .field_results
            .iter()
            .find(|r| r.field == "body_plain")
            .unwrap();
        assert_eq!(body_result.status, FieldStatus::Fail);
    }
    #[test]
    #[serial(jacs_env)]
    fn verify_email_content_message_id_unverifiable() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-mid");
        let pubkey = get_pubkey(&agent);
        let email = simple_text_email();
        let signed = sign_email(&email, &agent).unwrap();

        let (doc, parts) = verify_email_document(&signed, &agent, &pubkey).unwrap();
        let result = verify_email_content(&doc, &parts);

        let mid_result = result
            .field_results
            .iter()
            .find(|r| r.field == "headers.message_id")
            .unwrap();
        assert_eq!(mid_result.status, FieldStatus::Unverifiable);
    }
    #[test]
    #[serial(jacs_env)]
    fn verify_email_content_extra_attachment() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-extra-att");
        let pubkey = get_pubkey(&agent);
        let email_with_att = b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <test@example.com>\r\nContent-Type: multipart/mixed; boundary=\"mixbound\"\r\n\r\n--mixbound\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nBody\r\n--mixbound--\r\n";

        let signed = sign_email(email_with_att, &agent).unwrap();
        let (doc, mut parts) = verify_email_document(&signed, &agent, &pubkey).unwrap();

        parts
            .attachments
            .push(super::super::types::ParsedAttachment {
                filename: "extra.txt".to_string(),
                content_type: "text/plain".to_string(),
                content: b"extra content".to_vec(),
                content_transfer_encoding: None,
                content_disposition: Some("attachment".to_string()),
            });

        let result = verify_email_content(&doc, &parts);
        assert!(!result.valid);
        let att_result = result
            .field_results
            .iter()
            .find(|r| r.field == "attachments")
            .unwrap();
        assert_eq!(att_result.status, FieldStatus::Fail);
    }

    // -- Integration tests --
    #[test]
    #[serial(jacs_env)]
    fn sign_verify_roundtrip_valid() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-roundtrip");
        let pubkey = get_pubkey(&agent);
        let email = simple_text_email();
        let signed = sign_email(&email, &agent).unwrap();

        let result = verify_email(&signed, &agent, &pubkey).unwrap();
        assert!(
            result.valid,
            "roundtrip should be valid: {:?}",
            result.field_results
        );
        assert!(
            result
                .field_results
                .iter()
                .all(|r| r.status == FieldStatus::Pass || r.status == FieldStatus::Unverifiable),
            "unexpected field status: {:?}",
            result.field_results
        );
    }

    #[test]
    #[serial(jacs_env)]
    fn verify_signed_email_preserves_attachment_roundtrip() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-entrypoint-attachment");
        let pubkey = get_pubkey(&agent);
        let email = simple_text_email();
        let signed = sign_email(&email, &agent).unwrap();

        let result =
            verify_signed_email(&signed, &agent, &pubkey, VerificationMode::Strict).unwrap();

        assert_eq!(
            result.status,
            crate::email::EmailVerificationStatus::Verified,
            "unexpected verifier result: {result:?}"
        );
        assert_eq!(result.transport, SignedEmailTransport::AttachmentJacs);
        assert!(result.reasons.is_empty());
    }

    #[test]
    #[serial(jacs_env)]
    fn verify_signed_email_reports_missing_inline_envelope() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-inline-missing-envelope");
        let pubkey = get_pubkey(&agent);
        let raw = include_str!("../../tests/fixtures/email/html_inline/03_generated_html.eml")
            .replace(
                "data-hai-jacs-envelope=\"v1\"",
                "data-hai-jacs-envelope-missing=\"v1\"",
            );

        let result =
            verify_signed_email(raw.as_bytes(), &agent, &pubkey, VerificationMode::Strict).unwrap();

        assert_eq!(result.status, crate::email::EmailVerificationStatus::Failed);
        assert_eq!(result.transport, SignedEmailTransport::HtmlInline);
        assert_eq!(
            result.reasons,
            vec![EmailVerificationReason::MissingInlineJacsEnvelope]
        );
    }

    #[test]
    #[serial(jacs_env)]
    fn verify_signed_email_reports_logo_extract_failure_by_mode() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-inline-logo-extract");
        let pubkey = get_pubkey(&agent);
        let raw = html_inline_email_with_logo_header("fixture-header", None);

        let strict = verify_signed_email(&raw, &agent, &pubkey, VerificationMode::Strict).unwrap();
        let degraded =
            verify_signed_email(&raw, &agent, &pubkey, VerificationMode::Degraded).unwrap();

        assert_eq!(strict.status, crate::email::EmailVerificationStatus::Failed);
        assert_eq!(
            degraded.status,
            crate::email::EmailVerificationStatus::PartiallyVerified
        );
        assert_eq!(
            strict.reasons,
            vec![EmailVerificationReason::LogoSignatureExtractFailed]
        );
        assert_eq!(
            degraded.reasons,
            vec![EmailVerificationReason::LogoSignatureExtractFailed]
        );
    }

    #[test]
    #[serial(jacs_env)]
    fn verify_signed_email_reports_logo_signature_mismatch_in_all_modes() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-inline-logo-mismatch");
        let pubkey = get_pubkey(&agent);
        let raw = html_inline_email_with_logo_header(
            "fixture-header-envelope",
            Some("fixture-header-logo"),
        );

        for mode in [VerificationMode::Strict, VerificationMode::Degraded] {
            let result = verify_signed_email(&raw, &agent, &pubkey, mode).unwrap();

            assert_eq!(result.status, crate::email::EmailVerificationStatus::Failed);
            assert_eq!(result.transport, SignedEmailTransport::HtmlInline);
            assert_eq!(
                result.reasons,
                vec![EmailVerificationReason::LogoSignatureMismatch]
            );
        }
    }

    #[test]
    #[serial(jacs_env)]
    fn verify_signed_email_accepts_html_inline_roundtrip() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-inline-roundtrip");
        let pubkey = get_pubkey(&agent);
        let raw = signed_html_inline_email(&agent);

        let result = verify_signed_email(&raw, &agent, &pubkey, VerificationMode::Strict).unwrap();

        assert_eq!(
            result.status,
            crate::email::EmailVerificationStatus::Verified,
            "unexpected verifier result: {result:?}"
        );
        assert_eq!(result.transport, SignedEmailTransport::HtmlInline);
        assert!(result.reasons.is_empty());
    }

    #[test]
    #[serial(jacs_env)]
    fn verify_signed_email_rejects_html_inline_text_tamper() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-inline-text-tamper");
        let pubkey = get_pubkey(&agent);
        let raw = signed_html_inline_email(&agent);
        let tampered = String::from_utf8(raw)
            .unwrap()
            .replace("Hello from a signed HAI agent.\r\n", "Tampered body.\r\n");

        let result = verify_signed_email(
            tampered.as_bytes(),
            &agent,
            &pubkey,
            VerificationMode::Strict,
        )
        .unwrap();

        assert_eq!(result.status, crate::email::EmailVerificationStatus::Failed);
        assert_eq!(
            result.reasons,
            vec![EmailVerificationReason::CanonicalPreimageHashMismatch]
        );
    }

    #[test]
    #[serial(jacs_env)]
    fn verify_signed_email_reports_html_equivalence_by_mode() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-inline-html-tamper");
        let pubkey = get_pubkey(&agent);
        let raw = signed_html_inline_email(&agent);
        let tampered = String::from_utf8(raw).unwrap().replace(
            r#"data-hai-message-body="v1">Hello from a signed HAI agent.</main>"#,
            r#"data-hai-message-body="v1">Visible HTML tamper.</main>"#,
        );

        let strict = verify_signed_email(
            tampered.as_bytes(),
            &agent,
            &pubkey,
            VerificationMode::Strict,
        )
        .unwrap();
        let degraded = verify_signed_email(
            tampered.as_bytes(),
            &agent,
            &pubkey,
            VerificationMode::Degraded,
        )
        .unwrap();

        assert_eq!(strict.status, crate::email::EmailVerificationStatus::Failed);
        assert_eq!(
            degraded.status,
            crate::email::EmailVerificationStatus::PartiallyVerified
        );
        assert_eq!(
            strict.reasons,
            vec![EmailVerificationReason::HtmlEquivalenceFailed]
        );
        assert_eq!(
            degraded.reasons,
            vec![EmailVerificationReason::HtmlEquivalenceFailed]
        );
    }

    #[test]
    #[serial(jacs_env)]
    fn html_inline_artifact_removal_preserves_user_text() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-inline-artifact-user-text");
        let raw = signed_html_inline_email(&agent);

        let stripped = remove_inline_signature_artifacts(&raw).unwrap();

        assert!(
            stripped
                .html_without_artifacts
                .contains("Hello from a signed HAI agent."),
            "user text was removed: {}",
            stripped.html_without_artifacts
        );
        assert!(
            !stripped
                .html_without_artifacts
                .contains("application/jacs+json")
        );
        assert!(
            !stripped
                .html_without_artifacts
                .contains("data-hai-verify-footer")
        );
        assert!(
            !stripped
                .html_without_artifacts
                .contains("hai-jacs-logo@hai.ai")
        );
    }

    #[test]
    #[serial(jacs_env)]
    fn verify_signed_email_detects_inline_user_attachment_tamper() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-inline-attachment-tamper");
        let pubkey = get_pubkey(&agent);
        let raw = signed_html_inline_email_with_user_attachment(&agent);

        let original =
            verify_signed_email(&raw, &agent, &pubkey, VerificationMode::Strict).unwrap();
        assert_eq!(
            original.status,
            crate::email::EmailVerificationStatus::Verified,
            "unexpected verifier result: {original:?}"
        );

        let raw_text = String::from_utf8(raw).unwrap();
        let tampered_messages = [
            raw_text.replace("Tm90ZXMK", "QmFkCg=="),
            raw_text.replacen(
                "Content-Disposition: attachment; filename=\"notes.txt\"",
                "Content-Disposition: attachment; filename=\"renamed.txt\"",
                1,
            ),
            raw_text.replacen(
                "Content-Type: text/plain; name=\"notes.txt\"",
                "Content-Type: application/json; name=\"notes.txt\"",
                1,
            ),
        ];

        for tampered in tampered_messages {
            let result = verify_signed_email(
                tampered.as_bytes(),
                &agent,
                &pubkey,
                VerificationMode::Strict,
            )
            .unwrap();

            assert_eq!(
                result.status,
                crate::email::EmailVerificationStatus::Failed,
                "unexpected verifier result: {result:?}"
            );
            assert_eq!(
                result.reasons,
                vec![EmailVerificationReason::CanonicalPreimageHashMismatch]
            );
        }
    }

    #[test]
    #[serial(jacs_env)]
    fn sign_tamper_from_verify_shows_fail() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-tamper-from2");
        let pubkey = get_pubkey(&agent);
        let email = simple_text_email();
        let signed = sign_email(&email, &agent).unwrap();

        let (doc, mut parts) = verify_email_document(&signed, &agent, &pubkey).unwrap();
        parts
            .headers
            .insert("from".to_string(), vec!["fake@evil.com".to_string()]);

        let result = verify_email_content(&doc, &parts);
        assert!(!result.valid);
        let from_result = result
            .field_results
            .iter()
            .find(|r| r.field == "headers.from")
            .unwrap();
        assert_eq!(from_result.status, FieldStatus::Fail);
        assert!(from_result.original_value.is_some());
        assert!(from_result.current_value.is_some());
    }

    fn html_inline_email_with_logo_header(
        envelope_header: &str,
        logo_header: Option<&str>,
    ) -> Vec<u8> {
        let envelope = serde_json::json!({ "compactHeader": envelope_header }).to_string();
        html_inline_email_with_envelope(&envelope, logo_header)
    }

    fn signed_html_inline_email(agent: &SimpleAgent) -> Vec<u8> {
        use sha2::Digest as _;

        let placeholder = html_inline_email_with_envelope("{}", None);
        let payload = build_html_inline_email_signature_payload(&placeholder).unwrap();
        let signed_doc = agent
            .sign_message(&serde_json::to_value(payload).unwrap())
            .expect("sign inline payload");
        let signed_doc_json = signed_doc.raw;
        let compact_header = format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(signed_doc_json.as_bytes()))
        );
        let signed_doc_value: serde_json::Value =
            serde_json::from_str(&signed_doc_json).expect("signed doc json value");
        let envelope = serde_json::json!({
            "compactHeader": compact_header,
            "jacsEnvelope": signed_doc_value,
        })
        .to_string();

        html_inline_email_with_envelope(&envelope, Some(&compact_header))
    }

    fn signed_html_inline_email_with_user_attachment(agent: &SimpleAgent) -> Vec<u8> {
        use sha2::Digest as _;

        let placeholder = html_inline_email_with_envelope_and_attachment("{}", None);
        let payload = build_html_inline_email_signature_payload(&placeholder).unwrap();
        let signed_doc = agent
            .sign_message(&serde_json::to_value(payload).unwrap())
            .expect("sign inline attachment payload");
        let signed_doc_json = signed_doc.raw;
        let compact_header = format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(signed_doc_json.as_bytes()))
        );
        let signed_doc_value: serde_json::Value =
            serde_json::from_str(&signed_doc_json).expect("signed doc json value");
        let envelope = serde_json::json!({
            "compactHeader": compact_header,
            "jacsEnvelope": signed_doc_value,
        })
        .to_string();

        html_inline_email_with_envelope_and_attachment(&envelope, Some(&compact_header))
    }

    fn html_inline_email_with_envelope(envelope: &str, logo_header: Option<&str>) -> Vec<u8> {
        use base64::Engine as _;

        let base_logo = make_fixture_png();
        let logo_bytes = match logo_header {
            Some(header) => {
                crate::email::transport::embed_jacs_header_in_logo_png(&base_logo, header)
                    .expect("embed logo header")
                    .bytes
            }
            None => base_logo,
        };
        let logo_b64 = base64::engine::general_purpose::STANDARD.encode(logo_bytes);

        format!(
            concat!(
                "From: Agent <agent@hai.ai>\r\n",
                "To: Recipient <recipient@example.com>\r\n",
                "Subject: HTML inline verifier fixture\r\n",
                "Date: Fri, 08 May 2026 12:06:00 +0000\r\n",
                "Message-ID: <html-inline-verifier@hai.ai>\r\n",
                "MIME-Version: 1.0\r\n",
                "Content-Type: multipart/alternative; boundary=\"hai-inline-alt-test\"\r\n",
                "\r\n",
                "--hai-inline-alt-test\r\n",
                "Content-Type: text/plain; charset=utf-8\r\n",
                "Content-Transfer-Encoding: 8bit\r\n",
                "\r\n",
                "Hello from a signed HAI agent.\r\n",
                "\r\n",
                "--hai-inline-alt-test\r\n",
                "Content-Type: multipart/related; boundary=\"hai-inline-related-test\"\r\n",
                "\r\n",
                "--hai-inline-related-test\r\n",
                "Content-Type: text/html; charset=utf-8\r\n",
                "Content-Transfer-Encoding: 8bit\r\n",
                "\r\n",
                "<html data-hai-template-version=\"v1\"><body>",
                "<main data-hai-message-body=\"v1\">Hello from a signed HAI agent.</main>",
                "<img src=\"cid:hai-jacs-logo@hai.ai\" alt=\"HAI verification\">",
                "<script type=\"application/jacs+json\" data-hai-jacs-envelope=\"v1\">",
                "{}",
                "</script>",
                "<footer data-hai-verify-footer=\"v1\">",
                "This email is sent from an AI agent. Verify at ",
                "<a data-hai-verify-link=\"v1\" href=\"https://hai.ai/verify/email/test\">",
                "https://hai.ai/verify/email/test</a></footer>",
                "</body></html>\r\n",
                "\r\n",
                "--hai-inline-related-test\r\n",
                "Content-Type: image/png\r\n",
                "Content-ID: <hai-jacs-logo@hai.ai>\r\n",
                "Content-Disposition: inline; filename=\"hai-jacs-logo.png\"\r\n",
                "Content-Transfer-Encoding: base64\r\n",
                "\r\n",
                "{}\r\n",
                "--hai-inline-related-test--\r\n",
                "\r\n",
                "--hai-inline-alt-test--\r\n"
            ),
            envelope, logo_b64
        )
        .into_bytes()
    }

    fn html_inline_email_with_envelope_and_attachment(
        envelope: &str,
        logo_header: Option<&str>,
    ) -> Vec<u8> {
        use base64::Engine as _;

        let base_logo = make_fixture_png();
        let logo_bytes = match logo_header {
            Some(header) => {
                crate::email::transport::embed_jacs_header_in_logo_png(&base_logo, header)
                    .expect("embed logo header")
                    .bytes
            }
            None => base_logo,
        };
        let logo_b64 = base64::engine::general_purpose::STANDARD.encode(logo_bytes);

        format!(
            concat!(
                "From: Agent <agent@hai.ai>\r\n",
                "To: Recipient <recipient@example.com>\r\n",
                "Subject: HTML inline attachment fixture\r\n",
                "Date: Fri, 08 May 2026 12:07:00 +0000\r\n",
                "Message-ID: <html-inline-attachment@hai.ai>\r\n",
                "MIME-Version: 1.0\r\n",
                "Content-Type: multipart/mixed; boundary=\"hai-inline-mixed-test\"\r\n",
                "\r\n",
                "--hai-inline-mixed-test\r\n",
                "Content-Type: multipart/alternative; boundary=\"hai-inline-alt-test\"\r\n",
                "\r\n",
                "--hai-inline-alt-test\r\n",
                "Content-Type: text/plain; charset=utf-8\r\n",
                "Content-Transfer-Encoding: 8bit\r\n",
                "\r\n",
                "Hello from a signed HAI agent.\r\n",
                "\r\n",
                "--hai-inline-alt-test\r\n",
                "Content-Type: multipart/related; boundary=\"hai-inline-related-test\"\r\n",
                "\r\n",
                "--hai-inline-related-test\r\n",
                "Content-Type: text/html; charset=utf-8\r\n",
                "Content-Transfer-Encoding: 8bit\r\n",
                "\r\n",
                "<html data-hai-template-version=\"v1\"><body>",
                "<main data-hai-message-body=\"v1\">Hello from a signed HAI agent.</main>",
                "<img src=\"cid:hai-jacs-logo@hai.ai\" alt=\"HAI verification\">",
                "<script type=\"application/jacs+json\" data-hai-jacs-envelope=\"v1\">",
                "{}",
                "</script>",
                "<footer data-hai-verify-footer=\"v1\">",
                "This email is sent from an AI agent. Verify at ",
                "<a data-hai-verify-link=\"v1\" href=\"https://hai.ai/verify/email/test\">",
                "https://hai.ai/verify/email/test</a></footer>",
                "</body></html>\r\n",
                "\r\n",
                "--hai-inline-related-test\r\n",
                "Content-Type: image/png\r\n",
                "Content-ID: <hai-jacs-logo@hai.ai>\r\n",
                "Content-Disposition: inline; filename=\"hai-jacs-logo.png\"\r\n",
                "Content-Transfer-Encoding: base64\r\n",
                "\r\n",
                "{}\r\n",
                "--hai-inline-related-test--\r\n",
                "\r\n",
                "--hai-inline-alt-test--\r\n",
                "\r\n",
                "--hai-inline-mixed-test\r\n",
                "Content-Type: text/plain; name=\"notes.txt\"\r\n",
                "Content-Disposition: attachment; filename=\"notes.txt\"\r\n",
                "Content-Transfer-Encoding: base64\r\n",
                "\r\n",
                "Tm90ZXMK\r\n",
                "--hai-inline-mixed-test--\r\n"
            ),
            envelope, logo_b64
        )
        .into_bytes()
    }

    fn make_fixture_png() -> Vec<u8> {
        let img = image::RgbaImage::from_pixel(64, 64, image::Rgba([32, 64, 128, 255]));
        let mut buf = Vec::new();
        let mut cur = std::io::Cursor::new(&mut buf);
        img.write_to(&mut cur, image::ImageFormat::Png)
            .expect("png encode");
        buf
    }

    #[test]
    fn verify_html_inline_email_content_detects_attachment_tamper() {
        let raw = html_inline_with_user_attachment_email();
        let payload = build_html_inline_email_signature_payload(&raw).unwrap();
        let doc = jacs_email_doc_for_payload(payload);
        let parts = extract_email_parts(&raw).unwrap();

        let valid = verify_html_inline_email_content(&doc, &parts);

        assert!(valid.valid, "expected original inline content to verify");

        let tampered_raw = String::from_utf8(raw)
            .unwrap()
            .replace("Tm90ZXMK", "QmFkCg==")
            .into_bytes();
        let tampered_parts = extract_email_parts(&tampered_raw).unwrap();
        let tampered = verify_html_inline_email_content(&doc, &tampered_parts);

        assert!(!tampered.valid);
        let attachment_result = tampered
            .field_results
            .iter()
            .find(|result| result.field == "attachments[0]")
            .unwrap();
        assert_eq!(attachment_result.status, FieldStatus::Fail);
    }

    fn html_inline_with_user_attachment_email() -> Vec<u8> {
        b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Inline Test\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <inline-test@example.com>\r\nContent-Type: multipart/mixed; boundary=\"mixbound\"\r\n\r\n--mixbound\r\nContent-Type: multipart/alternative; boundary=\"altbound\"\r\n\r\n--altbound\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nBody text\r\n--altbound\r\nContent-Type: multipart/related; boundary=\"relbound\"\r\n\r\n--relbound\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<!doctype html><html data-hai-template-version=\"v1\"><body><p>Body text</p><img src=\"cid:hai-jacs-logo@hai.ai\"><script type=\"application/jacs+json\" data-hai-jacs-envelope=\"v1\">header</script><footer data-hai-verify-footer=\"v1\">footer</footer></body></html>\r\n--relbound\r\nContent-Type: image/png\r\nContent-ID: <hai-jacs-logo@hai.ai>\r\nContent-Disposition: inline; filename=\"hai-jacs-logo.png\"\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0KGgo=\r\n--relbound--\r\n--altbound--\r\n--mixbound\r\nContent-Type: text/plain; name=\"notes.txt\"\r\nContent-Disposition: attachment; filename=\"notes.txt\"\r\nContent-Transfer-Encoding: base64\r\n\r\nTm90ZXMK\r\n--mixbound--\r\n".to_vec()
    }

    fn jacs_email_doc_for_payload(payload: EmailSignaturePayload) -> JacsEmailSignatureDocument {
        JacsEmailSignatureDocument {
            version: "2.0".to_string(),
            document_type: "email_signature".to_string(),
            payload,
            metadata: JacsEmailMetadata {
                issuer: "test-agent".to_string(),
                document_id: "test-doc".to_string(),
                created_at: "2026-05-08T00:00:00Z".to_string(),
                hash: "sha256:test".to_string(),
            },
            signature: JacsEmailSignature {
                key_id: "test-key".to_string(),
                algorithm: "ed25519".to_string(),
                signature: "test".to_string(),
                signed_at: "2026-05-08T00:00:00Z".to_string(),
            },
        }
    }

    // -- Forwarding chain tests --

    /// Create a forwarded email: A signs, B re-signs.
    /// MUST be called while holding `EMAIL_TEST_MUTEX`.
    fn forwarded_email_from_b() -> (
        Vec<u8>,
        SimpleAgent,
        SimpleAgent,
        tempfile::TempDir,
        tempfile::TempDir,
    ) {
        let (agent_a, tmp_a, _env_guard_a) = create_test_agent("agent-a-fwd");
        // env now points to agent_a's keys
        let original = b"From: agentA@example.com\r\nTo: agentB@example.com\r\nSubject: Report\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <orig@example.com>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHere is the report.\r\n";
        let signed_by_a = sign_email(original, &agent_a).unwrap();

        // Create agent_b - this switches env to agent_b's keys
        let (agent_b, tmp_b, _env_guard_b) = create_test_agent("agent-b-fwd");

        let forwarded = rewrite_headers_for_forward(
            &signed_by_a,
            "agentB@example.com",
            "agentC@example.com",
            "Fwd: Report",
            "Fri, 28 Feb 2026 13:00:00 +0000",
            "<fwd@example.com>",
        );
        // env already points to agent_b's keys
        let signed_by_b = sign_email(&forwarded, &agent_b).unwrap();

        (signed_by_b, agent_a, agent_b, tmp_a, tmp_b)
    }
    #[test]
    #[serial(jacs_env)]
    fn forward_renames_parent_signature() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (signed_by_b, _, _, _tmp_a, _tmp_b) = forwarded_email_from_b();

        let parts = extract_email_parts(&signed_by_b).unwrap();
        let renamed = parts
            .jacs_attachments
            .iter()
            .find(|a| a.filename == "jacs-signature-0.json");
        assert!(
            renamed.is_some(),
            "Expected jacs-signature-0.json attachment, found: {:?}",
            parts
                .jacs_attachments
                .iter()
                .map(|a| &a.filename)
                .collect::<Vec<_>>()
        );
    }
    #[test]
    #[serial(jacs_env)]
    fn forward_sets_parent_signature_hash() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (signed_by_b, _, _, _tmp_a, _tmp_b) = forwarded_email_from_b();

        let payload = extract_payload(&signed_by_b);
        assert!(payload.parent_signature_hash.is_some());
        assert!(
            payload
                .parent_signature_hash
                .as_ref()
                .unwrap()
                .starts_with("sha256:")
        );
    }
    #[test]
    #[serial(jacs_env)]
    fn forward_verify_chain_has_two_entries() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (signed_by_b, _, agent_b, _tmp_a, _tmp_b) = forwarded_email_from_b();
        let pubkey_b = get_pubkey(&agent_b);

        let (doc, parts) = verify_email_document(&signed_by_b, &agent_b, &pubkey_b).unwrap();
        let result = verify_email_content(&doc, &parts);

        assert!(
            !result.valid,
            "expected valid=false for forwarded email at JACS level"
        );
        assert!(
            !result
                .field_results
                .iter()
                .any(|r| r.status == FieldStatus::Fail),
            "field-level failures unexpected: {:?}",
            result
                .field_results
                .iter()
                .filter(|r| r.status == FieldStatus::Fail)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            result.chain.len(),
            2,
            "Expected 2 chain entries, got {}: {:?}",
            result.chain.len(),
            result.chain
        );
        assert!(result.chain[0].forwarded);
        assert!(!result.chain[1].forwarded);
        assert!(!result.chain[1].valid);
    }
    #[test]
    #[serial(jacs_env)]
    fn non_forwarded_email_has_single_chain_entry() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-chain-single");
        let pubkey = get_pubkey(&agent);
        let email = simple_text_email();
        let signed = sign_email(&email, &agent).unwrap();

        let (doc, parts) = verify_email_document(&signed, &agent, &pubkey).unwrap();
        let result = verify_email_content(&doc, &parts);

        assert_eq!(result.chain.len(), 1);
        assert!(!result.chain[0].forwarded);
    }
    #[test]
    #[serial(jacs_env)]
    fn forward_parent_hash_matches_original_doc_bytes() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent_a, _tmp_a, _env_guard_a) = create_test_agent("agent-a-hash");
        // env points to agent_a
        let original = b"From: agentA@example.com\r\nTo: agentB@example.com\r\nSubject: Test\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <test@example.com>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello\r\n";
        let signed_by_a = sign_email(original, &agent_a).unwrap();

        let a_doc_bytes = crate::email::attachment::get_jacs_attachment(&signed_by_a).unwrap();
        let a_doc_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&a_doc_bytes);
            format!("sha256:{}", hex::encode(hasher.finalize()))
        };

        // Create agent_b, switches env
        let (agent_b, _tmp_b, _env_guard_b) = create_test_agent("agent-b-hash");
        let signed_by_b = sign_email(&signed_by_a, &agent_b).unwrap();

        let b_payload = extract_payload(&signed_by_b);
        assert_eq!(
            b_payload.parent_signature_hash.as_ref().unwrap(),
            &a_doc_hash
        );
    }
    #[test]
    #[serial(jacs_env)]
    fn deep_chain_a_to_b_to_c_has_three_entries() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

        let (agent_a, _tmp_a, _env_guard_a) = create_test_agent("agent-a-deep");
        let original = b"From: agentA@example.com\r\nTo: agentB@example.com\r\nSubject: Report\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <orig@example.com>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nOriginal report.\r\n";
        let signed_by_a = sign_email(original, &agent_a).unwrap();

        let (agent_b, _tmp_b, _env_guard_b) = create_test_agent("agent-b-deep");
        let forward_b = rewrite_headers_for_forward(
            &signed_by_a,
            "agentB@example.com",
            "agentC@example.com",
            "Fwd: Report",
            "Fri, 28 Feb 2026 13:00:00 +0000",
            "<fwd1@example.com>",
        );
        let signed_by_b = sign_email(&forward_b, &agent_b).unwrap();

        let (agent_c, _tmp_c, _env_guard_c) = create_test_agent("agent-c-deep");
        let forward_c = rewrite_headers_for_forward(
            &signed_by_b,
            "agentC@example.com",
            "agentD@example.com",
            "Fwd: Fwd: Report",
            "Fri, 28 Feb 2026 14:00:00 +0000",
            "<fwd2@example.com>",
        );
        let signed_by_c = sign_email(&forward_c, &agent_c).unwrap();
        let pubkey_c = get_pubkey(&agent_c);

        let (doc, parts) = verify_email_document(&signed_by_c, &agent_c, &pubkey_c).unwrap();
        let result = verify_email_content(&doc, &parts);

        assert!(
            !result.valid,
            "expected valid=false for deep forwarded email at JACS level"
        );
        assert!(
            !result
                .field_results
                .iter()
                .any(|r| r.status == FieldStatus::Fail),
            "field-level failures unexpected"
        );
        assert_eq!(
            result.chain.len(),
            3,
            "Expected 3 chain entries, got {}: {:?}",
            result.chain.len(),
            result.chain
        );
        assert!(result.chain[0].forwarded);
        assert!(result.chain[1].forwarded);
        assert!(!result.chain[2].forwarded);
        assert!(!result.chain[1].valid);
        assert!(!result.chain[2].valid);
    }

    // -- Custom-name forwarding tests --

    #[test]
    #[serial(jacs_env)]
    fn sign_email_named_uses_custom_attachment_name() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("custom-name-sign");
        let email = simple_text_email();
        let signed = sign_email_named(&email, &agent, "myapp.jacs.json").unwrap();
        let parts = extract_email_parts(&signed).unwrap();
        assert!(
            parts
                .jacs_attachments
                .iter()
                .any(|a| a.filename == "myapp.jacs.json"),
            "Expected custom attachment name 'myapp.jacs.json', found: {:?}",
            parts
                .jacs_attachments
                .iter()
                .map(|a| &a.filename)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    #[serial(jacs_env)]
    fn forward_with_custom_name_renames_correctly() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let custom_name = "myapp.jacs.json";

        let (agent_a, _tmp_a, _env_guard_a) = create_test_agent("custom-fwd-a");
        let original = b"From: a@example.com\r\nTo: b@example.com\r\nSubject: Test\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <custom@example.com>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello\r\n";
        let signed_by_a = sign_email_named(original, &agent_a, custom_name).unwrap();

        let (agent_b, _tmp_b, _env_guard_b) = create_test_agent("custom-fwd-b");
        let signed_by_b = sign_email_named(&signed_by_a, &agent_b, custom_name).unwrap();

        let parts = extract_email_parts(&signed_by_b).unwrap();
        let filenames: Vec<&str> = parts
            .jacs_attachments
            .iter()
            .map(|a| a.filename.as_str())
            .collect();

        // Active signature should be the custom name
        assert!(
            filenames.contains(&custom_name),
            "Expected active '{}', found: {:?}",
            custom_name,
            filenames
        );
        // Renamed original should be `myapp.0.jacs.json`
        assert!(
            filenames.contains(&"myapp.0.jacs.json"),
            "Expected forwarded 'myapp.0.jacs.json', found: {:?}",
            filenames
        );
    }

    #[test]
    #[serial(jacs_env)]
    fn verify_email_named_works_with_custom_name() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let custom_name = "branded.jacs.json";

        let (agent, _tmp, _env_guard) = create_test_agent("custom-verify");
        let pubkey = get_pubkey(&agent);
        let email = simple_text_email();
        let signed = sign_email_named(&email, &agent, custom_name).unwrap();

        // Default verify should fail (looks for jacs-signature.json)
        assert!(
            verify_email_document(&signed, &agent, &pubkey).is_err(),
            "Default verify should not find custom-named attachment"
        );

        // Named verify should succeed
        let result = verify_email_document_named(&signed, &agent, &pubkey, custom_name);
        assert!(
            result.is_ok(),
            "Named verify should find '{}': {:?}",
            custom_name,
            result.err()
        );
    }

    // -- Security regression tests --
    #[test]
    #[serial(jacs_env)]
    fn mime_header_tamper_on_body_causes_fail() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-mime-tamper");
        let pubkey = get_pubkey(&agent);
        let email = simple_text_email();
        let signed = sign_email(&email, &agent).unwrap();
        let (doc, mut parts) = verify_email_document(&signed, &agent, &pubkey).unwrap();

        if let Some(bp) = parts.body_plain.as_mut() {
            bp.content_type = Some("text/plain; charset=us-ascii".to_string());
        }

        let result = verify_email_content(&doc, &parts);
        let body_result = result
            .field_results
            .iter()
            .find(|r| r.field == "body_plain")
            .unwrap();
        assert_eq!(
            body_result.status,
            FieldStatus::Fail,
            "MIME header tamper should be Fail, not {:?}",
            body_result.status
        );
        assert!(!result.valid, "MIME header tamper should invalidate result");
    }
    #[test]
    #[serial(jacs_env)]
    fn attachment_trailing_byte_tamper_detected() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-att-tamper");
        let pubkey = get_pubkey(&agent);
        let email = b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <test@example.com>\r\nContent-Type: multipart/mixed; boundary=\"mixbound\"\r\n\r\n--mixbound\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nBody\r\n--mixbound\r\nContent-Type: application/pdf; name=\"report.pdf\"\r\nContent-Disposition: attachment; filename=\"report.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n--mixbound--\r\n";
        let signed = sign_email(email, &agent).unwrap();
        let (doc, mut parts) = verify_email_document(&signed, &agent, &pubkey).unwrap();

        if let Some(att) = parts.attachments.first_mut() {
            att.content.extend_from_slice(b"\r\n\t ");
        }

        let result = verify_email_content(&doc, &parts);
        assert!(!result.valid, "Trailing byte tamper should be detected");
    }
    #[test]
    #[serial(jacs_env)]
    fn oversized_email_rejected_on_verify() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-oversize");
        let pubkey = get_pubkey(&agent);
        let mut big_email = b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <test@example.com>\r\nContent-Type: text/plain\r\n\r\n".to_vec();
        big_email.resize(26 * 1024 * 1024, b'A');
        let result = verify_email_document(&big_email, &agent, &pubkey);
        assert!(result.is_err());
        match result.unwrap_err() {
            EmailError::EmailTooLarge { .. } => {}
            other => panic!("Expected EmailTooLarge, got {:?}", other),
        }
    }
    #[test]
    #[serial(jacs_env)]
    fn parent_chain_entry_valid_is_false() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (signed_by_b, _, agent_b, _tmp_a, _tmp_b) = forwarded_email_from_b();
        let pubkey_b = get_pubkey(&agent_b);
        let (doc, parts) = verify_email_document(&signed_by_b, &agent_b, &pubkey_b).unwrap();
        let result = verify_email_content(&doc, &parts);

        assert!(result.chain.len() >= 2);
        assert!(
            !result.chain[1].valid,
            "Parent chain entry should have valid=false without crypto verification"
        );
    }

    // -- Pure function tests (no agent needed, no mutex needed) --
    #[test]
    fn address_match_extracts_mailbox_addr_spec() {
        assert!(addresses_match_case_insensitive(
            "\"Alice Agent\" <alice@example.com>",
            "alice@example.com"
        ));
        assert!(addresses_match_case_insensitive(
            "<bob@example.com>",
            "bob@example.com"
        ));
        assert!(addresses_match_case_insensitive(
            "Alice <alice@example.com>, Bob <bob@example.com>",
            "bob@example.com, alice@example.com"
        ));
        assert!(addresses_match_case_insensitive(
            "\"ALICE\" <ALICE@EXAMPLE.COM>",
            "alice@example.com"
        ));
        assert!(!addresses_match_case_insensitive(
            "\"Alice\" <alice@example.com>",
            "bob@example.com"
        ));
    }
    #[test]
    fn extract_addr_specs_handles_rfc5322_edge_cases() {
        assert_eq!(
            extract_addr_specs("user@example.com"),
            vec!["user@example.com"]
        );
        assert_eq!(
            extract_addr_specs("<user@example.com>"),
            vec!["user@example.com"]
        );
        assert_eq!(
            extract_addr_specs("\"John Doe\" <john@example.com>"),
            vec!["john@example.com"]
        );
        let addrs = extract_addr_specs("Alice <alice@a.com>, Bob <bob@b.com>");
        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&"alice@a.com".to_string()));
        assert!(addrs.contains(&"bob@b.com".to_string()));
        assert_eq!(
            extract_addr_specs("USER@EXAMPLE.COM"),
            vec!["user@example.com"]
        );
    }
    #[test]
    #[serial(jacs_env)]
    fn chain_validity_gates_overall_valid() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-chain-gate");
        let pubkey = get_pubkey(&agent);
        let email = simple_text_email();
        let signed = sign_email(&email, &agent).unwrap();
        let (doc, parts) = verify_email_document(&signed, &agent, &pubkey).unwrap();
        let result = verify_email_content(&doc, &parts);
        assert!(result.valid, "non-forwarded email should be valid");

        let (signed_by_b, _, agent_b, _tmp_a, _tmp_b) = forwarded_email_from_b();
        let pubkey_b = get_pubkey(&agent_b);
        let (doc, parts) = verify_email_document(&signed_by_b, &agent_b, &pubkey_b).unwrap();
        let result = verify_email_content(&doc, &parts);
        assert!(
            !result.valid,
            "forwarded email should be invalid at JACS level due to unverified chain"
        );
        let failing_fields: Vec<_> = result
            .field_results
            .iter()
            .filter(|r| r.status == FieldStatus::Fail)
            .collect();
        assert!(
            failing_fields.is_empty(),
            "no field-level failures expected: {:?}",
            failing_fields
        );
    }
    #[test]
    fn normalize_algorithm_handles_variants() {
        assert_eq!(normalize_algorithm("ed25519"), "ed25519");
        assert_eq!(normalize_algorithm("ring-ed25519"), "ed25519");
        assert_eq!(normalize_algorithm("Ring-Ed25519"), "ed25519");
        assert_eq!(normalize_algorithm("pq2025"), "pq2025");
        assert_eq!(normalize_algorithm("PQ2025"), "pq2025");
        assert_eq!(normalize_algorithm("ml-dsa-87"), "ml-dsa-87");
        assert_eq!(normalize_algorithm("ML-DSA-87"), "ml-dsa-87");
    }

    /// Helper: rewrite the headers of a signed email to simulate forwarding.
    fn rewrite_headers_for_forward(
        signed_email: &[u8],
        from: &str,
        to: &str,
        subject: &str,
        date: &str,
        message_id: &str,
    ) -> Vec<u8> {
        let signed_str = String::from_utf8_lossy(signed_email);
        let body_start = signed_str.find("\r\n\r\n").unwrap_or(0) + 4;
        let body = &signed_email[body_start..];

        let ct_line = signed_str
            .lines()
            .find(|l| l.to_lowercase().starts_with("content-type:"))
            .unwrap_or("Content-Type: text/plain");

        let mut forwarded = Vec::new();
        forwarded.extend_from_slice(format!("From: {}\r\n", from).as_bytes());
        forwarded.extend_from_slice(format!("To: {}\r\n", to).as_bytes());
        forwarded.extend_from_slice(format!("Subject: {}\r\n", subject).as_bytes());
        forwarded.extend_from_slice(format!("Date: {}\r\n", date).as_bytes());
        forwarded.extend_from_slice(format!("Message-ID: {}\r\n", message_id).as_bytes());
        forwarded.extend_from_slice(ct_line.as_bytes());
        forwarded.extend_from_slice(b"\r\n\r\n");
        forwarded.extend_from_slice(body);
        forwarded
    }

    // =========================================================================
    // verify_email_yaml / verify_email_html convenience function tests
    // (conversion-related -- see also sign.rs email YAML/HTML signing tests)
    // =========================================================================

    #[test]
    #[serial(jacs_env)]
    fn verify_email_yaml_round_trip() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-yaml-rt");
        let pubkey = get_pubkey(&agent);
        let email = simple_text_email();

        // Sign with YAML attachment
        let signed = crate::email::sign_email_yaml(&email, &agent).unwrap();

        // Verify with the YAML convenience function
        let result = verify_email_yaml(&signed, &agent, &pubkey).unwrap();
        assert!(
            result.valid,
            "verify_email_yaml should succeed on sign_email_yaml output"
        );
    }

    #[test]
    #[serial(jacs_env)]
    fn verify_email_html_round_trip() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-html-rt");
        let pubkey = get_pubkey(&agent);
        let email = simple_text_email();

        // Sign with HTML attachment
        let signed = crate::email::sign_email_html(&email, &agent).unwrap();

        // Verify with the HTML convenience function
        let result = verify_email_html(&signed, &agent, &pubkey).unwrap();
        assert!(
            result.valid,
            "verify_email_html should succeed on sign_email_html output"
        );
    }

    #[test]
    #[serial(jacs_env)]
    fn verify_email_yaml_fails_on_json_attachment() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-yaml-wrong");
        let pubkey = get_pubkey(&agent);
        let email = simple_text_email();

        // Sign with default JSON attachment
        let signed = sign_email(&email, &agent).unwrap();

        // verify_email_yaml should fail (looks for jacs-signature.yaml, not .json)
        let result = verify_email_yaml(&signed, &agent, &pubkey);
        assert!(
            result.is_err(),
            "verify_email_yaml should fail when attachment is JSON, not YAML"
        );
    }

    #[test]
    #[serial(jacs_env)]
    fn verify_email_html_fails_on_json_attachment() {
        let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let (agent, _tmp, _env_guard) = create_test_agent("verify-html-wrong");
        let pubkey = get_pubkey(&agent);
        let email = simple_text_email();

        // Sign with default JSON attachment
        let signed = sign_email(&email, &agent).unwrap();

        // verify_email_html should fail (looks for jacs-signature.html, not .json)
        let result = verify_email_html(&signed, &agent, &pubkey);
        assert!(
            result.is_err(),
            "verify_email_html should fail when attachment is JSON, not HTML"
        );
    }
}
