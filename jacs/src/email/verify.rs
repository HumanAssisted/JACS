//! Email verification implementation for the JACS email system.
//!
//! Provides `verify_email_document()` for JACS signature validation and
//! `verify_email_content()` for comparing trusted hashes against actual
//! email content.

use sha2::{Digest, Sha256};

use super::attachment::{get_jacs_attachment, remove_jacs_attachment};
use super::canonicalize::{
    canonicalize_body, canonicalize_header, compute_attachment_hash, compute_body_hash,
    compute_header_entry, compute_mime_headers_hash, extract_email_parts,
};
use super::error::{EmailError, check_email_size};
use super::types::{
    ChainEntry, ContentVerificationResult, FieldResult, FieldStatus, JacsEmailSignatureDocument,
    ParsedEmailParts, SignedHeaderEntry,
};

/// Normalize an algorithm name to its canonical form.
///
/// Lowercases, strips "ring-" prefix and "-sha256"/"-sha384"/"-sha512" suffixes.
/// Examples:
/// - `"Ring-Ed25519"` → `"ed25519"`
/// - `"rsa-pss-sha256"` → `"rsa-pss"`
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

/// Extract and verify the JACS email signature document from a raw email.
///
/// Uses [`JacsSigner::verify_with_key()`] to validate the JACS document
/// signature against the supplied `public_key`, then extracts the email
/// payload and parsed email parts.
///
/// Steps:
/// 1. Extracts the `jacs-signature.json` attachment
/// 2. Removes the JACS attachment (the signature covers the email WITHOUT itself)
/// 3. Verifies the JACS document signature using the provided public key
/// 4. Extracts the email signature payload from the `content` field
/// 5. Returns a `JacsEmailSignatureDocument` and parsed email parts
///
/// # Arguments
/// * `raw_email` - The raw RFC 5322 email bytes (with JACS attachment)
/// * `verifier` - Any type implementing [`JacsSigner`] (e.g. `SimpleAgent`)
/// * `public_key` - The signer's public key bytes (from registry, trust store, etc.)
pub fn verify_email_document(
    raw_email: &[u8],
    verifier: &impl super::JacsSigner,
    public_key: &[u8],
) -> Result<(JacsEmailSignatureDocument, ParsedEmailParts), EmailError> {
    check_email_size(raw_email)?;

    let jacs_bytes = get_jacs_attachment(raw_email)?;
    let email_without_jacs = remove_jacs_attachment(raw_email)?;

    let jacs_str = std::str::from_utf8(&jacs_bytes).map_err(|e| {
        EmailError::InvalidJacsDocument(format!("attachment is not valid UTF-8: {e}"))
    })?;

    // Verify the JACS document using the provided public key
    let result = verifier
        .verify_with_key(jacs_str, public_key.to_vec())
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

    // Parse the JACS document to extract the email payload
    let jacs_value: serde_json::Value = serde_json::from_str(jacs_str).map_err(|e| {
        EmailError::InvalidJacsDocument(format!("failed to parse JACS document: {e}"))
    })?;

    // Extract the email signature payload from the content field
    let content = jacs_value.get("content").ok_or_else(|| {
        EmailError::InvalidJacsDocument("JACS document missing 'content' field".to_string())
    })?;

    let payload: super::types::EmailSignaturePayload = serde_json::from_value(content.clone())
        .map_err(|e| {
            EmailError::InvalidJacsDocument(format!(
                "failed to parse email payload from JACS document: {e}"
            ))
        })?;

    // Extract signer identity
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

    // Build JacsEmailSignatureDocument from the JACS document fields
    let doc = JacsEmailSignatureDocument {
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
    };

    let parts = extract_email_parts(&email_without_jacs)?;
    Ok((doc, parts))
}

/// Verify a JACS-signed .eml (RFC 5322) email in a single call.
///
/// This is the primary API for email verification. It combines
/// cryptographic signature validation and content hash comparison:
///
/// 1. Extracts and verifies the `jacs-signature.json` JACS document
/// 2. Compares every hash in the trusted JACS document against the actual
///    email content (headers, body parts, attachments)
/// 3. Returns field-level results showing which fields pass, fail, or were
///    modified
///
/// # Arguments
/// * `raw_eml` - Raw RFC 5322 email bytes (with `jacs-signature.json` attached)
/// * `verifier` - Any type implementing [`JacsSigner`] (e.g. `SimpleAgent`)
/// * `public_key` - The signer's public key bytes (from registry, trust store, etc.)
///
/// # Returns
/// `ContentVerificationResult` with field-level results. Check `.valid` for
/// overall pass/fail.
pub fn verify_email(
    raw_eml: &[u8],
    verifier: &impl super::JacsSigner,
    public_key: &[u8],
) -> Result<ContentVerificationResult, EmailError> {
    let (doc, parts) = verify_email_document(raw_eml, verifier, public_key)?;
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
    // For forwarded emails, the renamed jacs-signature-N.json files appear as
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
    use crate::email::sign::sign_email;
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
        let tmp_path = tmp.path().to_string_lossy().to_string();

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
        assert_eq!(normalize_algorithm("rsa-pss"), "rsa-pss");
        assert_eq!(normalize_algorithm("rsa-pss-sha256"), "rsa-pss");
        assert_eq!(normalize_algorithm("RSA-PSS-SHA256"), "rsa-pss");
        assert_eq!(normalize_algorithm("rsa-pss-sha384"), "rsa-pss");
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
}
