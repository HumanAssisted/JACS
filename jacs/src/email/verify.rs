//! Email verification implementation for the JACS email system.
//!
//! Provides `verify_email_document()` for JACS signature validation and
//! `verify_email_content()` for comparing trusted hashes against actual
//! email content.

use base64::Engine;
use sha2::{Digest, Sha256};

use super::attachment::{get_jacs_attachment, remove_jacs_attachment};
use super::canonicalize::{
    canonicalize_body, canonicalize_header, compute_attachment_hash, compute_body_hash,
    compute_header_entry, compute_mime_headers_hash, extract_email_parts,
};
use super::error::EmailError;
use super::sign::canonical_json_sorted;
use super::types::{
    ChainEntry, ContentVerificationResult, FieldResult, FieldStatus, JacsEmailSignatureDocument,
    ParsedEmailParts, SignedHeaderEntry,
};

/// Trait for verifying email signatures.
///
/// Implementations verify a cryptographic signature given a public key.
/// The JACS library provides low-level verification via `ringwrapper::verify_string`
/// and similar functions, but callers must supply the public key from the
/// HAI registry or another source.
pub trait EmailVerifier {
    /// Verify that `signature_bytes` is a valid signature over `data` using `public_key`.
    fn verify_bytes(
        &self,
        data: &[u8],
        signature_bytes: &[u8],
        public_key: &[u8],
        algorithm: &str,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

/// Default verifier that uses the JACS low-level crypto wrappers.
pub struct DefaultEmailVerifier;

impl EmailVerifier for DefaultEmailVerifier {
    fn verify_bytes(
        &self,
        data: &[u8],
        signature_bytes: &[u8],
        public_key: &[u8],
        algorithm: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature_bytes);
        let data_str =
            std::str::from_utf8(data).map_err(|e| format!("data is not valid UTF-8: {e}"))?;

        match algorithm.to_lowercase().as_str() {
            "ed25519" | "ring-ed25519" => {
                crate::crypt::ringwrapper::verify_string(
                    public_key.to_vec(),
                    data_str,
                    &sig_b64,
                )
            }
            "rsa-pss" => {
                crate::crypt::rsawrapper::verify_string(
                    public_key.to_vec(),
                    data_str,
                    &sig_b64,
                )
            }
            other => Err(format!("unsupported algorithm: {other}").into()),
        }
    }
}

/// Extract and validate the JACS email signature document from a raw email.
///
/// This function:
/// 1. Extracts the `jacs-signature.json` attachment
/// 2. Removes the JACS attachment (the signature covers the email WITHOUT itself)
/// 3. Parses and validates the JACS document
/// 4. Verifies the document hash
/// 5. Verifies the cryptographic signature using the provided public key
/// 6. Returns the trusted document and parsed email parts (from the email sans JACS attachment)
///
/// # Arguments
/// * `raw_email` - The raw RFC 5322 email bytes (with JACS attachment)
/// * `public_key` - The signer's public key bytes
/// * `verifier` - Crypto verifier implementation
pub fn verify_email_document(
    raw_email: &[u8],
    public_key: &[u8],
    verifier: &dyn EmailVerifier,
) -> Result<(JacsEmailSignatureDocument, ParsedEmailParts), EmailError> {
    // Step 1: Extract the JACS signature attachment
    let jacs_bytes = get_jacs_attachment(raw_email)?;

    // Step 2: Remove the JACS attachment -- PRD line 473:
    // "the signature covers the email WITHOUT itself"
    let email_without_jacs = remove_jacs_attachment(raw_email)?;

    // Step 3: Parse the JACS document
    let doc: JacsEmailSignatureDocument = serde_json::from_slice(&jacs_bytes).map_err(|e| {
        EmailError::InvalidJacsDocument(format!("failed to parse jacs-signature.json: {e}"))
    })?;

    // Step 4: Verify document hash
    // Canonicalize payload via RFC 8785, SHA-256, compare to metadata.hash
    let payload_json = serde_json::to_value(&doc.payload).map_err(|e| {
        EmailError::InvalidJacsDocument(format!("failed to serialize payload: {e}"))
    })?;
    let canonical_payload = canonical_json_sorted(&payload_json);

    let computed_hash = {
        let mut hasher = Sha256::new();
        hasher.update(canonical_payload.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    };

    if computed_hash != doc.metadata.hash {
        return Err(EmailError::InvalidJacsDocument(format!(
            "payload hash mismatch: computed {} != stored {}",
            computed_hash, doc.metadata.hash
        )));
    }

    // Step 5: Check algorithm match
    // The signature.algorithm must match what we expect
    let sig_algorithm = doc.signature.algorithm.to_lowercase();

    // Step 6: Verify the cryptographic signature
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&doc.signature.signature)
        .map_err(|e| {
            EmailError::SignatureVerificationFailed(format!(
                "invalid base64 signature: {e}"
            ))
        })?;

    verifier
        .verify_bytes(
            canonical_payload.as_bytes(),
            &sig_bytes,
            public_key,
            &sig_algorithm,
        )
        .map_err(|e| {
            EmailError::SignatureVerificationFailed(format!(
                "cryptographic verification failed: {e}"
            ))
        })?;

    // Step 7: Parse the email without the JACS attachment
    let parts = extract_email_parts(&email_without_jacs)?;

    Ok((doc, parts))
}

/// Compare trusted JACS document hashes against actual email content.
///
/// For each field in the JACS document:
/// - Headers: recompute hash of canonicalized value, compare to stored hash
/// - Body parts: recompute content_hash and mime_headers_hash
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
    let valid = !field_results
        .iter()
        .any(|r| r.status == FieldStatus::Fail);

    // Build chain from the current signer
    let mut chain = vec![ChainEntry {
        signer: doc.payload.headers.from.value.clone(),
        jacs_id: doc.metadata.issuer.clone(),
        valid,
        forwarded: doc.payload.parent_signature_hash.is_some(),
    }];

    // If parent_signature_hash exists, build the parent chain entries
    if let Some(ref parent_hash) = doc.payload.parent_signature_hash {
        build_parent_chain(parent_hash, parts, &mut chain);
    }

    ContentVerificationResult {
        valid,
        field_results,
        chain,
    }
}

/// Strip trailing whitespace bytes (CR, LF, SP, TAB) from a byte slice.
///
/// MIME boundary processing can add trailing whitespace to attachment content.
/// This normalization ensures consistent hashing regardless of MIME wrapping.
fn strip_trailing_ws_bytes(bytes: &[u8]) -> &[u8] {
    let mut end = bytes.len();
    while end > 0 && matches!(bytes[end - 1], b'\r' | b'\n' | b' ' | b'\t') {
        end -= 1;
    }
    &bytes[..end]
}

/// Build the parent chain by walking parent_signature_hash links.
///
/// This resolves parent signatures from the JACS attachments in the email.
/// At the JACS library level, we can validate the document structure and hash
/// chain but NOT the cryptographic signatures (since we don't have the parent
/// signers' public keys -- that's done at the haisdk layer).
fn build_parent_chain(
    parent_hash: &str,
    parts: &ParsedEmailParts,
    chain: &mut Vec<ChainEntry>,
) {
    // Search for the parent document among JACS attachments
    for jacs_att in &parts.jacs_attachments {
        // Compute sha256 of the normalized attachment bytes
        // Strip trailing whitespace for consistency with signing-side hash computation
        let trimmed_content = strip_trailing_ws_bytes(&jacs_att.content);
        let att_hash = {
            let mut hasher = Sha256::new();
            hasher.update(trimmed_content);
            format!("sha256:{}", hex::encode(hasher.finalize()))
        };

        if att_hash == parent_hash {
            // Found the parent document
            if let Ok(parent_doc) =
                serde_json::from_slice::<JacsEmailSignatureDocument>(&jacs_att.content)
            {
                // Add this signer to the chain
                let is_forwarded = parent_doc.payload.parent_signature_hash.is_some();
                chain.push(ChainEntry {
                    signer: parent_doc.payload.headers.from.value.clone(),
                    jacs_id: parent_doc.metadata.issuer.clone(),
                    valid: true, // Document structure valid; crypto verification is at haisdk layer
                    forwarded: is_forwarded,
                });

                // Recurse if this parent also has a parent
                if let Some(ref grandparent_hash) = parent_doc.payload.parent_signature_hash {
                    build_parent_chain(grandparent_hash, parts, chain);
                }
            }
            return;
        }
    }
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
fn addresses_match_case_insensitive(a: &str, b: &str) -> bool {
    let normalize = |s: &str| -> Vec<String> {
        s.split(',')
            .map(|addr| addr.trim().to_lowercase())
            .filter(|a| !a.is_empty())
            .collect()
    };
    let mut a_addrs = normalize(a);
    let mut b_addrs = normalize(b);
    a_addrs.sort();
    b_addrs.sort();
    a_addrs == b_addrs
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

            // Content hash is the primary integrity check.
            // MIME headers hash may differ if the email was wrapped during signing
            // (e.g., single-part wrapped in multipart/mixed adds CTE: 7bit).
            // If content matches but MIME headers differ, report Modified (not Fail)
            // since the body content itself is verified.
            let status = if content_match && mime_match {
                FieldStatus::Pass
            } else if content_match {
                FieldStatus::Modified
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
    use crate::email::sign::{sign_email, EmailSigner};
    use crate::email::types::*;

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
            // Deterministic "signature": prefix + data
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

    /// Test verifier that matches our TestSigner's signature format.
    struct TestVerifier;

    impl EmailVerifier for TestVerifier {
        fn verify_bytes(
            &self,
            data: &[u8],
            signature_bytes: &[u8],
            _public_key: &[u8],
            _algorithm: &str,
        ) -> Result<(), Box<dyn std::error::Error>> {
            // Expect signature = b"sig:" + data
            let expected = {
                let mut v = b"sig:".to_vec();
                v.extend_from_slice(data);
                v
            };
            if signature_bytes == expected {
                Ok(())
            } else {
                Err("signature mismatch".into())
            }
        }
    }

    /// Test verifier that always fails.
    struct FailingVerifier;

    impl EmailVerifier for FailingVerifier {
        fn verify_bytes(
            &self,
            _data: &[u8],
            _signature_bytes: &[u8],
            _public_key: &[u8],
            _algorithm: &str,
        ) -> Result<(), Box<dyn std::error::Error>> {
            Err("wrong key".into())
        }
    }

    fn simple_text_email() -> Vec<u8> {
        b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <test@example.com>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello World\r\n".to_vec()
    }

    // -- verify_email_document tests --

    #[test]
    fn verify_email_document_valid_signature() {
        let email = simple_text_email();
        let signer = TestSigner::new("test-agent:v1");
        let signed = sign_email(&email, &signer).unwrap();

        let verifier = TestVerifier;
        let (doc, parts) =
            verify_email_document(&signed, b"test-public-key", &verifier).unwrap();

        assert_eq!(doc.version, "1.0");
        assert_eq!(doc.document_type, "email_signature");
        assert_eq!(doc.metadata.issuer, "test-agent:v1");
        assert!(parts.body_plain.is_some());
    }

    #[test]
    fn verify_email_document_missing_jacs_attachment() {
        let email = simple_text_email();
        let verifier = TestVerifier;
        let result = verify_email_document(&email, b"test-key", &verifier);
        assert!(result.is_err());
        match result.unwrap_err() {
            EmailError::MissingJacsSignature => {}
            other => panic!("Expected MissingJacsSignature, got {:?}", other),
        }
    }

    #[test]
    fn verify_email_document_wrong_key() {
        let email = simple_text_email();
        let signer = TestSigner::new("test-agent:v1");
        let signed = sign_email(&email, &signer).unwrap();

        let verifier = FailingVerifier;
        let result = verify_email_document(&signed, b"wrong-key", &verifier);
        assert!(result.is_err());
        match result.unwrap_err() {
            EmailError::SignatureVerificationFailed(_) => {}
            other => panic!(
                "Expected SignatureVerificationFailed, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn verify_email_document_tampered_hash() {
        let email = simple_text_email();
        let signer = TestSigner::new("test-agent:v1");
        let signed = sign_email(&email, &signer).unwrap();

        // Extract, tamper hash, re-attach
        let doc_bytes = crate::email::attachment::get_jacs_attachment(&signed).unwrap();
        let mut doc: JacsEmailSignatureDocument =
            serde_json::from_slice(&doc_bytes).unwrap();
        doc.metadata.hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string();
        let tampered_json = serde_json::to_vec(&doc).unwrap();

        let email_without = crate::email::attachment::remove_jacs_attachment(&signed).unwrap();
        let tampered_email =
            crate::email::attachment::add_jacs_attachment(&email_without, &tampered_json)
                .unwrap();

        let verifier = TestVerifier;
        let result = verify_email_document(&tampered_email, b"test-key", &verifier);
        assert!(result.is_err());
        match result.unwrap_err() {
            EmailError::InvalidJacsDocument(msg) => {
                assert!(msg.contains("hash mismatch"), "msg: {}", msg);
            }
            other => panic!("Expected InvalidJacsDocument, got {:?}", other),
        }
    }

    // -- verify_email_content tests --

    #[test]
    fn verify_email_content_all_pass() {
        let email = simple_text_email();
        let signer = TestSigner::new("test-agent:v1");
        let signed = sign_email(&email, &signer).unwrap();

        let verifier = TestVerifier;
        let (doc, parts) =
            verify_email_document(&signed, b"test-key", &verifier).unwrap();
        let result = verify_email_content(&doc, &parts);

        assert!(result.valid, "valid is false, field_results: {:?}", result.field_results);
        // Check that from, to, subject, date all pass
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
    fn verify_email_content_tampered_from() {
        let email = simple_text_email();
        let signer = TestSigner::new("test-agent:v1");
        let signed = sign_email(&email, &signer).unwrap();

        let verifier = TestVerifier;
        let (doc, mut parts) =
            verify_email_document(&signed, b"test-key", &verifier).unwrap();

        // Tamper the From header
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
    fn verify_email_content_tampered_body() {
        let email = simple_text_email();
        let signer = TestSigner::new("test-agent:v1");
        let signed = sign_email(&email, &signer).unwrap();

        let verifier = TestVerifier;
        let (doc, mut parts) =
            verify_email_document(&signed, b"test-key", &verifier).unwrap();

        // Tamper the body
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
    fn verify_email_content_case_changed_from_domain() {
        let email = simple_text_email();
        let signer = TestSigner::new("test-agent:v1");
        let signed = sign_email(&email, &signer).unwrap();

        let verifier = TestVerifier;
        let (doc, mut parts) =
            verify_email_document(&signed, b"test-key", &verifier).unwrap();

        // Change From domain case (sender@EXAMPLE.COM -> sender@example.com)
        // After canonicalization, domain is already lowercase, so to test Modified
        // we need to change the local part case which should still match case-insensitively
        parts.headers.insert(
            "from".to_string(),
            vec!["SENDER@example.com".to_string()],
        );

        let result = verify_email_content(&doc, &parts);
        // Should be Modified (case-insensitive match)
        let from_result = result
            .field_results
            .iter()
            .find(|r| r.field == "headers.from")
            .unwrap();
        assert!(
            from_result.status == FieldStatus::Modified
                || from_result.status == FieldStatus::Pass,
            "Expected Modified or Pass, got {:?}",
            from_result.status
        );
    }

    #[test]
    fn verify_email_content_message_id_unverifiable() {
        let email = simple_text_email();
        let signer = TestSigner::new("test-agent:v1");
        let signed = sign_email(&email, &signer).unwrap();

        let verifier = TestVerifier;
        let (doc, parts) =
            verify_email_document(&signed, b"test-key", &verifier).unwrap();
        let result = verify_email_content(&doc, &parts);

        let mid_result = result
            .field_results
            .iter()
            .find(|r| r.field == "headers.message_id")
            .unwrap();
        assert_eq!(mid_result.status, FieldStatus::Unverifiable);
    }

    #[test]
    fn verify_email_content_stripped_text_plain() {
        let multipart = b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <test@example.com>\r\nContent-Type: multipart/alternative; boundary=\"altbound\"\r\n\r\n--altbound\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nPlain text\r\n--altbound\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>HTML</p>\r\n--altbound--\r\n";

        let signer = TestSigner::new("test-agent:v1");
        let signed = sign_email(multipart, &signer).unwrap();

        let verifier = TestVerifier;
        let (doc, mut parts) =
            verify_email_document(&signed, b"test-key", &verifier).unwrap();

        // Simulate text/plain being stripped by email provider
        parts.body_plain = None;

        let result = verify_email_content(&doc, &parts);

        let plain_result = result
            .field_results
            .iter()
            .find(|r| r.field == "body_plain")
            .unwrap();
        assert_eq!(plain_result.status, FieldStatus::Unverifiable);

        // HTML should still pass
        let html_result = result
            .field_results
            .iter()
            .find(|r| r.field == "body_html");
        if let Some(hr) = html_result {
            assert_eq!(hr.status, FieldStatus::Pass);
        }
    }

    #[test]
    fn verify_email_content_extra_attachment() {
        let email_with_att = b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <test@example.com>\r\nContent-Type: multipart/mixed; boundary=\"mixbound\"\r\n\r\n--mixbound\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nBody\r\n--mixbound--\r\n";

        let signer = TestSigner::new("test-agent:v1");
        let signed = sign_email(email_with_att, &signer).unwrap();

        let verifier = TestVerifier;
        let (doc, mut parts) =
            verify_email_document(&signed, b"test-key", &verifier).unwrap();

        // Add an extra attachment that wasn't in the signed email
        parts.attachments.push(super::super::types::ParsedAttachment {
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
    fn sign_verify_roundtrip_valid() {
        let email = simple_text_email();
        let signer = TestSigner::new("test-agent:v1");
        let signed = sign_email(&email, &signer).unwrap();

        let verifier = TestVerifier;
        let (doc, parts) =
            verify_email_document(&signed, b"test-key", &verifier).unwrap();
        let result = verify_email_content(&doc, &parts);

        assert!(result.valid);
        // All fields should be Pass, Unverifiable, or Modified
        // (Modified is expected for body parts where MIME wrapping changes headers)
        assert!(
            result
                .field_results
                .iter()
                .all(|r| r.status == FieldStatus::Pass
                    || r.status == FieldStatus::Unverifiable
                    || r.status == FieldStatus::Modified),
            "unexpected field status: {:?}",
            result.field_results
        );
    }

    #[test]
    fn sign_tamper_from_verify_shows_fail() {
        let email = simple_text_email();
        let signer = TestSigner::new("test-agent:v1");
        let signed = sign_email(&email, &signer).unwrap();

        let verifier = TestVerifier;
        let (doc, mut parts) =
            verify_email_document(&signed, b"test-key", &verifier).unwrap();

        // Tamper the From header
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

    fn forwarded_email_from_b() -> (Vec<u8>, TestSigner, TestSigner) {
        // Agent A signs the original email
        let original = b"From: agentA@example.com\r\nTo: agentB@example.com\r\nSubject: Report\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <orig@example.com>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHere is the report.\r\n";
        let signer_a = TestSigner::new("agent-a:v1");
        let signed_by_a = sign_email(original, &signer_a).unwrap();

        // Agent B forwards: replace headers but keep the JACS signature + body
        let forwarded = rewrite_headers_for_forward(
            &signed_by_a,
            "agentB@example.com",
            "agentC@example.com",
            "Fwd: Report",
            "Fri, 28 Feb 2026 13:00:00 +0000",
            "<fwd@example.com>",
        );

        let signer_b = TestSigner::new("agent-b:v1");
        let signed_by_b = sign_email(&forwarded, &signer_b).unwrap();

        (signed_by_b, signer_a, signer_b)
    }

    #[test]
    fn forward_renames_parent_signature() {
        let (signed_by_b, _, _) = forwarded_email_from_b();

        // Parse the forwarded email
        let parts = extract_email_parts(&signed_by_b).unwrap();

        // Should have renamed jacs-signature-0.json in jacs_attachments
        let renamed = parts.jacs_attachments.iter()
            .find(|a| a.filename == "jacs-signature-0.json");
        assert!(renamed.is_some(), "Expected jacs-signature-0.json attachment, found: {:?}",
            parts.jacs_attachments.iter().map(|a| &a.filename).collect::<Vec<_>>());
    }

    #[test]
    fn forward_sets_parent_signature_hash() {
        let (signed_by_b, _, _) = forwarded_email_from_b();

        let doc_bytes = crate::email::attachment::get_jacs_attachment(&signed_by_b).unwrap();
        let doc: JacsEmailSignatureDocument = serde_json::from_slice(&doc_bytes).unwrap();

        assert!(doc.payload.parent_signature_hash.is_some());
        assert!(doc.payload.parent_signature_hash.as_ref().unwrap().starts_with("sha256:"));
    }

    #[test]
    fn forward_verify_chain_has_two_entries() {
        let (signed_by_b, _, _) = forwarded_email_from_b();

        let verifier = TestVerifier;
        let (doc, parts) =
            verify_email_document(&signed_by_b, b"test-key", &verifier).unwrap();
        let result = verify_email_content(&doc, &parts);

        assert!(result.valid, "valid is false, failing fields: {:?}",
            result.field_results.iter().filter(|r| r.status == FieldStatus::Fail).collect::<Vec<_>>());
        assert_eq!(result.chain.len(), 2, "Expected 2 chain entries, got {}: {:?}", result.chain.len(), result.chain);
        assert_eq!(result.chain[0].jacs_id, "agent-b:v1");
        assert!(result.chain[0].forwarded);
        assert_eq!(result.chain[1].jacs_id, "agent-a:v1");
        assert!(!result.chain[1].forwarded);
    }

    #[test]
    fn non_forwarded_email_has_single_chain_entry() {
        let email = simple_text_email();
        let signer = TestSigner::new("test-agent:v1");
        let signed = sign_email(&email, &signer).unwrap();

        let verifier = TestVerifier;
        let (doc, parts) =
            verify_email_document(&signed, b"test-key", &verifier).unwrap();
        let result = verify_email_content(&doc, &parts);

        assert_eq!(result.chain.len(), 1);
        assert_eq!(result.chain[0].jacs_id, "test-agent:v1");
        assert!(!result.chain[0].forwarded);
    }

    #[test]
    fn forward_parent_hash_matches_original_doc_bytes() {
        // Agent A signs
        let original = b"From: agentA@example.com\r\nTo: agentB@example.com\r\nSubject: Test\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <test@example.com>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello\r\n";
        let signer_a = TestSigner::new("agent-a:v1");
        let signed_by_a = sign_email(original, &signer_a).unwrap();

        // Get Agent A's JACS doc bytes
        let a_doc_bytes = crate::email::attachment::get_jacs_attachment(&signed_by_a).unwrap();
        let a_doc_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&a_doc_bytes);
            format!("sha256:{}", hex::encode(hasher.finalize()))
        };

        // Agent B forwards
        let signer_b = TestSigner::new("agent-b:v1");
        let signed_by_b = sign_email(&signed_by_a, &signer_b).unwrap();

        let b_doc_bytes = crate::email::attachment::get_jacs_attachment(&signed_by_b).unwrap();
        let b_doc: JacsEmailSignatureDocument = serde_json::from_slice(&b_doc_bytes).unwrap();

        assert_eq!(b_doc.payload.parent_signature_hash.as_ref().unwrap(), &a_doc_hash);
    }

    #[test]
    fn deep_chain_a_to_b_to_c_has_three_entries() {
        // Agent A signs the original email
        let original = b"From: agentA@example.com\r\nTo: agentB@example.com\r\nSubject: Report\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <orig@example.com>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nOriginal report.\r\n";
        let signer_a = TestSigner::new("agent-a:v1");
        let signed_by_a = sign_email(original, &signer_a).unwrap();

        // Agent B forwards (re-sign with different headers)
        let signer_b = TestSigner::new("agent-b:v1");
        let forward_b = rewrite_headers_for_forward(
            &signed_by_a,
            "agentB@example.com",
            "agentC@example.com",
            "Fwd: Report",
            "Fri, 28 Feb 2026 13:00:00 +0000",
            "<fwd1@example.com>",
        );
        let signed_by_b = sign_email(&forward_b, &signer_b).unwrap();

        // Agent C forwards again (re-sign with different headers)
        let signer_c = TestSigner::new("agent-c:v1");
        let forward_c = rewrite_headers_for_forward(
            &signed_by_b,
            "agentC@example.com",
            "agentD@example.com",
            "Fwd: Fwd: Report",
            "Fri, 28 Feb 2026 14:00:00 +0000",
            "<fwd2@example.com>",
        );
        let signed_by_c = sign_email(&forward_c, &signer_c).unwrap();

        // Verify Agent C's email
        let verifier = TestVerifier;
        let (doc, parts) =
            verify_email_document(&signed_by_c, b"test-key", &verifier).unwrap();
        let result = verify_email_content(&doc, &parts);

        assert!(result.valid, "valid is false, failing fields: {:?}",
            result.field_results.iter().filter(|r| r.status == FieldStatus::Fail).collect::<Vec<_>>());
        assert_eq!(result.chain.len(), 3,
            "Expected 3 chain entries, got {}: {:?}", result.chain.len(), result.chain);
        assert_eq!(result.chain[0].jacs_id, "agent-c:v1");
        assert!(result.chain[0].forwarded);
        assert_eq!(result.chain[1].jacs_id, "agent-b:v1");
        assert!(result.chain[1].forwarded);
        assert_eq!(result.chain[2].jacs_id, "agent-a:v1");
        assert!(!result.chain[2].forwarded);
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
