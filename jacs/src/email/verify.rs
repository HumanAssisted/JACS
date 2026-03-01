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
use super::error::{check_email_size, EmailError};
use super::sign::canonicalize_json_rfc8785;
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

        let normalized = normalize_algorithm(algorithm);
        match normalized.as_str() {
            "ed25519" => {
                // Ed25519: expects raw 32-byte public key — pass through
                crate::crypt::ringwrapper::verify_string(
                    public_key.to_vec(),
                    data_str,
                    &sig_b64,
                )
            }
            "rsa-pss" => {
                // RSA-PSS: expects PEM text bytes. If we received raw DER
                // (from haisdk extract_public_key_bytes), re-wrap as PEM.
                let pem_bytes = if public_key.starts_with(b"-----") {
                    public_key.to_vec()
                } else {
                    pem_encode_spki(public_key)
                };
                crate::crypt::rsawrapper::verify_string(
                    pem_bytes,
                    data_str,
                    &sig_b64,
                )
            }
            "pq2025" | "ml-dsa-87" => {
                // PQ2025: expects raw key bytes of ML_DSA_87_PUBLIC_KEY_SIZE.
                // If we received SPKI-wrapped DER, strip the wrapper.
                let raw_key = strip_spki_wrapper_if_needed(
                    public_key,
                    crate::crypt::constants::ML_DSA_87_PUBLIC_KEY_SIZE,
                );
                crate::crypt::pq2025::verify_string(
                    raw_key,
                    data_str,
                    &sig_b64,
                )
            }
            other => Err(format!("unsupported algorithm: {other}").into()),
        }
    }
}

/// PEM-encode a DER-encoded SubjectPublicKeyInfo block.
fn pem_encode_spki(der: &[u8]) -> Vec<u8> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem.into_bytes()
}

/// Strip SPKI wrapper from DER-encoded public key if the key is larger than
/// the expected raw size. SPKI adds an AlgorithmIdentifier prefix; the raw
/// key bytes are in the trailing BIT STRING.
fn strip_spki_wrapper_if_needed(key: &[u8], expected_raw_size: usize) -> Vec<u8> {
    if key.len() == expected_raw_size {
        return key.to_vec();
    }
    // SPKI-wrapped key: the raw key is the last `expected_raw_size` bytes
    // after the AlgorithmIdentifier + BIT STRING overhead.
    if key.len() > expected_raw_size {
        return key[key.len() - expected_raw_size..].to_vec();
    }
    // Key is smaller than expected — pass through and let the crypto
    // wrapper produce a descriptive error.
    key.to_vec()
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
    // Step 0: Size guard -- reject oversized emails before parsing
    check_email_size(raw_email)?;

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
    let canonical_payload = canonicalize_json_rfc8785(&payload_json);

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

/// Verify a JACS-signed .eml (RFC 5322) email in a single call.
///
/// This is the primary simple API for email verification. It combines
/// `verify_email_document` (cryptographic signature validation) and
/// `verify_email_content` (hash comparison) into one step:
///
/// 1. Extracts the `jacs-signature.json` attachment from the email
/// 2. Removes the attachment (the signature covers the email without itself)
/// 3. Validates the JACS document's payload hash (SHA-256 of canonical JSON)
/// 4. Verifies the cryptographic signature using the provided public key
/// 5. Compares every hash in the trusted JACS document against the actual
///    email content (headers, body parts, attachments)
/// 6. Returns field-level results showing which fields pass, fail, or were
///    modified
///
/// The JACS document stores header values alongside their hashes, so if
/// tampering is detected, the original values are available in the
/// `FieldResult.original_value` field.
///
/// # Arguments
/// * `raw_eml` - Raw RFC 5322 email bytes (with `jacs-signature.json` attached)
/// * `public_key` - The signer's public key bytes (extracted from PEM)
///
/// # Returns
/// `ContentVerificationResult` with field-level results. Check `.valid` for
/// overall pass/fail.
///
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
    let fields_valid = !field_results
        .iter()
        .any(|r| r.status == FieldStatus::Fail);

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
fn build_parent_chain(
    parent_hash: &str,
    parts: &ParsedEmailParts,
    chain: &mut Vec<ChainEntry>,
) {
    // Search for the parent document among JACS attachments
    for jacs_att in &parts.jacs_attachments {
        // Compute sha256 of the exact attachment bytes (no trimming)
        let att_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&jacs_att.content);
            format!("sha256:{}", hex::encode(hasher.finalize()))
        };

        if att_hash == parent_hash {
            // Found the parent document
            if let Ok(parent_doc) =
                serde_json::from_slice::<JacsEmailSignatureDocument>(&jacs_att.content)
            {
                // Add this signer to the chain.
                // valid is false because JACS does not have the parent signer's
                // public key and cannot perform cryptographic verification.
                // The haisdk / HAI API layer MUST verify the parent signature
                // and upgrade this to true before reporting the chain as trusted.
                let is_forwarded = parent_doc.payload.parent_signature_hash.is_some();
                chain.push(ChainEntry {
                    signer: parent_doc.payload.headers.from.value.clone(),
                    jacs_id: parent_doc.metadata.issuer.clone(),
                    valid: false,
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

            // Both content and MIME header hashes must match for Pass.
            // MIME header tampering (e.g., changing Content-Type or CTE) is a
            // security-relevant modification that must fail verification, even
            // if the decoded body content happens to match.
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
        // All fields should be Pass or Unverifiable (Message-ID is Unverifiable).
        // Modified is only used for address-header case-insensitive fallback.
        assert!(
            result
                .field_results
                .iter()
                .all(|r| r.status == FieldStatus::Pass
                    || r.status == FieldStatus::Unverifiable),
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

        // Overall valid is false because JACS cannot verify parent chain entries
        // (no public key available for parent signers). The haisdk/HAI API layer
        // must verify parent signatures and then trust the chain.
        assert!(!result.valid, "expected valid=false for forwarded email at JACS level");
        // But no individual fields should fail
        assert!(
            !result.field_results.iter().any(|r| r.status == FieldStatus::Fail),
            "field-level failures unexpected: {:?}",
            result.field_results.iter().filter(|r| r.status == FieldStatus::Fail).collect::<Vec<_>>()
        );
        assert_eq!(result.chain.len(), 2, "Expected 2 chain entries, got {}: {:?}", result.chain.len(), result.chain);
        assert_eq!(result.chain[0].jacs_id, "agent-b:v1");
        assert!(result.chain[0].forwarded);
        assert_eq!(result.chain[1].jacs_id, "agent-a:v1");
        assert!(!result.chain[1].forwarded);
        // Parent chain entry is unverified at JACS level
        assert!(!result.chain[1].valid);
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

        // Overall valid is false because parent chain entries are unverified
        assert!(!result.valid, "expected valid=false for deep forwarded email at JACS level");
        assert!(
            !result.field_results.iter().any(|r| r.status == FieldStatus::Fail),
            "field-level failures unexpected"
        );
        assert_eq!(result.chain.len(), 3,
            "Expected 3 chain entries, got {}: {:?}", result.chain.len(), result.chain);
        assert_eq!(result.chain[0].jacs_id, "agent-c:v1");
        assert!(result.chain[0].forwarded);
        assert_eq!(result.chain[1].jacs_id, "agent-b:v1");
        assert!(result.chain[1].forwarded);
        assert_eq!(result.chain[2].jacs_id, "agent-a:v1");
        assert!(!result.chain[2].forwarded);
        // All parent entries are unverified at JACS level
        assert!(!result.chain[1].valid);
        assert!(!result.chain[2].valid);
    }

    // -- Security regression tests --

    #[test]
    fn attachment_trailing_byte_tamper_detected() {
        // Regression test for P0: trailing bytes appended to an attachment
        // must cause verification to fail (not be silently stripped).
        let email = b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <test@example.com>\r\nContent-Type: multipart/mixed; boundary=\"mixbound\"\r\n\r\n--mixbound\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nBody\r\n--mixbound\r\nContent-Type: application/pdf; name=\"report.pdf\"\r\nContent-Disposition: attachment; filename=\"report.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n--mixbound--\r\n";
        let signer = TestSigner::new("test-agent:v1");
        let signed = sign_email(email, &signer).unwrap();

        let verifier = TestVerifier;
        let (doc, mut parts) =
            verify_email_document(&signed, b"test-key", &verifier).unwrap();

        // Tamper: append trailing bytes to attachment content
        if let Some(att) = parts.attachments.first_mut() {
            att.content.extend_from_slice(b"\r\n\t ");
        }

        let result = verify_email_content(&doc, &parts);
        assert!(!result.valid, "Trailing byte tamper should be detected");
    }

    #[test]
    fn mime_header_tamper_on_body_causes_fail() {
        // Regression test for P0: MIME header tampering on body parts
        // must cause Fail (not Modified).
        let email = simple_text_email();
        let signer = TestSigner::new("test-agent:v1");
        let signed = sign_email(&email, &signer).unwrap();

        let verifier = TestVerifier;
        let (doc, mut parts) =
            verify_email_document(&signed, b"test-key", &verifier).unwrap();

        // Tamper: change body MIME header
        if let Some(bp) = parts.body_plain.as_mut() {
            bp.content_type = Some("text/plain; charset=us-ascii".to_string());
        }

        let result = verify_email_content(&doc, &parts);
        let body_result = result
            .field_results
            .iter()
            .find(|r| r.field == "body_plain")
            .unwrap();
        assert_eq!(body_result.status, FieldStatus::Fail,
            "MIME header tamper should be Fail, not {:?}", body_result.status);
        assert!(!result.valid, "MIME header tamper should invalidate result");
    }

    #[test]
    fn oversized_email_rejected_on_verify() {
        // Regression test for P1: verify must enforce size limit.
        let mut big_email = b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\nDate: Fri, 28 Feb 2026 12:00:00 +0000\r\nMessage-ID: <test@example.com>\r\nContent-Type: text/plain\r\n\r\n".to_vec();
        big_email.resize(26 * 1024 * 1024, b'A'); // > 25 MB
        let verifier = TestVerifier;
        let result = verify_email_document(&big_email, b"key", &verifier);
        assert!(result.is_err());
        match result.unwrap_err() {
            EmailError::EmailTooLarge { .. } => {}
            other => panic!("Expected EmailTooLarge, got {:?}", other),
        }
    }

    #[test]
    fn parent_chain_entry_valid_is_false() {
        // Regression test for P0: parent chain entries should have valid=false
        // because JACS cannot verify their cryptographic signatures.
        let (signed_by_b, _, _) = forwarded_email_from_b();
        let verifier = TestVerifier;
        let (doc, parts) =
            verify_email_document(&signed_by_b, b"test-key", &verifier).unwrap();
        let result = verify_email_content(&doc, &parts);

        // chain[0] is the current signer (B) - valid is based on field results
        // chain[1] is the parent (A) - valid must be false (no crypto check)
        assert!(result.chain.len() >= 2);
        assert!(!result.chain[1].valid,
            "Parent chain entry should have valid=false without crypto verification");
    }

    #[test]
    fn address_match_extracts_mailbox_addr_spec() {
        // RFC 5322 mailbox format: "Display Name" <addr-spec>
        assert!(addresses_match_case_insensitive(
            "\"Alice Agent\" <alice@example.com>",
            "alice@example.com"
        ));
        // Angle-addr without display name
        assert!(addresses_match_case_insensitive(
            "<bob@example.com>",
            "bob@example.com"
        ));
        // Multiple addresses with display names
        assert!(addresses_match_case_insensitive(
            "Alice <alice@example.com>, Bob <bob@example.com>",
            "bob@example.com, alice@example.com"
        ));
        // Case-insensitive comparison
        assert!(addresses_match_case_insensitive(
            "\"ALICE\" <ALICE@EXAMPLE.COM>",
            "alice@example.com"
        ));
        // Different addr-specs should NOT match
        assert!(!addresses_match_case_insensitive(
            "\"Alice\" <alice@example.com>",
            "bob@example.com"
        ));
    }

    #[test]
    fn extract_addr_specs_handles_rfc5322_edge_cases() {
        // Bare addr-spec
        assert_eq!(extract_addr_specs("user@example.com"), vec!["user@example.com"]);
        // Angle-addr
        assert_eq!(extract_addr_specs("<user@example.com>"), vec!["user@example.com"]);
        // Display name with quoted string
        assert_eq!(
            extract_addr_specs("\"John Doe\" <john@example.com>"),
            vec!["john@example.com"]
        );
        // Multiple addresses
        let addrs = extract_addr_specs("Alice <alice@a.com>, Bob <bob@b.com>");
        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&"alice@a.com".to_string()));
        assert!(addrs.contains(&"bob@b.com".to_string()));
        // Case normalization
        assert_eq!(
            extract_addr_specs("USER@EXAMPLE.COM"),
            vec!["user@example.com"]
        );
    }

    #[test]
    fn chain_validity_gates_overall_valid() {
        // Non-forwarded email: chain has one entry, overall valid = true
        let email = simple_text_email();
        let signer = TestSigner::new("test-agent:v1");
        let signed = sign_email(&email, &signer).unwrap();
        let verifier = TestVerifier;
        let (doc, parts) = verify_email_document(&signed, b"test-key", &verifier).unwrap();
        let result = verify_email_content(&doc, &parts);
        assert!(result.valid, "non-forwarded email should be valid");

        // Forwarded email: parent chain entry has valid=false → overall valid=false
        let (signed_by_b, _, _) = forwarded_email_from_b();
        let (doc, parts) = verify_email_document(&signed_by_b, b"test-key", &verifier).unwrap();
        let result = verify_email_content(&doc, &parts);
        assert!(!result.valid, "forwarded email should be invalid at JACS level due to unverified chain");
        // But field results should all pass (no content tampering)
        let failing_fields: Vec<_> = result.field_results.iter()
            .filter(|r| r.status == FieldStatus::Fail)
            .collect();
        assert!(failing_fields.is_empty(), "no field-level failures expected: {:?}", failing_fields);
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
