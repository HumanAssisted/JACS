//! Core email signature types for the JACS email signing system.
//!
//! These types represent the JACS email signature document structure,
//! parsed email parts, and content verification results. They are
//! consumed by both the JACS email module and haisdk.

use serde::{Deserialize, Serialize};

/// A signed header entry containing the raw value and its SHA-256 hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedHeaderEntry {
    /// Raw header value (canonicalized).
    pub value: String,
    /// Hash in the form "sha256:<hex>".
    pub hash: String,
}

/// A body part entry with its content hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BodyPartEntry {
    /// SHA-256 hash of the canonicalized body content.
    pub content_hash: String,
}

/// An attachment entry with content hash and filename.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentEntry {
    /// SHA-256 hash computed as `sha256(filename_nfc:content_type_lower:raw_bytes)`.
    pub content_hash: String,
    /// UTF-8 NFC normalized filename.
    pub filename: String,
}

/// The set of signed email headers in the JACS signature payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailSignatureHeaders {
    pub from: SignedHeaderEntry,
    pub to: SignedHeaderEntry,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc: Option<SignedHeaderEntry>,
    pub subject: SignedHeaderEntry,
    pub date: SignedHeaderEntry,
    /// Stored but NOT verified (may change after signing).
    pub message_id: SignedHeaderEntry,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<SignedHeaderEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<SignedHeaderEntry>,
}

/// The payload section of the JACS email signature document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailSignaturePayload {
    pub headers: EmailSignatureHeaders,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_plain: Option<BodyPartEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_html: Option<BodyPartEntry>,
    pub attachments: Vec<AttachmentEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_signature_hash: Option<String>,
}

/// Metadata for the JACS email signature document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JacsEmailMetadata {
    /// JACS agent ID of the signer.
    pub issuer: String,
    /// Unique document identifier.
    pub document_id: String,
    /// ISO 8601 timestamp of document creation.
    pub created_at: String,
    /// SHA-256 hash of the RFC 8785 canonicalized payload.
    pub hash: String,
}

/// Cryptographic signature of the JACS email signature document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JacsEmailSignature {
    /// Key identifier used for signing.
    pub key_id: String,
    /// Signing algorithm (e.g., "ed25519", "rsa-pss-sha256").
    pub algorithm: String,
    /// Base64-encoded signature bytes.
    pub signature: String,
    /// ISO 8601 timestamp of signing.
    pub signed_at: String,
}

/// The complete JACS email signature document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JacsEmailSignatureDocument {
    /// Document version (currently "1.0").
    pub version: String,
    /// Document type (always "email_signature").
    pub document_type: String,
    /// The email signature payload containing headers, body, and attachment hashes.
    pub payload: EmailSignaturePayload,
    /// Document metadata including issuer and hash.
    pub metadata: JacsEmailMetadata,
    /// Cryptographic signature over the canonical payload.
    pub signature: JacsEmailSignature,
}

/// Parsed email parts extracted from raw RFC 5322 bytes.
/// Used as intermediate representation for signing and verification.
#[derive(Debug, Clone)]
pub struct ParsedEmailParts {
    /// Raw header values keyed by lowercase header name.
    pub headers: std::collections::HashMap<String, Vec<String>>,
    /// Decoded text/plain body part, if present.
    pub body_plain: Option<ParsedBodyPart>,
    /// Decoded text/html body part, if present.
    pub body_html: Option<ParsedBodyPart>,
    /// Non-JACS attachments.
    pub attachments: Vec<ParsedAttachment>,
    /// JACS signature attachments found in the email.
    pub jacs_attachments: Vec<ParsedAttachment>,
}

/// A parsed body part with content and MIME metadata.
#[derive(Debug, Clone)]
pub struct ParsedBodyPart {
    /// Decoded and canonicalized body content.
    pub content: Vec<u8>,
    /// Content-Type header value.
    pub content_type: Option<String>,
    /// Content-Transfer-Encoding header value.
    pub content_transfer_encoding: Option<String>,
    /// Content-Disposition header value.
    pub content_disposition: Option<String>,
}

/// A parsed attachment with content and metadata.
#[derive(Debug, Clone)]
pub struct ParsedAttachment {
    /// Filename (UTF-8 NFC normalized).
    pub filename: String,
    /// Content-Type of the attachment.
    pub content_type: String,
    /// Raw decoded attachment bytes.
    pub content: Vec<u8>,
    /// Content-Transfer-Encoding header value.
    pub content_transfer_encoding: Option<String>,
    /// Content-Disposition header value.
    pub content_disposition: Option<String>,
}

/// Status of a single field in content verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldStatus {
    /// Hash matches exactly.
    Pass,
    /// Hash mismatch but case-insensitive email match (address headers only).
    Modified,
    /// Content does not match.
    Fail,
    /// Field absent or not verified (e.g., Message-ID, stripped body part).
    Unverifiable,
}

/// Result for a single field in content verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldResult {
    /// Field path (e.g., "headers.from", "body_plain", "headers.message_id").
    pub field: String,
    /// Verification status.
    pub status: FieldStatus,
    /// Hash from the JACS signature document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_hash: Option<String>,
    /// Hash computed from the current email content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_hash: Option<String>,
    /// Original value from the JACS signature document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_value: Option<String>,
    /// Current value from the email.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_value: Option<String>,
}

/// An entry in a forwarding chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainEntry {
    /// Signer identity (e.g., email address).
    pub signer: String,
    /// JACS agent ID.
    pub jacs_id: String,
    /// Whether this entry's signature is valid.
    pub valid: bool,
    /// Whether this entry represents a forwarding step.
    pub forwarded: bool,
}

/// Result of content verification comparing trusted JACS hashes against email.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentVerificationResult {
    /// Overall validity: true only if no Fail results.
    pub valid: bool,
    /// Per-field verification results.
    pub field_results: Vec<FieldResult>,
    /// Forwarding chain entries, if any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<ChainEntry>,
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_header_entry_serializes_with_value_and_hash() {
        let entry = SignedHeaderEntry {
            value: "agent@example.com".to_string(),
            hash: "sha256:abc123".to_string(),
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["value"], "agent@example.com");
        assert_eq!(json["hash"], "sha256:abc123");
    }

    #[test]
    fn email_signature_payload_roundtrips_through_serde() {
        let payload = EmailSignaturePayload {
            headers: EmailSignatureHeaders {
                from: SignedHeaderEntry {
                    value: "sender@example.com".to_string(),
                    hash: "sha256:from_hash".to_string(),
                },
                to: SignedHeaderEntry {
                    value: "recipient@example.com".to_string(),
                    hash: "sha256:to_hash".to_string(),
                },
                cc: None,
                subject: SignedHeaderEntry {
                    value: "Test Subject".to_string(),
                    hash: "sha256:subject_hash".to_string(),
                },
                date: SignedHeaderEntry {
                    value: "Fri, 28 Feb 2026 12:00:00 +0000".to_string(),
                    hash: "sha256:date_hash".to_string(),
                },
                message_id: SignedHeaderEntry {
                    value: "<test@example.com>".to_string(),
                    hash: "sha256:mid_hash".to_string(),
                },
                in_reply_to: None,
                references: None,
            },
            body_plain: Some(BodyPartEntry {
                content_hash: "sha256:body_hash".to_string(),
            }),
            body_html: None,
            attachments: vec![],
            parent_signature_hash: None,
        };

        let json_str = serde_json::to_string(&payload).unwrap();
        let roundtripped: EmailSignaturePayload = serde_json::from_str(&json_str).unwrap();
        assert_eq!(roundtripped.headers.from.value, "sender@example.com");
        assert!(roundtripped.body_html.is_none());
        assert!(roundtripped.parent_signature_hash.is_none());
    }

    #[test]
    fn jacs_email_signature_document_roundtrips_through_serde() {
        let doc = JacsEmailSignatureDocument {
            version: "1.0".to_string(),
            document_type: "email_signature".to_string(),
            payload: EmailSignaturePayload {
                headers: EmailSignatureHeaders {
                    from: SignedHeaderEntry {
                        value: "a@b.com".to_string(),
                        hash: "sha256:f".to_string(),
                    },
                    to: SignedHeaderEntry {
                        value: "c@d.com".to_string(),
                        hash: "sha256:t".to_string(),
                    },
                    cc: None,
                    subject: SignedHeaderEntry {
                        value: "s".to_string(),
                        hash: "sha256:s".to_string(),
                    },
                    date: SignedHeaderEntry {
                        value: "d".to_string(),
                        hash: "sha256:d".to_string(),
                    },
                    message_id: SignedHeaderEntry {
                        value: "m".to_string(),
                        hash: "sha256:m".to_string(),
                    },
                    in_reply_to: None,
                    references: None,
                },
                body_plain: None,
                body_html: None,
                attachments: vec![],
                parent_signature_hash: None,
            },
            metadata: JacsEmailMetadata {
                issuer: "test-agent".to_string(),
                document_id: "doc-1".to_string(),
                created_at: "2026-02-28T00:00:00Z".to_string(),
                hash: "sha256:meta_hash".to_string(),
            },
            signature: JacsEmailSignature {
                key_id: "key-1".to_string(),
                algorithm: "ed25519".to_string(),
                signature: "c2lnbmF0dXJl".to_string(),
                signed_at: "2026-02-28T00:00:00Z".to_string(),
            },
        };

        let json_str = serde_json::to_string(&doc).unwrap();
        let roundtripped: JacsEmailSignatureDocument = serde_json::from_str(&json_str).unwrap();
        assert_eq!(roundtripped.version, "1.0");
        assert_eq!(roundtripped.document_type, "email_signature");
        assert_eq!(roundtripped.metadata.issuer, "test-agent");
        assert_eq!(roundtripped.signature.algorithm, "ed25519");
    }

    #[test]
    fn content_verification_result_with_mixed_field_status() {
        let result = ContentVerificationResult {
            valid: false,
            field_results: vec![

                FieldResult {
                    field: "headers.from".to_string(),
                    status: FieldStatus::Pass,
                    original_hash: Some("sha256:a".to_string()),
                    current_hash: Some("sha256:a".to_string()),
                    original_value: Some("a@b.com".to_string()),
                    current_value: Some("a@b.com".to_string()),
                },
                FieldResult {
                    field: "headers.subject".to_string(),
                    status: FieldStatus::Fail,
                    original_hash: Some("sha256:b".to_string()),
                    current_hash: Some("sha256:c".to_string()),
                    original_value: Some("Original".to_string()),
                    current_value: Some("Tampered".to_string()),
                },
                FieldResult {
                    field: "headers.message_id".to_string(),
                    status: FieldStatus::Unverifiable,
                    original_hash: None,
                    current_hash: None,
                    original_value: None,
                    current_value: None,
                },
                FieldResult {
                    field: "headers.from".to_string(),
                    status: FieldStatus::Modified,
                    original_hash: Some("sha256:d".to_string()),
                    current_hash: Some("sha256:e".to_string()),
                    original_value: Some("User@Example.COM".to_string()),
                    current_value: Some("user@example.com".to_string()),
                },
            ],
            chain: vec![],
        };

        let json_str = serde_json::to_string(&result).unwrap();
        let roundtripped: ContentVerificationResult = serde_json::from_str(&json_str).unwrap();
        assert!(!roundtripped.valid);
        assert_eq!(roundtripped.field_results.len(), 4);
        assert_eq!(roundtripped.field_results[0].status, FieldStatus::Pass);
        assert_eq!(roundtripped.field_results[1].status, FieldStatus::Fail);
        assert_eq!(
            roundtripped.field_results[2].status,
            FieldStatus::Unverifiable
        );
        assert_eq!(roundtripped.field_results[3].status, FieldStatus::Modified);
    }

    #[test]
    fn parsed_email_parts_holds_optional_body_parts() {
        let parts = ParsedEmailParts {
            headers: std::collections::HashMap::new(),
            body_plain: Some(ParsedBodyPart {
                content: b"Hello".to_vec(),
                content_type: Some("text/plain; charset=utf-8".to_string()),
                content_transfer_encoding: Some("7bit".to_string()),
                content_disposition: None,
            }),
            body_html: None,
            attachments: vec![],
            jacs_attachments: vec![],
        };

        assert!(parts.body_plain.is_some());
        assert!(parts.body_html.is_none());
        assert_eq!(parts.body_plain.unwrap().content, b"Hello");
    }

    #[test]
    fn field_status_serializes_to_lowercase() {
        assert_eq!(
            serde_json::to_string(&FieldStatus::Pass).unwrap(),
            "\"pass\""
        );
        assert_eq!(
            serde_json::to_string(&FieldStatus::Modified).unwrap(),
            "\"modified\""
        );
        assert_eq!(
            serde_json::to_string(&FieldStatus::Fail).unwrap(),
            "\"fail\""
        );
        assert_eq!(
            serde_json::to_string(&FieldStatus::Unverifiable).unwrap(),
            "\"unverifiable\""
        );
    }
}
