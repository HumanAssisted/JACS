//! Email evidence adapter.
//!
//! Normalizes bytes described as email into digest-addressed attestation
//! evidence. This adapter does not verify DKIM, S/MIME, PGP, JACS, or any other
//! email signature or sender identity.
//! Zero new dependencies -- reuses existing jacs/src/email/ module.

use crate::attestation::adapters::{EvidenceAdapter, digest_recorded_claim};
use crate::attestation::digest::{compute_digest_set_bytes, should_embed_with_sensitivity};
use crate::attestation::types::*;
use crate::error::JacsError;
use serde_json::Value;
use tracing::info;

/// Email evidence adapter.
#[derive(Debug)]
pub struct EmailAdapter;

impl EvidenceAdapter for EmailAdapter {
    fn kind(&self) -> &str {
        "email"
    }

    fn normalize(
        &self,
        raw: &[u8],
        _metadata: &Value,
    ) -> Result<(Vec<Claim>, EvidenceRef), JacsError> {
        let digests = compute_digest_set_bytes(raw);
        let sensitivity = EvidenceSensitivity::Public;
        let embedded = should_embed_with_sensitivity(raw, &sensitivity);
        let embedded_data = if embedded {
            Some(Value::String(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                raw,
            )))
        } else {
            None
        };

        // Raw bytes and caller-controlled metadata cannot establish email
        // signature validity. Record only what this adapter actually computed.
        let claims = vec![digest_recorded_claim("email", &digests)];

        let evidence = EvidenceRef {
            kind: EvidenceKind::Email,
            digests,
            uri: None,
            embedded,
            embedded_data,
            collected_at: crate::time_utils::now_rfc3339(),
            resolved_at: None,
            sensitivity,
            verifier: VerifierInfo {
                name: "jacs-email-adapter".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
        };

        info!(
            target: "jacs::attestation::adapters",
            event = "evidence_normalized",
            adapter = "email",
            data_size = raw.len(),
            embedded = embedded,
            claims_count = claims.len(),
        );

        Ok((claims, evidence))
    }

    fn verify_evidence(
        &self,
        evidence: &EvidenceRef,
    ) -> Result<EvidenceVerificationResult, JacsError> {
        let digest_valid = if let Some(ref data) = evidence.embedded_data {
            let data_str = data.as_str().unwrap_or("");
            let decoded =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, data_str)
                    .unwrap_or_default();
            let recomputed = compute_digest_set_bytes(&decoded);
            recomputed.sha256 == evidence.digests.sha256
        } else {
            false
        };

        info!(
            target: "jacs::attestation::adapters",
            event = "evidence_digest_checked",
            adapter = "email",
            verification_scope = "digest_only",
            digest_valid = digest_valid,
        );

        Ok(EvidenceVerificationResult {
            kind: "email".into(),
            digest_valid,
            freshness_valid: true,
            detail: if digest_valid {
                "Embedded email evidence bytes match the recorded digest; email signature and sender identity were not verified".into()
            } else {
                "Email evidence digest could not be verified; email signature and sender identity were not verified".into()
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::digest::compute_digest_set_bytes;
    use serde_json::json;

    #[test]
    fn email_adapter_kind() {
        let adapter = EmailAdapter;
        assert_eq!(adapter.kind(), "email");
    }

    #[test]
    fn email_normalize_records_digest_only_claim() {
        let adapter = EmailAdapter;
        let raw = b"From: test@example.com\r\nSubject: Test\r\n\r\nBody";
        let (claims, evidence) = adapter.normalize(raw, &json!({})).unwrap();

        assert!(!claims.is_empty());
        assert_eq!(claims[0].name, "email-evidence-digest-recorded");
        assert_eq!(claims[0].value, evidence.digests.sha256);
        assert_eq!(
            claims[0].assurance_level,
            Some(AssuranceLevel::SelfAsserted)
        );
        assert_eq!(evidence.kind, EvidenceKind::Email);
    }

    #[test]
    fn email_normalize_never_claims_arbitrary_bytes_have_a_verified_signature() {
        let adapter = EmailAdapter;
        let raw = b"not an email and not signed";
        let metadata = json!({
            "verified": true,
            "signatureVerified": true,
            "assuranceLevel": "verified"
        });

        let (claims, _) = adapter.normalize(raw, &metadata).unwrap();

        assert!(
            claims
                .iter()
                .all(|claim| claim.assurance_level != Some(AssuranceLevel::Verified)),
            "normalizing bytes and checking a digest is not email signature verification"
        );
        assert!(
            claims
                .iter()
                .all(|claim| claim.name != "email-signature-verified"),
            "unverified input must not produce a signature-verification claim"
        );
    }

    #[test]
    fn email_normalize_sets_collected_at() {
        let adapter = EmailAdapter;
        let raw = b"email data";
        let (_, evidence) = adapter.normalize(raw, &json!({})).unwrap();

        assert!(
            chrono::DateTime::parse_from_rfc3339(&evidence.collected_at).is_ok(),
            "collected_at should be valid RFC 3339: {}",
            evidence.collected_at
        );
    }

    #[test]
    fn email_normalize_computes_digest() {
        let adapter = EmailAdapter;
        let raw = b"deterministic email";
        let expected = compute_digest_set_bytes(raw);
        let (_, evidence) = adapter.normalize(raw, &json!({})).unwrap();

        assert_eq!(evidence.digests.sha256, expected.sha256);
    }

    #[test]
    fn email_normalize_auto_embeds_small() {
        let adapter = EmailAdapter;
        let small = vec![0u8; 100];
        let (_, evidence) = adapter.normalize(&small, &json!({})).unwrap();

        assert!(evidence.embedded);
        assert!(evidence.embedded_data.is_some());
    }

    #[test]
    fn email_normalize_references_large() {
        let adapter = EmailAdapter;
        let large = vec![0u8; 100_000];
        let (_, evidence) = adapter.normalize(&large, &json!({})).unwrap();

        assert!(!evidence.embedded);
        assert!(evidence.embedded_data.is_none());
    }

    #[test]
    fn email_verify_evidence_valid_digest() {
        let adapter = EmailAdapter;
        let raw = b"verify this email";
        let (_, evidence) = adapter.normalize(raw, &json!({})).unwrap();

        let result = adapter.verify_evidence(&evidence).unwrap();
        assert!(
            result.digest_valid,
            "Embedded email evidence digest should verify: {}",
            result.detail
        );
        assert!(result.detail.contains("not verified"));
        assert!(result.detail.contains("email signature"));
    }

    #[test]
    fn email_verify_evidence_invalid_digest() {
        let adapter = EmailAdapter;
        let evidence = EvidenceRef {
            kind: EvidenceKind::Email,
            digests: DigestSet {
                sha256: "wrong_hash".into(),
                sha512: None,
                additional: std::collections::HashMap::new(),
            },
            uri: None,
            embedded: true,
            embedded_data: Some(Value::String(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                b"data",
            ))),
            collected_at: crate::time_utils::now_rfc3339(),
            resolved_at: None,
            sensitivity: EvidenceSensitivity::Public,
            verifier: VerifierInfo {
                name: "test".into(),
                version: "1.0".into(),
            },
        };

        let result = adapter.verify_evidence(&evidence).unwrap();
        assert!(!result.digest_valid);
    }

    #[test]
    fn email_adapter_verifier_info() {
        let adapter = EmailAdapter;
        let raw = b"test";
        let (_, evidence) = adapter.normalize(raw, &json!({})).unwrap();

        assert_eq!(evidence.verifier.name, "jacs-email-adapter");
        assert_eq!(evidence.verifier.version, env!("CARGO_PKG_VERSION"));
    }
}
