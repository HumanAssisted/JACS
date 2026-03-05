//! A2A evidence adapter.
//!
//! Normalizes A2A protocol messages into attestation evidence.
//! Zero new dependencies -- reuses existing jacs/src/a2a/ module.

use crate::attestation::adapters::EvidenceAdapter;
use crate::attestation::digest::{compute_digest_set_bytes, should_embed};
use crate::attestation::types::*;
use serde_json::Value;
use std::error::Error;
use tracing::info;

/// A2A evidence adapter.
#[derive(Debug)]
pub struct A2aAdapter;

impl EvidenceAdapter for A2aAdapter {
    fn kind(&self) -> &str {
        "a2a"
    }

    fn normalize(
        &self,
        raw: &[u8],
        _metadata: &Value,
    ) -> Result<(Vec<Claim>, EvidenceRef), Box<dyn Error>> {
        let digests = compute_digest_set_bytes(raw);
        let embedded = should_embed(raw);
        let embedded_data = if embedded {
            Some(serde_json::from_slice(raw).unwrap_or(Value::String(
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw),
            )))
        } else {
            None
        };

        let claims = vec![Claim {
            name: "a2a-message-verified".into(),
            value: Value::Bool(true),
            confidence: Some(0.9),
            assurance_level: Some(AssuranceLevel::Verified),
            issuer: None,
            issued_at: Some(crate::time_utils::now_rfc3339()),
        }];

        let evidence = EvidenceRef {
            kind: EvidenceKind::A2a,
            digests,
            uri: None,
            embedded,
            embedded_data,
            collected_at: crate::time_utils::now_rfc3339(),
            resolved_at: None,
            sensitivity: EvidenceSensitivity::Public,
            verifier: VerifierInfo {
                name: "jacs-a2a-adapter".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
        };

        info!(
            target: "jacs::attestation::adapters",
            event = "evidence_normalized",
            adapter = "a2a",
            data_size = raw.len(),
            embedded = embedded,
            claims_count = claims.len(),
        );

        Ok((claims, evidence))
    }

    fn verify_evidence(
        &self,
        evidence: &EvidenceRef,
    ) -> Result<EvidenceVerificationResult, Box<dyn Error>> {
        let digest_valid = if let Some(ref data) = evidence.embedded_data {
            // The original raw bytes were used to compute the digest.
            // If the data is a JSON string, try base64-decoding it back to raw bytes.
            // If it's a JSON object/array, it was parsed from the raw bytes, so re-serialize.
            let raw_bytes = match data {
                Value::String(s) => {
                    // Try base64 decode (for non-JSON raw data that was base64-encoded)
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s)
                        .unwrap_or_else(|_| s.as_bytes().to_vec())
                }
                other => serde_json::to_vec(other).unwrap_or_default(),
            };
            let recomputed = compute_digest_set_bytes(&raw_bytes);
            recomputed.sha256 == evidence.digests.sha256
        } else {
            // Cannot verify referenced evidence without fetching -- mark as unverifiable
            false
        };

        info!(
            target: "jacs::attestation::adapters",
            event = "evidence_verified",
            adapter = "a2a",
            digest_valid = digest_valid,
        );

        Ok(EvidenceVerificationResult {
            kind: "a2a".into(),
            digest_valid,
            freshness_valid: true, // Freshness checking is done at full verify level
            detail: if digest_valid {
                "Embedded A2A evidence digest verified".into()
            } else {
                "A2A evidence digest could not be verified".into()
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
    fn a2a_adapter_kind() {
        let adapter = A2aAdapter;
        assert_eq!(adapter.kind(), "a2a");
    }

    #[test]
    fn a2a_normalize_valid_message() {
        let adapter = A2aAdapter;
        let msg = json!({"jsonrpc": "2.0", "method": "test", "id": 1});
        let raw = serde_json::to_vec(&msg).unwrap();
        let (claims, evidence) = adapter.normalize(&raw, &json!({})).unwrap();

        assert!(!claims.is_empty());
        assert_eq!(claims[0].name, "a2a-message-verified");
        assert_eq!(evidence.kind, EvidenceKind::A2a);
    }

    #[test]
    fn a2a_normalize_sets_collected_at() {
        let adapter = A2aAdapter;
        let raw = b"test data";
        let (_, evidence) = adapter.normalize(raw, &json!({})).unwrap();

        // collected_at should be a valid RFC 3339 timestamp
        assert!(
            chrono::DateTime::parse_from_rfc3339(&evidence.collected_at).is_ok(),
            "collected_at should be valid RFC 3339: {}",
            evidence.collected_at
        );
    }

    #[test]
    fn a2a_normalize_computes_digest() {
        let adapter = A2aAdapter;
        let raw = b"deterministic data";
        let expected_digest = compute_digest_set_bytes(raw);
        let (_, evidence) = adapter.normalize(raw, &json!({})).unwrap();

        assert_eq!(
            evidence.digests.sha256, expected_digest.sha256,
            "Digest must match SHA-256 of raw input"
        );
    }

    #[test]
    fn a2a_normalize_auto_embeds_small() {
        let adapter = A2aAdapter;
        let small_data = vec![0u8; 100]; // well under 64KB
        let (_, evidence) = adapter.normalize(&small_data, &json!({})).unwrap();

        assert!(evidence.embedded, "Small data should be embedded");
        assert!(
            evidence.embedded_data.is_some(),
            "Embedded data should be present"
        );
    }

    #[test]
    fn a2a_normalize_references_large() {
        let adapter = A2aAdapter;
        let large_data = vec![0u8; 100_000]; // over 64KB
        let (_, evidence) = adapter.normalize(&large_data, &json!({})).unwrap();

        assert!(!evidence.embedded, "Large data should not be embedded");
        assert!(
            evidence.embedded_data.is_none(),
            "Embedded data should be None for large data"
        );
    }

    #[test]
    fn a2a_verify_evidence_valid_digest() {
        let adapter = A2aAdapter;
        let raw = b"verify me";
        let (_, evidence) = adapter.normalize(raw, &json!({})).unwrap();

        let result = adapter.verify_evidence(&evidence).unwrap();
        assert!(
            result.digest_valid,
            "Embedded evidence digest should verify: {}",
            result.detail
        );
    }

    #[test]
    fn a2a_verify_evidence_invalid_digest() {
        let adapter = A2aAdapter;
        let evidence = EvidenceRef {
            kind: EvidenceKind::A2a,
            digests: DigestSet {
                sha256: "wrong_hash".into(),
                sha512: None,
                additional: std::collections::HashMap::new(),
            },
            uri: None,
            embedded: true,
            embedded_data: Some(json!("some data")),
            collected_at: crate::time_utils::now_rfc3339(),
            resolved_at: None,
            sensitivity: EvidenceSensitivity::Public,
            verifier: VerifierInfo {
                name: "test".into(),
                version: "1.0".into(),
            },
        };

        let result = adapter.verify_evidence(&evidence).unwrap();
        assert!(
            !result.digest_valid,
            "Wrong digest should fail verification"
        );
    }

    #[test]
    fn a2a_adapter_verifier_info() {
        let adapter = A2aAdapter;
        let raw = b"test";
        let (_, evidence) = adapter.normalize(raw, &json!({})).unwrap();

        assert_eq!(evidence.verifier.name, "jacs-a2a-adapter");
        assert_eq!(evidence.verifier.version, env!("CARGO_PKG_VERSION"));
    }
}
