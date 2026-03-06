//! Core attestation types matching the attestation JSON schema.
//!
//! All field names use camelCase in JSON (via serde rename attributes)
//! to match the attestation.schema.json specification.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Algorithm-agile digest set (sha256 required, others optional).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DigestSet {
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha512: Option<String>,
    #[serde(flatten)]
    pub additional: HashMap<String, String>,
}

/// The subject of an attestation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationSubject {
    #[serde(rename = "type")]
    pub subject_type: SubjectType,
    pub id: String,
    pub digests: DigestSet,
}

/// Subject type enum.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SubjectType {
    Agent,
    Artifact,
    Workflow,
    Identity,
}

/// A single claim in an attestation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Claim {
    pub name: String,
    pub value: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assurance_level: Option<AssuranceLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
}

/// Categorical assurance level.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum AssuranceLevel {
    SelfAsserted,
    Verified,
    IndependentlyAttested,
}

/// Reference to a piece of evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceRef {
    pub kind: EvidenceKind,
    pub digests: DigestSet,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default)]
    pub embedded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedded_data: Option<Value>,
    pub collected_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<String>,
    #[serde(default = "default_sensitivity")]
    pub sensitivity: EvidenceSensitivity,
    pub verifier: VerifierInfo,
}

fn default_sensitivity() -> EvidenceSensitivity {
    EvidenceSensitivity::Public
}

/// Type of evidence source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceKind {
    A2a,
    Email,
    Jwt,
    Tlsnotary,
    Custom,
}

impl EvidenceKind {
    /// Returns the lowercase string form matching the serde serialization.
    pub fn as_str(&self) -> &str {
        match self {
            Self::A2a => "a2a",
            Self::Email => "email",
            Self::Jwt => "jwt",
            Self::Tlsnotary => "tlsnotary",
            Self::Custom => "custom",
        }
    }
}

/// Privacy classification of evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceSensitivity {
    #[default]
    Public,
    Restricted,
    Confidential,
}

/// Information about the verifier that produced evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerifierInfo {
    pub name: String,
    pub version: String,
}

/// Transform receipt (derivation chain).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Derivation {
    pub inputs: Vec<DerivationInput>,
    pub transform: TransformRef,
    pub output_digests: DigestSet,
}

/// A single input in a derivation chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DerivationInput {
    pub digests: DigestSet,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// Content-addressable reference to a transformation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransformRef {
    pub name: String,
    pub hash: String,
    #[serde(default)]
    pub reproducible: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<HashMap<String, String>>,
}

/// Optional policy context (evaluation deferred to N+2).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_trust_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_evidence_age: Option<String>,
}

// --- Verification Results ---

/// Full attestation verification result.
/// `.valid` is true only if all present fields pass.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationVerificationResult {
    pub valid: bool,
    pub crypto: CryptoVerificationResult,
    pub evidence: Vec<EvidenceVerificationResult>,
    pub chain: Option<ChainVerificationResult>,
    pub errors: Vec<String>,
}

/// Cryptographic verification result.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoVerificationResult {
    pub signature_valid: bool,
    pub hash_valid: bool,
    pub signer_id: String,
    pub algorithm: String,
}

/// Verification result for a single piece of evidence.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceVerificationResult {
    pub kind: String,
    pub digest_valid: bool,
    pub freshness_valid: bool,
    pub detail: String,
}

/// Verification result for derivation chain traversal.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainVerificationResult {
    pub valid: bool,
    pub depth: u32,
    pub max_depth: u32,
    pub links: Vec<ChainLink>,
}

/// A single link in a derivation chain.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainLink {
    pub document_id: String,
    pub valid: bool,
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn digest_set_serialization() {
        let ds = DigestSet {
            sha256: "abc".into(),
            sha512: Some("def".into()),
            additional: HashMap::new(),
        };
        let json = serde_json::to_value(&ds).unwrap();
        assert_eq!(json["sha256"], "abc");
        assert_eq!(json["sha512"], "def");
    }

    #[test]
    fn digest_set_skips_none_sha512() {
        let ds = DigestSet {
            sha256: "abc".into(),
            sha512: None,
            additional: HashMap::new(),
        };
        let json = serde_json::to_value(&ds).unwrap();
        assert_eq!(json["sha256"], "abc");
        assert!(
            json.get("sha512").is_none(),
            "sha512 should be absent when None"
        );
    }

    #[test]
    fn subject_type_serialization() {
        assert_eq!(
            serde_json::to_string(&SubjectType::Agent).unwrap(),
            "\"agent\""
        );
        assert_eq!(
            serde_json::to_string(&SubjectType::Artifact).unwrap(),
            "\"artifact\""
        );
        assert_eq!(
            serde_json::to_string(&SubjectType::Workflow).unwrap(),
            "\"workflow\""
        );
        assert_eq!(
            serde_json::to_string(&SubjectType::Identity).unwrap(),
            "\"identity\""
        );
    }

    #[test]
    fn assurance_level_serialization() {
        assert_eq!(
            serde_json::to_string(&AssuranceLevel::SelfAsserted).unwrap(),
            "\"self-asserted\""
        );
        assert_eq!(
            serde_json::to_string(&AssuranceLevel::Verified).unwrap(),
            "\"verified\""
        );
        assert_eq!(
            serde_json::to_string(&AssuranceLevel::IndependentlyAttested).unwrap(),
            "\"independently-attested\""
        );
    }

    #[test]
    fn evidence_kind_serialization() {
        assert_eq!(
            serde_json::to_string(&EvidenceKind::A2a).unwrap(),
            "\"a2a\""
        );
        assert_eq!(
            serde_json::to_string(&EvidenceKind::Email).unwrap(),
            "\"email\""
        );
        assert_eq!(
            serde_json::to_string(&EvidenceKind::Jwt).unwrap(),
            "\"jwt\""
        );
        assert_eq!(
            serde_json::to_string(&EvidenceKind::Tlsnotary).unwrap(),
            "\"tlsnotary\""
        );
        assert_eq!(
            serde_json::to_string(&EvidenceKind::Custom).unwrap(),
            "\"custom\""
        );
    }

    #[test]
    fn claim_minimal_serialization() {
        let claim = Claim {
            name: "test".into(),
            value: json!("ok"),
            confidence: None,
            assurance_level: None,
            issuer: None,
            issued_at: None,
        };
        let json = serde_json::to_value(&claim).unwrap();
        assert_eq!(json["name"], "test");
        assert_eq!(json["value"], "ok");
        assert!(
            json.get("confidence").is_none(),
            "Optional fields should be absent"
        );
        assert!(json.get("assuranceLevel").is_none());
        assert!(json.get("issuer").is_none());
        assert!(json.get("issuedAt").is_none());
    }

    #[test]
    fn evidence_ref_defaults() {
        let evidence = EvidenceRef {
            kind: EvidenceKind::A2a,
            digests: DigestSet {
                sha256: "abc".into(),
                sha512: None,
                additional: HashMap::new(),
            },
            uri: None,
            embedded: false,
            embedded_data: None,
            collected_at: "2026-01-01T00:00:00Z".into(),
            resolved_at: None,
            sensitivity: EvidenceSensitivity::default(),
            verifier: VerifierInfo {
                name: "test".into(),
                version: "1.0".into(),
            },
        };
        assert_eq!(evidence.sensitivity, EvidenceSensitivity::Public);
    }

    #[test]
    fn derivation_round_trip() {
        let derivation = Derivation {
            inputs: vec![DerivationInput {
                digests: DigestSet {
                    sha256: "input_hash".into(),
                    sha512: None,
                    additional: HashMap::new(),
                },
                id: Some("doc-123".into()),
            }],
            transform: TransformRef {
                name: "summarize-v2".into(),
                hash: "transform_hash".into(),
                reproducible: false,
                environment: None,
            },
            output_digests: DigestSet {
                sha256: "output_hash".into(),
                sha512: None,
                additional: HashMap::new(),
            },
        };
        let json = serde_json::to_string(&derivation).unwrap();
        let round_tripped: Derivation = serde_json::from_str(&json).unwrap();
        assert_eq!(derivation, round_tripped);
    }

    #[test]
    fn verification_result_valid_flag() {
        let result = AttestationVerificationResult {
            valid: true,
            crypto: CryptoVerificationResult {
                signature_valid: true,
                hash_valid: true,
                signer_id: "agent-1".into(),
                algorithm: "ed25519".into(),
            },
            evidence: vec![],
            chain: None,
            errors: vec![],
        };
        assert!(result.valid);
    }

    /// Regression test: AssuranceLevel serialization must match the schema-defined
    /// kebab-case enum values in attestation.schema.json exactly.
    #[test]
    fn assurance_level_matches_schema_enum() {
        // Schema defines: ["self-asserted", "verified", "independently-attested"]
        assert_eq!(
            serde_json::to_string(&AssuranceLevel::SelfAsserted).unwrap(),
            "\"self-asserted\""
        );
        assert_eq!(
            serde_json::to_string(&AssuranceLevel::Verified).unwrap(),
            "\"verified\""
        );
        assert_eq!(
            serde_json::to_string(&AssuranceLevel::IndependentlyAttested).unwrap(),
            "\"independently-attested\""
        );

        // Round-trip: schema string -> Rust enum -> schema string
        let self_asserted: AssuranceLevel = serde_json::from_str("\"self-asserted\"").unwrap();
        assert_eq!(self_asserted, AssuranceLevel::SelfAsserted);

        let verified: AssuranceLevel = serde_json::from_str("\"verified\"").unwrap();
        assert_eq!(verified, AssuranceLevel::Verified);

        let independently: AssuranceLevel =
            serde_json::from_str("\"independently-attested\"").unwrap();
        assert_eq!(independently, AssuranceLevel::IndependentlyAttested);
    }

    #[test]
    fn verification_result_invalid_on_any_failure() {
        let result = AttestationVerificationResult {
            valid: false,
            crypto: CryptoVerificationResult {
                signature_valid: true,
                hash_valid: true,
                signer_id: "agent-1".into(),
                algorithm: "ed25519".into(),
            },
            evidence: vec![EvidenceVerificationResult {
                kind: "a2a".into(),
                digest_valid: false,
                freshness_valid: true,
                detail: "digest mismatch".into(),
            }],
            chain: None,
            errors: vec!["evidence digest verification failed".into()],
        };
        assert!(!result.valid);
    }

    #[test]
    fn test_crypto_verification_result_uses_camel_case_signer_id() {
        let result = CryptoVerificationResult {
            signature_valid: true,
            hash_valid: true,
            signer_id: "agent-test-001".into(),
            algorithm: "ed25519".into(),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(
            json.get("signerId").is_some(),
            "Expected camelCase 'signerId'"
        );
        assert!(
            json.get("signer_id").is_none(),
            "Should not have snake_case 'signer_id'"
        );
    }

    #[test]
    fn test_crypto_verification_result_uses_camel_case_signature_valid() {
        let result = CryptoVerificationResult {
            signature_valid: true,
            hash_valid: false,
            signer_id: "agent-1".into(),
            algorithm: "ed25519".into(),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(
            json.get("signatureValid").is_some(),
            "Expected camelCase 'signatureValid'"
        );
        assert!(
            json.get("hashValid").is_some(),
            "Expected camelCase 'hashValid'"
        );
        assert!(json.get("signature_valid").is_none());
        assert!(json.get("hash_valid").is_none());
    }

    #[test]
    fn test_attestation_verification_result_uses_camel_case() {
        let result = AttestationVerificationResult {
            valid: true,
            crypto: CryptoVerificationResult {
                signature_valid: true,
                hash_valid: true,
                signer_id: "agent-1".into(),
                algorithm: "ed25519".into(),
            },
            evidence: vec![EvidenceVerificationResult {
                kind: "a2a".into(),
                digest_valid: true,
                freshness_valid: true,
                detail: "ok".into(),
            }],
            chain: Some(ChainVerificationResult {
                valid: true,
                depth: 1,
                max_depth: 5,
                links: vec![ChainLink {
                    document_id: "doc-1".into(),
                    valid: true,
                    detail: "ok".into(),
                }],
            }),
            errors: vec![],
        };
        let json = serde_json::to_value(&result).unwrap();
        // Top-level camelCase
        let crypto = json.get("crypto").unwrap();
        assert!(crypto.get("signerId").is_some());
        assert!(crypto.get("signatureValid").is_some());
        assert!(crypto.get("hashValid").is_some());
        // Evidence camelCase
        let ev = &json.get("evidence").unwrap()[0];
        assert!(ev.get("digestValid").is_some());
        assert!(ev.get("freshnessValid").is_some());
        // Chain camelCase
        let chain = json.get("chain").unwrap();
        assert!(chain.get("maxDepth").is_some());
        let link = &chain.get("links").unwrap()[0];
        assert!(link.get("documentId").is_some());
    }
}
