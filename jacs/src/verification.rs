//! Explicit-public-key document integrity verification without a signing identity.
//!
//! This deliberately reduced API supports document signature v2, built-in header
//! validation, and embedded attachments. It does not load configuration, resolve
//! keys, access document storage, or establish identity authorization, freshness,
//! revocation, application-schema validity, or agreement completion.

use crate::agent::document::document_hash;
use crate::crypt::hash::{hash_bytes, hash_public_key};
use crate::error::JacsError;
use crate::schema::Schema;
use jacs_core::sign::SigningAlgorithm;
use serde::Serialize;
use serde_json::Value;

pub use jacs_core::verification::{
    ContextExpectation, DocumentIntegrityChecks, EvaluationTimeSource, ExactExpectation,
    FieldResult, FieldStatus, ReasonCode, ReportField, SchemaExpectation, TemporalExpectation,
    VerificationIntent, VerificationPolicy, VerificationReport, VersionExpectation,
};

fn algorithm_from_alias(value: &str) -> Option<SigningAlgorithm> {
    match value {
        "Ed25519" => Some(SigningAlgorithm::Ed25519),
        "ML-DSA-87" => Some(SigningAlgorithm::Pq2025),
        other => SigningAlgorithm::from_wire_str(other),
    }
}

/// Compare the signed algorithm with caller/resolver metadata before dispatch.
/// The returned spelling is the native dispatch token; signed bytes are untouched.
pub(crate) fn matching_algorithm(
    claimed: Option<&str>,
    expected: Option<&str>,
) -> Result<Option<String>, JacsError> {
    let parse = |value: &str| {
        algorithm_from_alias(value).ok_or_else(|| JacsError::SignatureVerificationFailed {
            reason: format!("Unsupported signing algorithm '{value}'"),
        })
    };
    let claimed = claimed.map(parse).transpose()?;
    let expected = expected.map(parse).transpose()?;
    if let (Some(claimed), Some(expected)) = (claimed, expected)
        && claimed != expected
    {
        tracing::warn!(
            event = "signature_algorithm_mismatch",
            "Signed and resolved algorithms differ"
        );
        return Err(JacsError::SignatureVerificationFailed {
            reason: "Signed algorithm does not match the supplied public key algorithm".to_string(),
        });
    }
    Ok(expected.or(claimed).map(|algorithm| match algorithm {
        SigningAlgorithm::Ed25519 => "ring-Ed25519".to_string(),
        SigningAlgorithm::Pq2025 => "pq2025".to_string(),
    }))
}

/// Optional expected signed claims. Matching them is not an authenticated key
/// binding; the application still supplies identity and authorization evidence.
#[derive(Debug, Clone, Copy)]
pub struct ExpectedSigner<'a> {
    pub agent_id: &'a str,
    pub agent_version: &'a str,
}

/// A document-integrity report, intentionally distinct from a trust-policy report.
#[derive(Debug, Clone, Serialize)]
pub struct IntegrityVerificationReport {
    pub profile: &'static str,
    pub integrity_valid: bool,
    pub header_valid: bool,
    pub document_hash_valid: bool,
    pub public_key_hash_valid: bool,
    pub attachments_valid: bool,
    pub signature_valid: bool,
    pub signature_profile_matches: bool,
    pub algorithm_matches: bool,
    pub signer_claims_match: Option<bool>,
    /// Always false: a supplied key and matching claims are not an identity anchor.
    pub identity_bound: bool,
    /// Canonical ID of the exact raw public key supplied by the caller.
    pub canonical_key_id: String,
    pub verified_algorithm: Option<String>,
    /// Exact submitted bytes' digest, including on parse failure.
    pub input_sha256: String,
    /// Only the top-level fields covered by the signature, present after all
    /// integrity checks pass. Unsigned reserved extensions are never released.
    pub verified_fields: Option<Value>,
    pub errors: Vec<String>,
}

/// A verifier holding only built-in public schemas, with no signing-key state.
pub struct NonSigningVerifier {
    schema: Schema,
}

impl NonSigningVerifier {
    pub fn new() -> Result<Self, JacsError> {
        Ok(Self {
            schema: Schema::new("v1", "v1", "v1")?,
        })
    }

    /// Verify document-v2 or contextual response-v2 bytes with a complete intent and
    /// policy. This public-key-only context has no authenticated lifecycle/time
    /// snapshot, so its report cannot authorize an identity under a trust policy.
    /// Use `policy_accepted()` when evaluating an authorization result.
    #[must_use = "verification reports must be evaluated before application use"]
    pub fn verify_for(
        &self,
        signed_document: &str,
        public_key: &[u8],
        algorithm: &str,
        intent: &VerificationIntent,
        policy: &VerificationPolicy,
    ) -> Result<VerificationReport, JacsError> {
        policy.validate_intent(intent)?;
        if matches!(
            intent.operation,
            jacs_core::signing::SigningOperation::SignBoundResponse
                | jacs_core::signing::SigningOperation::SignAsyncEvent
        ) {
            let parsed = jacs_core::strict_json::parse_strict_json(signed_document).ok();
            let header_valid = parsed.as_ref().is_some_and(|value| {
                value.get("version").and_then(Value::as_str)
                    == Some(crate::protocol::RESPONSE_ENVELOPE_VERSION)
                    && value.get("document_type").and_then(Value::as_str) == Some("job_response")
                    && value
                        .pointer("/jacsSignature/signatureContentVersion")
                        .and_then(Value::as_str)
                        == Some(crate::protocol::RESPONSE_SIGNATURE_CONTENT_VERSION)
                    && value
                        .pointer("/metadata/issuer")
                        .and_then(Value::as_str)
                        .is_some()
                    && value.pointer("/metadata/issuer") == value.pointer("/jacsSignature/agentID")
                    && value.pointer("/metadata/created_at") == value.pointer("/jacsSignature/date")
                    && value
                        .pointer("/jacsSignature/date")
                        .and_then(Value::as_str)
                        .is_some_and(|time| {
                            crate::time_utils::validate_signature_timestamp(time).is_ok()
                        })
                    && value
                        .pointer("/metadata/document_id")
                        .and_then(Value::as_str)
                        .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
            });
            let content_hash_valid = parsed.as_ref().is_some_and(|value| {
                value
                    .get("data")
                    .and_then(|data| jacs_core::canonical::canonicalize_json_try(data).ok())
                    .is_some_and(|canonical| {
                        value.pointer("/metadata/hash").and_then(Value::as_str)
                            == Some(hash_bytes(canonical.as_bytes()).as_str())
                    })
            });
            let public_key_hash_valid = parsed.as_ref().is_some_and(|value| {
                value
                    .pointer("/jacsSignature/publicKeyHash")
                    .and_then(Value::as_str)
                    == Some(hash_public_key(public_key).as_str())
            });
            return jacs_core::verification::document_integrity_report(
                signed_document,
                public_key,
                algorithm,
                intent,
                policy,
                DocumentIntegrityChecks {
                    header_valid,
                    content_hash_valid,
                    public_key_hash_valid,
                    referenced_content_valid: None,
                },
            )
            .map_err(Into::into);
        }
        let integrity = self.verify_with_key(signed_document, public_key, algorithm, None)?;
        let has_references = jacs_core::strict_json::parse_strict_json(signed_document)
            .ok()
            .is_some_and(|value| value.get("jacsFiles").is_some());
        jacs_core::verification::document_integrity_report(
            signed_document,
            public_key,
            algorithm,
            intent,
            policy,
            DocumentIntegrityChecks {
                header_valid: integrity.header_valid,
                content_hash_valid: integrity.document_hash_valid,
                public_key_hash_valid: integrity.public_key_hash_valid,
                referenced_content_valid: has_references.then_some(integrity.attachments_valid),
            },
        )
        .map_err(Into::into)
    }

    /// Verify exactly these JSON bytes against a caller-selected raw Ed25519 or
    /// ML-DSA-87 public key. Import PEM/SPKI separately before calling this API.
    /// Nonembedded files fail closed because no attachment source was supplied.
    #[must_use = "inspect integrity_valid before using verified_fields"]
    pub fn verify_with_key(
        &self,
        signed_document: &str,
        public_key: &[u8],
        algorithm: &str,
        expected_signer: Option<ExpectedSigner<'_>>,
    ) -> Result<IntegrityVerificationReport, JacsError> {
        let algorithm = algorithm_from_alias(algorithm).ok_or_else(|| {
            JacsError::CryptoError("Explicit verifier requires ed25519 or pq2025".to_string())
        })?;
        let expected_length = match algorithm {
            SigningAlgorithm::Ed25519 => jacs_core::sign::ED25519_PUBLIC_KEY_SIZE,
            SigningAlgorithm::Pq2025 => jacs_core::sign::ML_DSA_87_PUBLIC_KEY_SIZE,
        };
        if public_key.len() != expected_length {
            return Err(JacsError::CryptoError(
                "Public key must use the exact raw algorithm encoding".to_string(),
            ));
        }
        let mut report = IntegrityVerificationReport {
            profile: "jacs-document-integrity-v1",
            integrity_valid: false,
            header_valid: false,
            document_hash_valid: false,
            public_key_hash_valid: false,
            attachments_valid: false,
            signature_valid: false,
            signature_profile_matches: false,
            algorithm_matches: false,
            signer_claims_match: expected_signer.map(|_| false),
            identity_bound: false,
            canonical_key_id: jacs_core::identity::canonical_key_id(
                algorithm.as_str(),
                public_key,
            )?,
            verified_algorithm: None,
            input_sha256: format!("sha256:{}", hash_bytes(signed_document.as_bytes())),
            verified_fields: None,
            errors: Vec::new(),
        };
        let value = match self.schema.validate_header(signed_document) {
            Ok(value) => {
                report.header_valid = true;
                value
            }
            Err(error) => {
                report.errors.push(error.to_string());
                tracing::warn!(
                    event = "document_integrity_failed",
                    "Document header validation failed"
                );
                return Ok(report);
            }
        };
        report.document_hash_valid = value.get("jacsSha256").and_then(Value::as_str)
            == Some(document_hash(&value)?.as_str());
        let signed_public_key_hash = value
            .pointer("/jacsSignature/publicKeyHash")
            .and_then(Value::as_str);
        // Native v2 documents use the frozen normalized alias; portable-core
        // v2 documents use the raw-byte hash. Both must be recomputed from the
        // exact supplied key, and neither establishes an identity binding.
        report.public_key_hash_valid = signed_public_key_hash
            == Some(hash_public_key(public_key).as_str())
            || signed_public_key_hash == Some(hash_bytes(public_key).as_str());
        report.algorithm_matches = value
            .pointer("/jacsSignature/signingAlgorithm")
            .and_then(Value::as_str)
            .and_then(algorithm_from_alias)
            == Some(algorithm);
        report.signature_profile_matches = value
            .pointer("/jacsSignature/signatureContentVersion")
            .and_then(Value::as_str)
            == Some(jacs_core::verify::SIGNATURE_CONTENT_VERSION_V2);
        report.signer_claims_match = expected_signer.map(|expected| {
            !expected.agent_id.is_empty()
                && !expected.agent_version.is_empty()
                && value
                    .pointer("/jacsSignature/agentID")
                    .and_then(Value::as_str)
                    == Some(expected.agent_id)
                && value
                    .pointer("/jacsSignature/agentVersion")
                    .and_then(Value::as_str)
                    == Some(expected.agent_version)
        });
        report.attachments_valid = embedded_attachments_valid(&value);
        match jacs_core::verify::verify_document(&value, public_key, algorithm, "jacsSignature") {
            Ok(outcome) => {
                report.signature_valid = outcome.valid;
                report.errors.extend(outcome.errors);
                if outcome.valid {
                    report.verified_algorithm = Some(algorithm.as_str().to_string());
                }
            }
            Err(error) => report.errors.push(error.to_string()),
        }
        for (valid, error) in [
            (report.document_hash_valid, "Document hash mismatch"),
            (
                report.public_key_hash_valid,
                "Supplied public key hash mismatch",
            ),
            (
                report.algorithm_matches,
                "Signed algorithm does not match the supplied algorithm",
            ),
            (
                report.signature_profile_matches,
                "Explicit verifier requires document signature v2",
            ),
            (
                report.attachments_valid,
                "Attachments require valid embedded contents",
            ),
            (
                report.signer_claims_match != Some(false),
                "Signed signer claims do not match caller expectations",
            ),
        ] {
            if !valid {
                report.errors.push(error.to_string());
            }
        }
        report.integrity_valid = report.signature_valid && report.errors.is_empty();
        if report.integrity_valid {
            let mut fields = serde_json::Map::new();
            if let Some(names) = value
                .pointer("/jacsSignature/fields")
                .and_then(Value::as_array)
            {
                for name in names.iter().filter_map(Value::as_str) {
                    if let Some(field) = value.get(name) {
                        fields.insert(name.to_string(), field.clone());
                    }
                }
            }
            report.verified_fields = Some(Value::Object(fields));
        } else {
            tracing::warn!(
                event = "document_integrity_failed",
                "Explicit-key document integrity verification failed"
            );
        }
        Ok(report)
    }
}

fn embedded_attachments_valid(document: &Value) -> bool {
    let Some(files) = document.get("jacsFiles") else {
        return true;
    };
    let Some(files) = files.as_array() else {
        return false;
    };
    files.iter().all(|file| {
        if file.get("embed").and_then(Value::as_bool) != Some(true) {
            return false;
        }
        match (
            file.get("contents").and_then(Value::as_str),
            file.get("sha256").and_then(Value::as_str),
        ) {
            (Some(contents), Some(expected)) => hash_bytes(contents.as_bytes()) == expected,
            _ => false,
        }
    })
}
