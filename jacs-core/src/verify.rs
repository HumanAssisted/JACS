//! `VerificationOutcome` + the canonical signature payload helpers used by
//! both `CoreAgent::sign_message` and `CoreAgent::verify`.
//!
//! The signature payload layout matches `jacs::agent::build_signature_content_v2`
//! exactly (PRD §4.4 / §4.5) so canonical bytes are identical across native
//! `jacs` and `jacs-core`. The fields written into / read out of the
//! `jacsSignature` object match `jacs::agent::signing_procedure` so the wire
//! shape is interchangeable.
//!
//! See PRD §4.2.

use crate::CoreError;
use crate::canonical::canonicalize_json_try;
use crate::sign::{Ed25519DalekSigner, Pq2025Signer, SigningAlgorithm};
use serde_json::{Map, Value, json};

// =========================================================================
// Wire constants — identical to native `jacs::agent` so the canonical
// bytes round-trip across the protocol boundary.
// =========================================================================

/// Field name carrying the signed payload metadata version. Matches
/// `jacs::agent::SIGNATURE_CONTENT_VERSION_FIELDNAME`.
pub const SIGNATURE_CONTENT_VERSION_FIELDNAME: &str = "signatureContentVersion";
/// Wire value for v2 signature payloads. Matches
/// `jacs::agent::SIGNATURE_CONTENT_VERSION_V2`.
pub const SIGNATURE_CONTENT_VERSION_V2: &str = "jacs-signature-v2";
/// Domain separator embedded in the canonical signature payload. Matches
/// `jacs::agent::SIGNATURE_CONTENT_DOMAIN_V2`.
pub const SIGNATURE_CONTENT_DOMAIN_V2: &str = "jacs.signature.v2";

/// Fields excluded from signed-field selection. Mirrors
/// `jacs::agent::JACS_IGNORE_FIELDS` for the subset jacs-core needs (it does
/// not need agreement / agent-registration / task-agreement fields because
/// those live in higher-layer schemas — `jacs-core::agreements` will add
/// its own equivalents in Task 014).
pub const JACS_IGNORE_FIELDS: &[&str] = &[
    "jacsSha256",
    "jacsSignature",
    "jacsAgentSignature",
    "jacsAgreement",
    "jacsRegistration",
    "jacsTaskStartAgreement",
    "jacsTaskEndAgreement",
];

// =========================================================================
// VerificationOutcome
// =========================================================================

/// Structured verification result returned by `CoreAgent::verify` and
/// `CoreAgent::verify_with_key`.
///
/// `valid` is `true` iff the cryptographic signature reconstructs and the
/// algorithm matches the expected algorithm. The other fields are
/// extracted from the signed document so callers do not have to re-parse
/// the JSON to find them.
///
/// `errors` is a list of human-readable error strings when `valid` is
/// `false`. It is always empty when `valid` is `true`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerificationOutcome {
    /// Whether the cryptographic signature verified.
    pub valid: bool,
    /// `jacsSignature.agentID`, empty if the field is absent.
    pub signer_id: String,
    /// `jacsSignature.date`, empty if the field is absent.
    pub timestamp: String,
    /// The full signed document, returned as-is so callers do not have to
    /// re-parse the JSON.
    pub data: Value,
    /// Human-readable error descriptions when `valid` is `false`.
    pub errors: Vec<String>,
}

// =========================================================================
// Canonical signature payload builder (v2)
// =========================================================================

/// Build the canonical bytes that the signer signs over (and the verifier
/// reconstructs).
///
/// The shape is JSON-canonicalized via `serde_json_canonicalizer` — same
/// canonicalizer used by native `jacs`. The four required keys are
/// `domain`, `placementKey`, `fields`, and `signatureMetadata`.
///
/// `signature_metadata` carries everything that ends up under
/// `jacsSignature` *except* the `signature` field itself (which is
/// stripped here because it is undefined at sign time).
pub fn build_signature_content_v2(
    document: &Value,
    fields: &[String],
    placement_key: &str,
    signature_metadata: &Value,
) -> Result<String, CoreError> {
    let mut metadata = signature_metadata.clone();
    let metadata_obj = metadata.as_object_mut().ok_or_else(|| {
        CoreError::MalformedDocument(format!(
            "signature metadata at '{}' must be a JSON object",
            placement_key
        ))
    })?;
    metadata_obj.remove("signature");

    let mut field_entries = Vec::with_capacity(fields.len());
    for key in fields {
        if key == placement_key || JACS_IGNORE_FIELDS.contains(&key.as_str()) {
            return Err(CoreError::MalformedDocument(format!(
                "signed field '{}' is reserved",
                key
            )));
        }
        let value = document.get(key).ok_or_else(|| {
            CoreError::MalformedDocument(format!("signed field '{}' missing from document", key))
        })?;
        field_entries.push(json!({ "name": key, "value": value }));
    }

    let payload = json!({
        "domain": SIGNATURE_CONTENT_DOMAIN_V2,
        "placementKey": placement_key,
        "fields": field_entries,
        "signatureMetadata": metadata,
    });

    canonicalize_json_try(&payload)
}

/// Build the list of fields to sign. With `None` we take every top-level
/// object key of `document` minus the placement key + the reserved
/// `JACS_IGNORE_FIELDS`, sorted lexicographically (matches native default
/// behavior in `jacs::agent::build_signature_content`).
pub fn default_signed_fields(document: &Value, placement_key: &str) -> Vec<String> {
    let Some(obj) = document.as_object() else {
        return Vec::new();
    };
    let mut fields: Vec<String> = obj
        .keys()
        .filter(|k| k.as_str() != placement_key && !JACS_IGNORE_FIELDS.contains(&k.as_str()))
        .cloned()
        .collect();
    fields.sort();
    fields.dedup();
    fields
}

// =========================================================================
// Verifier dispatch
// =========================================================================

/// Verify a raw signature for `message` using `public_key` under
/// `algorithm`. Dispatches to the right `DetachedSigner` impl.
pub fn verify_detached(
    algorithm: SigningAlgorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CoreError> {
    match algorithm {
        SigningAlgorithm::Ed25519 => Ed25519DalekSigner::verify(public_key, message, signature),
        SigningAlgorithm::Pq2025 => Pq2025Signer::verify(public_key, message, signature),
    }
}

// =========================================================================
// Static verify_with_key — used by both `CoreAgent::verify_with_key` and
// internally by `CoreAgent::verify` after the algorithm match check.
// =========================================================================

/// Verify a signed JACS document against an explicit public key + algorithm.
///
/// Extracts `jacsSignature.signature` (base64) + the signed-fields list +
/// the metadata, reconstructs the canonical payload bytes, and runs
/// cryptographic verification. The publicKeyHash baked into the
/// metadata is **not** checked against `public_key` here — that is an
/// identity check that lives one layer up (the caller is asserting the
/// key they pass is the right one for this document).
pub fn verify_document(
    signed: &Value,
    public_key: &[u8],
    algorithm: SigningAlgorithm,
    placement_key: &str,
) -> Result<VerificationOutcome, CoreError> {
    let sig_obj = signed.get(placement_key).ok_or_else(|| {
        CoreError::MalformedDocument(format!(
            "signed document missing '{}' object",
            placement_key
        ))
    })?;

    // signing algorithm check — extracted from the document, must match
    // the caller's expectation. This is the strong-typing guard against
    // verifying a pq2025 doc with an Ed25519 key. The doc may carry the
    // native-side wire form (`"ring-Ed25519"`) instead of jacs-core's
    // (`"ed25519"`); both resolve to the same algorithm via
    // `SigningAlgorithm::from_wire_str` for cross-compat (PRD §4.5).
    let doc_algorithm_str = sig_obj
        .get("signingAlgorithm")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CoreError::MalformedDocument(format!(
                "'{}.signingAlgorithm' missing or not a string",
                placement_key
            ))
        })?;
    let doc_algorithm = SigningAlgorithm::from_wire_str(doc_algorithm_str).ok_or_else(|| {
        CoreError::UnsupportedAlgorithm(format!(
            "signed document algorithm '{}' is not recognized",
            doc_algorithm_str
        ))
    })?;
    if doc_algorithm != algorithm {
        return Err(CoreError::AlgorithmMismatch {
            expected: algorithm.to_string(),
            actual: doc_algorithm_str.to_string(),
        });
    }

    let signature_b64 = sig_obj
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CoreError::MalformedDocument(format!(
                "'{}.signature' missing or not a string",
                placement_key
            ))
        })?;
    let signature_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, signature_b64).map_err(
            |e| CoreError::MalformedDocument(format!("invalid base64 signature: {}", e)),
        )?;

    let fields = sig_obj
        .get("fields")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            CoreError::MalformedDocument(format!(
                "'{}.fields' missing or not an array",
                placement_key
            ))
        })?
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect::<Vec<_>>();

    // SECURITY (SV-5): a v2 signature authenticates only the fields named in
    // `<placement>.fields`. `jacsSha256` is not itself signed, so an attacker can
    // append an unsigned top-level field, recompute the hash, and slip
    // unauthenticated data past both the signature and hash checks. The document
    // signature (`jacsSignature`) must attest the *whole* document, so reject any
    // top-level key under a document signature that is not a signed field, a
    // reserved JACS field, or the placement itself. Agreement placements sign a
    // trimmed subset and are exempt (this guard only fires for "jacsSignature").
    if placement_key == "jacsSignature"
        && let Some(obj) = signed.as_object()
    {
        for key in obj.keys() {
            if key == placement_key
                || JACS_IGNORE_FIELDS.contains(&key.as_str())
                || fields.iter().any(|f| f == key)
            {
                continue;
            }
            return Err(CoreError::MalformedDocument(format!(
                "Unsigned top-level field '{}' is present but not covered by '{}.fields'; the v2 signature does not authenticate it.",
                key, placement_key
            )));
        }
    }

    // Reconstruct canonical bytes using the embedded metadata as-is so the
    // bytes are identical to what the signer produced (PRD §4.5).
    let canonical = build_signature_content_v2(signed, &fields, placement_key, sig_obj)?;

    let mut outcome = VerificationOutcome {
        valid: false,
        signer_id: sig_obj
            .get("agentID")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        timestamp: sig_obj
            .get("date")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        data: signed.clone(),
        errors: Vec::new(),
    };

    match verify_detached(
        algorithm,
        public_key,
        canonical.as_bytes(),
        &signature_bytes,
    ) {
        Ok(()) => {
            outcome.valid = true;
        }
        Err(e) => {
            outcome.errors.push(format!("{}", e));
        }
    }
    Ok(outcome)
}

// =========================================================================
// Helpers shared with the agreements module (Task 014)
// =========================================================================

/// Stable SHA-256 hex digest of raw bytes. Mirrors
/// `jacs::crypt::hash::hash_bytes` and is the function jacs-core uses for
/// `publicKeyHash` (sha256 of the raw public-key bytes — no PEM-aware
/// trimming, no UTF-8 lossy decode). Native callers that need to match
/// jacs-core's hash convention can compute the same value through
/// `sha2::Sha256` over the raw bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Build the `signatureMetadata` object embedded in a `jacsSignature`. The
/// shape exactly mirrors what `jacs::agent::signing_procedure` produces
/// so verifiers using `build_signature_content_v2` reconstruct the same
/// canonical bytes from either side.
///
/// This helper does not include the `signature` field — `build_signature_content_v2`
/// strips it anyway, and `CoreAgent::sign_message` fills it in after
/// running the signer.
#[allow(clippy::too_many_arguments)]
pub fn build_signature_metadata(
    agent_id: &str,
    agent_version: &str,
    date: &str,
    iat: i64,
    jti: &str,
    algorithm: SigningAlgorithm,
    public_key_hash: &str,
    fields: &[String],
) -> Value {
    let mut obj = Map::new();
    obj.insert("agentID".into(), json!(agent_id));
    obj.insert("agentVersion".into(), json!(agent_version));
    obj.insert("date".into(), json!(date));
    obj.insert("iat".into(), json!(iat));
    obj.insert("jti".into(), json!(jti));
    obj.insert("signature".into(), json!(""));
    obj.insert("signingAlgorithm".into(), json!(algorithm.as_str()));
    obj.insert("publicKeyHash".into(), json!(public_key_hash));
    obj.insert("fields".into(), json!(fields));
    obj.insert(
        SIGNATURE_CONTENT_VERSION_FIELDNAME.into(),
        json!(SIGNATURE_CONTENT_VERSION_V2),
    );
    Value::Object(obj)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::CoreAgent;
    use serde_json::json;

    #[test]
    fn verify_document_rejects_unsigned_top_level_field_under_document_signature() {
        let mut agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).expect("ephemeral");
        let public_key = agent.public_key().to_vec();
        let mut signed = agent
            .sign_message(&json!({ "safe": "x" }))
            .expect("sign message");

        signed["evil"] = json!("x");

        let err = verify_document(
            &signed,
            &public_key,
            SigningAlgorithm::Ed25519,
            "jacsSignature",
        )
        .expect_err("unsigned top-level field must be rejected");
        match err {
            CoreError::MalformedDocument(message) => {
                assert!(message.contains("Unsigned top-level field 'evil'"));
            }
            other => panic!("expected MalformedDocument, got {:?}", other),
        }
    }
}
