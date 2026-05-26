//! Multi-party agreement payload manipulation: create, sign, verify.
//!
//! The browser side (`jacs-wasm`) needs to manipulate JACS agreement
//! documents without touching native I/O. This module mirrors the
//! **payload shape** that native `jacs::agent::agreement::Agreement`
//! produces (`jacsAgreement = { signatures: [], agentIDs: [...],
//! question, context }`) so a signature appended in the browser is
//! byte-for-byte compatible with one appended by the CLI.
//!
//! V1 deliberately omits the optional timeout / quorum / required-
//! algorithms / minimum-strength fields native carries. Browser callers
//! that need them can attach them to the `jacsAgreement` object
//! themselves before / after `sign`; jacs-core does not enforce them in
//! this module (PRD §4.2: "no I/O, no policy").
//!
//! ## Verification model
//!
//! `verify(doc, signers)` returns a `QuorumOutcome` listing the
//! per-signer result for every entry in `jacsAgreement.signatures[]`. A
//! signature is `Valid` iff the cryptographic verification succeeds
//! using the matching `(agent_id, public_key, algorithm)` triple from
//! `signers`. `SignerKeyMissing` flags a signer whose entry the caller
//! did not provide a key for; the signature is not crypto-checked.
//!
//! See PRD §4.2, §4.4.

use crate::CoreError;
use crate::agent::CoreAgent;
use crate::sign::SigningAlgorithm;
use crate::verify::{build_signature_content_v2, verify_detached};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Wire field name for the agreement object. Mirrors
/// `jacs::agent::AGENT_AGREEMENT_FIELDNAME`.
pub const JACS_AGREEMENT_FIELDNAME: &str = "jacsAgreement";

// =========================================================================
// Outcome types
// =========================================================================

/// Outcome of a multi-party agreement verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumOutcome {
    /// `true` iff every entry in `per_signer` is `SignerStatus::Valid`. A
    /// missing key or tampered payload flips this to `false`.
    pub all_valid: bool,
    /// Number of `Valid` entries in `per_signer`.
    pub verified_signers: usize,
    /// Total number of signature entries actually present in the document.
    pub expected_signers: usize,
    /// Per-signer detail. Iteration order matches the order of
    /// `jacsAgreement.signatures[]`.
    pub per_signer: Vec<SignerResult>,
}

/// Result for one signer entry inside the agreement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerResult {
    /// The signer's agent ID, taken from `signatures[i].agentID`. Empty
    /// string if the field was missing.
    pub agent_id: String,
    /// What happened when this signer's signature was checked.
    pub status: SignerStatus,
}

/// Status of one signer's check.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "detail")]
pub enum SignerStatus {
    /// Cryptographic verification succeeded.
    Valid,
    /// Cryptographic verification failed. Carries a short reason.
    Invalid(String),
    /// The caller did not provide a key for this signer's `agentID`. The
    /// signature was not crypto-checked.
    SignerKeyMissing,
    /// The caller provided a key for this signer but with the wrong
    /// algorithm (e.g. Ed25519 key for a pq2025 signature).
    KeyAlgorithmMismatch,
}

// =========================================================================
// create / sign / verify
// =========================================================================

/// Create the initial `jacsAgreement` skeleton on a document.
///
/// Caller passes the document JSON + the list of agents required to sign +
/// optional question / context strings. The agreement object is inserted
/// (overwriting any existing one) at the canonical
/// `jacsAgreement` field; the rest of the document is left untouched.
///
/// V1 does not validate that the document is otherwise well-formed — that
/// is the caller's concern (a wasm consumer that bundles a schema check
/// can use `jacs_core::schema`).
pub fn create(
    document: &Value,
    agent_ids: &[String],
    question: Option<&str>,
    context: Option<&str>,
) -> Result<Value, CoreError> {
    let mut new_doc = document.clone();
    let agreement_obj = json!({
        "signatures": [],
        "agentIDs": agent_ids,
        "question": question.unwrap_or(""),
        "context": context.unwrap_or(""),
    });
    new_doc
        .as_object_mut()
        .ok_or_else(|| {
            CoreError::MalformedDocument("agreement target must be a JSON object".into())
        })?
        .insert(JACS_AGREEMENT_FIELDNAME.into(), agreement_obj);
    Ok(new_doc)
}

/// Append a signature from `agent` to the agreement on `document`.
///
/// The `role` string is recorded in the agent's signature object under a
/// `role` field — purely informational; verification does not enforce
/// role values. Tasks 016 and 018 surface this through the browser API.
///
/// Mutates the document in place. Requires that `jacsAgreement` already
/// exist (caller should invoke [`create`] first).
///
/// Returns `CoreError::Locked` if `agent` has been cleared.
pub fn sign(agent: &mut CoreAgent, document: &mut Value, role: &str) -> Result<(), CoreError> {
    // We want the signature to cover the agreement payload — the same
    // canonical bytes any other signer would produce — so we sign
    // through `sign_document_inplace` with the agreement placement key.
    // That helper builds the v2 canonical payload, attaches the
    // signature object, and returns the document with `jacsAgreement`
    // replaced by the signature.
    //
    // For multi-party we instead append to an existing
    // `jacsAgreement.signatures[]` array. The signature object we append
    // has the same shape as `jacsSignature` plus the optional `role`
    // field for traceability.

    // Ensure the agreement object exists.
    if document.get(JACS_AGREEMENT_FIELDNAME).is_none() {
        return Err(CoreError::AgreementFailed(
            "missing jacsAgreement; call create() first".into(),
        ));
    }

    // Build the per-signer signature using a scratch document whose
    // placement key is unique so we don't disturb the existing agreement
    // structure. We then move the produced signature object into the
    // `signatures[]` array.
    let mut scratch = document.clone();
    agent.sign_document_inplace(&mut scratch, JACS_AGREEMENT_FIELDNAME)?;
    // After `sign_document_inplace`, `scratch[JACS_AGREEMENT_FIELDNAME]`
    // is the new signature object (overwrites the prior agreement). We
    // copy it out, then push into the real document's signatures array.
    let signature_object = scratch
        .get(JACS_AGREEMENT_FIELDNAME)
        .cloned()
        .ok_or_else(|| {
            CoreError::AgreementFailed(
                "internal: scratch signing dropped jacsAgreement field".into(),
            )
        })?;

    // The `role` is a sibling field on the signature entry — it is *not*
    // part of the canonical bytes (so adding it doesn't invalidate the
    // signature). The verifier in [`verify`] ignores it.
    let mut signature_with_role = signature_object;
    if let Some(obj) = signature_with_role.as_object_mut() {
        obj.insert("role".to_string(), json!(role));
    }

    // Push into the existing agreement's `signatures[]`.
    let agreement_value = document
        .get_mut(JACS_AGREEMENT_FIELDNAME)
        .expect("checked above");
    let agreement_obj = agreement_value.as_object_mut().ok_or_else(|| {
        CoreError::MalformedDocument(format!(
            "'{}' must be a JSON object",
            JACS_AGREEMENT_FIELDNAME
        ))
    })?;
    let signatures_entry = agreement_obj
        .entry("signatures".to_string())
        .or_insert_with(|| json!([]));
    let signatures_arr = signatures_entry.as_array_mut().ok_or_else(|| {
        CoreError::MalformedDocument("'jacsAgreement.signatures' must be an array".into())
    })?;
    signatures_arr.push(signature_with_role);

    Ok(())
}

/// Strip non-canonical fields from a signature object before passing it as
/// `signatureMetadata`. The signer's role (`role`) is stored alongside the
/// signature for traceability but is **not** part of the canonical bytes
/// (so it can be edited after signing without invalidating the signature).
/// Mirrors the way native `jacs` does not embed per-signer role data in
/// the v2 canonical payload.
fn canonical_signature_metadata(sig_obj: &Value) -> Value {
    let mut cleaned = sig_obj.clone();
    if let Some(obj) = cleaned.as_object_mut() {
        obj.remove("role");
    }
    cleaned
}

/// Verify every signature in `document.jacsAgreement.signatures[]` against
/// the supplied `(agent_id, public_key, algorithm)` triples.
///
/// `signers` must include an entry for every signer whose signature is
/// to be checked. Missing entries surface as `SignerKeyMissing` (not a
/// hard error — the caller can decide how to react).
pub fn verify(
    document: &Value,
    signers: &[(&str, &[u8], SigningAlgorithm)],
) -> Result<QuorumOutcome, CoreError> {
    let agreement = document.get(JACS_AGREEMENT_FIELDNAME).ok_or_else(|| {
        CoreError::AgreementFailed(format!("missing '{}' object", JACS_AGREEMENT_FIELDNAME))
    })?;
    let signatures = agreement
        .get("signatures")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            CoreError::AgreementFailed("missing 'jacsAgreement.signatures' array".into())
        })?;

    let mut per_signer = Vec::with_capacity(signatures.len());
    let mut verified = 0usize;

    for sig_obj in signatures {
        let agent_id = sig_obj
            .get("agentID")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Find the matching key in `signers`.
        let lookup = signers.iter().find(|(id, _, _)| *id == agent_id.as_str());
        let Some(&(_, pk, expected_algo)) = lookup else {
            per_signer.push(SignerResult {
                agent_id,
                status: SignerStatus::SignerKeyMissing,
            });
            continue;
        };

        // The signature object stores its own algorithm tag. Compare to
        // the caller's expectation.
        let doc_algo_str = sig_obj
            .get("signingAlgorithm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let doc_algo = SigningAlgorithm::from_wire_str(doc_algo_str);
        if doc_algo != Some(expected_algo) {
            per_signer.push(SignerResult {
                agent_id,
                status: SignerStatus::KeyAlgorithmMismatch,
            });
            continue;
        }

        // Extract signature bytes + signed-fields list.
        let signature_b64 = match sig_obj.get("signature").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                per_signer.push(SignerResult {
                    agent_id,
                    status: SignerStatus::Invalid("'signature' missing on signer entry".into()),
                });
                continue;
            }
        };
        let signature_bytes =
            match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, signature_b64)
            {
                Ok(b) => b,
                Err(e) => {
                    per_signer.push(SignerResult {
                        agent_id,
                        status: SignerStatus::Invalid(format!("base64 signature decode: {e}")),
                    });
                    continue;
                }
            };
        let fields: Vec<String> = sig_obj
            .get("fields")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        // Reconstruct canonical bytes using the per-signer metadata. The
        // signature object IS the metadata (sans `signature` field, which
        // `build_signature_content_v2` strips on its own; we strip
        // `role` here because it is a sibling traceability field, not
        // part of the canonical payload).
        let metadata_for_canonical = canonical_signature_metadata(sig_obj);
        let canonical = match build_signature_content_v2(
            document,
            &fields,
            JACS_AGREEMENT_FIELDNAME,
            &metadata_for_canonical,
        ) {
            Ok(s) => s,
            Err(e) => {
                per_signer.push(SignerResult {
                    agent_id,
                    status: SignerStatus::Invalid(format!("canonical reconstruction: {e}")),
                });
                continue;
            }
        };

        match verify_detached(expected_algo, pk, canonical.as_bytes(), &signature_bytes) {
            Ok(()) => {
                per_signer.push(SignerResult {
                    agent_id,
                    status: SignerStatus::Valid,
                });
                verified += 1;
            }
            Err(e) => {
                per_signer.push(SignerResult {
                    agent_id,
                    status: SignerStatus::Invalid(format!("{e}")),
                });
            }
        }
    }

    Ok(QuorumOutcome {
        all_valid: per_signer
            .iter()
            .all(|s| matches!(s.status, SignerStatus::Valid)),
        verified_signers: verified,
        expected_signers: per_signer.len(),
        per_signer,
    })
}
