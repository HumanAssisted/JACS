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

// =========================================================================
// Agreement v2 — standalone consent artifacts
// =========================================================================

pub mod v2 {
    use crate::CoreError;
    use crate::agent::CoreAgent;
    use crate::canonical::canonicalize_json_try;
    use crate::sign::SigningAlgorithm;
    use crate::verify::{sha256_hex, verify_document};
    use serde_json::{Map, Value, json};
    use std::collections::HashSet;

    const CONSENT_HASH_FIELDS: &[&str] = &[
        "title",
        "description",
        "terms",
        "termsFormat",
        "effectiveFrom",
        "expiresAt",
        "parties",
        "signaturePolicy",
    ];
    const AUTO_MERGE_GUARD_FIELDS: &[&str] =
        &["status", "agreementSignatures", "links", "controllers"];

    pub fn create(agent: &mut CoreAgent, input: &Value) -> Result<Value, CoreError> {
        let agent_id = agent_id(agent);
        let version = uuid::Uuid::now_v7().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let controllers = input
            .get("controllers")
            .cloned()
            .filter(|v| v.as_array().is_some_and(|a| !a.is_empty()))
            .unwrap_or_else(|| json!([agent_id]));

        let mut doc = json!({
            "$schema": crate::schema::V2_SCHEMA_ID,
            "jacsId": uuid::Uuid::new_v4().to_string(),
            "jacsType": "agreement",
            "jacsVersion": version,
            "jacsVersionDate": now,
            "jacsOriginalVersion": version,
            "jacsOriginalDate": now,
            "jacsLevel": "artifact",
            "jacsVisibility": "private",
            "title": required_string(input, "title")?,
            "description": required_string(input, "description")?,
            "terms": required_string(input, "terms")?,
            "termsFormat": input.get("termsFormat").cloned().unwrap_or_else(|| json!("text/plain")),
            "status": input.get("status").cloned().unwrap_or_else(|| json!("draft")),
            "parties": required_array(input, "parties")?,
            "signaturePolicy": required_object(input, "signaturePolicy")?,
            "agreementSignatures": input.get("agreementSignatures").cloned().unwrap_or_else(|| json!([])),
            "transcript": input.get("transcript").cloned().unwrap_or_else(|| json!([])),
            "allPreviousVersions": input.get("allPreviousVersions").cloned().unwrap_or_else(|| json!([])),
            "links": input.get("links").cloned().unwrap_or_else(|| json!([])),
            "controllers": controllers,
            "owners": input.get("owners").cloned().unwrap_or_else(|| json!([])),
        });
        copy_optional(input, &mut doc, "effectiveFrom");
        copy_optional(input, &mut doc, "expiresAt");
        finalize_document(agent, &mut doc)?;
        Ok(doc)
    }

    pub fn apply(
        agent: &mut CoreAgent,
        document: &Value,
        mutation: &Value,
    ) -> Result<Value, CoreError> {
        assert_agreement(document)?;
        let mut next = document.clone();
        apply_mutation(&mut next, mutation)?;
        emit_successor(agent, document, next)
    }

    pub fn sign(agent: &mut CoreAgent, document: &Value, role: &str) -> Result<Value, CoreError> {
        assert_agreement(document)?;
        if !matches!(role, "signer" | "witness" | "notary") {
            return Err(CoreError::AgreementFailed(
                "role must be signer, witness, or notary".into(),
            ));
        }
        let stored_hash = required_string(document, "jacsAgreementHash")?;
        let recomputed_hash = compute_agreement_hash(document)?;
        if stored_hash != recomputed_hash {
            return Err(CoreError::AgreementFailed(format!(
                "jacsAgreementHash mismatch: stored {}, recomputed {}",
                stored_hash, recomputed_hash
            )));
        }

        let signer_id = agent_id(agent);
        assert_party_role(document, &signer_id, role)?;
        assert_not_already_signed(document, &signer_id, role)?;
        if let Some(effective_from) = document.get("effectiveFrom").and_then(Value::as_str)
            && let Some(effective_ts) = parse_rfc3339_timestamp(effective_from)
            && effective_ts > now_timestamp()
        {
            return Err(CoreError::AgreementFailed(format!(
                "agreement is not yet effective (effectiveFrom '{}'); signing is not permitted until then",
                effective_from
            )));
        }
        if agreement_expired(document) || timeout_expired(document) {
            return Err(CoreError::AgreementFailed(
                "agreement signing window has closed (past expiresAt/timeout); no new signatures are accepted"
                    .into(),
            ));
        }

        let transcript_hash = compute_transcript_hash(document)?;
        let transcript_non_empty = document
            .get("transcript")
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty());
        let agreement_jacs_id = required_string(document, "jacsId")?;
        let mut context = json!({
            "jacsId": agreement_jacs_id,
            "jacsAgreementHash": stored_hash,
            "agreementSignature": {}
        });
        if transcript_non_empty {
            context["signedTranscriptHash"] = json!(transcript_hash.clone());
        }
        agent.sign_document_inplace(&mut context, "agreementSignature")?;
        let signature = context
            .get("agreementSignature")
            .cloned()
            .ok_or_else(|| CoreError::AgreementFailed("agreement signature missing".into()))?;

        let mut entry = json!({
            "signature": signature,
            "role": role,
        });
        if transcript_non_empty {
            entry["signedTranscriptHash"] = json!(transcript_hash);
        }

        let mut next = document.clone();
        array_mut(&mut next, "agreementSignatures")?.push(entry);
        next["status"] = json!(recompute_status(&next));
        emit_successor(agent, document, next)
    }

    pub fn verify(
        document: &Value,
        signers: &[(&str, &[u8], SigningAlgorithm)],
    ) -> Result<Value, CoreError> {
        assert_agreement(document)?;
        let recomputed_agreement_hash = compute_agreement_hash(document)?;
        let recomputed_transcript_hash = compute_transcript_hash(document)?;
        let status = document
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let expected_status = recompute_status(document);
        let mut errors = Vec::new();
        if document.get("jacsAgreementHash").and_then(Value::as_str)
            != Some(recomputed_agreement_hash.as_str())
        {
            errors.push("jacsAgreementHash mismatch".to_string());
        }
        if status != expected_status {
            errors.push(format!(
                "status '{}' is inconsistent with signaturePolicy; expected '{}'",
                status, expected_status
            ));
        }

        let transcript_non_empty = document
            .get("transcript")
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty());
        let mut signer_agents = HashSet::new();
        let mut witness_agents = HashSet::new();
        let mut notary_agents = HashSet::new();
        let mut signature_results = Vec::new();
        for entry in signatures(document) {
            let role = entry.get("role").and_then(Value::as_str).unwrap_or("");
            let signature = entry.get("signature");
            let agent_id = signature
                .and_then(|s| s.get("agentID"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let mut entry_errors = Vec::new();

            if !matches!(role, "signer" | "witness" | "notary") {
                entry_errors.push(format!("invalid agreement signature role '{}'", role));
            }

            let Some(signature) = signature else {
                entry_errors.push("agreement signature object missing".to_string());
                let error = entry_errors.join("; ");
                errors.push(error.clone());
                signature_results.push(json!({
                    "agentID": agent_id,
                    "role": role,
                    "valid": false,
                    "error": error,
                }));
                continue;
            };

            if agent_id.is_empty() {
                entry_errors.push("agreement signature agentID missing".to_string());
            } else if !is_listed_party(document, &agent_id, role) {
                entry_errors.push(format!(
                    "agreement signature agentID '{}' is not a listed {} party",
                    agent_id, role
                ));
            }

            if transcript_non_empty
                && entry.get("signedTranscriptHash").and_then(Value::as_str)
                    != Some(recomputed_transcript_hash.as_str())
            {
                entry_errors.push("signedTranscriptHash mismatch".to_string());
            }

            let normalized_agent_id = normalize_agent_id(&agent_id);
            let signer = signers
                .iter()
                .find(|(id, _, _)| normalize_agent_id(id) == normalized_agent_id);
            let Some(&(_, public_key, algorithm)) = signer else {
                entry_errors.push(format!(
                    "no key supplied for agreement signer '{}'",
                    agent_id
                ));
                let error = entry_errors.join("; ");
                errors.push(error.clone());
                signature_results.push(json!({
                    "agentID": agent_id,
                    "role": role,
                    "valid": false,
                    "error": error,
                }));
                continue;
            };

            let mut context = json!({
                "jacsId": document
                    .get("jacsId")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                "jacsAgreementHash": document
                    .get("jacsAgreementHash")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                "agreementSignature": signature.clone(),
            });
            let mut required_fields = vec!["jacsId", "jacsAgreementHash"];
            if let Some(signed_transcript_hash) =
                entry.get("signedTranscriptHash").and_then(Value::as_str)
            {
                context["signedTranscriptHash"] = json!(signed_transcript_hash);
                required_fields.push("signedTranscriptHash");
            }
            let signed_fields: Vec<&str> = signature
                .get("fields")
                .and_then(Value::as_array)
                .map(|fields| fields.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            for required_field in required_fields {
                if !signed_fields.contains(&required_field) {
                    entry_errors.push(format!(
                        "agreement signature fields missing '{}'",
                        required_field
                    ));
                }
            }

            match verify_document(&context, public_key, algorithm, "agreementSignature") {
                Ok(outcome) if outcome.valid => {}
                Ok(outcome) => {
                    entry_errors.push(if outcome.errors.is_empty() {
                        "agreement signature verification failed".to_string()
                    } else {
                        outcome.errors.join("; ")
                    });
                }
                Err(err) => entry_errors.push(err.to_string()),
            }

            if entry_errors.is_empty() {
                match role {
                    "signer" => {
                        signer_agents.insert(normalized_agent_id.to_string());
                    }
                    "witness" => {
                        witness_agents.insert(normalized_agent_id.to_string());
                    }
                    "notary" => {
                        notary_agents.insert(normalized_agent_id.to_string());
                    }
                    _ => {}
                }
                signature_results.push(json!({
                    "agentID": agent_id,
                    "role": role,
                    "valid": true,
                }));
            } else {
                let error = entry_errors.join("; ");
                errors.push(error.clone());
                signature_results.push(json!({
                    "agentID": agent_id,
                    "role": role,
                    "valid": false,
                    "error": error,
                }));
            }
        }

        Ok(json!({
            "valid": errors.is_empty(),
            "status": status,
            "expectedStatus": expected_status,
            "recomputedAgreementHash": recomputed_agreement_hash,
            "recomputedTranscriptHash": recomputed_transcript_hash,
            "signerCount": signer_agents.len(),
            "witnessCount": witness_agents.len(),
            "notaryCount": notary_agents.len(),
            "verificationDepth": "cryptographic",
            "signatures": signature_results,
            "errors": errors,
        }))
    }

    pub fn detect_branch_conflict(
        base: &Value,
        left: &Value,
        right: &Value,
    ) -> Result<Value, CoreError> {
        assert_agreement(base)?;
        assert_agreement(left)?;
        assert_agreement(right)?;
        let same_document =
            base.get("jacsId") == left.get("jacsId") && base.get("jacsId") == right.get("jacsId");
        let base_version = base
            .get("jacsVersion")
            .and_then(Value::as_str)
            .unwrap_or("");
        let same_parent = left.get("jacsPreviousVersion").and_then(Value::as_str)
            == Some(base_version)
            && right.get("jacsPreviousVersion").and_then(Value::as_str) == Some(base_version);

        let mut left_changed = changed_fields(base, left);
        let mut right_changed = changed_fields(base, right);
        left_changed.sort();
        right_changed.sort();

        let left_transcript = transcript_append_additions(base, left)?;
        let right_transcript = transcript_append_additions(base, right)?;
        let transcript_only_left = left_changed.iter().all(|f| version_or_transcript_field(f))
            && left_transcript.is_some();
        let transcript_only_right = right_changed.iter().all(|f| version_or_transcript_field(f))
            && right_transcript.is_some();

        let left_set: HashSet<String> = left_changed.iter().cloned().collect();
        let right_set: HashSet<String> = right_changed.iter().cloned().collect();
        let mut conflicts = Vec::new();
        for field in left_set.intersection(&right_set) {
            if !version_or_transcript_field(field) && left.get(field) != right.get(field) {
                conflicts.push(field.clone());
            }
        }
        for guard in AUTO_MERGE_GUARD_FIELDS {
            if left_set.contains(*guard) || right_set.contains(*guard) {
                conflicts.push((*guard).to_string());
            }
        }
        conflicts.sort();
        conflicts.dedup();

        let auto_mergeable = same_document
            && same_parent
            && transcript_only_left
            && transcript_only_right
            && conflicts.is_empty();
        Ok(json!({
            "sameDocument": same_document,
            "sameParent": same_parent,
            "autoMergeable": auto_mergeable,
            "conflictFields": conflicts,
            "leftChangedFields": left_changed,
            "rightChangedFields": right_changed,
            "leftTranscriptAdditions": left_transcript.as_ref().map_or(0, Vec::len),
            "rightTranscriptAdditions": right_transcript.as_ref().map_or(0, Vec::len),
            "errors": Vec::<String>::new(),
        }))
    }

    pub fn merge_transcript_branches(
        agent: &mut CoreAgent,
        base: &Value,
        left: &Value,
        right: &Value,
    ) -> Result<Value, CoreError> {
        let analysis = detect_branch_conflict(base, left, right)?;
        if analysis.get("autoMergeable").and_then(Value::as_bool) != Some(true) {
            return Err(CoreError::AgreementFailed(
                "agreement branches are not transcript-only auto-mergeable".into(),
            ));
        }
        let left_additions = transcript_append_additions(base, left)?.unwrap_or_default();
        let right_additions = transcript_append_additions(base, right)?.unwrap_or_default();
        let mut merged = left.clone();
        let mut transcript = transcript_values(base);
        for entry in left_additions.iter().chain(right_additions.iter()) {
            if !transcript.contains(entry) {
                transcript.push(entry.clone());
            }
        }
        merged["transcript"] = Value::Array(transcript);
        append_link(&mut merged, right)?;
        emit_successor(agent, left, merged)
    }

    pub fn resolve_branch_conflict(
        agent: &mut CoreAgent,
        base: &Value,
        previous: &Value,
        side: &Value,
        mutation: &Value,
    ) -> Result<Value, CoreError> {
        let analysis = detect_branch_conflict(base, previous, side)?;
        if analysis.get("sameDocument").and_then(Value::as_bool) != Some(true)
            || analysis.get("sameParent").and_then(Value::as_bool) != Some(true)
        {
            return Err(CoreError::AgreementFailed(
                "agreement branches cannot be resolved from supplied base".into(),
            ));
        }
        let mut resolved = previous.clone();
        apply_mutation(&mut resolved, mutation)?;
        append_link(&mut resolved, side)?;
        emit_successor(agent, previous, resolved)
    }

    fn finalize_document(agent: &mut CoreAgent, doc: &mut Value) -> Result<(), CoreError> {
        update_agreement_hash(doc)?;
        let obj = doc
            .as_object_mut()
            .ok_or_else(|| CoreError::MalformedDocument("agreement must be an object".into()))?;
        obj.remove("jacsSignature");
        obj.remove("jacsSha256");
        agent.sign_document_inplace(doc, "jacsSignature")?;
        update_document_hash(doc)?;
        crate::schema::validate_agreement_v2_document(doc)?;
        Ok(())
    }

    fn emit_successor(
        agent: &mut CoreAgent,
        current: &Value,
        mut next: Value,
    ) -> Result<Value, CoreError> {
        let current_version = required_string(current, "jacsVersion")?;
        let new_version = uuid::Uuid::now_v7().to_string();
        next["jacsId"] = current.get("jacsId").cloned().unwrap_or(Value::Null);
        next["jacsOriginalVersion"] = current
            .get("jacsOriginalVersion")
            .cloned()
            .unwrap_or_else(|| current.get("jacsVersion").cloned().unwrap_or(Value::Null));
        next["jacsOriginalDate"] = current.get("jacsOriginalDate").cloned().unwrap_or_else(|| {
            current
                .get("jacsVersionDate")
                .cloned()
                .unwrap_or(Value::Null)
        });
        next["jacsPreviousVersion"] = json!(current_version);
        next["jacsVersion"] = json!(new_version);
        next["jacsVersionDate"] = json!(chrono::Utc::now().to_rfc3339());
        let previous = array_mut(&mut next, "allPreviousVersions")?;
        if !previous
            .iter()
            .any(|v| v.as_str() == Some(current_version.as_str()))
        {
            previous.push(json!(current_version));
        }
        finalize_document(agent, &mut next)?;
        Ok(next)
    }

    fn update_agreement_hash(doc: &mut Value) -> Result<(), CoreError> {
        let hash = compute_agreement_hash(doc)?;
        doc["jacsAgreementHash"] = json!(hash);
        Ok(())
    }

    fn compute_agreement_hash(doc: &Value) -> Result<String, CoreError> {
        let mut scoped = Map::new();
        for field in CONSENT_HASH_FIELDS {
            if let Some(value) = doc.get(*field) {
                scoped.insert((*field).to_string(), value.clone());
            }
        }
        let canonical = canonicalize_json_try(&Value::Object(scoped))?;
        Ok(sha256_hex(canonical.as_bytes()))
    }

    fn compute_transcript_hash(doc: &Value) -> Result<String, CoreError> {
        let transcript = doc.get("transcript").cloned().unwrap_or_else(|| json!([]));
        let canonical = canonicalize_json_try(&transcript)?;
        Ok(sha256_hex(canonical.as_bytes()))
    }

    fn update_document_hash(doc: &mut Value) -> Result<(), CoreError> {
        let mut clone = doc.clone();
        clone
            .as_object_mut()
            .ok_or_else(|| CoreError::MalformedDocument("agreement must be an object".into()))?
            .remove("jacsSha256");
        let canonical = canonicalize_json_try(&clone)?;
        doc["jacsSha256"] = json!(sha256_hex(canonical.as_bytes()));
        Ok(())
    }

    fn apply_mutation(doc: &mut Value, mutation: &Value) -> Result<(), CoreError> {
        let typ = mutation
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CoreError::MalformedDocument(
                    "agreement v2 mutation requires string field 'type'".into(),
                )
            })?;
        match typ {
            "appendTranscript" => {
                let entry = mutation.get("entry").cloned().ok_or_else(|| {
                    CoreError::MalformedDocument("appendTranscript requires entry".into())
                })?;
                array_mut(doc, "transcript")?.push(entry);
            }
            "updateTerms" => {
                if let Some(title) = mutation.get("title") {
                    doc["title"] = title.clone();
                }
                if let Some(description) = mutation.get("description") {
                    doc["description"] = description.clone();
                }
                doc["terms"] = mutation.get("terms").cloned().ok_or_else(|| {
                    CoreError::MalformedDocument("updateTerms requires terms".into())
                })?;
                if let Some(format) = mutation.get("termsFormat") {
                    doc["termsFormat"] = format.clone();
                }
                copy_optional(mutation, doc, "effectiveFrom");
                copy_optional(mutation, doc, "expiresAt");
            }
            "setStatus" => {
                doc["status"] = mutation.get("status").cloned().ok_or_else(|| {
                    CoreError::MalformedDocument("setStatus requires status".into())
                })?;
            }
            "setParties" => doc["parties"] = required_array(mutation, "parties")?,
            "setSignaturePolicy" => {
                doc["signaturePolicy"] = required_object(mutation, "signaturePolicy")?;
            }
            "addLink" => array_mut(doc, "links")?.push(
                mutation
                    .get("link")
                    .cloned()
                    .ok_or_else(|| CoreError::MalformedDocument("addLink requires link".into()))?,
            ),
            "setOwners" => doc["owners"] = required_array(mutation, "owners")?,
            _ => {
                return Err(CoreError::MalformedDocument(format!(
                    "unsupported agreement v2 mutation type '{}'",
                    typ
                )));
            }
        }
        Ok(())
    }

    fn recompute_status(doc: &Value) -> String {
        let current = doc.get("status").and_then(Value::as_str).unwrap_or("draft");
        if matches!(current, "disputed" | "superseded" | "terminated") {
            return current.to_string();
        }
        let signer_needed = required_count(doc, "signer");
        let witness_needed = policy_usize(doc, "witnessRequired");
        let notary_needed = policy_usize(doc, "notaryRequired");
        let signers = unique_signature_agents(doc, "signer").len();
        let witnesses = unique_signature_agents(doc, "witness").len();
        let notaries = unique_signature_agents(doc, "notary").len();
        // Quorum satisfaction concludes the agreement and wins over expiry, so a
        // concluded agreement is never retroactively downgraded to "expired".
        if signers >= signer_needed && witnesses >= witness_needed && notaries >= notary_needed {
            return "final".to_string();
        }
        // Not concluded: expiry / timeout move the agreement to "expired".
        if agreement_expired(doc) || timeout_expired(doc) {
            return "expired".to_string();
        }
        if signers + witnesses + notaries > 0 {
            "partially_signed".to_string()
        } else if current == "proposed" {
            "proposed".to_string()
        } else {
            "draft".to_string()
        }
    }

    fn required_count(doc: &Value, role: &str) -> usize {
        let parties = parties_by_role(doc, role);
        let policy = doc.get("signaturePolicy").unwrap_or(&Value::Null);
        match policy.get("partyQuorum") {
            Some(Value::String(s)) if s == "majority" => parties.len() / 2 + 1,
            Some(Value::Number(n)) => n.as_u64().unwrap_or(parties.len() as u64) as usize,
            _ => parties.len(),
        }
    }

    fn policy_usize(doc: &Value, field: &str) -> usize {
        doc.get("signaturePolicy")
            .and_then(|p| p.get(field))
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize
    }

    fn now_timestamp() -> i64 {
        chrono::Utc::now().timestamp()
    }

    fn parse_rfc3339_timestamp(value: &str) -> Option<i64> {
        chrono::DateTime::parse_from_rfc3339(value)
            .ok()
            .map(|dt| dt.timestamp())
    }

    fn agreement_expired(doc: &Value) -> bool {
        doc.get("expiresAt")
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_timestamp)
            .map(|deadline| deadline < now_timestamp())
            .unwrap_or(false)
    }

    fn timeout_expired(doc: &Value) -> bool {
        doc.get("signaturePolicy")
            .and_then(|p| p.get("timeout"))
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_timestamp)
            .map(|deadline| deadline < now_timestamp())
            .unwrap_or(false)
    }

    fn parties_by_role(doc: &Value, role: &str) -> Vec<String> {
        doc.get("parties")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|p| p.get("role").and_then(Value::as_str) == Some(role))
            .filter_map(|p| p.get("agentId").and_then(Value::as_str).map(str::to_string))
            .collect()
    }

    fn unique_signature_agents(doc: &Value, role: &str) -> HashSet<String> {
        signatures(doc)
            .into_iter()
            .filter(|entry| entry.get("role").and_then(Value::as_str) == Some(role))
            .filter_map(|entry| {
                entry
                    .get("signature")
                    .and_then(|s| s.get("agentID"))
                    .and_then(Value::as_str)
                    .filter(|agent_id| is_listed_party(doc, agent_id, role))
                    .map(|agent_id| normalize_agent_id(agent_id).to_string())
            })
            .collect()
    }

    fn signatures(doc: &Value) -> Vec<&Value> {
        doc.get("agreementSignatures")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .collect()
    }

    fn normalize_agent_id(agent_id: &str) -> &str {
        agent_id.split(':').next().unwrap_or(agent_id)
    }

    fn is_listed_party(doc: &Value, agent_id: &str, role: &str) -> bool {
        let normalized = normalize_agent_id(agent_id);
        doc.get("parties")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|party| {
                party
                    .get("agentId")
                    .and_then(Value::as_str)
                    .map(normalize_agent_id)
                    == Some(normalized)
                    && party.get("role").and_then(Value::as_str) == Some(role)
            })
    }

    fn assert_party_role(doc: &Value, agent_id: &str, role: &str) -> Result<(), CoreError> {
        if is_listed_party(doc, agent_id, role) {
            Ok(())
        } else {
            Err(CoreError::AgreementFailed(format!(
                "agent {} is not a listed {} party",
                agent_id, role
            )))
        }
    }

    fn assert_not_already_signed(doc: &Value, agent_id: &str, role: &str) -> Result<(), CoreError> {
        let already = signatures(doc).into_iter().any(|entry| {
            entry.get("role").and_then(Value::as_str) == Some(role)
                && entry
                    .get("signature")
                    .and_then(|s| s.get("agentID"))
                    .and_then(Value::as_str)
                    == Some(agent_id)
        });
        if already {
            Err(CoreError::AgreementFailed(format!(
                "agent {} already signed as {}",
                agent_id, role
            )))
        } else {
            Ok(())
        }
    }

    fn changed_fields(base: &Value, side: &Value) -> Vec<String> {
        let mut keys = HashSet::new();
        if let Some(obj) = base.as_object() {
            keys.extend(obj.keys().cloned());
        }
        if let Some(obj) = side.as_object() {
            keys.extend(obj.keys().cloned());
        }
        keys.into_iter()
            .filter(|key| base.get(key) != side.get(key))
            .collect()
    }

    fn version_or_transcript_field(field: &str) -> bool {
        matches!(
            field,
            "transcript"
                | "jacsVersion"
                | "jacsVersionDate"
                | "jacsPreviousVersion"
                | "allPreviousVersions"
                | "jacsSignature"
                | "jacsSha256"
        )
    }

    fn transcript_append_additions(
        base: &Value,
        side: &Value,
    ) -> Result<Option<Vec<Value>>, CoreError> {
        let base_items = transcript_values(base);
        let side_items = transcript_values(side);
        if side_items.len() < base_items.len() {
            return Ok(None);
        }
        if !base_items
            .iter()
            .zip(side_items.iter())
            .all(|(a, b)| a == b)
        {
            return Ok(None);
        }
        Ok(Some(side_items[base_items.len()..].to_vec()))
    }

    fn transcript_values(doc: &Value) -> Vec<Value> {
        doc.get("transcript")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    }

    fn append_link(doc: &mut Value, target: &Value) -> Result<(), CoreError> {
        let link = json!({
            "jacsId": required_string(target, "jacsId")?,
            "jacsVersion": required_string(target, "jacsVersion")?,
        });
        array_mut(doc, "links")?.push(link);
        Ok(())
    }

    fn array_mut<'a>(doc: &'a mut Value, field: &str) -> Result<&'a mut Vec<Value>, CoreError> {
        if doc.get(field).is_none() {
            doc[field] = json!([]);
        }
        doc.get_mut(field)
            .and_then(Value::as_array_mut)
            .ok_or_else(|| CoreError::MalformedDocument(format!("'{}' must be an array", field)))
    }

    fn required_string(doc: &Value, field: &str) -> Result<String, CoreError> {
        doc.get(field)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                CoreError::MalformedDocument(format!(
                    "agreement v2 requires string field '{}'",
                    field
                ))
            })
    }

    fn required_array(doc: &Value, field: &str) -> Result<Value, CoreError> {
        let value = doc.get(field).cloned().ok_or_else(|| {
            CoreError::MalformedDocument(format!("agreement v2 requires array field '{}'", field))
        })?;
        if value.as_array().is_some() {
            Ok(value)
        } else {
            Err(CoreError::MalformedDocument(format!(
                "'{}' must be an array",
                field
            )))
        }
    }

    fn required_object(doc: &Value, field: &str) -> Result<Value, CoreError> {
        let value = doc.get(field).cloned().ok_or_else(|| {
            CoreError::MalformedDocument(format!("agreement v2 requires object field '{}'", field))
        })?;
        if value.as_object().is_some() {
            Ok(value)
        } else {
            Err(CoreError::MalformedDocument(format!(
                "'{}' must be an object",
                field
            )))
        }
    }

    fn copy_optional(input: &Value, doc: &mut Value, field: &str) {
        if let Some(value) = input.get(field) {
            doc[field] = value.clone();
        }
    }

    fn assert_agreement(doc: &Value) -> Result<(), CoreError> {
        if doc.get("jacsType").and_then(Value::as_str) == Some("agreement") {
            Ok(())
        } else {
            Err(CoreError::AgreementFailed(
                "document is not an agreement v2 artifact".into(),
            ))
        }
    }

    fn agent_id(agent: &CoreAgent) -> String {
        agent
            .export_agent()
            .get("jacsId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    }
}
