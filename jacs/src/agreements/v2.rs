//! Agreement v2 helpers.
//!
//! Agreement v2 is a standalone JACS document (`jacsType = "agreement"`). This
//! module keeps agreement-specific policy and hashing here while reusing the
//! existing JACS document signing, versioning, storage, and verification
//! primitives.

use crate::agent::agreement::algorithm_strength;
use crate::agent::boilerplate::BoilerPlate;
use crate::agent::document::{DocumentTraits, JACSDocument};
use crate::agent::loaders::{FileLoader, fetch_remote_public_key};
use crate::agent::{
    Agent, DOCUMENT_AGENT_SIGNATURE_FIELDNAME, JACS_PREVIOUS_VERSION_FIELDNAME,
    JACS_VERSION_DATE_FIELDNAME, JACS_VERSION_FIELDNAME, SHA256_FIELDNAME, canonicalize_json,
};
use crate::crypt::hash::{hash_public_key, hash_string};
use crate::error::JacsError;
use crate::simple::SimpleAgent;
use crate::simple::types::SignedDocument;
use crate::time_utils;
use crate::validation::normalize_agent_id;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

const AGREEMENT_SIGNATURE_PLACEMENT: &str = "agreementSignature";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAgreementV2 {
    pub title: String,
    pub description: String,
    pub terms: String,
    #[serde(default = "default_terms_format")]
    pub terms_format: String,
    #[serde(default = "default_status")]
    pub status: String,
    #[serde(default)]
    pub effective_from: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    pub parties: Vec<Value>,
    pub signature_policy: Value,
    #[serde(default)]
    pub agreement_signatures: Vec<Value>,
    #[serde(default)]
    pub transcript: Vec<Value>,
    #[serde(default)]
    pub all_previous_versions: Vec<String>,
    #[serde(default)]
    pub links: Vec<Value>,
    #[serde(default)]
    pub controllers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum AgreementV2Mutation {
    AppendTranscript {
        entry: Value,
    },
    UpdateTerms {
        #[serde(default)]
        title: Option<String>,
        #[serde(default)]
        description: Option<String>,
        terms: String,
        #[serde(default)]
        terms_format: Option<String>,
        #[serde(default)]
        effective_from: Option<String>,
        #[serde(default)]
        expires_at: Option<String>,
    },
    SetStatus {
        status: String,
    },
    SetParties {
        parties: Vec<Value>,
    },
    SetSignaturePolicy {
        signature_policy: Value,
    },
    AddLink {
        link: Value,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgreementV2Role {
    Signer,
    Witness,
    Notary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgreementV2VerificationReport {
    pub valid: bool,
    pub status: String,
    pub expected_status: String,
    pub recomputed_agreement_hash: String,
    pub recomputed_transcript_hash: String,
    pub signer_count: usize,
    pub witness_count: usize,
    pub notary_count: usize,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Signer,
    Witness,
    Notary,
    Observer,
}

fn default_terms_format() -> String {
    "text/plain".to_string()
}

fn default_status() -> String {
    "draft".to_string()
}

impl AgreementV2Role {
    pub fn as_str(self) -> &'static str {
        match self {
            AgreementV2Role::Signer => "signer",
            AgreementV2Role::Witness => "witness",
            AgreementV2Role::Notary => "notary",
        }
    }
}

impl Role {
    fn parse(role: &str) -> Option<Self> {
        match role {
            "signer" => Some(Self::Signer),
            "witness" => Some(Self::Witness),
            "notary" => Some(Self::Notary),
            "observer" => Some(Self::Observer),
            _ => None,
        }
    }

    fn from_agreement_role(role: AgreementV2Role) -> Self {
        match role {
            AgreementV2Role::Signer => Self::Signer,
            AgreementV2Role::Witness => Self::Witness,
            AgreementV2Role::Notary => Self::Notary,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Signer => "signer",
            Self::Witness => "witness",
            Self::Notary => "notary",
            Self::Observer => "observer",
        }
    }
}

/// Create and sign a new v2 agreement document.
#[must_use = "agreement document must be used or stored"]
pub fn create(agent: &SimpleAgent, input: CreateAgreementV2) -> Result<SignedDocument, JacsError> {
    let mut inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;
    let doc = create_with_agent(&mut inner, input)?;
    SignedDocument::from_jacs_document(doc, "agreement v2")
}

/// Apply a policy-controlled v2 agreement mutation and emit a successor version.
#[must_use = "updated agreement document must be used or stored"]
pub fn apply(
    agent: &SimpleAgent,
    document: &str,
    mutation: AgreementV2Mutation,
) -> Result<SignedDocument, JacsError> {
    let mut inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;
    let doc = apply_with_agent(&mut inner, document, mutation)?;
    SignedDocument::from_jacs_document(doc, "agreement v2 update")
}

/// Add an agreement consent, witness, or notary signature and emit a successor version.
#[must_use = "signed agreement document must be used or stored"]
pub fn sign(
    agent: &SimpleAgent,
    document: &str,
    role: AgreementV2Role,
) -> Result<SignedDocument, JacsError> {
    let mut inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;
    let doc = sign_with_agent(&mut inner, document, role)?;
    SignedDocument::from_jacs_document(doc, "agreement v2 signature")
}

/// Verify agreement v2 structural, hash, policy, and signature invariants.
pub fn verify(
    agent: &SimpleAgent,
    document: &str,
) -> Result<AgreementV2VerificationReport, JacsError> {
    let mut inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;
    verify_with_agent(&mut inner, document)
}

pub fn create_with_agent(
    agent: &mut Agent,
    input: CreateAgreementV2,
) -> Result<JACSDocument, JacsError> {
    let creator_id = agent.get_id()?;
    let controllers = if input.controllers.is_empty() {
        vec![normalize_agent_id(&creator_id).to_string()]
    } else {
        input.controllers
    };

    let mut document = json!({
        "$schema": "https://hai.ai/schemas/agreement/v2/agreement.schema.json",
        "jacsType": "agreement",
        "jacsLevel": "artifact",
        "title": input.title,
        "description": input.description,
        "terms": input.terms,
        "termsFormat": input.terms_format,
        "status": input.status,
        "parties": input.parties,
        "signaturePolicy": input.signature_policy,
        "agreementSignatures": input.agreement_signatures,
        "transcript": input.transcript,
        "allPreviousVersions": input.all_previous_versions,
        "links": input.links,
        "controllers": controllers
    });

    insert_optional_string(&mut document, "effectiveFrom", input.effective_from);
    insert_optional_string(&mut document, "expiresAt", input.expires_at);
    update_agreement_hash(&mut document)?;

    agent.create_document_and_load(&document.to_string(), None, None)
}

pub fn apply_with_agent(
    agent: &mut Agent,
    document: &str,
    mutation: AgreementV2Mutation,
) -> Result<JACSDocument, JacsError> {
    let current = agent.load_document(document)?;
    assert_agreement_v2(&current.value)?;
    assert_controller(agent, &current.value)?;

    let mut next = current.value.clone();
    match mutation {
        AgreementV2Mutation::AppendTranscript { entry } => {
            array_mut(&mut next, "transcript")?.push(entry);
        }
        AgreementV2Mutation::UpdateTerms {
            title,
            description,
            terms,
            terms_format,
            effective_from,
            expires_at,
        } => {
            if let Some(title) = title {
                next["title"] = json!(title);
            }
            if let Some(description) = description {
                next["description"] = json!(description);
            }
            next["terms"] = json!(terms);
            if let Some(terms_format) = terms_format {
                next["termsFormat"] = json!(terms_format);
            }
            set_optional_string(&mut next, "effectiveFrom", effective_from);
            set_optional_string(&mut next, "expiresAt", expires_at);
            clear_agreement_signatures(&mut next);
            update_agreement_hash(&mut next)?;
        }
        AgreementV2Mutation::SetStatus { status } => {
            next["status"] = json!(status);
        }
        AgreementV2Mutation::SetParties { parties } => {
            next["parties"] = Value::Array(parties);
            clear_agreement_signatures(&mut next);
            update_agreement_hash(&mut next)?;
        }
        AgreementV2Mutation::SetSignaturePolicy { signature_policy } => {
            next["signaturePolicy"] = signature_policy;
            clear_agreement_signatures(&mut next);
            update_agreement_hash(&mut next)?;
        }
        AgreementV2Mutation::AddLink { link } => {
            array_mut(&mut next, "links")?.push(link);
        }
    }

    emit_successor(agent, &current.value, next)
}

pub fn sign_with_agent(
    agent: &mut Agent,
    document: &str,
    role: AgreementV2Role,
) -> Result<JACSDocument, JacsError> {
    let current = agent.load_document(document)?;
    assert_agreement_v2(&current.value)?;

    let stored_hash = required_str(&current.value, "jacsAgreementHash")?;
    let recomputed_hash = compute_agreement_hash(&current.value)?;
    if stored_hash != recomputed_hash {
        return Err(JacsError::HashMismatch {
            expected: recomputed_hash,
            got: stored_hash.to_string(),
        });
    }

    let agent_id = agent.get_id()?;
    let normalized_agent_id = normalize_agent_id(&agent_id).to_string();
    let requested_role = Role::from_agreement_role(role);
    assert_party_role(&current.value, &normalized_agent_id, requested_role)?;
    assert_not_already_signed(&current.value, &normalized_agent_id, requested_role)?;

    let transcript_hash = compute_transcript_hash(&current.value)?;
    let transcript_non_empty =
        transcript_array(&current.value).is_some_and(|items| !items.is_empty());

    let mut signature_context = json!({
        "jacsAgreementHash": stored_hash,
        AGREEMENT_SIGNATURE_PLACEMENT: {}
    });
    let mut fields = vec!["jacsAgreementHash".to_string()];

    if transcript_non_empty {
        signature_context["signedTranscriptHash"] = json!(transcript_hash.clone());
        fields.push("signedTranscriptHash".to_string());
    }

    let signature = agent.signing_procedure(
        &signature_context,
        Some(&fields),
        AGREEMENT_SIGNATURE_PLACEMENT,
    )?;
    verify_signature_policy_for_signature(&current.value, &signature)?;
    let mut entry = json!({
        "signature": signature,
        "role": role.as_str()
    });
    if transcript_non_empty {
        entry["signedTranscriptHash"] = json!(transcript_hash);
    }

    let mut next = current.value.clone();
    array_mut(&mut next, "agreementSignatures")?.push(entry);
    let expected_status = recompute_status(&next);
    next["status"] = json!(expected_status);

    emit_successor(agent, &current.value, next)
}

pub fn verify_with_agent(
    agent: &mut Agent,
    document: &str,
) -> Result<AgreementV2VerificationReport, JacsError> {
    let doc = agent.load_document(document)?;
    assert_agreement_v2(&doc.value)?;

    let recomputed_agreement_hash = compute_agreement_hash(&doc.value)?;
    let recomputed_transcript_hash = compute_transcript_hash(&doc.value)?;
    let status = doc
        .value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let expected_status = recompute_status(&doc.value);
    let mut errors = Vec::new();

    match doc.value.get("jacsAgreementHash").and_then(Value::as_str) {
        Some(stored) if stored == recomputed_agreement_hash => {}
        Some(stored) => errors.push(format!(
            "jacsAgreementHash mismatch: stored {}, recomputed {}",
            stored, recomputed_agreement_hash
        )),
        None => errors.push("missing jacsAgreementHash".to_string()),
    }

    if status != expected_status {
        errors.push(format!(
            "status '{}' is inconsistent with signaturePolicy; expected '{}'",
            status, expected_status
        ));
    }

    if let Err(err) = verify_previous_versions_hint(&doc.value) {
        errors.push(err);
    }

    let mut signed_counts = SignedRoleCounts::default();
    for signature_entry in signature_entries(&doc.value) {
        if let Err(err) = verify_signature_entry(
            agent,
            &doc.value,
            signature_entry,
            &recomputed_transcript_hash,
            &mut signed_counts,
        ) {
            errors.push(err.to_string());
        }
    }

    Ok(AgreementV2VerificationReport {
        valid: errors.is_empty(),
        status,
        expected_status,
        recomputed_agreement_hash,
        recomputed_transcript_hash,
        signer_count: signed_counts.signers.len(),
        witness_count: signed_counts.witnesses.len(),
        notary_count: signed_counts.notaries.len(),
        errors,
    })
}

pub fn compute_agreement_hash(document: &Value) -> Result<String, JacsError> {
    let mut scope = Map::new();
    for field in [
        "title",
        "description",
        "terms",
        "termsFormat",
        "effectiveFrom",
        "expiresAt",
        "parties",
        "signaturePolicy",
    ] {
        if let Some(value) = document.get(field) {
            scope.insert(field.to_string(), value.clone());
        }
    }
    let canonical = canonicalize_json(&Value::Object(scope))?;
    Ok(hash_string(&canonical))
}

pub fn compute_transcript_hash(document: &Value) -> Result<String, JacsError> {
    let transcript = document
        .get("transcript")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let canonical = canonicalize_json(&transcript)?;
    Ok(hash_string(&canonical))
}

pub fn recompute_status(document: &Value) -> String {
    let current_status = document
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("draft");
    if matches!(current_status, "disputed" | "superseded" | "terminated") {
        return current_status.to_string();
    }

    let complete = signature_policy_satisfied(document);
    if complete {
        return "final".to_string();
    }

    if timeout_expired(document) {
        return "expired".to_string();
    }

    if signature_entries(document).next().is_some() {
        return "partially_signed".to_string();
    }

    current_status.to_string()
}

fn insert_optional_string(document: &mut Value, field: &str, value: Option<String>) {
    if let Some(value) = value {
        document[field] = json!(value);
    }
}

fn set_optional_string(document: &mut Value, field: &str, value: Option<String>) {
    if let Some(value) = value {
        document[field] = json!(value);
    }
}

fn clear_agreement_signatures(document: &mut Value) {
    document["agreementSignatures"] = json!([]);
}

fn update_agreement_hash(document: &mut Value) -> Result<(), JacsError> {
    let hash = compute_agreement_hash(document)?;
    document["jacsAgreementHash"] = json!(hash);
    Ok(())
}

fn array_mut<'a>(document: &'a mut Value, field: &str) -> Result<&'a mut Vec<Value>, JacsError> {
    if document.get(field).is_none() {
        document[field] = json!([]);
    }
    document
        .get_mut(field)
        .and_then(Value::as_array_mut)
        .ok_or_else(|| JacsError::DocumentMalformed {
            field: field.to_string(),
            reason: "expected array".to_string(),
        })
}

fn transcript_array(document: &Value) -> Option<&Vec<Value>> {
    document.get("transcript").and_then(Value::as_array)
}

fn signature_entries(document: &Value) -> impl Iterator<Item = &Value> {
    document
        .get("agreementSignatures")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn assert_agreement_v2(document: &Value) -> Result<(), JacsError> {
    let jacs_type = required_str(document, "jacsType")?;
    if jacs_type != "agreement" {
        return Err(JacsError::DocumentMalformed {
            field: "jacsType".to_string(),
            reason: format!("expected agreement, got {}", jacs_type),
        });
    }
    Ok(())
}

fn assert_controller(agent: &Agent, document: &Value) -> Result<(), JacsError> {
    let agent_id = agent.get_id()?;
    let normalized = normalize_agent_id(&agent_id);
    let controllers = document
        .get("controllers")
        .and_then(Value::as_array)
        .ok_or_else(|| JacsError::DocumentMalformed {
            field: "controllers".to_string(),
            reason: "agreement update requires controllers[]".to_string(),
        })?;

    let allowed = controllers.iter().any(|id| {
        id.as_str()
            .map(|id| normalize_agent_id(id) == normalized)
            .unwrap_or(false)
    });

    if allowed {
        Ok(())
    } else {
        Err(JacsError::DocumentError(format!(
            "Agent '{}' is not a controller for agreement '{}'",
            normalized,
            document
                .get("jacsId")
                .and_then(Value::as_str)
                .unwrap_or("<unknown>")
        )))
    }
}

fn assert_party_role(document: &Value, agent_id: &str, role: Role) -> Result<(), JacsError> {
    let found = party_roles(document)
        .into_iter()
        .any(|(party_id, party_role)| party_id == agent_id && party_role == role);
    if found {
        Ok(())
    } else {
        Err(JacsError::DocumentError(format!(
            "Agent '{}' is not listed as a {} party",
            agent_id,
            role.as_str()
        )))
    }
}

fn assert_not_already_signed(
    document: &Value,
    agent_id: &str,
    role: Role,
) -> Result<(), JacsError> {
    let duplicate = signature_entries(document).any(|entry| {
        signature_agent_id(entry)
            .map(|signed_agent_id| signed_agent_id == agent_id)
            .unwrap_or(false)
            && signature_role(entry) == Some(role)
    });
    if duplicate {
        Err(JacsError::DocumentError(format!(
            "Agent '{}' has already signed as {}",
            agent_id,
            role.as_str()
        )))
    } else {
        Ok(())
    }
}

fn required_str<'a>(document: &'a Value, field: &str) -> Result<&'a str, JacsError> {
    document
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| JacsError::DocumentMalformed {
            field: field.to_string(),
            reason: "missing or non-string field".to_string(),
        })
}

fn emit_successor(
    agent: &mut Agent,
    previous: &Value,
    mut next: Value,
) -> Result<JACSDocument, JacsError> {
    let previous_version = required_str(previous, JACS_VERSION_FIELDNAME)?.to_string();

    let all_previous_versions = array_mut(&mut next, "allPreviousVersions")?;
    if !all_previous_versions
        .iter()
        .any(|version| version.as_str() == Some(previous_version.as_str()))
    {
        all_previous_versions.push(json!(previous_version.clone()));
    }

    next[JACS_PREVIOUS_VERSION_FIELDNAME] = json!(previous_version);
    next[JACS_VERSION_FIELDNAME] = json!(Uuid::new_v4().to_string());
    next[JACS_VERSION_DATE_FIELDNAME] = json!(time_utils::now_rfc3339());
    if let Some(obj) = next.as_object_mut() {
        obj.remove(DOCUMENT_AGENT_SIGNATURE_FIELDNAME);
        obj.remove(SHA256_FIELDNAME);
    }
    next[DOCUMENT_AGENT_SIGNATURE_FIELDNAME] =
        agent.signing_procedure(&next, None, DOCUMENT_AGENT_SIGNATURE_FIELDNAME)?;
    let document_hash = agent.hash_doc(&next)?;
    next[SHA256_FIELDNAME] = json!(document_hash);
    agent.store_jacs_document(&next)
}

#[derive(Default)]
struct SignedRoleCounts {
    signers: HashSet<String>,
    witnesses: HashSet<String>,
    notaries: HashSet<String>,
}

fn verify_signature_entry(
    agent: &mut Agent,
    document: &Value,
    entry: &Value,
    transcript_hash: &str,
    counts: &mut SignedRoleCounts,
) -> Result<(), JacsError> {
    let role = signature_role(entry).ok_or_else(|| JacsError::DocumentMalformed {
        field: "agreementSignatures[].role".to_string(),
        reason: "missing or invalid role".to_string(),
    })?;
    if role == Role::Observer {
        return Err(JacsError::DocumentMalformed {
            field: "agreementSignatures[].role".to_string(),
            reason: "observers cannot sign".to_string(),
        });
    }

    let signature = entry
        .get("signature")
        .ok_or_else(|| JacsError::DocumentMalformed {
            field: "agreementSignatures[].signature".to_string(),
            reason: "missing signature".to_string(),
        })?;
    let signature_agent = signature
        .get("agentID")
        .and_then(Value::as_str)
        .ok_or_else(|| JacsError::DocumentMalformed {
            field: "agreementSignatures[].signature.agentID".to_string(),
            reason: "missing signer".to_string(),
        })?;
    let signer_id = normalize_agent_id(signature_agent).to_string();
    assert_party_role(document, &signer_id, role)?;
    verify_signature_policy_for_signature(document, signature)?;

    let transcript_non_empty = transcript_array(document).is_some_and(|items| !items.is_empty());
    let mut signature_context = json!({
        "jacsAgreementHash": required_str(document, "jacsAgreementHash")?,
        AGREEMENT_SIGNATURE_PLACEMENT: signature.clone()
    });
    let mut fields = vec!["jacsAgreementHash".to_string()];
    let signed_transcript_hash = entry.get("signedTranscriptHash").and_then(Value::as_str);
    if let Some(signed_transcript_hash) = signed_transcript_hash {
        if signed_transcript_hash != transcript_hash {
            return Err(JacsError::HashMismatch {
                expected: transcript_hash.to_string(),
                got: signed_transcript_hash.to_string(),
            });
        }
        signature_context["signedTranscriptHash"] = json!(signed_transcript_hash);
        fields.push("signedTranscriptHash".to_string());
    } else if transcript_non_empty {
        return Err(JacsError::DocumentMalformed {
            field: "agreementSignatures[].signedTranscriptHash".to_string(),
            reason: "required when transcript is non-empty".to_string(),
        });
    }

    let (public_key, public_key_type, public_key_hash) =
        resolve_signature_public_key(agent, signature)?;
    agent.signature_verification_procedure(
        &signature_context,
        Some(&fields),
        AGREEMENT_SIGNATURE_PLACEMENT,
        public_key,
        Some(public_key_type),
        Some(public_key_hash),
        None,
    )?;

    match role {
        Role::Signer => {
            counts.signers.insert(signer_id);
        }
        Role::Witness => {
            counts.witnesses.insert(signer_id);
        }
        Role::Notary => {
            counts.notaries.insert(signer_id);
        }
        Role::Observer => {}
    }
    Ok(())
}

fn resolve_signature_public_key(
    agent: &mut Agent,
    signature: &Value,
) -> Result<(Vec<u8>, String, String), JacsError> {
    let public_key_hash = signature
        .get("publicKeyHash")
        .and_then(Value::as_str)
        .ok_or_else(|| JacsError::DocumentMalformed {
            field: "signature.publicKeyHash".to_string(),
            reason: "missing public key hash".to_string(),
        })?
        .to_string();
    let signing_algorithm = signature
        .get("signingAlgorithm")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    if let Ok(local_key) = agent.get_public_key()
        && hash_public_key(&local_key) == public_key_hash
    {
        return Ok((local_key, signing_algorithm, public_key_hash));
    }

    if let Ok(local_key) = agent.fs_load_public_key(&public_key_hash) {
        let key_type = agent
            .fs_load_public_key_type(&public_key_hash)
            .unwrap_or_else(|_| signing_algorithm.clone());
        return Ok((local_key, key_type, public_key_hash));
    }

    let agent_id = signature
        .get("agentID")
        .and_then(Value::as_str)
        .unwrap_or("");
    let agent_version = signature
        .get("agentVersion")
        .and_then(Value::as_str)
        .unwrap_or("latest");
    let remote_key = fetch_remote_public_key(agent_id, agent_version)?;
    Ok((remote_key.public_key, remote_key.algorithm, public_key_hash))
}

fn verify_signature_policy_for_signature(
    document: &Value,
    signature: &Value,
) -> Result<(), JacsError> {
    let policy = document
        .get("signaturePolicy")
        .and_then(Value::as_object)
        .ok_or_else(|| JacsError::DocumentMalformed {
            field: "signaturePolicy".to_string(),
            reason: "missing signature policy".to_string(),
        })?;

    let algorithm = signature
        .get("signingAlgorithm")
        .and_then(Value::as_str)
        .unwrap_or("");

    if let Some(required) = policy.get("requiredAlgorithms").and_then(Value::as_array) {
        let accepted = required
            .iter()
            .filter_map(Value::as_str)
            .any(|required_algorithm| required_algorithm == algorithm);
        if !accepted {
            return Err(JacsError::CryptoError(format!(
                "signature algorithm '{}' not allowed by signaturePolicy.requiredAlgorithms",
                algorithm
            )));
        }
    }

    if let Some(minimum_strength) = policy.get("minimumStrength").and_then(Value::as_str)
        && minimum_strength == "post-quantum"
        && algorithm_strength(algorithm) != "post-quantum"
    {
        return Err(JacsError::CryptoError(format!(
            "signature algorithm '{}' does not satisfy minimumStrength '{}'",
            algorithm, minimum_strength
        )));
    }

    Ok(())
}

fn verify_previous_versions_hint(document: &Value) -> Result<(), String> {
    let Some(previous_version) = document
        .get(JACS_PREVIOUS_VERSION_FIELDNAME)
        .and_then(Value::as_str)
    else {
        return Ok(());
    };
    let Some(all_previous_versions) = document
        .get("allPreviousVersions")
        .and_then(Value::as_array)
    else {
        return Err(
            "jacsPreviousVersion is present but allPreviousVersions is missing".to_string(),
        );
    };
    if all_previous_versions.last().and_then(Value::as_str) == Some(previous_version) {
        Ok(())
    } else {
        Err("allPreviousVersions does not reconcile with jacsPreviousVersion".to_string())
    }
}

fn party_roles(document: &Value) -> HashMap<String, Role> {
    document
        .get("parties")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|party| {
            let id = party.get("agentId").and_then(Value::as_str)?;
            let role = party
                .get("role")
                .and_then(Value::as_str)
                .and_then(Role::parse)?;
            Some((normalize_agent_id(id).to_string(), role))
        })
        .collect()
}

fn signature_agent_id(entry: &Value) -> Option<String> {
    entry
        .get("signature")
        .and_then(|signature| signature.get("agentID"))
        .and_then(Value::as_str)
        .map(|id| normalize_agent_id(id).to_string())
}

fn signature_role(entry: &Value) -> Option<Role> {
    entry
        .get("role")
        .and_then(Value::as_str)
        .and_then(Role::parse)
}

fn signature_policy_satisfied(document: &Value) -> bool {
    let parties = party_roles(document);
    let signer_total = parties
        .values()
        .filter(|role| **role == Role::Signer)
        .count();
    let witness_required = policy_count(document, "witnessRequired");
    let notary_required = policy_count(document, "notaryRequired");
    let party_quorum = party_quorum_required(document, signer_total);

    let mut signers = HashSet::new();
    let mut witnesses = HashSet::new();
    let mut notaries = HashSet::new();
    for entry in signature_entries(document) {
        let Some(agent_id) = signature_agent_id(entry) else {
            continue;
        };
        match signature_role(entry) {
            Some(Role::Signer) if parties.get(&agent_id) == Some(&Role::Signer) => {
                signers.insert(agent_id);
            }
            Some(Role::Witness) if parties.get(&agent_id) == Some(&Role::Witness) => {
                witnesses.insert(agent_id);
            }
            Some(Role::Notary) if parties.get(&agent_id) == Some(&Role::Notary) => {
                notaries.insert(agent_id);
            }
            _ => {}
        }
    }

    signers.len() >= party_quorum
        && witnesses.len() >= witness_required
        && notaries.len() >= notary_required
}

fn policy_count(document: &Value, field: &str) -> usize {
    document
        .get("signaturePolicy")
        .and_then(|policy| policy.get(field))
        .and_then(Value::as_u64)
        .unwrap_or(0) as usize
}

fn party_quorum_required(document: &Value, signer_total: usize) -> usize {
    let Some(quorum) = document
        .get("signaturePolicy")
        .and_then(|policy| policy.get("partyQuorum"))
    else {
        return signer_total;
    };

    if let Some(kind) = quorum.as_str() {
        return match kind {
            "majority" => signer_total / 2 + 1,
            _ => signer_total,
        };
    }

    quorum
        .as_u64()
        .map(|count| count as usize)
        .unwrap_or(signer_total)
}

fn timeout_expired(document: &Value) -> bool {
    let Some(timeout) = document
        .get("signaturePolicy")
        .and_then(|policy| policy.get("timeout"))
        .and_then(Value::as_str)
    else {
        return false;
    };
    time_utils::parse_rfc3339_to_timestamp(timeout)
        .map(|deadline| deadline < time_utils::now_timestamp())
        .unwrap_or(false)
}
