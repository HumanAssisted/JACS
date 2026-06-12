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
use tracing::{info, warn};
use uuid::Uuid;

const AGREEMENT_SIGNATURE_PLACEMENT: &str = "agreementSignature";
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
const TERMS_FORMATS: &[&str] = &["text/plain", "text/markdown"];
const STATUSES: &[&str] = &[
    "draft",
    "proposed",
    "partially_signed",
    "final",
    "expired",
    "disputed",
    "superseded",
    "terminated",
];
const AGENT_TYPES: &[&str] = &["human", "human-org", "hybrid", "ai"];
const PARTY_ROLES: &[&str] = &["signer", "witness", "notary", "observer"];
const SIGNATURE_ROLES: &[&str] = &["signer", "witness", "notary"];
const MINIMUM_STRENGTHS: &[&str] = &["classical", "post-quantum"];
const PARTY_FIELDS: &[&str] = &[
    "agentId",
    "agentVersion",
    "agentType",
    "role",
    "displayName",
];
const SIGNATURE_POLICY_FIELDS: &[&str] = &[
    "partyQuorum",
    "witnessRequired",
    "notaryRequired",
    "timeout",
    "requiredAlgorithms",
    "minimumStrength",
];
const AGREEMENT_SIGNATURE_FIELDS: &[&str] = &["signature", "role", "signedTranscriptHash"];
const JACS_DOCUMENT_REF_FIELDS: &[&str] = &["jacsId", "jacsVersion", "jacsSha256"];
const AGREEMENT_LINK_FIELDS: &[&str] = &["jacsId", "jacsVersion", "jacsSha256"];
const TERMINAL_NON_SIGNING_STATUSES: &[&str] =
    &["final", "expired", "disputed", "superseded", "terminated"];
const AUTO_MERGE_GUARD_FIELDS: &[&str] = &["status", "agreementSignatures", "links", "controllers"];

// Resource limits applied to untrusted agreement v2 input at the binding/FFI
// boundary, closing the legacy M1/M2 recursion/size DoS. These caps are
// deliberately generous (orders of magnitude above realistic agreements); they
// exist to reject hostile inputs that would otherwise drive unbounded
// allocation or stack-overflowing recursive descent over a parsed `Value`.
//
// The raw-byte cap reuses the existing `JACS_MAX_DOCUMENT_SIZE` document-size
// limit (default 10MB) via `crate::schema::utils::check_document_size`.

/// Maximum JSON nesting depth for an agreement v2 document `Value`.
const MAX_AGREEMENT_NESTING_DEPTH: usize = 64;
/// Maximum number of transcript entries.
const MAX_TRANSCRIPT_ENTRIES: usize = 10_000;
/// Maximum number of agreement signatures.
const MAX_AGREEMENT_SIGNATURES: usize = 1_000;
/// Maximum number of parties.
const MAX_PARTIES: usize = 1_000;
/// Maximum number of merge/cross links.
const MAX_LINKS: usize = 1_000;
/// Maximum number of entries in `allPreviousVersions`.
const MAX_PREVIOUS_VERSIONS: usize = 10_000;

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
    #[serde(default)]
    pub owners: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
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
    SetOwners {
        owners: Vec<String>,
    },
}

impl AgreementV2Mutation {
    fn touches_consent_scope(&self) -> bool {
        matches!(
            self,
            Self::UpdateTerms { .. } | Self::SetParties { .. } | Self::SetSignaturePolicy { .. }
        )
    }
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
    pub verified_chain_depth: usize,
    pub chain_fully_verified: bool,
    #[serde(default)]
    pub notes: Vec<String>,
}

struct ChainVerification {
    error: Option<String>,
    verified_depth: usize,
    fully_verified: bool,
    notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgreementV2MergeAnalysis {
    pub same_document: bool,
    pub same_parent: bool,
    pub auto_mergeable: bool,
    pub conflict_fields: Vec<String>,
    pub left_changed_fields: Vec<String>,
    pub right_changed_fields: Vec<String>,
    pub left_transcript_additions: usize,
    pub right_transcript_additions: usize,
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

/// Auto-merge two transcript-only branches and emit a successor version.
#[must_use = "merged agreement document must be used or stored"]
pub fn merge_transcript_branches(
    agent: &SimpleAgent,
    base_document: &str,
    left_document: &str,
    right_document: &str,
) -> Result<SignedDocument, JacsError> {
    let mut inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;
    let doc = merge_transcript_branches_with_agent(
        &mut inner,
        base_document,
        left_document,
        right_document,
    )?;
    SignedDocument::from_jacs_document(doc, "agreement v2 transcript merge")
}

/// Resolve a conflicting branch by applying an explicit resolution mutation.
#[must_use = "resolved agreement document must be used or stored"]
pub fn resolve_branch_conflict(
    agent: &SimpleAgent,
    base_document: &str,
    previous_document: &str,
    side_branch_document: &str,
    resolution: AgreementV2Mutation,
) -> Result<SignedDocument, JacsError> {
    let mut inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;
    let doc = resolve_branch_conflict_with_agent(
        &mut inner,
        base_document,
        previous_document,
        side_branch_document,
        resolution,
    )?;
    SignedDocument::from_jacs_document(doc, "agreement v2 branch resolution")
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

    if !input.agreement_signatures.is_empty() {
        return Err(JacsError::DocumentError(
            "agreementSignatures must be empty at creation; signatures are added through the sign operation after the agreement is hashed and stored"
                .to_string(),
        ));
    }

    let mut document = json!({
        "$schema": jacs_core::schema::V2_SCHEMA_ID,
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
        "controllers": controllers,
        "owners": input.owners
    });

    insert_optional_string(&mut document, "effectiveFrom", input.effective_from);
    insert_optional_string(&mut document, "expiresAt", input.expires_at);
    update_agreement_hash(&mut document)?;
    validate_agreement_v2(&document)?;
    assert_status_consistent(&document)?;

    let doc = agent.create_document_and_load(&document.to_string(), None, None)?;
    validate_agreement_v2_schema(&doc.value)?;
    let created_status = doc
        .value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let created_party_count = doc
        .value
        .get("parties")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    info!(
        event = "agreement_v2_created",
        document_id = %doc.id,
        status = %created_status,
        party_count = created_party_count,
        "Agreement v2 created"
    );
    Ok(doc)
}

pub fn apply_with_agent(
    agent: &mut Agent,
    document: &str,
    mutation: AgreementV2Mutation,
) -> Result<JACSDocument, JacsError> {
    let current = agent.load_document(document)?;
    assert_agreement_v2(&current.value)?;
    assert_controller(agent, &current.value)?;

    if let AgreementV2Mutation::SetSignaturePolicy { signature_policy } = &mutation
        && signature_policy_past_point_of_reliance(&current.value)
        && signature_policy_is_weaker(&current.value, signature_policy)
    {
        return Err(JacsError::DocumentError(
            "signaturePolicy cannot be loosened after proposal or signatures (consent-scope quorum); create a superseding agreement instead"
                .to_string(),
        ));
    }

    if current.value.get("status").and_then(Value::as_str) == Some("final")
        && mutation.touches_consent_scope()
    {
        return Err(JacsError::DocumentError(
            "final agreements cannot change consent-scope fields; create a superseding agreement"
                .to_string(),
        ));
    }

    let mut next = current.value.clone();
    apply_mutation_to_document(&mut next, mutation)?;

    validate_agreement_v2(&next)?;
    assert_status_consistent(&next)?;
    let updated = emit_successor(agent, &current.value, next)?;
    let updated_status = updated
        .value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    info!(
        event = "agreement_v2_applied",
        document_id = %updated.id,
        status = %updated_status,
        "Agreement v2 mutation applied"
    );
    Ok(updated)
}

pub fn sign_with_agent(
    agent: &mut Agent,
    document: &str,
    role: AgreementV2Role,
) -> Result<JACSDocument, JacsError> {
    let current = agent.load_document(document)?;
    assert_agreement_v2(&current.value)?;
    assert_accepts_signature(&current.value)?;

    let stored_hash = required_str(&current.value, "jacsAgreementHash")?;
    let agreement_jacs_id = required_str(&current.value, "jacsId")?;
    let recomputed_hash = compute_agreement_hash(&current.value)?;
    if stored_hash != recomputed_hash {
        return Err(JacsError::HashMismatch {
            expected: recomputed_hash,
            got: stored_hash.to_string(),
        });
    }

    let agent_id = agent.get_id()?;
    let normalized_agent_id = normalize_agent_id(&agent_id).to_string();
    let agent_version = agent.get_version()?;
    let requested_role = Role::from_agreement_role(role);
    assert_party_role_and_version(
        &current.value,
        &normalized_agent_id,
        Some(agent_version.as_str()),
        requested_role,
    )?;
    assert_not_already_signed(&current.value, &normalized_agent_id, requested_role)?;

    let transcript_hash = compute_transcript_hash(&current.value)?;
    let transcript_non_empty =
        transcript_array(&current.value).is_some_and(|items| !items.is_empty());

    let mut signature_context = json!({
        "jacsId": agreement_jacs_id,
        "jacsAgreementHash": stored_hash,
        AGREEMENT_SIGNATURE_PLACEMENT: {}
    });
    let mut fields = vec!["jacsId".to_string(), "jacsAgreementHash".to_string()];

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

    let signed = emit_successor(agent, &current.value, next)?;
    let signed_status = signed
        .value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    info!(
        event = "agreement_v2_signed",
        document_id = %signed.id,
        role = %role.as_str(),
        status = %signed_status,
        "Agreement v2 signature added"
    );
    Ok(signed)
}

pub fn verify_with_agent(
    agent: &mut Agent,
    document: &str,
) -> Result<AgreementV2VerificationReport, JacsError> {
    let doc = load_agreement_no_store(agent, document)?;
    assert_agreement_v2(&doc.value)?;
    build_verification_report(agent, &doc.value)
}

fn build_verification_report(
    agent: &mut Agent,
    value: &Value,
) -> Result<AgreementV2VerificationReport, JacsError> {
    let recomputed_agreement_hash = compute_agreement_hash(value)?;
    let recomputed_transcript_hash = compute_transcript_hash(value)?;
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let expected_status = recompute_status(value);
    let mut errors = Vec::new();
    let mut notes = Vec::new();

    match value.get("jacsAgreementHash").and_then(Value::as_str) {
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

    if let Err(err) = verify_header_signature_and_controller(agent, value) {
        errors.push(err.to_string());
    }

    let chain = verify_previous_versions_chain(agent, value);
    if let Some(err) = chain.error {
        errors.push(err);
    }
    let verified_chain_depth = chain.verified_depth;
    let mut chain_fully_verified = chain.fully_verified;
    notes.extend(chain.notes);

    let (merge_link_errors, merge_link_notes, merge_targets_loaded) =
        verify_merge_links(agent, value);
    let merge_links_valid = merge_link_errors.is_empty();
    errors.extend(merge_link_errors);
    notes.extend(merge_link_notes);
    if !merge_targets_loaded || !merge_links_valid {
        chain_fully_verified = false;
    }

    if let Some(note) = check_freshness(agent, value) {
        notes.push(note);
    }

    let transcript_prefix_hashes = compute_transcript_prefix_hashes(value)?;
    let mut signed_counts = SignedRoleCounts::default();
    for signature_entry in signature_entries(value) {
        if let Err(err) = verify_signature_entry(
            agent,
            value,
            signature_entry,
            &recomputed_transcript_hash,
            &transcript_prefix_hashes,
            &mut signed_counts,
        ) {
            errors.push(err.to_string());
        }
    }

    let agreement_id = value
        .get("jacsId")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let valid = errors.is_empty();
    if valid {
        info!(
            event = "agreement_v2_verified",
            document_id = %agreement_id,
            status = %status,
            valid = true,
            signer_count = signed_counts.signers.len(),
            witness_count = signed_counts.witnesses.len(),
            notary_count = signed_counts.notaries.len(),
            "Agreement v2 verification successful"
        );
    } else {
        warn!(
            event = "agreement_v2_verified",
            document_id = %agreement_id,
            valid = false,
            error_count = errors.len(),
            errors = ?errors,
            "Agreement v2 verification failed"
        );
    }

    Ok(AgreementV2VerificationReport {
        valid,
        status,
        expected_status,
        recomputed_agreement_hash,
        recomputed_transcript_hash,
        signer_count: signed_counts.signers.len(),
        witness_count: signed_counts.witnesses.len(),
        notary_count: signed_counts.notaries.len(),
        errors,
        verified_chain_depth,
        chain_fully_verified,
        notes,
    })
}

pub fn detect_branch_conflict(
    base_document: &str,
    left_document: &str,
    right_document: &str,
) -> Result<AgreementV2MergeAnalysis, JacsError> {
    let base = parse_agreement_value(base_document)?;
    let left = parse_agreement_value(left_document)?;
    let right = parse_agreement_value(right_document)?;
    analyze_branch_values(&base, &left, &right)
}

pub fn merge_transcript_branches_with_agent(
    agent: &mut Agent,
    base_document: &str,
    left_document: &str,
    right_document: &str,
) -> Result<JACSDocument, JacsError> {
    let base = load_agreement_no_store(agent, base_document)?;
    let left = load_agreement_no_store(agent, left_document)?;
    let right = load_agreement_no_store(agent, right_document)?;
    assert_agreement_v2(&base.value)?;
    assert_agreement_v2(&left.value)?;
    assert_agreement_v2(&right.value)?;
    assert_controller(agent, &left.value)?;

    let left_report = build_verification_report(agent, &left.value)?;
    if !left_report.valid {
        return Err(JacsError::DocumentError(format!(
            "left branch failed verification; refusing to merge unverified agreement: {:?}",
            left_report.errors
        )));
    }
    let right_report = build_verification_report(agent, &right.value)?;
    if !right_report.valid {
        return Err(JacsError::DocumentError(format!(
            "right branch failed verification; refusing to merge unverified agreement: {:?}",
            right_report.errors
        )));
    }

    let analysis = analyze_branch_values(&base.value, &left.value, &right.value)?;
    if !analysis.auto_mergeable {
        return Err(JacsError::DocumentError(format!(
            "agreement branches are not transcript-only auto-mergeable: conflicts {:?}, errors {:?}",
            analysis.conflict_fields, analysis.errors
        )));
    }

    let left_additions =
        transcript_append_additions(&base.value, &left.value)?.ok_or_else(|| {
            JacsError::Internal {
            message:
                "merge invariant violated: left branch was not append-only after auto-merge check"
                    .to_string(),
        }
        })?;
    let right_additions =
        transcript_append_additions(&base.value, &right.value)?.ok_or_else(|| {
            JacsError::Internal {
            message:
                "merge invariant violated: right branch was not append-only after auto-merge check"
                    .to_string(),
        }
        })?;

    let mut merged = left.value.clone();
    let mut merged_transcript = transcript_values(&base.value);
    for entry in left_additions.iter().chain(right_additions.iter()) {
        if !contains_canonical_value(&merged_transcript, entry)? {
            merged_transcript.push(entry.clone());
        }
    }
    merged["transcript"] = Value::Array(merged_transcript);
    append_merge_link(agent, &mut merged, &right.value)?;
    validate_agreement_v2(&merged)?;
    assert_status_consistent(&merged)?;

    let merged_doc = emit_successor(agent, &left.value, merged)?;
    let merged_status = merged_doc
        .value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    info!(
        event = "agreement_v2_merged",
        document_id = %merged_doc.id,
        status = %merged_status,
        "Agreement v2 transcript branches merged"
    );
    Ok(merged_doc)
}

pub fn resolve_branch_conflict_with_agent(
    agent: &mut Agent,
    base_document: &str,
    previous_document: &str,
    side_branch_document: &str,
    resolution: AgreementV2Mutation,
) -> Result<JACSDocument, JacsError> {
    let base = load_agreement_no_store(agent, base_document)?;
    let previous = load_agreement_no_store(agent, previous_document)?;
    let side_branch = load_agreement_no_store(agent, side_branch_document)?;
    assert_agreement_v2(&base.value)?;
    assert_agreement_v2(&previous.value)?;
    assert_agreement_v2(&side_branch.value)?;
    assert_controller(agent, &previous.value)?;

    let previous_report = build_verification_report(agent, &previous.value)?;
    if !previous_report.valid {
        return Err(JacsError::DocumentError(format!(
            "previous branch failed verification; refusing to resolve unverified agreement: {:?}",
            previous_report.errors
        )));
    }
    let side_branch_report = build_verification_report(agent, &side_branch.value)?;
    if !side_branch_report.valid {
        return Err(JacsError::DocumentError(format!(
            "side branch failed verification; refusing to resolve unverified agreement: {:?}",
            side_branch_report.errors
        )));
    }

    if previous.value.get("status").and_then(Value::as_str) == Some("final")
        && resolution.touches_consent_scope()
    {
        return Err(JacsError::DocumentError(
            "final agreements cannot change consent-scope fields; create a superseding agreement"
                .to_string(),
        ));
    }

    let analysis = analyze_branch_values(&base.value, &previous.value, &side_branch.value)?;
    if !analysis.same_document || !analysis.same_parent {
        return Err(JacsError::DocumentError(format!(
            "agreement branches cannot be resolved from the supplied base: same_document={}, same_parent={}, errors={:?}",
            analysis.same_document, analysis.same_parent, analysis.errors
        )));
    }

    let mut resolved = previous.value.clone();
    apply_mutation_to_document(&mut resolved, resolution)?;
    append_merge_link(agent, &mut resolved, &side_branch.value)?;
    validate_agreement_v2(&resolved)?;
    assert_status_consistent(&resolved)?;
    let resolved_doc = emit_successor(agent, &previous.value, resolved)?;
    let resolved_status = resolved_doc
        .value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    info!(
        event = "agreement_v2_resolved",
        document_id = %resolved_doc.id,
        status = %resolved_status,
        "Agreement v2 branch conflict resolved"
    );
    Ok(resolved_doc)
}

pub fn compute_agreement_hash(document: &Value) -> Result<String, JacsError> {
    // Single-sourced in jacs-core so the native and portable/wasm engines can
    // never produce divergent consent hashes (the canonical signed seam).
    jacs_core::agreements::v2::compute_agreement_hash(document).map_err(JacsError::from)
}

pub fn compute_transcript_hash(document: &Value) -> Result<String, JacsError> {
    jacs_core::agreements::v2::compute_transcript_hash(document).map_err(JacsError::from)
}

/// Reject oversized raw agreement JSON before it is parsed/processed, reusing
/// the shared `JACS_MAX_DOCUMENT_SIZE` document-size limit (DRY). This bounds
/// parse-time and allocation work for untrusted input crossing the binding/FFI
/// boundary.
fn guard_agreement_input_size(raw: &str) -> Result<(), JacsError> {
    crate::schema::utils::check_document_size(raw)
}

fn parse_agreement_value(document: &str) -> Result<Value, JacsError> {
    guard_agreement_input_size(document)?;
    let value: Value = serde_json::from_str(document)?;
    assert_agreement_v2(&value)?;
    Ok(value)
}

fn analyze_branch_values(
    base: &Value,
    left: &Value,
    right: &Value,
) -> Result<AgreementV2MergeAnalysis, JacsError> {
    let base_id = required_str(base, "jacsId")?;
    let base_version = required_str(base, JACS_VERSION_FIELDNAME)?;
    let left_id = required_str(left, "jacsId")?;
    let right_id = required_str(right, "jacsId")?;
    let left_previous = left
        .get(JACS_PREVIOUS_VERSION_FIELDNAME)
        .and_then(Value::as_str);
    let right_previous = right
        .get(JACS_PREVIOUS_VERSION_FIELDNAME)
        .and_then(Value::as_str);

    let same_document = base_id == left_id && base_id == right_id;
    let same_parent = left_previous == Some(base_version) && right_previous == Some(base_version);
    let mut errors = Vec::new();
    if !same_document {
        errors.push("branches do not belong to the same agreement jacsId".to_string());
    }
    if !same_parent {
        errors.push("branches do not share the supplied base as their predecessor".to_string());
    }

    let left_transcript_additions = match transcript_append_additions(base, left)? {
        Some(additions) => additions,
        None => {
            errors.push("left transcript branch is not append-only".to_string());
            Vec::new()
        }
    };
    let right_transcript_additions = match transcript_append_additions(base, right)? {
        Some(additions) => additions,
        None => {
            errors.push("right transcript branch is not append-only".to_string());
            Vec::new()
        }
    };

    let left_changed_fields = changed_fields(base, left, CONSENT_HASH_FIELDS)?;
    let right_changed_fields = changed_fields(base, right, CONSENT_HASH_FIELDS)?;
    let mut conflict_fields = Vec::new();
    for field in CONSENT_HASH_FIELDS {
        let left_changed = left_changed_fields.iter().any(|changed| changed == field);
        let right_changed = right_changed_fields.iter().any(|changed| changed == field);
        if left_changed
            && right_changed
            && !canonical_values_equal(left.get(*field), right.get(*field))?
        {
            conflict_fields.push((*field).to_string());
        }
    }

    let left_guard_changes = changed_fields(base, left, AUTO_MERGE_GUARD_FIELDS)?;
    let right_guard_changes = changed_fields(base, right, AUTO_MERGE_GUARD_FIELDS)?;
    if !left_guard_changes.is_empty() {
        errors.push(format!(
            "left branch changed non-transcript fields that require manual resolution: {:?}",
            left_guard_changes
        ));
    }
    if !right_guard_changes.is_empty() {
        errors.push(format!(
            "right branch changed non-transcript fields that require manual resolution: {:?}",
            right_guard_changes
        ));
    }

    let auto_mergeable = same_document
        && same_parent
        && errors.is_empty()
        && conflict_fields.is_empty()
        && left_changed_fields.is_empty()
        && right_changed_fields.is_empty();

    Ok(AgreementV2MergeAnalysis {
        same_document,
        same_parent,
        auto_mergeable,
        conflict_fields,
        left_changed_fields,
        right_changed_fields,
        left_transcript_additions: left_transcript_additions.len(),
        right_transcript_additions: right_transcript_additions.len(),
        errors,
    })
}

fn changed_fields(base: &Value, branch: &Value, fields: &[&str]) -> Result<Vec<String>, JacsError> {
    let mut changed = Vec::new();
    for field in fields {
        if !canonical_values_equal(base.get(*field), branch.get(*field))? {
            changed.push((*field).to_string());
        }
    }
    Ok(changed)
}

fn transcript_append_additions(
    base: &Value,
    branch: &Value,
) -> Result<Option<Vec<Value>>, JacsError> {
    let base_transcript = transcript_values(base);
    let branch_transcript = transcript_values(branch);
    if branch_transcript.len() < base_transcript.len() {
        return Ok(None);
    }
    for (index, base_entry) in base_transcript.iter().enumerate() {
        if !canonical_values_equal(Some(base_entry), branch_transcript.get(index))? {
            return Ok(None);
        }
    }
    Ok(Some(branch_transcript[base_transcript.len()..].to_vec()))
}

fn transcript_values(document: &Value) -> Vec<Value> {
    document
        .get("transcript")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn canonical_values_equal(left: Option<&Value>, right: Option<&Value>) -> Result<bool, JacsError> {
    let left = left.cloned().unwrap_or(Value::Null);
    let right = right.cloned().unwrap_or(Value::Null);
    Ok(canonicalize_json(&left)? == canonicalize_json(&right)?)
}

fn contains_canonical_value(items: &[Value], candidate: &Value) -> Result<bool, JacsError> {
    for item in items {
        if canonical_values_equal(Some(item), Some(candidate))? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn append_merge_link(
    agent: &Agent,
    document: &mut Value,
    merged_branch: &Value,
) -> Result<(), JacsError> {
    let branch_hash = agent.hash_doc(merged_branch)?;
    let link = json!({
        "jacsId": required_str(merged_branch, "jacsId")?,
        "jacsVersion": required_str(merged_branch, JACS_VERSION_FIELDNAME)?,
        "jacsSha256": branch_hash
    });
    let links = array_mut(document, "links")?;
    if !contains_canonical_value(links, &link)? {
        links.push(link);
    }
    Ok(())
}

fn compute_transcript_prefix_hashes(document: &Value) -> Result<HashSet<String>, JacsError> {
    let transcript = document
        .get("transcript")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut hashes = HashSet::new();
    // Prefix of length 0 is the canonical empty array.
    let mut prefix = String::from("[");
    hashes.insert(hash_string("[]"));
    for (index, entry) in transcript.iter().enumerate() {
        if index > 0 {
            prefix.push(',');
        }
        // Canonicalize each entry exactly once; the canonical form of an array
        // is "[" + comma-joined element canonicalizations + "]" (RFC 8785), so
        // appending one entry's canonical bytes yields the next prefix without
        // re-canonicalizing the whole slice.
        prefix.push_str(&canonicalize_json(entry)?);
        let mut closed = prefix.clone();
        closed.push(']');
        hashes.insert(hash_string(&closed));
    }
    Ok(hashes)
}

pub fn recompute_status(document: &Value) -> String {
    let current_status = document
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("draft");
    if matches!(current_status, "disputed" | "superseded" | "terminated") {
        return current_status.to_string();
    }

    // Quorum satisfaction concludes the agreement. A concluded ("final")
    // agreement is a valid historical terminal state and must NOT be
    // retroactively downgraded to "expired" once `now > expiresAt`: expiry
    // bounds NEW signing, it does not nullify an agreement that already met
    // its signaturePolicy.
    if signature_policy_satisfied(document) {
        return "final".to_string();
    }

    // Not concluded: expiry / timeout move the agreement to a terminal
    // "expired" state that rejects further signatures.
    if agreement_expired(document) || timeout_expired(document) {
        return "expired".to_string();
    }

    if signature_entries(document).next().is_some() {
        return "partially_signed".to_string();
    }

    if current_status == "proposed" {
        "proposed".to_string()
    } else {
        "draft".to_string()
    }
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

fn apply_mutation_to_document(
    document: &mut Value,
    mutation: AgreementV2Mutation,
) -> Result<(), JacsError> {
    match mutation {
        AgreementV2Mutation::AppendTranscript { entry } => {
            array_mut(document, "transcript")?.push(entry);
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
                document["title"] = json!(title);
            }
            if let Some(description) = description {
                document["description"] = json!(description);
            }
            document["terms"] = json!(terms);
            if let Some(terms_format) = terms_format {
                document["termsFormat"] = json!(terms_format);
            }
            set_optional_string(document, "effectiveFrom", effective_from);
            set_optional_string(document, "expiresAt", expires_at);
            clear_agreement_signatures(document);
            reset_status_after_consent_change(document);
            update_agreement_hash(document)?;
        }
        AgreementV2Mutation::SetStatus { status } => {
            document["status"] = json!(status);
        }
        AgreementV2Mutation::SetParties { parties } => {
            document["parties"] = Value::Array(parties);
            clear_agreement_signatures(document);
            reset_status_after_consent_change(document);
            update_agreement_hash(document)?;
        }
        AgreementV2Mutation::SetSignaturePolicy { signature_policy } => {
            document["signaturePolicy"] = signature_policy;
            clear_agreement_signatures(document);
            reset_status_after_consent_change(document);
            update_agreement_hash(document)?;
        }
        AgreementV2Mutation::AddLink { link } => {
            array_mut(document, "links")?.push(link);
        }
        AgreementV2Mutation::SetOwners { owners } => {
            document["owners"] = Value::Array(owners.into_iter().map(Value::String).collect());
        }
    }
    Ok(())
}

fn clear_agreement_signatures(document: &mut Value) {
    document["agreementSignatures"] = json!([]);
}

fn reset_status_after_consent_change(document: &mut Value) {
    if document.get("status").and_then(Value::as_str) != Some("draft") {
        document["status"] = json!("proposed");
    }
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
    if let Some(level) = document.get("jacsLevel").and_then(Value::as_str)
        && level != "artifact"
    {
        return Err(JacsError::DocumentMalformed {
            field: "jacsLevel".to_string(),
            reason: format!("expected artifact, got {}", level),
        });
    }
    validate_agreement_v2(document)?;
    validate_agreement_v2_schema(document)?;
    Ok(())
}

fn validate_agreement_v2_schema(document: &Value) -> Result<(), JacsError> {
    jacs_core::schema::validate_agreement_v2_document(document).map_err(JacsError::from)
}

/// Enforce nesting-depth and per-collection count caps on a parsed agreement
/// document. Iterative (explicit stack) so checking a hostile deeply-nested
/// input cannot itself overflow the stack. Returns `DocumentMalformed` on any
/// breach so callers get a clear typed error instead of a panic/hang.
fn enforce_agreement_resource_limits(document: &Value) -> Result<(), JacsError> {
    // Per-collection count caps (top-level arrays only; nested counts are
    // bounded by the depth + total-byte caps).
    let count_cap = |field: &str, cap: usize| -> Result<(), JacsError> {
        if let Some(items) = document.get(field).and_then(Value::as_array)
            && items.len() > cap
        {
            return Err(malformed(
                field,
                &format!("exceeds maximum of {} entries", cap),
            ));
        }
        Ok(())
    };
    count_cap("transcript", MAX_TRANSCRIPT_ENTRIES)?;
    count_cap("agreementSignatures", MAX_AGREEMENT_SIGNATURES)?;
    count_cap("parties", MAX_PARTIES)?;
    count_cap("links", MAX_LINKS)?;
    count_cap("allPreviousVersions", MAX_PREVIOUS_VERSIONS)?;

    // Iterative nesting-depth bound. The root object is depth 1.
    let mut stack: Vec<(&Value, usize)> = vec![(document, 1)];
    while let Some((value, depth)) = stack.pop() {
        if depth > MAX_AGREEMENT_NESTING_DEPTH {
            return Err(malformed(
                "agreement",
                &format!(
                    "JSON nesting depth exceeds maximum of {}",
                    MAX_AGREEMENT_NESTING_DEPTH
                ),
            ));
        }
        match value {
            Value::Object(map) => {
                for child in map.values() {
                    stack.push((child, depth + 1));
                }
            }
            Value::Array(items) => {
                for child in items {
                    stack.push((child, depth + 1));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_agreement_v2(document: &Value) -> Result<(), JacsError> {
    enforce_agreement_resource_limits(document)?;
    for field in [
        "jacsAgreementHash",
        "title",
        "description",
        "terms",
        "status",
    ] {
        let value = required_str(document, field)?;
        if value.is_empty() {
            return Err(malformed(field, "must not be empty"));
        }
    }

    require_enum(document, "termsFormat", TERMS_FORMATS, true)?;
    require_enum(document, "status", STATUSES, false)?;
    validate_optional_datetime(document, "effectiveFrom")?;
    validate_optional_datetime(document, "expiresAt")?;
    validate_parties(document)?;
    validate_signature_policy(document)?;
    validate_transcript(document)?;
    validate_agreement_signatures_shape(document)?;
    validate_string_array(document, "allPreviousVersions", true)?;
    validate_string_array(document, "controllers", true)?;
    validate_string_array(document, "owners", true)?;
    validate_links(document)?;
    Ok(())
}

fn validate_parties(document: &Value) -> Result<(), JacsError> {
    let parties = array_ref(document, "parties")?;
    if parties.is_empty() {
        return Err(malformed("parties", "must include at least one party"));
    }

    let mut seen_agent_ids = HashSet::new();
    let mut signer_count = 0usize;
    for party in parties {
        let Some(party_object) = party.as_object() else {
            return Err(malformed("parties[]", "expected object"));
        };
        reject_unknown_fields(party_object, "parties[]", PARTY_FIELDS)?;
        for field in ["agentId", "agentType", "role"] {
            if party_object.get(field).and_then(Value::as_str).is_none() {
                return Err(malformed(&format!("parties[].{}", field), "missing string"));
            }
        }
        let agent_id = party_object
            .get("agentId")
            .and_then(Value::as_str)
            .expect("agentId checked above");
        let normalized_agent_id = normalize_agent_id(agent_id).to_string();
        if !seen_agent_ids.insert(normalized_agent_id.clone()) {
            return Err(malformed(
                "parties[].agentId",
                &format!("duplicate party agent id '{}'", normalized_agent_id),
            ));
        }
        enum_value(
            party_object.get("agentType"),
            "parties[].agentType",
            AGENT_TYPES,
        )?;
        enum_value(party_object.get("role"), "parties[].role", PARTY_ROLES)?;
        if party_object.get("role").and_then(Value::as_str) == Some("signer") {
            signer_count += 1;
        }
        if let Some(agent_version) = party_object.get("agentVersion")
            && !agent_version.is_string()
        {
            return Err(malformed("parties[].agentVersion", "expected string"));
        }
        if party_object.contains_key("delegatedBy") {
            return Err(malformed(
                "parties[].delegatedBy",
                "delegation is reserved for a future delegated-signing feature",
            ));
        }
        if let Some(display_name) = party_object.get("displayName")
            && !display_name.is_string()
        {
            return Err(malformed("parties[].displayName", "expected string"));
        }
    }
    if signer_count == 0 {
        return Err(malformed(
            "parties",
            "agreement requires at least one signer-role party",
        ));
    }
    Ok(())
}

fn validate_signature_policy(document: &Value) -> Result<(), JacsError> {
    let policy = document
        .get("signaturePolicy")
        .and_then(Value::as_object)
        .ok_or_else(|| malformed("signaturePolicy", "expected object"))?;
    reject_unknown_fields(policy, "signaturePolicy", SIGNATURE_POLICY_FIELDS)?;

    let quorum = policy
        .get("partyQuorum")
        .ok_or_else(|| malformed("signaturePolicy.partyQuorum", "missing"))?;
    if let Some(kind) = quorum.as_str() {
        if !matches!(kind, "all" | "majority") {
            return Err(malformed(
                "signaturePolicy.partyQuorum",
                "expected all, majority, or positive integer",
            ));
        }
    } else if quorum.as_u64().unwrap_or(0) == 0 {
        return Err(malformed(
            "signaturePolicy.partyQuorum",
            "expected all, majority, or positive integer",
        ));
    }

    for field in ["witnessRequired", "notaryRequired"] {
        if let Some(value) = policy.get(field)
            && value.as_u64().is_none()
        {
            return Err(malformed(
                &format!("signaturePolicy.{}", field),
                "expected non-negative integer",
            ));
        }
    }

    if let Some(required_algorithms) = policy.get("requiredAlgorithms") {
        let Some(algorithms) = required_algorithms.as_array() else {
            return Err(malformed(
                "signaturePolicy.requiredAlgorithms",
                "expected array",
            ));
        };
        if algorithms.iter().any(|algorithm| !algorithm.is_string()) {
            return Err(malformed(
                "signaturePolicy.requiredAlgorithms[]",
                "expected string",
            ));
        }
    }

    if let Some(minimum_strength) = policy.get("minimumStrength") {
        enum_value(
            Some(minimum_strength),
            "signaturePolicy.minimumStrength",
            MINIMUM_STRENGTHS,
        )?;
    }
    if let Some(timeout) = policy.get("timeout")
        && !timeout.is_string()
    {
        return Err(malformed("signaturePolicy.timeout", "expected string"));
    }
    validate_policy_datetime(policy, "timeout")?;

    validate_signature_policy_counts(document)?;

    Ok(())
}

fn validate_signature_policy_counts(document: &Value) -> Result<(), JacsError> {
    let (signer_total, witness_total, notary_total) = party_role_totals(document);
    let party_quorum = party_quorum_required(document, signer_total);
    if party_quorum > signer_total {
        return Err(malformed(
            "signaturePolicy.partyQuorum",
            "cannot exceed signer-role party count",
        ));
    }

    let witness_required = policy_count(document, "witnessRequired");
    if witness_required > witness_total {
        return Err(malformed(
            "signaturePolicy.witnessRequired",
            "cannot exceed witness-role party count",
        ));
    }

    let notary_required = policy_count(document, "notaryRequired");
    if notary_required > notary_total {
        return Err(malformed(
            "signaturePolicy.notaryRequired",
            "cannot exceed notary-role party count",
        ));
    }

    Ok(())
}

fn validate_transcript(document: &Value) -> Result<(), JacsError> {
    if document.get("transcript").is_none() {
        return Ok(());
    }
    for entry in array_ref(document, "transcript")? {
        validate_document_ref(entry, "transcript[]")?;
    }
    Ok(())
}

fn validate_agreement_signatures_shape(document: &Value) -> Result<(), JacsError> {
    for entry in array_ref(document, "agreementSignatures")? {
        let Some(entry_object) = entry.as_object() else {
            return Err(malformed("agreementSignatures[]", "expected object"));
        };
        reject_unknown_fields(
            entry_object,
            "agreementSignatures[]",
            AGREEMENT_SIGNATURE_FIELDS,
        )?;
        if !entry_object.contains_key("signature") {
            return Err(malformed("agreementSignatures[].signature", "missing"));
        }
        enum_value(
            entry_object.get("role"),
            "agreementSignatures[].role",
            SIGNATURE_ROLES,
        )?;
        if let Some(signed_transcript_hash) = entry_object.get("signedTranscriptHash")
            && !signed_transcript_hash.is_string()
        {
            return Err(malformed(
                "agreementSignatures[].signedTranscriptHash",
                "expected string",
            ));
        }
        if entry_object.contains_key("delegationChain") {
            return Err(malformed(
                "agreementSignatures[].delegationChain",
                "delegation is reserved for a future delegated-signing feature",
            ));
        }
    }
    Ok(())
}

fn validate_links(document: &Value) -> Result<(), JacsError> {
    if document.get("links").is_none() {
        return Ok(());
    }
    for link in array_ref(document, "links")? {
        let Some(link_object) = link.as_object() else {
            return Err(malformed("links[]", "expected object"));
        };
        reject_unknown_fields(link_object, "links[]", AGREEMENT_LINK_FIELDS)?;
        for field in ["jacsId", "jacsVersion"] {
            if link_object.get(field).and_then(Value::as_str).is_none() {
                return Err(malformed(&format!("links[].{}", field), "missing string"));
            }
        }
        if let Some(hash) = link_object.get(SHA256_FIELDNAME) {
            match hash.as_str() {
                Some(hash) if !hash.is_empty() => {}
                _ => return Err(malformed("links[].jacsSha256", "missing non-empty string")),
            }
        }
    }
    Ok(())
}

fn validate_document_ref(value: &Value, field: &str) -> Result<(), JacsError> {
    let Some(object) = value.as_object() else {
        return Err(malformed(field, "expected object"));
    };
    reject_unknown_fields(object, field, JACS_DOCUMENT_REF_FIELDS)?;
    for key in ["jacsId", "jacsVersion", "jacsSha256"] {
        if object.get(key).and_then(Value::as_str).is_none() {
            return Err(malformed(&format!("{}.{}", field, key), "missing string"));
        }
    }
    Ok(())
}

fn validate_string_array(document: &Value, field: &str, optional: bool) -> Result<(), JacsError> {
    if optional && document.get(field).is_none() {
        return Ok(());
    }
    let items = array_ref(document, field)?;
    if items.iter().any(|item| !item.is_string()) {
        return Err(malformed(&format!("{}[]", field), "expected string"));
    }
    let mut seen = HashSet::new();
    for item in items {
        let value = item.as_str().expect("string checked above");
        if !seen.insert(value) {
            return Err(malformed(
                &format!("{}[]", field),
                "duplicate values are not allowed",
            ));
        }
    }
    Ok(())
}

fn validate_optional_datetime(document: &Value, field: &str) -> Result<(), JacsError> {
    let Some(value) = document.get(field) else {
        return Ok(());
    };
    let Some(value) = value.as_str() else {
        return Err(malformed(field, "expected string"));
    };
    time_utils::parse_rfc3339_to_timestamp(value)
        .map(|_| ())
        .map_err(|err| malformed(field, &format!("invalid RFC3339 timestamp: {}", err)))
}

fn validate_policy_datetime(policy: &Map<String, Value>, field: &str) -> Result<(), JacsError> {
    let Some(value) = policy.get(field) else {
        return Ok(());
    };
    let Some(value) = value.as_str() else {
        return Err(malformed(
            &format!("signaturePolicy.{}", field),
            "expected string",
        ));
    };
    time_utils::parse_rfc3339_to_timestamp(value)
        .map(|_| ())
        .map_err(|err| {
            malformed(
                &format!("signaturePolicy.{}", field),
                &format!("invalid RFC3339 timestamp: {}", err),
            )
        })
}

fn reject_unknown_fields(
    object: &Map<String, Value>,
    field: &str,
    allowed: &[&str],
) -> Result<(), JacsError> {
    if let Some(extra) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(malformed(
            &format!("{}.{}", field, extra),
            &format!("unknown field; expected only {}", allowed.join(", ")),
        ));
    }
    Ok(())
}

fn require_enum(
    document: &Value,
    field: &str,
    allowed: &[&str],
    optional: bool,
) -> Result<(), JacsError> {
    if optional && document.get(field).is_none() {
        return Ok(());
    }
    enum_value(document.get(field), field, allowed)
}

fn enum_value(value: Option<&Value>, field: &str, allowed: &[&str]) -> Result<(), JacsError> {
    let Some(value) = value.and_then(Value::as_str) else {
        return Err(malformed(field, "missing string"));
    };
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(malformed(
            field,
            &format!("expected one of {}", allowed.join(", ")),
        ))
    }
}

fn array_ref<'a>(document: &'a Value, field: &str) -> Result<&'a Vec<Value>, JacsError> {
    document
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| malformed(field, "expected array"))
}

fn malformed(field: &str, reason: &str) -> JacsError {
    JacsError::DocumentMalformed {
        field: field.to_string(),
        reason: reason.to_string(),
    }
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

fn assert_status_consistent(document: &Value) -> Result<(), JacsError> {
    let status = required_str(document, "status")?;
    let expected_status = recompute_status(document);
    if status == expected_status {
        Ok(())
    } else {
        Err(JacsError::DocumentError(format!(
            "status '{}' is inconsistent with agreement policy; expected '{}'",
            status, expected_status
        )))
    }
}

fn assert_within_signing_window(document: &Value) -> Result<(), JacsError> {
    // effectiveFrom: a party may not sign before the agreement is effective.
    if let Some(effective_from) = document.get("effectiveFrom").and_then(Value::as_str)
        && let Ok(effective_ts) = time_utils::parse_rfc3339_to_timestamp(effective_from)
        && effective_ts > time_utils::now_timestamp()
    {
        return Err(JacsError::DocumentError(format!(
            "agreement is not yet effective (effectiveFrom '{}'); signing is not permitted until then",
            effective_from
        )));
    }
    // expiresAt / timeout: a party may not sign an expired agreement.
    if agreement_expired(document) || timeout_expired(document) {
        return Err(JacsError::DocumentError(
            "agreement signing window has closed (past expiresAt/timeout); no new signatures are accepted"
                .to_string(),
        ));
    }
    Ok(())
}

fn assert_accepts_signature(document: &Value) -> Result<(), JacsError> {
    assert_status_consistent(document)?;
    assert_within_signing_window(document)?;
    let status = required_str(document, "status")?;
    if TERMINAL_NON_SIGNING_STATUSES.contains(&status) {
        Err(JacsError::DocumentError(format!(
            "agreement status '{}' does not accept new signatures",
            status
        )))
    } else {
        Ok(())
    }
}

fn assert_party_role_and_version(
    document: &Value,
    agent_id: &str,
    agent_version: Option<&str>,
    role: Role,
) -> Result<(), JacsError> {
    let found = party_roles(document)
        .into_iter()
        .any(|(party_id, party_role)| party_id == agent_id && party_role == role);
    if !found {
        return Err(JacsError::DocumentError(format!(
            "Agent '{}' is not listed as a {} party",
            agent_id,
            role.as_str()
        )));
    }

    let Some(expected_version) = party_agent_version(document, agent_id) else {
        return Ok(());
    };
    match agent_version {
        Some(actual_version) if actual_version == expected_version => Ok(()),
        Some(actual_version) => Err(JacsError::DocumentError(format!(
            "Agent '{}' signed with agentVersion '{}' but party requires agentVersion '{}'",
            agent_id, actual_version, expected_version
        ))),
        None => Err(JacsError::DocumentError(format!(
            "Agent '{}' is pinned to agentVersion '{}' but signature has no agentVersion",
            agent_id, expected_version
        ))),
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

/// Parse + validate (JSON schema + hash) an agreement document WITHOUT persisting it.
///
/// `Agent::load_document` performs the same `validate_header` checks but then
/// calls `store_jacs_document`, persisting attacker-controlled input before any
/// verdict is known. Read-only operations (verify, merge/resolve input parsing)
/// must use this instead so they never write unverified documents to storage.
fn load_agreement_no_store(agent: &mut Agent, document: &str) -> Result<JACSDocument, JacsError> {
    guard_agreement_input_size(document)?;
    let value = agent.validate_header(document)?;
    let id = required_str(&value, "jacsId")?.to_string();
    let version = required_str(&value, JACS_VERSION_FIELDNAME)?.to_string();
    let jacs_type = required_str(&value, "jacsType")?.to_string();
    Ok(JACSDocument {
        id,
        version,
        value,
        jacs_type,
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
    validate_agreement_v2_schema(&next)?;
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
    transcript_prefix_hashes: &HashSet<String>,
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
    let signature_agent_version = signature.get("agentVersion").and_then(Value::as_str);
    let signer_id = normalize_agent_id(signature_agent).to_string();
    assert_party_role_and_version(document, &signer_id, signature_agent_version, role)?;
    verify_signature_policy_for_signature(document, signature)?;

    let transcript_non_empty = transcript_array(document).is_some_and(|items| !items.is_empty());
    let mut signature_context = json!({
        "jacsId": required_str(document, "jacsId")?,
        "jacsAgreementHash": required_str(document, "jacsAgreementHash")?,
        AGREEMENT_SIGNATURE_PLACEMENT: signature.clone()
    });
    let mut fields = vec!["jacsId".to_string(), "jacsAgreementHash".to_string()];
    let signed_transcript_hash = entry.get("signedTranscriptHash").and_then(Value::as_str);
    if let Some(signed_transcript_hash) = signed_transcript_hash {
        if !transcript_prefix_hashes.contains(signed_transcript_hash) {
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
    let metadata_fields: Vec<String> = signature
        .get("fields")
        .and_then(Value::as_array)
        .ok_or_else(|| JacsError::DocumentMalformed {
            field: "agreementSignatures[].signature.fields".to_string(),
            reason: "missing or invalid fields".to_string(),
        })?
        .iter()
        .filter_map(|field| field.as_str().map(str::to_string))
        .collect();
    for required_field in &fields {
        if !metadata_fields.iter().any(|field| field == required_field) {
            return Err(JacsError::DocumentMalformed {
                field: "agreementSignatures[].signature.fields".to_string(),
                reason: format!("missing signed field '{}'", required_field),
            });
        }
    }
    fields = metadata_fields;

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
            if !counts.signers.insert(signer_id.clone()) {
                return Err(JacsError::DocumentError(format!(
                    "Agent '{}' has already signed as signer",
                    signer_id
                )));
            }
        }
        Role::Witness => {
            if !counts.witnesses.insert(signer_id.clone()) {
                return Err(JacsError::DocumentError(format!(
                    "Agent '{}' has already signed as witness",
                    signer_id
                )));
            }
        }
        Role::Notary => {
            if !counts.notaries.insert(signer_id.clone()) {
                return Err(JacsError::DocumentError(format!(
                    "Agent '{}' has already signed as notary",
                    signer_id
                )));
            }
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

fn verify_header_signature_and_controller(
    agent: &mut Agent,
    document: &Value,
) -> Result<(), JacsError> {
    let signature = document
        .get(DOCUMENT_AGENT_SIGNATURE_FIELDNAME)
        .ok_or_else(|| malformed(DOCUMENT_AGENT_SIGNATURE_FIELDNAME, "missing"))?;
    let signer = signature
        .get("agentID")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("jacsSignature.agentID", "missing string"))?;
    let normalized_signer = normalize_agent_id(signer).to_string();
    if !controller_allows(document, &normalized_signer)? {
        return Err(JacsError::DocumentError(format!(
            "header signer '{}' is not a controller for agreement '{}'",
            normalized_signer,
            document
                .get("jacsId")
                .and_then(Value::as_str)
                .unwrap_or("<unknown>")
        )));
    }

    let (public_key, public_key_type, public_key_hash) =
        resolve_signature_public_key(agent, signature)?;
    agent.signature_verification_procedure(
        document,
        None,
        DOCUMENT_AGENT_SIGNATURE_FIELDNAME,
        public_key,
        Some(public_key_type),
        Some(public_key_hash),
        None,
    )
}

fn verify_merge_links(agent: &mut Agent, document: &Value) -> (Vec<String>, Vec<String>, bool) {
    let mut errors = Vec::new();
    let mut notes = Vec::new();
    let mut all_targets_loaded = true;
    let Some(links) = document.get("links").and_then(Value::as_array) else {
        return (errors, notes, all_targets_loaded);
    };

    for link in links {
        let Some(recorded_hash) = link.get(SHA256_FIELDNAME).and_then(Value::as_str) else {
            continue;
        };
        let id = link.get("jacsId").and_then(Value::as_str).unwrap_or("");
        let version = link
            .get(JACS_VERSION_FIELDNAME)
            .and_then(Value::as_str)
            .unwrap_or("");
        if id.is_empty() || version.is_empty() {
            continue;
        }

        let key = format!("{}:{}", id, version);
        let Ok(linked_doc) = agent.get_document(&key) else {
            all_targets_loaded = false;
            notes.push(format!(
                "merge link target {}:{} could not be loaded; merge content not revalidated",
                id, version
            ));
            continue;
        };

        match agent.hash_doc(&linked_doc.value) {
            Ok(recomputed_hash) if recomputed_hash == recorded_hash => {}
            Ok(recomputed_hash) => errors.push(format!(
                "merge link target {}:{} content hash mismatch: link records {}, recomputed {}",
                id, version, recorded_hash, recomputed_hash
            )),
            Err(err) => errors.push(format!(
                "merge link target {}:{} content hash could not be recomputed: {}",
                id, version, err
            )),
        }
    }

    (errors, notes, all_targets_loaded)
}

fn check_freshness(agent: &mut Agent, document: &Value) -> Option<String> {
    let jacs_id = document.get("jacsId").and_then(Value::as_str)?;
    let current_version = document
        .get(JACS_VERSION_FIELDNAME)
        .and_then(Value::as_str)?;
    let current_version_date = document
        .get(JACS_VERSION_DATE_FIELDNAME)
        .and_then(Value::as_str)?;
    let current_timestamp = time_utils::parse_rfc3339_to_timestamp(current_version_date).ok()?;
    let prefix = format!("{}:", jacs_id);
    let mut latest_newer_version: Option<(i64, String)> = None;

    for key in agent.get_document_keys() {
        if !key.starts_with(&prefix) {
            continue;
        }
        let Ok(stored_doc) = agent.get_document(&key) else {
            continue;
        };
        let Some(version) = stored_doc
            .value
            .get(JACS_VERSION_FIELDNAME)
            .and_then(Value::as_str)
        else {
            continue;
        };
        if version == current_version {
            continue;
        }
        let Some(version_date) = stored_doc
            .value
            .get(JACS_VERSION_DATE_FIELDNAME)
            .and_then(Value::as_str)
        else {
            continue;
        };
        let Ok(timestamp) = time_utils::parse_rfc3339_to_timestamp(version_date) else {
            continue;
        };
        if timestamp <= current_timestamp {
            continue;
        }

        let replace = latest_newer_version
            .as_ref()
            .map(|(latest_timestamp, _)| timestamp > *latest_timestamp)
            .unwrap_or(true);
        if replace {
            latest_newer_version = Some((timestamp, version.to_string()));
        }
    }

    latest_newer_version.map(|(_, newer_version)| {
        format!(
            "a newer stored version exists for this agreement; verified document may be superseded by {}",
            newer_version
        )
    })
}

fn verify_previous_versions_chain(agent: &mut Agent, document: &Value) -> ChainVerification {
    let Some(all_previous_versions) = document
        .get("allPreviousVersions")
        .and_then(Value::as_array)
    else {
        return ChainVerification {
            error: Some(
                "jacsPreviousVersion chain cannot be verified because allPreviousVersions is missing"
                    .to_string(),
            ),
            verified_depth: 0,
            fully_verified: false,
            notes: Vec::new(),
        };
    };
    let listed_versions: Result<Vec<String>, String> = all_previous_versions
        .iter()
        .map(|version| {
            version
                .as_str()
                .map(ToString::to_string)
                .ok_or_else(|| "allPreviousVersions contains a non-string value".to_string())
        })
        .collect();
    let listed_versions = match listed_versions {
        Ok(listed_versions) => listed_versions,
        Err(err) => {
            return ChainVerification {
                error: Some(err),
                verified_depth: 0,
                fully_verified: false,
                notes: Vec::new(),
            };
        }
    };

    let Some(previous_version) = document
        .get(JACS_PREVIOUS_VERSION_FIELDNAME)
        .and_then(Value::as_str)
    else {
        if listed_versions.is_empty() {
            return ChainVerification {
                error: None,
                verified_depth: 0,
                fully_verified: true,
                notes: Vec::new(),
            };
        }
        return ChainVerification {
            error: Some(
                "allPreviousVersions is non-empty but jacsPreviousVersion is missing".to_string(),
            ),
            verified_depth: 0,
            fully_verified: false,
            notes: Vec::new(),
        };
    };

    if all_previous_versions.last().and_then(Value::as_str) != Some(previous_version) {
        return ChainVerification {
            error: Some(
                "allPreviousVersions does not reconcile with jacsPreviousVersion".to_string(),
            ),
            verified_depth: 0,
            fully_verified: false,
            notes: Vec::new(),
        };
    }

    let Some(jacs_id) = document.get("jacsId").and_then(Value::as_str) else {
        return ChainVerification {
            error: Some("allPreviousVersions chain cannot be verified without jacsId".to_string()),
            verified_depth: 0,
            fully_verified: false,
            notes: Vec::new(),
        };
    };

    let mut walked_versions = Vec::new();
    let mut cursor = Some(previous_version.to_string());
    let mut guard = 0usize;
    let mut verification = ChainVerification {
        error: None,
        verified_depth: 0,
        fully_verified: true,
        notes: Vec::new(),
    };
    while let Some(version) = cursor {
        guard += 1;
        if guard > listed_versions.len() + 1 {
            verification.error =
                Some("allPreviousVersions chain appears to contain a cycle".to_string());
            verification.fully_verified = false;
            return verification;
        }
        let key = format!("{}:{}", jacs_id, version);
        let Ok(previous_doc) = agent.get_document(&key) else {
            walked_versions.reverse();
            if let Err(err) = verify_walked_version_suffix(&listed_versions, &walked_versions) {
                verification.error = Some(err);
            } else {
                verification.fully_verified = false;
                verification.notes.push(format!(
                    "prior version '{}' referenced in allPreviousVersions could not be loaded; chain not fully verified",
                    version
                ));
            }
            return verification;
        };
        if let Err(err) = verify_header_signature_and_controller(agent, &previous_doc.value) {
            verification.error = Some(format!(
                "prior version '{}' failed header verification: {}",
                version, err
            ));
            verification.fully_verified = false;
            return verification;
        }
        verification.verified_depth += 1;
        walked_versions.push(version.clone());
        cursor = previous_doc
            .value
            .get(JACS_PREVIOUS_VERSION_FIELDNAME)
            .and_then(Value::as_str)
            .map(ToString::to_string);
    }

    walked_versions.reverse();
    if walked_versions == listed_versions {
        return verification;
    }

    verification.error = Some(format!(
        "allPreviousVersions does not reconcile with stored jacsPreviousVersion chain: listed {:?}, walked {:?}",
        listed_versions, walked_versions
    ));
    verification.fully_verified = false;
    verification
}

fn verify_walked_version_suffix(
    listed_versions: &[String],
    walked_versions: &[String],
) -> Result<(), String> {
    if walked_versions.is_empty() {
        return Ok(());
    }
    if walked_versions.len() > listed_versions.len() {
        return Err(format!(
            "allPreviousVersions does not reconcile with stored jacsPreviousVersion chain: listed {:?}, walked {:?}",
            listed_versions, walked_versions
        ));
    }
    let suffix = &listed_versions[listed_versions.len() - walked_versions.len()..];
    if suffix == walked_versions {
        Ok(())
    } else {
        Err(format!(
            "allPreviousVersions does not reconcile with stored jacsPreviousVersion chain: listed {:?}, walked {:?}",
            listed_versions, walked_versions
        ))
    }
}

fn controller_allows(document: &Value, normalized_agent_id: &str) -> Result<bool, JacsError> {
    let controllers = document
        .get("controllers")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("controllers", "agreement requires controllers[]"))?;
    Ok(controllers.iter().any(|id| {
        id.as_str()
            .map(|id| normalize_agent_id(id) == normalized_agent_id)
            .unwrap_or(false)
    }))
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

fn party_role_totals(document: &Value) -> (usize, usize, usize) {
    let mut signer_total = 0usize;
    let mut witness_total = 0usize;
    let mut notary_total = 0usize;
    for role in party_roles(document).values() {
        match role {
            Role::Signer => signer_total += 1,
            Role::Witness => witness_total += 1,
            Role::Notary => notary_total += 1,
            Role::Observer => {}
        }
    }
    (signer_total, witness_total, notary_total)
}

fn party_agent_version(document: &Value, agent_id: &str) -> Option<String> {
    document
        .get("parties")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find_map(|party| {
            let party_id = party.get("agentId").and_then(Value::as_str)?;
            if normalize_agent_id(party_id) == agent_id {
                party
                    .get("agentVersion")
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
            } else {
                None
            }
        })
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

fn signature_policy_past_point_of_reliance(document: &Value) -> bool {
    jacs_core::agreements::v2::signature_policy_past_point_of_reliance(document)
}

fn signature_policy_is_weaker(current_doc: &Value, new_policy: &Value) -> bool {
    jacs_core::agreements::v2::signature_policy_is_weaker(current_doc, new_policy)
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

fn agreement_expired(document: &Value) -> bool {
    let Some(expires_at) = document.get("expiresAt").and_then(Value::as_str) else {
        return false;
    };
    time_utils::parse_rfc3339_to_timestamp(expires_at)
        .map(|deadline| deadline < time_utils::now_timestamp())
        .unwrap_or(false)
}

#[cfg(test)]
mod differential_parity {
    //! Differential parity between the two Agreement v2 engines.
    //!
    //! A document signed under one engine may be judged under the other
    //! (native signs, WASM/browser verifies, and vice versa), so the pure
    //! agreement *policy* functions — status recomputation, consent /
    //! transcript hashing, and the signature-policy guards — MUST agree
    //! byte-for-byte on every valid agreement. This test pins that agreement
    //! across a broad generated corpus.
    //!
    //! It was written against two parallel implementations and used as the
    //! safety net for single-sourcing them: the hashing and policy-guard
    //! helpers in this module now delegate to `jacs_core::agreements::v2`, so
    //! for those the assertions guard against a divergent native
    //! reimplementation ever being reintroduced. `recompute_status` remains a
    //! genuinely independent native implementation (merging it would drag
    //! agent-coupled scaffolding across crates), so for it this test is the
    //! live cross-engine equivalence proof. The corpus is restricted to
    //! *valid* agreements (signatures only from listed parties with matching
    //! roles), which is the input contract both engines enforce upstream of
    //! these pure functions.
    use jacs_core::agreements::v2 as core_v2;
    use serde_json::{Map, Value, json};

    const PAST: &str = "2000-01-01T00:00:00Z";
    const FUTURE: &str = "2999-01-01T00:00:00Z";

    fn party(id: &str, role: &str) -> Value {
        json!({
            "agentId": id,
            "agentVersion": "00000000-0000-0000-0000-000000000001",
            "agentType": "ai",
            "role": role,
        })
    }

    fn signature(agent_id: &str, role: &str) -> Value {
        json!({
            "role": role,
            "signature": { "agentID": agent_id },
        })
    }

    fn policy(
        party_quorum: Option<Value>,
        witness_required: u64,
        notary_required: u64,
        minimum_strength: Option<&str>,
        required_algorithms: Option<Vec<&str>>,
        timeout: Option<&str>,
    ) -> Value {
        let mut p = Map::new();
        if let Some(q) = party_quorum {
            p.insert("partyQuorum".into(), q);
        }
        p.insert("witnessRequired".into(), json!(witness_required));
        p.insert("notaryRequired".into(), json!(notary_required));
        if let Some(s) = minimum_strength {
            p.insert("minimumStrength".into(), json!(s));
        }
        if let Some(a) = required_algorithms {
            p.insert("requiredAlgorithms".into(), json!(a));
        }
        if let Some(t) = timeout {
            p.insert("timeout".into(), json!(t));
        }
        Value::Object(p)
    }

    /// A broad, deterministic corpus of valid agreement documents. Primary axes
    /// (party shape, quorum policy, signature progress, status, expiry) are
    /// enumerated exhaustively; secondary axes (strength, algorithms, timeout,
    /// effectiveFrom, transcript, prior versions, witness/notary signing) are
    /// rotated by a running index so every combination is exercised somewhere
    /// without a full cartesian explosion.
    fn corpus() -> Vec<Value> {
        // Includes numeric quorums at, above, and well above the signer count
        // (3, 5) so the "no clamp to signer total" arithmetic both engines share
        // is exercised on the over-quorum path.
        let pq_opts: [Option<Value>; 6] = [
            None,
            Some(json!("majority")),
            Some(json!(1)),
            Some(json!(2)),
            Some(json!(3)),
            Some(json!(5)),
        ];
        let strengths = [None, Some("classical"), Some("post-quantum")];
        let algs: [Option<Vec<&str>>; 3] = [
            None,
            Some(vec!["ring-Ed25519"]),
            Some(vec!["ring-Ed25519", "pq2025"]),
        ];
        let timeouts = [None, Some(PAST), Some(FUTURE)];
        let efroms = [None, Some(PAST)];
        let transcripts = [0usize, 1, 2];
        let prevs = [0usize, 1];
        let statuses = ["draft", "proposed", "partially_signed", "final"];
        let expiries = [None, Some(PAST), Some(FUTURE)];

        let mut out = Vec::new();
        let mut idx = 0usize;

        for s in 1..=3usize {
            for w in 0..=1usize {
                for n in 0..=1usize {
                    let mut parties = Vec::new();
                    let mut signer_ids = Vec::new();
                    for i in 0..s {
                        let id = format!("agent-s{i}");
                        parties.push(party(&id, "signer"));
                        signer_ids.push(id);
                    }
                    let mut witness_ids = Vec::new();
                    for i in 0..w {
                        let id = format!("agent-w{i}");
                        parties.push(party(&id, "witness"));
                        witness_ids.push(id);
                    }
                    let mut notary_ids = Vec::new();
                    for i in 0..n {
                        let id = format!("agent-n{i}");
                        parties.push(party(&id, "notary"));
                        notary_ids.push(id);
                    }

                    let signed_signer_opts = {
                        let mut v = vec![0usize, 1usize, s];
                        v.sort_unstable();
                        v.dedup();
                        v
                    };

                    for party_quorum in &pq_opts {
                        for witness_required in 0..=1u64 {
                            for notary_required in 0..=1u64 {
                                for &signed_signers in &signed_signer_opts {
                                    for &status in &statuses {
                                        for &expires in &expiries {
                                            idx += 1;
                                            let minimum_strength = strengths[idx % 3];
                                            let required_algorithms = algs[(idx / 3) % 3].clone();
                                            let timeout = timeouts[(idx / 9) % 3];
                                            let efrom = efroms[(idx / 27) % 2];
                                            let n_trans = transcripts[(idx / 54) % 3];
                                            let n_prev = prevs[(idx / 108) % 2];
                                            let sign_witnesses = (idx / 2).is_multiple_of(2);
                                            let sign_notaries = (idx / 4).is_multiple_of(2);
                                            // Signatures carry an `agentId:version`
                                            // suffix while parties stay bare, so the
                                            // `normalize_agent_id` (split-on-`:`) path
                                            // both engines use to match a signature to
                                            // its party is exercised.
                                            let suffix_sig_ids = (idx / 8).is_multiple_of(2);
                                            // A second entry from the first signer (a
                                            // different version of the same agent) must
                                            // de-duplicate to one signer in BOTH engines.
                                            let duplicate_signer_sig = (idx / 16).is_multiple_of(2);
                                            let sig_id = |id: &str, tag: &str| -> String {
                                                if suffix_sig_ids {
                                                    format!("{id}:{tag}")
                                                } else {
                                                    id.to_string()
                                                }
                                            };

                                            let pol = policy(
                                                party_quorum.clone(),
                                                witness_required,
                                                notary_required,
                                                minimum_strength,
                                                required_algorithms,
                                                timeout,
                                            );

                                            let mut sigs = Vec::new();
                                            for id in signer_ids.iter().take(signed_signers) {
                                                sigs.push(signature(&sig_id(id, "v1"), "signer"));
                                            }
                                            if duplicate_signer_sig && signed_signers > 0 {
                                                sigs.push(signature(
                                                    &sig_id(&signer_ids[0], "v2"),
                                                    "signer",
                                                ));
                                            }
                                            if sign_witnesses {
                                                for id in &witness_ids {
                                                    sigs.push(signature(
                                                        &sig_id(id, "v1"),
                                                        "witness",
                                                    ));
                                                }
                                            }
                                            if sign_notaries {
                                                for id in &notary_ids {
                                                    sigs.push(signature(
                                                        &sig_id(id, "v1"),
                                                        "notary",
                                                    ));
                                                }
                                            }

                                            let mut doc = Map::new();
                                            doc.insert(
                                                "title".into(),
                                                json!(format!("Agreement {idx}")),
                                            );
                                            doc.insert("description".into(), json!("d"));
                                            doc.insert("terms".into(), json!("the terms"));
                                            doc.insert("termsFormat".into(), json!("text/plain"));
                                            if let Some(ef) = efrom {
                                                doc.insert("effectiveFrom".into(), json!(ef));
                                            }
                                            if let Some(ex) = expires {
                                                doc.insert("expiresAt".into(), json!(ex));
                                            }
                                            doc.insert("parties".into(), json!(parties));
                                            doc.insert("signaturePolicy".into(), pol);
                                            doc.insert("agreementSignatures".into(), json!(sigs));
                                            doc.insert("status".into(), json!(status));
                                            let trans: Vec<Value> = (0..n_trans)
                                                .map(|t| json!({"seq": t, "note": format!("entry {t}")}))
                                                .collect();
                                            doc.insert("transcript".into(), json!(trans));
                                            let prev: Vec<Value> = (0..n_prev)
                                                .map(|p| json!({"jacsId": "prev", "jacsVersion": format!("v{p}")}))
                                                .collect();
                                            doc.insert("allPreviousVersions".into(), json!(prev));

                                            out.push(Value::Object(doc));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        out
    }

    /// Candidate replacement signature policies, spanning weaker / equal /
    /// stronger relative to a corpus document, to exercise every branch of the
    /// quorum-loosening guard.
    fn candidate_policies() -> Vec<Value> {
        vec![
            policy(None, 0, 0, None, None, None),
            policy(Some(json!("majority")), 0, 0, None, None, None),
            policy(Some(json!(1)), 0, 0, None, None, None),
            policy(Some(json!(2)), 1, 1, None, None, None),
            policy(None, 1, 0, None, None, None),
            policy(None, 0, 1, None, None, None),
            policy(None, 0, 0, Some("classical"), None, None),
            policy(None, 0, 0, Some("post-quantum"), None, None),
            policy(None, 0, 0, None, Some(vec!["ring-Ed25519"]), None),
            policy(None, 0, 0, None, Some(vec!["ring-Ed25519", "pq2025"]), None),
            policy(None, 0, 0, None, Some(vec![]), None),
        ]
    }

    #[test]
    fn engines_agree_on_status_and_hashes() {
        let corpus = corpus();
        assert!(corpus.len() > 1000, "corpus too small: {}", corpus.len());
        for doc in &corpus {
            assert_eq!(
                super::recompute_status(doc),
                core_v2::recompute_status(doc),
                "recompute_status mismatch for {doc}"
            );
            assert_eq!(
                super::compute_agreement_hash(doc).unwrap(),
                core_v2::compute_agreement_hash(doc).unwrap(),
                "compute_agreement_hash mismatch for {doc}"
            );
            assert_eq!(
                super::compute_transcript_hash(doc).unwrap(),
                core_v2::compute_transcript_hash(doc).unwrap(),
                "compute_transcript_hash mismatch for {doc}"
            );
            assert_eq!(
                super::signature_policy_past_point_of_reliance(doc),
                core_v2::signature_policy_past_point_of_reliance(doc),
                "signature_policy_past_point_of_reliance mismatch for {doc}"
            );
        }
    }

    #[test]
    fn engines_agree_on_policy_weakening() {
        let candidates = candidate_policies();
        for doc in &corpus() {
            for cand in &candidates {
                assert_eq!(
                    super::signature_policy_is_weaker(doc, cand),
                    core_v2::signature_policy_is_weaker(doc, cand),
                    "signature_policy_is_weaker mismatch\n  doc={doc}\n  candidate={cand}"
                );
            }
        }
    }
}
