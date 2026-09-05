//! Portable, actionable Agreement v3 protocol.
//!
//! V1 is an unauthenticated-policy sidecar and v2 party proofs do not bind a
//! role or portable finalization policy.  This module is intentionally a new
//! wire protocol rather than an in-place reinterpretation of either format.
//! It performs no I/O: callers select immutable schema bundles, identity
//! anchors, trust-row digests, verification policy, keys, and (for amendments)
//! the accepted predecessor before invoking the verifier.

use crate::CoreError;
use crate::agent::CoreAgent;
use crate::canonical::canonicalize_json_try;
use crate::sign::SigningAlgorithm;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::error::Error;

use crate::identity::BootstrapProfile;
pub use crate::identity::{
    AuthorityAnchor as AuthorityAnchorV3, IdentityAnchor as IdentityAnchorV3,
};
use crate::signing::SigningOperation;
pub use crate::verification::TemporalExpectation as TemporalExpectationV3;
use crate::verification::{
    DetachedProofInput, ExactExpectation, FieldStatus, ObservationPolicy, ReportField,
    VerificationIntent, VerificationPolicy, VersionExpectation, detached_proof_integrity_report,
    missing_proof_integrity_report,
};

pub const AGREEMENT_V3_SCHEMA_ID: &str =
    "https://hai.ai/schemas/agreement/v3/agreement.schema.json";
pub const AGREEMENT_V3_PROFILE: &str = "jacs-agreement-v3";
pub const FINALIZATION_V3_PROFILE: &str = "jacs-agreement-finalization-v3";
pub const PROOF_SIGNATURE_DOMAIN: &str = "JACS-AGREEMENT-PROOF-V3";
pub const HUMAN_SEAL_SIGNATURE_DOMAIN: &str = "JACS-AGREEMENT-HUMAN-SEAL-V1";
pub const AUTHORITY_RECORD_SIGNATURE_DOMAIN: &str = "JACS-AUTHORITY-RECORD-V1";
const SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;
const MAX_WEIGHT: u64 = 4_294_967_295;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgreementTermsV3 {
    pub profile: String,
    pub schema_id: String,
    pub schema_bundle_digest: String,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgreementContextV3 {
    pub profile: String,
    pub context_profile_id: String,
    pub schema_id: String,
    pub schema_bundle_digest: String,
    pub audience: Vec<String>,
    pub value: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantRoleV3 {
    Signer,
    Witness,
    Notary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRoleV3 {
    Controller,
    Signer,
    Witness,
    Notary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationRequirementV3 {
    AgentSignature,
    AgentPlusHumanSeal,
}

/// Closed portable algorithm vocabulary for Agreement v3 evidence. ES256 is
/// verification-only for the native CoreAgent today, but is required for OS
/// broker and managed-authority evidence produced by mobile platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgreementAlgorithmV3 {
    Ed25519,
    Pq2025,
    Es256,
}

impl AgreementAlgorithmV3 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::Pq2025 => "pq2025",
            Self::Es256 => "es256",
        }
    }
}

impl From<SigningAlgorithm> for AgreementAlgorithmV3 {
    fn from(value: SigningAlgorithm) -> Self {
        match value {
            SigningAlgorithm::Ed25519 => Self::Ed25519,
            SigningAlgorithm::Pq2025 => Self::Pq2025,
        }
    }
}

impl std::fmt::Display for AgreementAlgorithmV3 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgreementParticipantV3 {
    pub participant_id: String,
    pub role: ParticipantRoleV3,
    pub weight: u64,
    pub identity_anchor: IdentityAnchorV3,
    pub trust_record_digest: String,
    pub authorization_requirement: AuthorizationRequirementV3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerQuorumModeV3 {
    All,
    CountAtLeast,
    WeightAtLeast,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessQuorumModeV3 {
    None,
    All,
    CountAtLeast,
    WeightAtLeast,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SignerQuorumRuleV3 {
    pub mode: SignerQuorumModeV3,
    pub threshold: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WitnessQuorumRuleV3 {
    pub mode: WitnessQuorumModeV3,
    pub threshold: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgreementQuorumV3 {
    pub profile: String,
    pub signer: SignerQuorumRuleV3,
    pub witness: WitnessQuorumRuleV3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgreementVersionKindV3 {
    Proposal,
    Amendment,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgreementCoreV3 {
    pub profile: String,
    pub agreement_id: String,
    pub version: u64,
    pub version_kind: AgreementVersionKindV3,
    pub previous_agreement_digest: Option<String>,
    pub previous_finalization_evidence_digest: Option<String>,
    pub controller_participant_id: String,
    pub controller_identity_anchor: IdentityAnchorV3,
    pub controller_trust_record_digest: String,
    pub controller_authorization_requirement: AuthorizationRequirementV3,
    pub terms_digest: String,
    pub context_digest: String,
    pub participants: Vec<AgreementParticipantV3>,
    pub quorum: AgreementQuorumV3,
    pub notary_required: bool,
    pub status: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgreementOperationV3 {
    SignAgreementProposal,
    SignAgreementAmendment,
    SignAgreementConsent,
    SignAgreementWitness,
    SignAgreementNotary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgreementPurposeV3 {
    AgreementProposal,
    AgreementAmendment,
    AgreementConsent,
    AgreementWitness,
    AgreementNotary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgreementProofProfileV3 {
    #[serde(rename = "jacs-agreement-proposal-proof-v3")]
    Proposal,
    #[serde(rename = "jacs-agreement-amendment-proof-v3")]
    Amendment,
    #[serde(rename = "jacs-agreement-consent-proof-v3")]
    Consent,
    #[serde(rename = "jacs-agreement-witness-proof-v3")]
    Witness,
    #[serde(rename = "jacs-agreement-notary-proof-v3")]
    Notary,
}

impl AgreementProofProfileV3 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposal => "jacs-agreement-proposal-proof-v3",
            Self::Amendment => "jacs-agreement-amendment-proof-v3",
            Self::Consent => "jacs-agreement-consent-proof-v3",
            Self::Witness => "jacs-agreement-witness-proof-v3",
            Self::Notary => "jacs-agreement-notary-proof-v3",
        }
    }

    pub const fn operation(self) -> AgreementOperationV3 {
        match self {
            Self::Proposal => AgreementOperationV3::SignAgreementProposal,
            Self::Amendment => AgreementOperationV3::SignAgreementAmendment,
            Self::Consent => AgreementOperationV3::SignAgreementConsent,
            Self::Witness => AgreementOperationV3::SignAgreementWitness,
            Self::Notary => AgreementOperationV3::SignAgreementNotary,
        }
    }

    pub const fn purpose(self) -> AgreementPurposeV3 {
        match self {
            Self::Proposal => AgreementPurposeV3::AgreementProposal,
            Self::Amendment => AgreementPurposeV3::AgreementAmendment,
            Self::Consent => AgreementPurposeV3::AgreementConsent,
            Self::Witness => AgreementPurposeV3::AgreementWitness,
            Self::Notary => AgreementPurposeV3::AgreementNotary,
        }
    }

    pub const fn role(self) -> EvidenceRoleV3 {
        match self {
            Self::Proposal | Self::Amendment => EvidenceRoleV3::Controller,
            Self::Consent => EvidenceRoleV3::Signer,
            Self::Witness => EvidenceRoleV3::Witness,
            Self::Notary => EvidenceRoleV3::Notary,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgreementCeremonyTargetV3 {
    pub profile: String,
    pub agreement_core_digest: String,
    pub participant_id: String,
    pub role: EvidenceRoleV3,
    pub operation: AgreementOperationV3,
    pub terms_digest: String,
    pub context_digest: String,
    pub ceremony_id: String,
    pub human_principal_id: String,
    pub agent_canonical_key_id: String,
    pub agent_version: String,
    pub challenge: String,
    pub not_before: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgreementCeremonyContextV3 {
    pub profile: String,
    pub authorization_target: AgreementCeremonyTargetV3,
    pub authorization_target_digest: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgreementProofPayloadV3 {
    pub profile: AgreementProofProfileV3,
    pub agreement_core_digest: String,
    pub operation: AgreementOperationV3,
    pub purpose: AgreementPurposeV3,
    pub participant_id: String,
    pub role: EvidenceRoleV3,
    pub signer_identity_anchor: IdentityAnchorV3,
    pub signer_trust_record_digest: String,
    pub canonical_key_id: String,
    pub ceremony_context_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgreementProofSignatureV3 {
    pub key_id: String,
    pub algorithm: AgreementAlgorithmV3,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgreementProofV3 {
    pub profile: AgreementProofProfileV3,
    pub proof_id: String,
    pub agreement_core_digest: String,
    pub operation: AgreementOperationV3,
    pub purpose: AgreementPurposeV3,
    pub participant_id: String,
    pub role: EvidenceRoleV3,
    pub signer_identity_anchor: IdentityAnchorV3,
    pub signer_trust_record_digest: String,
    pub canonical_key_id: String,
    pub ceremony_context_digest: Option<String>,
    pub signature: AgreementProofSignatureV3,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgreementHumanSealPayloadV3 {
    pub profile: String,
    pub seal_id: String,
    pub human_principal_id: String,
    pub agreement_core_digest: String,
    pub terms_digest: String,
    pub participant_id: String,
    pub role: EvidenceRoleV3,
    pub agent_canonical_key_id: String,
    pub agent_version: String,
    pub ceremony_context_digest: String,
    pub signed_proof_evidence_digest: String,
    pub application_authorization_digest: Option<String>,
    pub signer_completion_receipt_digest: Option<String>,
    pub approved_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LocalOsBrokerSignatureV3 {
    #[serde(rename = "type")]
    pub authentication_type: String,
    pub credential_id: String,
    pub credential_generation: u64,
    pub credential_status_digest: String,
    pub assurance: String,
    pub algorithm: AgreementAlgorithmV3,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthorityRecordPayloadV3 {
    pub profile: String,
    pub authority_anchor: AuthorityAnchorV3,
    pub authority_enrollment_handle: String,
    pub record_profile: String,
    pub record_id: String,
    pub sequence: u64,
    pub previous_authority_record_digest: Option<String>,
    pub body_digest: String,
    pub authenticated_commit_time: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthorityRecordAuthenticationV3 {
    #[serde(rename = "type")]
    pub authentication_type: String,
    pub credential_id: String,
    pub algorithm: AgreementAlgorithmV3,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthorityRecordV3 {
    pub payload: AuthorityRecordPayloadV3,
    pub authentication: AuthorityRecordAuthenticationV3,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgreementHumanSealAuthenticationV3 {
    LocalOsBrokerSignature {
        #[serde(rename = "credentialId")]
        credential_id: String,
        #[serde(rename = "credentialGeneration")]
        credential_generation: u64,
        #[serde(rename = "credentialStatusDigest")]
        credential_status_digest: String,
        assurance: String,
        algorithm: AgreementAlgorithmV3,
        value: String,
    },
    HaiAuthorityRecord {
        record: AuthorityRecordV3,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgreementHumanSealV3 {
    pub payload: AgreementHumanSealPayloadV3,
    pub authentication: AgreementHumanSealAuthenticationV3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgreementRoleEvidenceProfileV3 {
    #[serde(rename = "jacs-agreement-controller-evidence-v3")]
    Controller,
    #[serde(rename = "jacs-agreement-consent-v3")]
    Consent,
    #[serde(rename = "jacs-agreement-witness-v3")]
    Witness,
    #[serde(rename = "jacs-agreement-notary-v3")]
    Notary,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgreementRoleEvidenceV3 {
    pub profile: AgreementRoleEvidenceProfileV3,
    pub proof: AgreementProofV3,
    pub ceremony_context: Option<AgreementCeremonyContextV3>,
    pub human_seal: Option<AgreementHumanSealV3>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgreementVersionV3 {
    pub profile: String,
    pub core: AgreementCoreV3,
    pub terms: AgreementTermsV3,
    pub context: AgreementContextV3,
    pub controller_evidence: AgreementRoleEvidenceV3,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgreementFinalizationV3 {
    pub profile: String,
    pub agreement_version: AgreementVersionV3,
    pub consents: Vec<AgreementRoleEvidenceV3>,
    pub witnesses: Vec<AgreementRoleEvidenceV3>,
    pub notary: Option<AgreementRoleEvidenceV3>,
    pub agreement_digest: String,
    pub outcome: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CeremonyExpectationV3 {
    pub mode: String,
    pub ceremony_context_digest: Option<String>,
    pub human_principal_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgreementParticipantExpectationV3 {
    pub participant_id: String,
    pub role: EvidenceRoleV3,
    pub identity_anchor: IdentityAnchorV3,
    pub trust_record_digest: String,
    pub operation: AgreementOperationV3,
    pub signature_profile: AgreementProofProfileV3,
    pub temporal: TemporalExpectationV3,
    pub ceremony: CeremonyExpectationV3,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExpectedFinalizationV3 {
    pub mode: String,
    pub evidence_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgreementVerificationIntentV3 {
    pub profile: String,
    pub verification_policy_digest: String,
    pub expected_agreement_id: String,
    pub expected_agreement_core_digest: String,
    pub expected_previous_agreement_digest: Option<String>,
    pub expected_previous_finalization_evidence_digest: Option<String>,
    pub expected_terms_digest: String,
    pub expected_context_digest: String,
    pub expected_controller: AgreementParticipantExpectationV3,
    pub expected_participants: Vec<AgreementParticipantExpectationV3>,
    pub expected_quorum: AgreementQuorumV3,
    pub expected_notary: Option<AgreementParticipantExpectationV3>,
    pub expected_agreement_digest: String,
    pub expected_finalization: ExpectedFinalizationV3,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgreementVerificationKeyV3 {
    pub participant_id: String,
    pub role: EvidenceRoleV3,
    pub identity_anchor: IdentityAnchorV3,
    pub trust_record_digest: String,
    pub canonical_key_id: String,
    pub algorithm: AgreementAlgorithmV3,
    pub public_key_base64url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HumanSealVerificationKeyV3 {
    pub credential_id: String,
    pub human_principal_id: Option<String>,
    pub credential_generation: Option<u64>,
    pub credential_status_digest: Option<String>,
    pub authority_anchor: Option<AuthorityAnchorV3>,
    pub authority_enrollment_handle: Option<String>,
    pub algorithm: AgreementAlgorithmV3,
    pub public_key_base64url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SchemaResourceV3 {
    pub uri: String,
    pub content_base64url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ResolvedSchemaBundleV3 {
    pub resources: Vec<SchemaResourceV3>,
}

/// Complete, I/O-free verification request.  Native and browser bindings
/// deserialize this same closed shape so neither surface can silently omit an
/// intent, a pinned schema bundle, or an amendment predecessor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgreementV3VerificationInput {
    /// Canonical base64url of the exact submitted Agreement finalization JSON.
    /// Carrying octets, rather than a pre-parsed value, keeps TP-26 artifact
    /// digests honest across native and browser bindings.
    pub finalization_base64url: String,
    pub intent: AgreementVerificationIntentV3,
    pub keys: Vec<AgreementVerificationKeyV3>,
    pub human_keys: Vec<HumanSealVerificationKeyV3>,
    pub terms_schema_bundle: ResolvedSchemaBundleV3,
    pub context_schema_bundle: ResolvedSchemaBundleV3,
    pub predecessor_base64url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgreementCryptographicResultV3 {
    Valid,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgreementProofVerificationV3 {
    pub proof_id: String,
    pub participant_id: String,
    pub role: EvidenceRoleV3,
    pub actual_algorithm: Option<AgreementAlgorithmV3>,
    pub signature_input_digest: Option<String>,
    pub human_seal_evidence_digest: Option<String>,
    pub cryptographic_result: AgreementCryptographicResultV3,
    /// Exact TP-26 report digest once the lifecycle/trust verifier has run.
    /// `None` means the proof is mathematical evidence only.
    pub verification_report_digest: Option<String>,
    pub policy_accepted: bool,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgreementV3VerificationReport {
    pub profile: String,
    pub verification_intent_digest: Option<String>,
    pub agreement_core_digest: Option<String>,
    pub agreement_digest: Option<String>,
    pub finalization_evidence_digest: Option<String>,
    pub terms_schema_valid: bool,
    pub context_schema_valid: bool,
    pub controller: Option<AgreementProofVerificationV3>,
    pub consents: Vec<AgreementProofVerificationV3>,
    pub witnesses: Vec<AgreementProofVerificationV3>,
    pub notary: Option<AgreementProofVerificationV3>,
    pub cryptographic_result: AgreementCryptographicResultV3,
    pub policy_accepted: bool,
    pub errors: Vec<String>,
    pub policy_errors: Vec<String>,
}

pub fn digest_json<T: Serialize>(label: &str, value: &T) -> Result<String, CoreError> {
    let value = serde_json::to_value(value)
        .map_err(|e| CoreError::MalformedDocument(format!("serialize digest input: {e}")))?;
    let canonical = canonicalize_json_try(&value)?;
    Ok(digest_octets(label, canonical.as_bytes()))
}

pub fn digest_octets(label: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

pub fn canonical_key_id(
    algorithm: impl Into<AgreementAlgorithmV3>,
    public_key: &[u8],
) -> Result<String, CoreError> {
    crate::identity::canonical_key_id(algorithm.into().as_str(), public_key)
}

pub fn terms_digest(value: &AgreementTermsV3) -> Result<String, CoreError> {
    digest_json("JACS-AGREEMENT-TERMS-V3", value)
}

pub fn context_digest(value: &AgreementContextV3) -> Result<String, CoreError> {
    digest_json("JACS-AGREEMENT-CONTEXT-V3", value)
}

pub fn core_digest(value: &AgreementCoreV3) -> Result<String, CoreError> {
    digest_json("JACS-AGREEMENT-CORE-V3", value)
}

pub fn ceremony_target_digest(value: &AgreementCeremonyTargetV3) -> Result<String, CoreError> {
    digest_json("JACS-AGREEMENT-CEREMONY-TARGET-V3", value)
}

pub fn ceremony_context_digest(value: &AgreementCeremonyContextV3) -> Result<String, CoreError> {
    digest_json("JACS-AGREEMENT-CEREMONY-CONTEXT-V3", value)
}

pub fn proof_id(value: &AgreementProofV3) -> Result<String, CoreError> {
    digest_json(
        "JACS-AGREEMENT-PROOF-ID-V3",
        &json!({
            "agreementCoreDigest": value.agreement_core_digest,
            "operation": value.operation,
            "participantId": value.participant_id,
            "role": value.role,
        }),
    )
}

pub fn proof_evidence_digest(value: &AgreementProofV3) -> Result<String, CoreError> {
    digest_json("JACS-AGREEMENT-PROOF-EVIDENCE-V3", value)
}

pub fn proof_payload_digest(value: &AgreementProofV3) -> Result<String, CoreError> {
    let mut payload = serde_json::to_value(value)
        .map_err(|e| CoreError::MalformedDocument(format!("serialize agreement proof: {e}")))?;
    payload
        .pointer_mut("/signature")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| CoreError::MalformedDocument("agreement proof signature missing".into()))?
        .remove("value");
    digest_json("JACS-AGREEMENT-PROOF-PAYLOAD-V3", &payload)
}

pub fn role_evidence_digest(value: &AgreementRoleEvidenceV3) -> Result<String, CoreError> {
    digest_json("JACS-AGREEMENT-ROLE-EVIDENCE-V3", value)
}

pub fn agreement_version_evidence_digest(value: &AgreementVersionV3) -> Result<String, CoreError> {
    digest_json("JACS-AGREEMENT-VERSION-EVIDENCE-V3", value)
}

pub fn accepted_agreement_digest(core_digest: &str) -> Result<String, CoreError> {
    digest_json(
        "JACS-AGREEMENT-ACCEPTED-V3",
        &json!({"agreementCoreDigest": core_digest}),
    )
}

pub fn finalization_evidence_digest(value: &AgreementFinalizationV3) -> Result<String, CoreError> {
    digest_json("JACS-AGREEMENT-FINALIZATION-EVIDENCE-V3", value)
}

pub fn verification_intent_digest(
    value: &AgreementVerificationIntentV3,
) -> Result<String, CoreError> {
    digest_json("JACS-AGREEMENT-VERIFICATION-INTENT-V3", value)
}

pub fn human_seal_payload_digest(value: &AgreementHumanSealPayloadV3) -> Result<String, CoreError> {
    digest_json("JACS-AGREEMENT-HUMAN-SEAL-PAYLOAD-V1", value)
}

pub fn human_seal_evidence_digest(value: &AgreementHumanSealV3) -> Result<String, CoreError> {
    digest_json("JACS-AGREEMENT-HUMAN-SEAL-EVIDENCE-V1", value)
}

fn new_profile_signature_input(
    domain: &str,
    profile: &str,
    envelope: &Value,
) -> Result<Vec<u8>, CoreError> {
    let canonical = canonicalize_json_try(envelope)?;
    let domain_len = u32::try_from(domain.len())
        .map_err(|_| CoreError::MalformedDocument("signature domain too long".into()))?;
    let profile_len = u32::try_from(profile.len())
        .map_err(|_| CoreError::MalformedDocument("signature profile too long".into()))?;
    let envelope_len = u64::try_from(canonical.len())
        .map_err(|_| CoreError::MalformedDocument("signature envelope too long".into()))?;
    let mut input = Vec::with_capacity(16 + domain.len() + profile.len() + canonical.len());
    input.extend_from_slice(&domain_len.to_be_bytes());
    input.extend_from_slice(domain.as_bytes());
    input.extend_from_slice(&profile_len.to_be_bytes());
    input.extend_from_slice(profile.as_bytes());
    input.extend_from_slice(&envelope_len.to_be_bytes());
    input.extend_from_slice(canonical.as_bytes());
    Ok(input)
}

pub fn proof_signature_input(proof: &AgreementProofV3) -> Result<Vec<u8>, CoreError> {
    let mut value = serde_json::to_value(proof)
        .map_err(|e| CoreError::MalformedDocument(format!("serialize agreement proof: {e}")))?;
    value
        .pointer_mut("/signature")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| CoreError::MalformedDocument("agreement proof signature missing".into()))?
        .remove("value");
    new_profile_signature_input(PROOF_SIGNATURE_DOMAIN, proof.profile.as_str(), &value)
}

pub fn sign_proof(
    agent: &CoreAgent,
    payload: AgreementProofPayloadV3,
) -> Result<AgreementProofV3, CoreError> {
    let expected_key_id = canonical_key_id(agent.algorithm, &agent.public_key)?;
    if payload.canonical_key_id != expected_key_id {
        return Err(CoreError::AgreementFailed(
            "agreement proof canonicalKeyId does not identify the selected signing key".into(),
        ));
    }
    let mut proof = AgreementProofV3 {
        profile: payload.profile,
        proof_id: String::new(),
        agreement_core_digest: payload.agreement_core_digest,
        operation: payload.operation,
        purpose: payload.purpose,
        participant_id: payload.participant_id,
        role: payload.role,
        signer_identity_anchor: payload.signer_identity_anchor,
        signer_trust_record_digest: payload.signer_trust_record_digest,
        canonical_key_id: payload.canonical_key_id,
        ceremony_context_digest: payload.ceremony_context_digest,
        signature: AgreementProofSignatureV3 {
            key_id: expected_key_id,
            algorithm: agent.algorithm.into(),
            value: String::new(),
        },
    };
    proof.proof_id = proof_id(&proof)?;
    validate_proof_shape(&proof)?;
    let input = proof_signature_input(&proof)?;
    let signer = agent.signer.as_ref().ok_or(CoreError::Locked)?;
    let signature = signer.sign(&input)?;
    proof.signature.value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature);
    Ok(proof)
}

fn validate_token(field: &str, value: &str) -> Result<(), CoreError> {
    if value.is_empty() || value.len() > 128 || !value.is_ascii() {
        return Err(CoreError::MalformedDocument(format!(
            "{field} must be a nonempty ASCII token of at most 128 bytes"
        )));
    }
    Ok(())
}

fn validate_digest(field: &str, value: &str) -> Result<(), CoreError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(CoreError::MalformedDocument(format!(
            "{field} must use sha256:<64 lowercase hex>"
        )));
    };
    if hex.len() != 64
        || !hex
            .as_bytes()
            .iter()
            .all(|c| c.is_ascii_digit() || matches!(c, b'a'..=b'f'))
    {
        return Err(CoreError::MalformedDocument(format!(
            "{field} must use sha256:<64 lowercase hex>"
        )));
    }
    Ok(())
}

fn validate_absolute_schema_uri(field: &str, value: &str) -> Result<(), CoreError> {
    if value.is_empty()
        || value.chars().any(char::is_whitespace)
        || !value
            .split_once(':')
            .is_some_and(|(scheme, rest)| !scheme.is_empty() && !rest.is_empty())
    {
        return Err(CoreError::MalformedDocument(format!(
            "{field} must be an absolute schema URI"
        )));
    }
    Ok(())
}

fn validate_uuid(field: &str, value: &str) -> Result<(), CoreError> {
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| {
        CoreError::MalformedDocument(format!(
            "{field} must be lowercase hyphenated RFC 4122 UUID text"
        ))
    })?;
    if parsed.hyphenated().to_string() != value {
        return Err(CoreError::MalformedDocument(format!(
            "{field} must be lowercase hyphenated RFC 4122 UUID text"
        )));
    }
    Ok(())
}

fn validate_jacs_time(field: &str, value: &str) -> Result<i64, CoreError> {
    if value.len() != 20
        || !value.is_ascii()
        || value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
        || value.as_bytes().get(10) != Some(&b'T')
        || value.as_bytes().get(13) != Some(&b':')
        || value.as_bytes().get(16) != Some(&b':')
        || value.as_bytes().get(19) != Some(&b'Z')
    {
        return Err(CoreError::MalformedDocument(format!(
            "{field} must be jacs-time-v1 (YYYY-MM-DDTHH:MM:SSZ)"
        )));
    }
    let parsed =
        chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%SZ").map_err(|_| {
            CoreError::MalformedDocument(format!("{field} must be a valid jacs-time-v1 instant"))
        })?;
    Ok(parsed.and_utc().timestamp())
}

fn decode_base64url(field: &str, value: &str) -> Result<Vec<u8>, CoreError> {
    if value.is_empty()
        || value.contains('=')
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err(CoreError::MalformedDocument(format!(
            "{field} must be canonical base64url without padding"
        )));
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| {
            CoreError::MalformedDocument(format!(
                "{field} must be canonical base64url without padding"
            ))
        })?;
    if base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(CoreError::MalformedDocument(format!(
            "{field} is not a canonical base64url encoding"
        )));
    }
    Ok(decoded)
}

fn validate_identity_anchor(anchor: &IdentityAnchorV3) -> Result<(), CoreError> {
    match anchor {
        IdentityAnchorV3::Portable {
            jacs_id,
            genesis_manifest_digest,
            genesis_root_canonical_key_id,
        } => {
            validate_token("identityAnchor.jacsId", jacs_id)?;
            validate_digest(
                "identityAnchor.genesisManifestDigest",
                genesis_manifest_digest,
            )?;
            validate_token(
                "identityAnchor.genesisRootCanonicalKeyId",
                genesis_root_canonical_key_id,
            )
        }
        IdentityAnchorV3::AuthorityBacked {
            authority_anchor,
            authority_enrollment_handle,
            authenticated_initial_record_digest,
        } => {
            validate_authority_anchor(authority_anchor)?;
            validate_token(
                "identityAnchor.authorityEnrollmentHandle",
                authority_enrollment_handle,
            )?;
            validate_digest(
                "identityAnchor.authenticatedInitialRecordDigest",
                authenticated_initial_record_digest,
            )
        }
    }
}

fn validate_authority_anchor(anchor: &AuthorityAnchorV3) -> Result<(), CoreError> {
    let AuthorityAnchorV3::Authority {
        authority_service_id,
        bootstrap_credential_id,
        bootstrap_record_digest,
        ..
    } = anchor;
    validate_token("authorityAnchor.authorityServiceId", authority_service_id)?;
    validate_token(
        "authorityAnchor.bootstrapCredentialId",
        bootstrap_credential_id,
    )?;
    validate_digest(
        "authorityAnchor.bootstrapRecordDigest",
        bootstrap_record_digest,
    )
}

fn validate_status_authority(
    authority: &crate::identity::StatusAuthority,
) -> Result<(), CoreError> {
    match authority {
        crate::identity::StatusAuthority::LocalOwnerStore {
            canonical_store_id,
            owner_id,
            bootstrap_digest,
        } => {
            validate_token("statusAuthority.canonicalStoreId", canonical_store_id)?;
            validate_token("statusAuthority.ownerId", owner_id)?;
            validate_digest("statusAuthority.bootstrapDigest", bootstrap_digest)
        }
        crate::identity::StatusAuthority::PortableRootStatus { identity_anchor } => {
            validate_identity_anchor(identity_anchor)
        }
        crate::identity::StatusAuthority::AuthorityBackedStatus {
            authority_anchor,
            authority_enrollment_handle,
        } => {
            validate_authority_anchor(authority_anchor)?;
            validate_token(
                "statusAuthority.authorityEnrollmentHandle",
                authority_enrollment_handle,
            )
        }
    }
}

fn validate_observation_policy(policy: &ObservationPolicy) -> Result<(), CoreError> {
    match policy {
        ObservationPolicy::RegisteredSignedObservation {
            observer_identity_anchor,
            observer_trust_record_digest,
            observer_key_id,
            receipt_authority_trust_record_digest,
        } => {
            validate_identity_anchor(observer_identity_anchor)?;
            validate_digest(
                "observationPolicy.observerTrustRecordDigest",
                observer_trust_record_digest,
            )?;
            validate_token("observationPolicy.observerKeyId", observer_key_id)?;
            validate_digest(
                "observationPolicy.receiptAuthorityTrustRecordDigest",
                receipt_authority_trust_record_digest,
            )
        }
        ObservationPolicy::AuthorityReceipt {
            authority_trust_record_digest,
        } => validate_digest(
            "observationPolicy.authorityTrustRecordDigest",
            authority_trust_record_digest,
        ),
        ObservationPolicy::TransparencyInclusion { log_trust_record } => {
            validate_token(
                "observationPolicy.logServiceId",
                &log_trust_record.log_anchor.log_service_id,
            )?;
            validate_token(
                "observationPolicy.bootstrapCheckpointSigningKeyId",
                &log_trust_record
                    .log_anchor
                    .bootstrap_checkpoint_signing_key_id,
            )?;
            validate_identity_anchor(&log_trust_record.log_anchor.identity_anchor)?;
            validate_status_authority(&log_trust_record.log_anchor.status_authority)?;
            validate_digest(
                "observationPolicy.initialCheckpointDigest",
                &log_trust_record.initial_checkpoint_digest,
            )?;
            validate_digest(
                "observationPolicy.trustLedgerRecordDigest",
                &log_trust_record.trust_ledger_record_digest,
            )
        }
    }
}

fn validate_terms(terms: &AgreementTermsV3) -> Result<(), CoreError> {
    if terms.profile != "jacs-agreement-terms-v3" {
        return Err(CoreError::MalformedDocument(
            "agreement terms profile must be jacs-agreement-terms-v3".into(),
        ));
    }
    validate_absolute_schema_uri("terms.schemaId", &terms.schema_id)?;
    validate_digest("terms.schemaBundleDigest", &terms.schema_bundle_digest)?;
    canonicalize_json_try(&terms.value)?;
    Ok(())
}

fn validate_context(context: &AgreementContextV3) -> Result<(), CoreError> {
    if context.profile != "jacs-agreement-context-v3" {
        return Err(CoreError::MalformedDocument(
            "agreement context profile must be jacs-agreement-context-v3".into(),
        ));
    }
    validate_token("context.contextProfileId", &context.context_profile_id)?;
    validate_absolute_schema_uri("context.schemaId", &context.schema_id)?;
    validate_digest("context.schemaBundleDigest", &context.schema_bundle_digest)?;
    let mut prior: Option<&str> = None;
    for item in &context.audience {
        if item.is_empty() {
            return Err(CoreError::MalformedDocument(
                "context.audience values must be nonempty".into(),
            ));
        }
        if prior.is_some_and(|p| p >= item.as_str()) {
            return Err(CoreError::MalformedDocument(
                "context.audience must be sorted and unique".into(),
            ));
        }
        prior = Some(item);
    }
    canonicalize_json_try(&context.value)?;
    Ok(())
}

fn participant_anchor_key(participant: &AgreementParticipantV3) -> Result<String, CoreError> {
    canonicalize_json_try(
        &serde_json::to_value(&participant.identity_anchor).map_err(|e| {
            CoreError::MalformedDocument(format!("serialize participant identity anchor: {e}"))
        })?,
    )
}

fn validate_quorum(
    quorum: &AgreementQuorumV3,
    participants: &[AgreementParticipantV3],
) -> Result<(), CoreError> {
    if quorum.profile != "jacs-agreement-quorum-v3" {
        return Err(CoreError::MalformedDocument(
            "agreement quorum profile must be jacs-agreement-quorum-v3".into(),
        ));
    }
    let signers: Vec<_> = participants
        .iter()
        .filter(|p| p.role == ParticipantRoleV3::Signer)
        .collect();
    let witnesses: Vec<_> = participants
        .iter()
        .filter(|p| p.role == ParticipantRoleV3::Witness)
        .collect();
    let signer_weight = signers.iter().try_fold(0u64, |total, p| {
        total
            .checked_add(p.weight)
            .ok_or_else(|| CoreError::MalformedDocument("signer weight sum overflow".into()))
    })?;
    let witness_weight = witnesses.iter().try_fold(0u64, |total, p| {
        total
            .checked_add(p.weight)
            .ok_or_else(|| CoreError::MalformedDocument("witness weight sum overflow".into()))
    })?;
    match quorum.signer.mode {
        SignerQuorumModeV3::All if quorum.signer.threshold.is_none() => {}
        SignerQuorumModeV3::CountAtLeast => {
            let threshold = quorum.signer.threshold.ok_or_else(|| {
                CoreError::MalformedDocument("signer count quorum requires threshold".into())
            })?;
            if threshold == 0 || threshold > signers.len() as u64 {
                return Err(CoreError::MalformedDocument(
                    "signer count threshold is outside the signer set".into(),
                ));
            }
        }
        SignerQuorumModeV3::WeightAtLeast => {
            let threshold = quorum.signer.threshold.ok_or_else(|| {
                CoreError::MalformedDocument("signer weight quorum requires threshold".into())
            })?;
            if threshold == 0 || threshold > signer_weight {
                return Err(CoreError::MalformedDocument(
                    "signer weight threshold is outside the signer weight sum".into(),
                ));
            }
        }
        _ => {
            return Err(CoreError::MalformedDocument(
                "signer all quorum requires null threshold".into(),
            ));
        }
    }
    match quorum.witness.mode {
        WitnessQuorumModeV3::None if quorum.witness.threshold.is_none() && witnesses.is_empty() => {
        }
        WitnessQuorumModeV3::All if quorum.witness.threshold.is_none() && !witnesses.is_empty() => {
        }
        WitnessQuorumModeV3::CountAtLeast => {
            let threshold = quorum.witness.threshold.ok_or_else(|| {
                CoreError::MalformedDocument("witness count quorum requires threshold".into())
            })?;
            if threshold == 0 || threshold > witnesses.len() as u64 {
                return Err(CoreError::MalformedDocument(
                    "witness count threshold is outside the witness set".into(),
                ));
            }
        }
        WitnessQuorumModeV3::WeightAtLeast => {
            let threshold = quorum.witness.threshold.ok_or_else(|| {
                CoreError::MalformedDocument("witness weight quorum requires threshold".into())
            })?;
            if threshold == 0 || threshold > witness_weight {
                return Err(CoreError::MalformedDocument(
                    "witness weight threshold is outside the witness weight sum".into(),
                ));
            }
        }
        _ => {
            return Err(CoreError::MalformedDocument(
                "witness none/all quorum has an invalid threshold or role set".into(),
            ));
        }
    }
    Ok(())
}

pub fn validate_core(core: &AgreementCoreV3) -> Result<(), CoreError> {
    if core.profile != "jacs-agreement-core-v3" {
        return Err(CoreError::MalformedDocument(
            "agreement core profile must be jacs-agreement-core-v3".into(),
        ));
    }
    validate_uuid("core.agreementId", &core.agreement_id)?;
    if core.version == 0 || core.version > SAFE_INTEGER_MAX {
        return Err(CoreError::MalformedDocument(
            "core.version must be a positive safe integer".into(),
        ));
    }
    match core.version_kind {
        AgreementVersionKindV3::Proposal
            if core.version == 1
                && core.previous_agreement_digest.is_none()
                && core.previous_finalization_evidence_digest.is_none() => {}
        AgreementVersionKindV3::Amendment
            if core.version > 1
                && core.previous_agreement_digest.is_some()
                && core.previous_finalization_evidence_digest.is_some() => {}
        _ => {
            return Err(CoreError::MalformedDocument(
                "proposal/amendment version and predecessor fields are inconsistent".into(),
            ));
        }
    }
    if let Some(digest) = &core.previous_agreement_digest {
        validate_digest("core.previousAgreementDigest", digest)?;
    }
    if let Some(digest) = &core.previous_finalization_evidence_digest {
        validate_digest("core.previousFinalizationEvidenceDigest", digest)?;
    }
    validate_token(
        "core.controllerParticipantId",
        &core.controller_participant_id,
    )?;
    validate_identity_anchor(&core.controller_identity_anchor)?;
    validate_digest(
        "core.controllerTrustRecordDigest",
        &core.controller_trust_record_digest,
    )?;
    validate_digest("core.termsDigest", &core.terms_digest)?;
    validate_digest("core.contextDigest", &core.context_digest)?;
    if core.status != "open" {
        return Err(CoreError::MalformedDocument(
            "agreement v3 core status must be open".into(),
        ));
    }
    if core.participants.is_empty() {
        return Err(CoreError::MalformedDocument(
            "agreement v3 requires participants".into(),
        ));
    }
    let mut prior: Option<&str> = None;
    let mut anchors = HashSet::new();
    let mut signer_count = 0usize;
    let mut notary_count = 0usize;
    for participant in &core.participants {
        validate_token("participant.participantId", &participant.participant_id)?;
        if prior.is_some_and(|p| p >= participant.participant_id.as_str()) {
            return Err(CoreError::MalformedDocument(
                "participants must be participantId-sorted and unique".into(),
            ));
        }
        prior = Some(&participant.participant_id);
        validate_identity_anchor(&participant.identity_anchor)?;
        validate_digest(
            "participant.trustRecordDigest",
            &participant.trust_record_digest,
        )?;
        match participant.role {
            ParticipantRoleV3::Signer | ParticipantRoleV3::Witness => {
                if !(1..=MAX_WEIGHT).contains(&participant.weight) {
                    return Err(CoreError::MalformedDocument(
                        "signer/witness weight must be within 1..=4294967295".into(),
                    ));
                }
            }
            ParticipantRoleV3::Notary if participant.weight == 0 => {}
            ParticipantRoleV3::Notary => {
                return Err(CoreError::MalformedDocument(
                    "notary weight must be zero".into(),
                ));
            }
        }
        signer_count += usize::from(participant.role == ParticipantRoleV3::Signer);
        notary_count += usize::from(participant.role == ParticipantRoleV3::Notary);
        let anchor = participant_anchor_key(participant)?;
        if !anchors.insert(anchor) {
            return Err(CoreError::MalformedDocument(
                "participant identity anchors must be unique".into(),
            ));
        }
    }
    if signer_count == 0 {
        return Err(CoreError::MalformedDocument(
            "agreement v3 requires at least one signer".into(),
        ));
    }
    if notary_count != usize::from(core.notary_required) {
        return Err(CoreError::MalformedDocument(
            "exactly one notary is required iff notaryRequired is true".into(),
        ));
    }
    validate_quorum(&core.quorum, &core.participants)
}

pub(crate) fn validate_proof_shape(proof: &AgreementProofV3) -> Result<(), CoreError> {
    if proof.operation != proof.profile.operation()
        || proof.purpose != proof.profile.purpose()
        || proof.role != proof.profile.role()
    {
        return Err(CoreError::AgreementFailed(
            "proof profile, operation, purpose, and role do not use the closed mapping".into(),
        ));
    }
    validate_token("proof.participantId", &proof.participant_id)?;
    validate_identity_anchor(&proof.signer_identity_anchor)?;
    validate_digest(
        "proof.signerTrustRecordDigest",
        &proof.signer_trust_record_digest,
    )?;
    validate_digest("proof.agreementCoreDigest", &proof.agreement_core_digest)?;
    validate_token("proof.canonicalKeyId", &proof.canonical_key_id)?;
    if proof.signature.key_id != proof.canonical_key_id {
        return Err(CoreError::AgreementFailed(
            "proof signature keyId differs from canonicalKeyId".into(),
        ));
    }
    if proof.proof_id != proof_id(proof)? {
        return Err(CoreError::AgreementFailed("proofId mismatch".into()));
    }
    if let Some(digest) = &proof.ceremony_context_digest {
        validate_digest("proof.ceremonyContextDigest", digest)?;
    }
    if !proof.signature.value.is_empty() {
        decode_base64url("proof.signature.value", &proof.signature.value)?;
    }
    Ok(())
}

/// Strictly parse and structurally validate an Agreement v3 core.
pub fn parse_core(bytes: &[u8]) -> Result<AgreementCoreV3, CoreError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| CoreError::MalformedDocument("agreement core must be UTF-8 JSON".into()))?;
    let core: AgreementCoreV3 = crate::strict_json::deserialize_strict_json(text)?;
    validate_core(&core)?;
    Ok(core)
}

pub fn parse_version(bytes: &[u8]) -> Result<AgreementVersionV3, CoreError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| CoreError::MalformedDocument("agreement v3 must be UTF-8 JSON".into()))?;
    let version: AgreementVersionV3 = crate::strict_json::deserialize_strict_json(text)?;
    validate_version_shape(&version)?;
    Ok(version)
}

pub fn parse_finalization(bytes: &[u8]) -> Result<AgreementFinalizationV3, CoreError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        CoreError::MalformedDocument("agreement finalization must be UTF-8 JSON".into())
    })?;
    let finalization: AgreementFinalizationV3 = crate::strict_json::deserialize_strict_json(text)?;
    validate_finalization_shape(&finalization)?;
    Ok(finalization)
}

pub fn validate_version_shape(version: &AgreementVersionV3) -> Result<(), CoreError> {
    if version.profile != AGREEMENT_V3_PROFILE {
        return Err(CoreError::MalformedDocument(
            "agreement version profile must be jacs-agreement-v3".into(),
        ));
    }
    validate_core(&version.core)?;
    validate_terms(&version.terms)?;
    validate_context(&version.context)?;
    if version.core.terms_digest != terms_digest(&version.terms)? {
        return Err(CoreError::AgreementFailed("termsDigest mismatch".into()));
    }
    if version.core.context_digest != context_digest(&version.context)? {
        return Err(CoreError::AgreementFailed("contextDigest mismatch".into()));
    }
    let expected_profile = if version.core.version == 1 {
        AgreementProofProfileV3::Proposal
    } else {
        AgreementProofProfileV3::Amendment
    };
    if version.controller_evidence.profile != AgreementRoleEvidenceProfileV3::Controller
        || version.controller_evidence.proof.profile != expected_profile
    {
        return Err(CoreError::AgreementFailed(
            "controller evidence must contain the version-appropriate controller proof".into(),
        ));
    }
    Ok(())
}

pub fn validate_finalization_shape(
    finalization: &AgreementFinalizationV3,
) -> Result<(), CoreError> {
    if finalization.profile != FINALIZATION_V3_PROFILE || finalization.outcome != "accepted" {
        return Err(CoreError::MalformedDocument(
            "only jacs-agreement-finalization-v3 outcome accepted parses as finalization".into(),
        ));
    }
    validate_version_shape(&finalization.agreement_version)?;
    let core_hash = core_digest(&finalization.agreement_version.core)?;
    if finalization.agreement_digest != accepted_agreement_digest(&core_hash)? {
        return Err(CoreError::AgreementFailed(
            "agreementDigest mismatch".into(),
        ));
    }
    validate_sorted_evidence("consents", &finalization.consents)?;
    validate_sorted_evidence("witnesses", &finalization.witnesses)?;
    if finalization
        .consents
        .iter()
        .any(|e| e.profile != AgreementRoleEvidenceProfileV3::Consent)
        || finalization
            .witnesses
            .iter()
            .any(|e| e.profile != AgreementRoleEvidenceProfileV3::Witness)
        || finalization
            .notary
            .as_ref()
            .is_some_and(|e| e.profile != AgreementRoleEvidenceProfileV3::Notary)
    {
        return Err(CoreError::AgreementFailed(
            "role evidence appears in the wrong finalization collection".into(),
        ));
    }
    Ok(())
}

fn validate_sorted_evidence(
    field: &str,
    evidence: &[AgreementRoleEvidenceV3],
) -> Result<(), CoreError> {
    let mut prior: Option<&str> = None;
    for item in evidence {
        if prior.is_some_and(|p| p >= item.proof.participant_id.as_str()) {
            return Err(CoreError::MalformedDocument(format!(
                "{field} must be participantId-sorted and unique"
            )));
        }
        prior = Some(&item.proof.participant_id);
    }
    Ok(())
}

#[derive(Clone)]
struct SchemaBundleResolver {
    by_uri: HashMap<String, Value>,
}

impl jsonschema::Retrieve for SchemaBundleResolver {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn Error + Send + Sync>> {
        self.by_uri.get(uri.as_str()).cloned().ok_or_else(|| {
            Box::new(CoreError::SchemaInvalid(format!(
                "schema resource '{}' is not in the pinned bundle",
                uri.as_str()
            ))) as Box<dyn Error + Send + Sync>
        })
    }
}

fn raw_sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

impl ResolvedSchemaBundleV3 {
    pub fn digest(&self) -> Result<String, CoreError> {
        let mut prior: Option<&str> = None;
        let mut projection = Vec::with_capacity(self.resources.len());
        for resource in &self.resources {
            validate_absolute_schema_uri("schema resource URI", &resource.uri)?;
            if prior.is_some_and(|p| p >= resource.uri.as_str()) {
                return Err(CoreError::SchemaInvalid(
                    "schema resources must be URI-sorted and unique".into(),
                ));
            }
            prior = Some(&resource.uri);
            let bytes = decode_base64url(
                "schema resource contentBase64url",
                &resource.content_base64url,
            )?;
            projection.push(json!({"uri": resource.uri, "sha256": raw_sha256(&bytes)}));
        }
        digest_json("JACS-SCHEMA-BUNDLE-V1", &projection)
    }

    pub fn validate(
        &self,
        schema_id: &str,
        expected_bundle_digest: &str,
        instance: &Value,
    ) -> Result<(), CoreError> {
        validate_absolute_schema_uri("schemaId", schema_id)?;
        validate_digest("schemaBundleDigest", expected_bundle_digest)?;
        if self.digest()? != expected_bundle_digest {
            return Err(CoreError::SchemaInvalid(
                "resolved schema bundle digest does not match agreement".into(),
            ));
        }
        let mut root = None;
        let mut by_uri = HashMap::new();
        let mut total = 0usize;
        for resource in &self.resources {
            let bytes = decode_base64url(
                "schema resource contentBase64url",
                &resource.content_base64url,
            )?;
            total = total.checked_add(bytes.len()).ok_or_else(|| {
                CoreError::SchemaInvalid("schema bundle byte length overflow".into())
            })?;
            if total > 10 * 1024 * 1024 {
                return Err(CoreError::SchemaInvalid(
                    "schema bundle exceeds the 10 MiB portable limit".into(),
                ));
            }
            let text = std::str::from_utf8(&bytes).map_err(|_| {
                CoreError::SchemaInvalid(format!("schema '{}' is not UTF-8", resource.uri))
            })?;
            let parsed = crate::strict_json::parse_strict_json(text).map_err(|e| {
                CoreError::SchemaInvalid(format!(
                    "schema '{}' is not strict JSON: {e}",
                    resource.uri
                ))
            })?;
            if parsed.get("$schema").and_then(Value::as_str)
                != Some("http://json-schema.org/draft-07/schema#")
            {
                return Err(CoreError::SchemaInvalid(format!(
                    "schema '{}' does not declare the supported draft-07 vocabulary",
                    resource.uri
                )));
            }
            if resource.uri == schema_id {
                root = Some(parsed.clone());
            }
            if by_uri.insert(resource.uri.clone(), parsed).is_some() {
                return Err(CoreError::SchemaInvalid(format!(
                    "schema bundle contains duplicate resource URI '{}'",
                    resource.uri
                )));
            }
        }
        let root = root.ok_or_else(|| {
            CoreError::SchemaInvalid(format!("root schema '{schema_id}' is absent from bundle"))
        })?;
        let validator = jsonschema::Validator::options()
            .with_retriever(SchemaBundleResolver { by_uri })
            .build(&root)
            .map_err(|e| CoreError::SchemaInvalid(format!("compile schema bundle: {e}")))?;
        validator.validate(instance).map_err(|e| {
            CoreError::SchemaInvalid(format!(
                "agreement value failed schema '{}' at '{}': {}",
                schema_id, e.instance_path, e
            ))
        })
    }
}

fn key_bytes(key: &AgreementVerificationKeyV3) -> Result<Vec<u8>, CoreError> {
    let bytes = decode_base64url(
        "verification key publicKeyBase64url",
        &key.public_key_base64url,
    )?;
    if canonical_key_id(key.algorithm, &bytes)? != key.canonical_key_id {
        return Err(CoreError::MalformedKey(
            "verification key canonicalKeyId does not match its algorithm/public key".into(),
        ));
    }
    Ok(bytes)
}

fn human_key_bytes(key: &HumanSealVerificationKeyV3) -> Result<Vec<u8>, CoreError> {
    let bytes = decode_base64url(
        "human seal key publicKeyBase64url",
        &key.public_key_base64url,
    )?;
    if canonical_key_id(key.algorithm, &bytes)? != key.credential_id {
        return Err(CoreError::MalformedKey(
            "human seal credentialId does not match its algorithm/public key".into(),
        ));
    }
    Ok(bytes)
}

fn proof_signature_report(
    proof: &AgreementProofV3,
    key: Option<&AgreementVerificationKeyV3>,
) -> AgreementProofVerificationV3 {
    let mut report = AgreementProofVerificationV3 {
        proof_id: proof.proof_id.clone(),
        participant_id: proof.participant_id.clone(),
        role: proof.role,
        actual_algorithm: Some(proof.signature.algorithm),
        signature_input_digest: None,
        human_seal_evidence_digest: None,
        cryptographic_result: AgreementCryptographicResultV3::Invalid,
        verification_report_digest: None,
        policy_accepted: false,
        errors: Vec::new(),
    };
    let result = (|| -> Result<(), CoreError> {
        validate_proof_shape(proof)?;
        let key = key.ok_or_else(|| {
            CoreError::AgreementFailed(format!(
                "no preselected verification key for {} {:?}",
                proof.participant_id, proof.role
            ))
        })?;
        if key.participant_id != proof.participant_id
            || key.role != proof.role
            || key.identity_anchor != proof.signer_identity_anchor
            || key.trust_record_digest != proof.signer_trust_record_digest
            || key.canonical_key_id != proof.canonical_key_id
            || key.algorithm != proof.signature.algorithm
        {
            return Err(CoreError::AgreementFailed(
                "proof does not match the caller-preselected identity, trust row, role, key, and algorithm"
                    .into(),
            ));
        }
        let input = proof_signature_input(proof)?;
        report.signature_input_digest =
            Some(digest_octets("JACS-VERIFIED-SIGNATURE-INPUT-V1", &input));
        let signature = decode_base64url("proof.signature.value", &proof.signature.value)?;
        let public_key = key_bytes(key)?;
        crate::identity::verify_signature(key.algorithm.as_str(), &public_key, &input, &signature)
    })();
    match result {
        Ok(()) => report.cryptographic_result = AgreementCryptographicResultV3::Valid,
        Err(error) => report.errors.push(error.to_string()),
    }
    report
}

/// Verify one Agreement v3 proof against exactly one caller-selected key.
/// Trust, lifecycle, and operation policy remain inputs to the surrounding
/// TP-24/TP-26 verifier; this helper reports only the closed proof binding and
/// mathematical signature result.
pub fn verify_proof(
    proof: &AgreementProofV3,
    key: &AgreementVerificationKeyV3,
) -> AgreementProofVerificationV3 {
    proof_signature_report(proof, Some(key))
}

fn human_seal_local_signature_input(seal: &AgreementHumanSealV3) -> Result<Vec<u8>, CoreError> {
    let mut value = serde_json::to_value(seal)
        .map_err(|e| CoreError::MalformedDocument(format!("serialize human seal: {e}")))?;
    value
        .pointer_mut("/authentication")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| CoreError::MalformedDocument("human seal authentication missing".into()))?
        .remove("value");
    new_profile_signature_input(
        HUMAN_SEAL_SIGNATURE_DOMAIN,
        "jacs-agreement-human-seal-v1",
        &value,
    )
}

fn authority_record_signature_input(record: &AuthorityRecordV3) -> Result<Vec<u8>, CoreError> {
    let mut value = serde_json::to_value(record)
        .map_err(|e| CoreError::MalformedDocument(format!("serialize authority record: {e}")))?;
    value
        .pointer_mut("/authentication")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| CoreError::MalformedDocument("authority authentication missing".into()))?
        .remove("value");
    new_profile_signature_input(
        AUTHORITY_RECORD_SIGNATURE_DOMAIN,
        "jacs-authority-record-v1",
        &value,
    )
}

fn verify_human_seal(
    seal: &AgreementHumanSealV3,
    ceremony: &AgreementCeremonyContextV3,
    proof: &AgreementProofV3,
    core: &AgreementCoreV3,
    human_keys: &[HumanSealVerificationKeyV3],
) -> Result<String, CoreError> {
    if seal.payload.profile != "jacs-agreement-human-seal-v1" {
        return Err(CoreError::AgreementFailed(
            "invalid human seal profile".into(),
        ));
    }
    validate_token("humanSeal.sealId", &seal.payload.seal_id)?;
    validate_token(
        "humanSeal.humanPrincipalId",
        &seal.payload.human_principal_id,
    )?;
    validate_token("humanSeal.agentVersion", &seal.payload.agent_version)?;
    validate_jacs_time("humanSeal.approvedAt", &seal.payload.approved_at)?;
    let target = &ceremony.authorization_target;
    validate_token("ceremony.ceremonyId", &target.ceremony_id)?;
    validate_token("ceremony.humanPrincipalId", &target.human_principal_id)?;
    validate_token(
        "ceremony.agentCanonicalKeyId",
        &target.agent_canonical_key_id,
    )?;
    validate_token("ceremony.agentVersion", &target.agent_version)?;
    let expected_context_digest = ceremony_context_digest(ceremony)?;
    if target.profile != "jacs-agreement-ceremony-target-v3"
        || ceremony.profile != "jacs-agreement-ceremony-context-v3"
        || ceremony.authorization_target_digest != ceremony_target_digest(target)?
        || proof.ceremony_context_digest.as_deref() != Some(expected_context_digest.as_str())
    {
        return Err(CoreError::AgreementFailed(
            "human ceremony target/context digest mismatch".into(),
        ));
    }
    let challenge = decode_base64url("ceremony.challenge", &target.challenge)?;
    if challenge.len() != 32 {
        return Err(CoreError::AgreementFailed(
            "ceremony challenge must decode to exactly 32 bytes".into(),
        ));
    }
    let not_before = validate_jacs_time("ceremony.notBefore", &target.not_before)?;
    let expires_at = validate_jacs_time("ceremony.expiresAt", &target.expires_at)?;
    let approved_at = validate_jacs_time("humanSeal.approvedAt", &seal.payload.approved_at)?;
    if not_before >= expires_at || approved_at < not_before || approved_at >= expires_at {
        return Err(CoreError::AgreementFailed(
            "human seal approval is outside the half-open ceremony interval".into(),
        ));
    }
    let expected_proof_digest = proof_evidence_digest(proof)?;
    if target.agreement_core_digest != core_digest(core)?
        || target.participant_id != proof.participant_id
        || target.role != proof.role
        || target.operation != proof.operation
        || target.terms_digest != core.terms_digest
        || target.context_digest != core.context_digest
        || target.human_principal_id != seal.payload.human_principal_id
        || target.agent_canonical_key_id != proof.canonical_key_id
        || seal.payload.agreement_core_digest != target.agreement_core_digest
        || seal.payload.terms_digest != target.terms_digest
        || seal.payload.participant_id != target.participant_id
        || seal.payload.role != target.role
        || seal.payload.agent_canonical_key_id != target.agent_canonical_key_id
        || seal.payload.agent_version != target.agent_version
        || seal.payload.ceremony_context_digest != expected_context_digest
        || seal.payload.signed_proof_evidence_digest != expected_proof_digest
    {
        return Err(CoreError::AgreementFailed(
            "human seal does not repeat the exact ceremony, proof, participant, role, key, and core"
                .into(),
        ));
    }

    match &seal.authentication {
        AgreementHumanSealAuthenticationV3::LocalOsBrokerSignature {
            credential_id,
            credential_generation,
            credential_status_digest,
            assurance,
            algorithm,
            value,
        } => {
            if seal.payload.application_authorization_digest.is_some()
                || seal.payload.signer_completion_receipt_digest.is_some()
                || *credential_generation == 0
                || assurance != "local_os_user_presence"
            {
                return Err(CoreError::AgreementFailed(
                    "local human seal nullability/generation/assurance is invalid".into(),
                ));
            }
            validate_digest("humanSeal.credentialStatusDigest", credential_status_digest)?;
            let key = human_keys
                .iter()
                .find(|key| {
                    key.credential_id == *credential_id
                        && key.human_principal_id.as_deref()
                            == Some(seal.payload.human_principal_id.as_str())
                        && key.credential_generation == Some(*credential_generation)
                        && key.credential_status_digest.as_deref()
                            == Some(credential_status_digest.as_str())
                        && key.authority_anchor.is_none()
                        && key.authority_enrollment_handle.is_none()
                })
                .ok_or_else(|| {
                    CoreError::AgreementFailed("local broker key was not preselected".into())
                })?;
            if key.algorithm != *algorithm {
                return Err(CoreError::AlgorithmMismatch {
                    expected: key.algorithm.to_string(),
                    actual: algorithm.to_string(),
                });
            }
            let input = human_seal_local_signature_input(seal)?;
            let signature = decode_base64url("humanSeal.authentication.value", value)?;
            crate::identity::verify_signature(
                algorithm.as_str(),
                &human_key_bytes(key)?,
                &input,
                &signature,
            )?;
        }
        AgreementHumanSealAuthenticationV3::HaiAuthorityRecord { record } => {
            let app_digest = seal
                .payload
                .application_authorization_digest
                .as_ref()
                .ok_or_else(|| {
                    CoreError::AgreementFailed("HAI seal lacks application authorization".into())
                })?;
            let completion_digest = seal
                .payload
                .signer_completion_receipt_digest
                .as_ref()
                .ok_or_else(|| {
                    CoreError::AgreementFailed("HAI seal lacks signer completion receipt".into())
                })?;
            validate_digest("humanSeal.applicationAuthorizationDigest", app_digest)?;
            validate_digest("humanSeal.signerCompletionReceiptDigest", completion_digest)?;
            if record.payload.profile != "jacs-authority-record-v1"
                || record.payload.record_profile != "jacs-agreement-human-seal-v1"
                || record.payload.body_digest != human_seal_payload_digest(&seal.payload)?
                || record.payload.record_id != seal.payload.seal_id
                || record.payload.sequence > SAFE_INTEGER_MAX
                || (record.payload.sequence == 0)
                    != record.payload.previous_authority_record_digest.is_none()
            {
                return Err(CoreError::AgreementFailed(
                    "HAI seal authority record does not bind the exact seal payload/scope".into(),
                ));
            }
            validate_token(
                "authorityRecord.authorityEnrollmentHandle",
                &record.payload.authority_enrollment_handle,
            )?;
            if let Some(previous) = &record.payload.previous_authority_record_digest {
                validate_digest("authorityRecord.previousAuthorityRecordDigest", previous)?;
            }
            validate_authority_anchor(&record.payload.authority_anchor)?;
            validate_jacs_time(
                "authorityRecord.authenticatedCommitTime",
                &record.payload.authenticated_commit_time,
            )?;
            let AuthorityAnchorV3::Authority {
                bootstrap_profile,
                bootstrap_credential_id,
                ..
            } = &record.payload.authority_anchor;
            let expected_auth_type = match bootstrap_profile {
                BootstrapProfile::PinnedSigningCredentialV1 => "pinned_credential_signature",
                BootstrapProfile::ManagedControlPlaneV1 => "managed_row_signature",
            };
            if record.authentication.authentication_type != expected_auth_type
                || record.authentication.credential_id.as_str() != bootstrap_credential_id.as_str()
            {
                return Err(CoreError::AgreementFailed(
                    "HAI authority record authentication does not match its anchor".into(),
                ));
            }
            let key = human_keys
                .iter()
                .find(|key| {
                    key.credential_id == record.authentication.credential_id
                        && key.authority_anchor.as_ref() == Some(&record.payload.authority_anchor)
                        && key.authority_enrollment_handle.as_deref()
                            == Some(record.payload.authority_enrollment_handle.as_str())
                })
                .ok_or_else(|| {
                    CoreError::AgreementFailed("HAI authority key was not preselected".into())
                })?;
            if key.algorithm != record.authentication.algorithm {
                return Err(CoreError::AlgorithmMismatch {
                    expected: key.algorithm.to_string(),
                    actual: record.authentication.algorithm.to_string(),
                });
            }
            let input = authority_record_signature_input(record)?;
            let signature = decode_base64url(
                "authorityRecord.authentication.value",
                &record.authentication.value,
            )?;
            crate::identity::verify_signature(
                key.algorithm.as_str(),
                &human_key_bytes(key)?,
                &input,
                &signature,
            )?;
        }
    }
    human_seal_evidence_digest(seal)
}

fn expected_role_profile(role: EvidenceRoleV3) -> AgreementRoleEvidenceProfileV3 {
    match role {
        EvidenceRoleV3::Controller => AgreementRoleEvidenceProfileV3::Controller,
        EvidenceRoleV3::Signer => AgreementRoleEvidenceProfileV3::Consent,
        EvidenceRoleV3::Witness => AgreementRoleEvidenceProfileV3::Witness,
        EvidenceRoleV3::Notary => AgreementRoleEvidenceProfileV3::Notary,
    }
}

fn core_authorization_requirement(
    core: &AgreementCoreV3,
    participant_id: &str,
    role: EvidenceRoleV3,
) -> Option<AuthorizationRequirementV3> {
    if role == EvidenceRoleV3::Controller && participant_id == core.controller_participant_id {
        return Some(core.controller_authorization_requirement);
    }
    let participant_role = match role {
        EvidenceRoleV3::Signer => ParticipantRoleV3::Signer,
        EvidenceRoleV3::Witness => ParticipantRoleV3::Witness,
        EvidenceRoleV3::Notary => ParticipantRoleV3::Notary,
        EvidenceRoleV3::Controller => return None,
    };
    core.participants
        .iter()
        .find(|p| p.participant_id == participant_id && p.role == participant_role)
        .map(|p| p.authorization_requirement)
}

fn portable_operation(operation: AgreementOperationV3) -> SigningOperation {
    match operation {
        AgreementOperationV3::SignAgreementProposal => SigningOperation::SignAgreementProposal,
        AgreementOperationV3::SignAgreementAmendment => SigningOperation::SignAgreementAmendment,
        AgreementOperationV3::SignAgreementConsent => SigningOperation::SignAgreementConsent,
        AgreementOperationV3::SignAgreementWitness => SigningOperation::SignAgreementWitness,
        AgreementOperationV3::SignAgreementNotary => SigningOperation::SignAgreementNotary,
    }
}

/// Build the deliberately non-authorizing TP-24/TP-25 pair used to report
/// detached proof mathematics. The aggregate agreement verifier must not
/// confuse this integrity-only policy digest with the caller's requested
/// trust-bearing `verificationPolicyDigest`.
fn proof_integrity_context(
    proof: &AgreementProofV3,
) -> Result<(VerificationIntent, VerificationPolicy), CoreError> {
    let registry_digest = crate::identity::digest_json(
        "JACS-SECURITY-PROFILE-REGISTRY-V1",
        &json!({"profiles":[proof.profile.as_str()]}),
    )?;
    let policy = VerificationPolicy::integrity_only(
        "jacs-agreement-v3-proof-inspection".into(),
        registry_digest,
    )?;
    let mut intent = VerificationIntent::document_integrity();
    intent.expected_identity = match &proof.signer_identity_anchor {
        IdentityAnchorV3::Portable { jacs_id, .. } => ExactExpectation::exact(jacs_id.clone()),
        IdentityAnchorV3::AuthorityBacked { .. } => ExactExpectation::not_applicable(),
    };
    intent.expected_jacs_version = VersionExpectation::not_applicable();
    intent.operation = portable_operation(proof.operation);
    intent.signature_profile = proof.profile.as_str().into();
    Ok((intent, policy))
}

fn verify_role_evidence(
    evidence: &AgreementRoleEvidenceV3,
    expected_role: EvidenceRoleV3,
    core: &AgreementCoreV3,
    keys: &[AgreementVerificationKeyV3],
    human_keys: &[HumanSealVerificationKeyV3],
    exact_artifact: Option<&str>,
) -> AgreementProofVerificationV3 {
    let proof = &evidence.proof;
    let key_matches: Vec<_> = keys
        .iter()
        .filter(|key| key.participant_id == proof.participant_id && key.role == expected_role)
        .collect();
    let mut report =
        proof_signature_report(proof, (key_matches.len() == 1).then(|| key_matches[0]));
    if key_matches.len() > 1 {
        report.errors.push(
            "multiple preselected keys match one participant/role; key selection is ambiguous"
                .into(),
        );
    }
    if let Some(raw) = exact_artifact {
        let tp26_report = (|| {
            let (proof_intent, proof_policy) = proof_integrity_context(proof)?;
            if key_matches.len() == 1 {
                let public_key = key_bytes(key_matches[0])?;
                detached_proof_integrity_report(
                    raw,
                    &public_key,
                    key_matches[0].algorithm.as_str(),
                    &proof_intent,
                    &proof_policy,
                    DetachedProofInput::AgreementV3 { proof },
                )
            } else {
                missing_proof_integrity_report(raw, &proof_intent, &proof_policy)
            }
        })();
        match tp26_report {
            Ok(tp26_report) => {
                let signature = tp26_report.field(ReportField::SignatureValid);
                if signature.status != FieldStatus::Valid || signature.value != Value::Bool(true) {
                    report.cryptographic_result = AgreementCryptographicResultV3::Invalid;
                }
                match tp26_report.digest() {
                    Ok(digest) => report.verification_report_digest = Some(digest),
                    Err(error) => report.errors.push(error.to_string()),
                }
            }
            Err(error) => report.errors.push(error.to_string()),
        }
    }
    let result = (|| -> Result<(), CoreError> {
        if evidence.profile != expected_role_profile(expected_role)
            || proof.role != expected_role
            || proof.agreement_core_digest != core_digest(core)?
        {
            return Err(CoreError::AgreementFailed(
                "role evidence profile/role/core does not match finalization".into(),
            ));
        }
        let requirement =
            core_authorization_requirement(core, &proof.participant_id, expected_role).ok_or_else(
                || CoreError::AgreementFailed("role proof is not declared by the core".into()),
            )?;
        match requirement {
            AuthorizationRequirementV3::AgentSignature => {
                if evidence.ceremony_context.is_some()
                    || evidence.human_seal.is_some()
                    || proof.ceremony_context_digest.is_some()
                {
                    return Err(CoreError::AgreementFailed(
                        "agent_signature evidence must not contain ceremony or human seal".into(),
                    ));
                }
            }
            AuthorizationRequirementV3::AgentPlusHumanSeal => {
                let ceremony = evidence.ceremony_context.as_ref().ok_or_else(|| {
                    CoreError::AgreementFailed("human-required proof lacks ceremony context".into())
                })?;
                let seal = evidence.human_seal.as_ref().ok_or_else(|| {
                    CoreError::AgreementFailed("human-required proof lacks human seal".into())
                })?;
                report.human_seal_evidence_digest =
                    Some(verify_human_seal(seal, ceremony, proof, core, human_keys)?);
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        report.errors.push(error.to_string());
    }
    if !report.errors.is_empty() {
        report.cryptographic_result = AgreementCryptographicResultV3::Invalid;
    }
    report
}

fn governance_projection(core: &AgreementCoreV3) -> Result<Value, CoreError> {
    let participants = core
        .participants
        .iter()
        .map(|participant| {
            json!({
                "participantId": participant.participant_id,
                "role": participant.role,
                "weight": participant.weight,
                "identityAnchor": participant.identity_anchor,
                "authorizationRequirement": participant.authorization_requirement,
            })
        })
        .collect::<Vec<_>>();
    let projection = json!({
        "controllerParticipantId": core.controller_participant_id,
        "controllerIdentityAnchor": core.controller_identity_anchor,
        "controllerAuthorizationRequirement": core.controller_authorization_requirement,
        "participants": participants,
        "quorum": core.quorum,
        "notaryRequired": core.notary_required,
    });
    canonicalize_json_try(&projection)?;
    Ok(projection)
}

pub fn validate_amendment_lineage(
    core: &AgreementCoreV3,
    predecessor: Option<&AgreementFinalizationV3>,
) -> Result<(), CoreError> {
    match core.version_kind {
        AgreementVersionKindV3::Proposal => {
            if predecessor.is_some() {
                return Err(CoreError::AgreementFailed(
                    "version-one proposal must not receive predecessor evidence".into(),
                ));
            }
            Ok(())
        }
        AgreementVersionKindV3::Amendment => {
            let predecessor = predecessor.ok_or_else(|| {
                CoreError::AgreementFailed(
                    "amendment requires exact predecessor finalization".into(),
                )
            })?;
            validate_finalization_shape(predecessor)?;
            let prior_core = &predecessor.agreement_version.core;
            if prior_core.agreement_id != core.agreement_id
                || prior_core.version.checked_add(1) != Some(core.version)
                || core.previous_agreement_digest.as_deref()
                    != Some(predecessor.agreement_digest.as_str())
                || core.previous_finalization_evidence_digest.as_deref()
                    != Some(finalization_evidence_digest(predecessor)?.as_str())
                || governance_projection(prior_core)? != governance_projection(core)?
            {
                return Err(CoreError::AgreementFailed(
                    "amendment lineage/version/immutable governance does not match the accepted predecessor"
                        .into(),
                ));
            }
            Ok(())
        }
    }
}

fn expectation_for<'a>(
    intent: &'a AgreementVerificationIntentV3,
    participant_id: &str,
    role: EvidenceRoleV3,
) -> Option<&'a AgreementParticipantExpectationV3> {
    if role == EvidenceRoleV3::Controller {
        return (intent.expected_controller.participant_id == participant_id)
            .then_some(&intent.expected_controller);
    }
    if role == EvidenceRoleV3::Notary {
        return intent
            .expected_notary
            .as_ref()
            .filter(|value| value.participant_id == participant_id);
    }
    intent
        .expected_participants
        .iter()
        .find(|value| value.participant_id == participant_id && value.role == role)
}

fn validate_expectation(
    expectation: &AgreementParticipantExpectationV3,
    proof: &AgreementProofV3,
    key: &AgreementVerificationKeyV3,
) -> Result<(), CoreError> {
    if expectation.participant_id != proof.participant_id
        || expectation.role != proof.role
        || expectation.identity_anchor != proof.signer_identity_anchor
        || expectation.trust_record_digest != proof.signer_trust_record_digest
        || expectation.operation != proof.operation
        || expectation.signature_profile != proof.profile
        || key.identity_anchor != expectation.identity_anchor
        || key.trust_record_digest != expectation.trust_record_digest
    {
        return Err(CoreError::AgreementFailed(
            "proof/key does not match the exact participant expectation".into(),
        ));
    }
    match expectation.ceremony.mode.as_str() {
        "none"
            if expectation.ceremony.ceremony_context_digest.is_none()
                && expectation.ceremony.human_principal_id.is_none()
                && proof.ceremony_context_digest.is_none() => {}
        "required"
            if expectation.ceremony.ceremony_context_digest.is_some()
                && expectation.ceremony.human_principal_id.is_some()
                && expectation.ceremony.ceremony_context_digest
                    == proof.ceremony_context_digest => {}
        _ => {
            return Err(CoreError::AgreementFailed(
                "ceremony expectation mode/nullability/digest mismatch".into(),
            ));
        }
    }
    match &expectation.temporal {
        TemporalExpectationV3::Current {
            max_checkpoint_age_seconds,
            max_revocation_checkpoint_age_seconds,
        } if *max_checkpoint_age_seconds > 0 && *max_revocation_checkpoint_age_seconds > 0 => {}
        TemporalExpectationV3::AsOf {
            lifecycle_checkpoint_digest,
        } => validate_digest(
            "expectation.temporal.lifecycleCheckpointDigest",
            lifecycle_checkpoint_digest,
        )?,
        TemporalExpectationV3::Archival {
            observation_policy,
            authorization_status_checkpoint_digest,
            max_revocation_checkpoint_age_seconds,
        } => {
            validate_observation_policy(observation_policy)?;
            validate_digest(
                "expectation.temporal.authorizationStatusCheckpointDigest",
                authorization_status_checkpoint_digest,
            )?;
            if *max_revocation_checkpoint_age_seconds == 0 {
                return Err(CoreError::MalformedDocument(
                    "archival revocation checkpoint age must be positive".into(),
                ));
            }
        }
        TemporalExpectationV3::NotApplicable => {}
        _ => {
            return Err(CoreError::MalformedDocument(
                "current temporal bounds must be positive".into(),
            ));
        }
    }
    Ok(())
}

fn validate_expectation_descriptor(
    expectation: &AgreementParticipantExpectationV3,
    required_profile: AgreementProofProfileV3,
) -> Result<(), CoreError> {
    validate_token("expectation.participantId", &expectation.participant_id)?;
    validate_identity_anchor(&expectation.identity_anchor)?;
    validate_digest(
        "expectation.trustRecordDigest",
        &expectation.trust_record_digest,
    )?;
    if expectation.signature_profile != required_profile
        || expectation.operation != required_profile.operation()
        || expectation.role != required_profile.role()
    {
        return Err(CoreError::AgreementFailed(
            "participant expectation does not use the exact role/operation/profile mapping".into(),
        ));
    }
    match expectation.ceremony.mode.as_str() {
        "none"
            if expectation.ceremony.ceremony_context_digest.is_none()
                && expectation.ceremony.human_principal_id.is_none() => {}
        "required"
            if expectation.ceremony.ceremony_context_digest.is_some()
                && expectation.ceremony.human_principal_id.is_some() =>
        {
            validate_digest(
                "expectation.ceremony.ceremonyContextDigest",
                expectation
                    .ceremony
                    .ceremony_context_digest
                    .as_deref()
                    .expect("guarded above"),
            )?;
            validate_token(
                "expectation.ceremony.humanPrincipalId",
                expectation
                    .ceremony
                    .human_principal_id
                    .as_deref()
                    .expect("guarded above"),
            )?;
        }
        _ => {
            return Err(CoreError::MalformedDocument(
                "ceremony expectation mode and nullability are inconsistent".into(),
            ));
        }
    }
    match &expectation.temporal {
        TemporalExpectationV3::Current {
            max_checkpoint_age_seconds,
            max_revocation_checkpoint_age_seconds,
        } if *max_checkpoint_age_seconds > 0 && *max_revocation_checkpoint_age_seconds > 0 => {}
        TemporalExpectationV3::AsOf {
            lifecycle_checkpoint_digest,
        } => validate_digest(
            "expectation.temporal.lifecycleCheckpointDigest",
            lifecycle_checkpoint_digest,
        )?,
        TemporalExpectationV3::Archival {
            observation_policy,
            authorization_status_checkpoint_digest,
            max_revocation_checkpoint_age_seconds,
        } if *max_revocation_checkpoint_age_seconds > 0 => {
            validate_observation_policy(observation_policy)?;
            validate_digest(
                "expectation.temporal.authorizationStatusCheckpointDigest",
                authorization_status_checkpoint_digest,
            )?;
        }
        TemporalExpectationV3::NotApplicable => {}
        _ => {
            return Err(CoreError::MalformedDocument(
                "temporal checkpoint age bounds must be positive".into(),
            ));
        }
    }
    Ok(())
}

fn validate_intent_against_finalization(
    intent: &AgreementVerificationIntentV3,
    finalization: &AgreementFinalizationV3,
    core_hash: &str,
    finalization_hash: &str,
    keys: &[AgreementVerificationKeyV3],
) -> Result<(), CoreError> {
    if intent.profile != "jacs-agreement-verification-intent-v3" {
        return Err(CoreError::MalformedDocument(
            "verification intent profile must be jacs-agreement-verification-intent-v3".into(),
        ));
    }
    validate_digest(
        "intent.verificationPolicyDigest",
        &intent.verification_policy_digest,
    )?;
    let core = &finalization.agreement_version.core;
    validate_expectation_descriptor(
        &intent.expected_controller,
        if core.version == 1 {
            AgreementProofProfileV3::Proposal
        } else {
            AgreementProofProfileV3::Amendment
        },
    )?;
    for expectation in &intent.expected_participants {
        let profile = match expectation.role {
            EvidenceRoleV3::Signer => AgreementProofProfileV3::Consent,
            EvidenceRoleV3::Witness => AgreementProofProfileV3::Witness,
            _ => {
                return Err(CoreError::MalformedDocument(
                    "expectedParticipants contains a controller/notary role".into(),
                ));
            }
        };
        validate_expectation_descriptor(expectation, profile)?;
    }
    if let Some(expectation) = &intent.expected_notary {
        validate_expectation_descriptor(expectation, AgreementProofProfileV3::Notary)?;
    }
    if intent.expected_agreement_id != core.agreement_id
        || intent.expected_agreement_core_digest != core_hash
        || intent.expected_previous_agreement_digest != core.previous_agreement_digest
        || intent.expected_previous_finalization_evidence_digest
            != core.previous_finalization_evidence_digest
        || intent.expected_terms_digest != core.terms_digest
        || intent.expected_context_digest != core.context_digest
        || intent.expected_quorum != core.quorum
        || intent.expected_agreement_digest != finalization.agreement_digest
    {
        return Err(CoreError::AgreementFailed(
            "verification intent does not match the exact agreement core/lineage/terms/context/quorum"
                .into(),
        ));
    }
    match intent.expected_finalization.mode.as_str() {
        "exact"
            if intent.expected_finalization.evidence_digest.as_deref()
                == Some(finalization_hash) => {}
        "any_valid" if intent.expected_finalization.evidence_digest.is_none() => {}
        _ => {
            return Err(CoreError::AgreementFailed(
                "expectedFinalization mode/evidenceDigest mismatch".into(),
            ));
        }
    }

    let expected_participant_count = core
        .participants
        .iter()
        .filter(|participant| participant.role != ParticipantRoleV3::Notary)
        .count();
    if intent.expected_participants.len() != expected_participant_count {
        return Err(CoreError::AgreementFailed(
            "expectedParticipants must equal the complete signer/witness core set".into(),
        ));
    }
    let mut prior: Option<(&str, EvidenceRoleV3)> = None;
    for expected in &intent.expected_participants {
        if prior.is_some_and(|p| p >= (expected.participant_id.as_str(), expected.role)) {
            return Err(CoreError::MalformedDocument(
                "expectedParticipants must be participant/role sorted and unique".into(),
            ));
        }
        prior = Some((&expected.participant_id, expected.role));
        let participant_role = match expected.role {
            EvidenceRoleV3::Signer => ParticipantRoleV3::Signer,
            EvidenceRoleV3::Witness => ParticipantRoleV3::Witness,
            _ => {
                return Err(CoreError::MalformedDocument(
                    "expectedParticipants contains a controller/notary role".into(),
                ));
            }
        };
        let participant = core
            .participants
            .iter()
            .find(|p| p.participant_id == expected.participant_id && p.role == participant_role)
            .ok_or_else(|| {
                CoreError::AgreementFailed("expected participant absent from core".into())
            })?;
        if participant.identity_anchor != expected.identity_anchor
            || participant.trust_record_digest != expected.trust_record_digest
        {
            return Err(CoreError::AgreementFailed(
                "expected participant identity/trust row differs from core".into(),
            ));
        }
    }
    if intent.expected_controller.participant_id != core.controller_participant_id
        || intent.expected_controller.role != EvidenceRoleV3::Controller
        || intent.expected_controller.identity_anchor != core.controller_identity_anchor
        || intent.expected_controller.trust_record_digest != core.controller_trust_record_digest
    {
        return Err(CoreError::AgreementFailed(
            "expected controller differs from core controller".into(),
        ));
    }
    let core_notary = core
        .participants
        .iter()
        .find(|p| p.role == ParticipantRoleV3::Notary);
    match (core_notary, &intent.expected_notary) {
        (None, None) => {}
        (Some(core_notary), Some(expected))
            if expected.role == EvidenceRoleV3::Notary
                && expected.participant_id == core_notary.participant_id
                && expected.identity_anchor == core_notary.identity_anchor
                && expected.trust_record_digest == core_notary.trust_record_digest => {}
        _ => {
            return Err(CoreError::AgreementFailed(
                "expected notary does not exactly match notaryRequired/core".into(),
            ));
        }
    }

    for proof in std::iter::once(&finalization.agreement_version.controller_evidence.proof)
        .chain(finalization.consents.iter().map(|item| &item.proof))
        .chain(finalization.witnesses.iter().map(|item| &item.proof))
        .chain(finalization.notary.iter().map(|item| &item.proof))
    {
        let expectation =
            expectation_for(intent, &proof.participant_id, proof.role).ok_or_else(|| {
                CoreError::AgreementFailed("proof has no exact intent expectation".into())
            })?;
        let matching_keys: Vec<_> = keys
            .iter()
            .filter(|key| key.participant_id == proof.participant_id && key.role == proof.role)
            .collect();
        if matching_keys.len() != 1 {
            return Err(CoreError::AgreementFailed(
                "each proof must resolve exactly one caller-preselected key".into(),
            ));
        }
        validate_expectation(expectation, proof, matching_keys[0])?;
    }
    Ok(())
}

fn quorum_satisfied(
    core: &AgreementCoreV3,
    consents: &[AgreementProofVerificationV3],
    witnesses: &[AgreementProofVerificationV3],
) -> Result<bool, CoreError> {
    let valid_consent_ids: HashSet<_> = consents
        .iter()
        .filter(|r| r.cryptographic_result == AgreementCryptographicResultV3::Valid)
        .map(|r| r.participant_id.as_str())
        .collect();
    let valid_witness_ids: HashSet<_> = witnesses
        .iter()
        .filter(|r| r.cryptographic_result == AgreementCryptographicResultV3::Valid)
        .map(|r| r.participant_id.as_str())
        .collect();
    let signer_participants: Vec<_> = core
        .participants
        .iter()
        .filter(|p| p.role == ParticipantRoleV3::Signer)
        .collect();
    let witness_participants: Vec<_> = core
        .participants
        .iter()
        .filter(|p| p.role == ParticipantRoleV3::Witness)
        .collect();
    let signer_count = signer_participants
        .iter()
        .filter(|p| valid_consent_ids.contains(p.participant_id.as_str()))
        .count() as u64;
    let signer_weight = signer_participants
        .iter()
        .filter(|p| valid_consent_ids.contains(p.participant_id.as_str()))
        .try_fold(0u64, |total, p| total.checked_add(p.weight))
        .ok_or_else(|| CoreError::AgreementFailed("valid signer weight overflow".into()))?;
    let witness_count = witness_participants
        .iter()
        .filter(|p| valid_witness_ids.contains(p.participant_id.as_str()))
        .count() as u64;
    let witness_weight = witness_participants
        .iter()
        .filter(|p| valid_witness_ids.contains(p.participant_id.as_str()))
        .try_fold(0u64, |total, p| total.checked_add(p.weight))
        .ok_or_else(|| CoreError::AgreementFailed("valid witness weight overflow".into()))?;
    let signers_ok = match core.quorum.signer.mode {
        SignerQuorumModeV3::All => signer_count == signer_participants.len() as u64,
        SignerQuorumModeV3::CountAtLeast => {
            signer_count >= core.quorum.signer.threshold.unwrap_or(u64::MAX)
        }
        SignerQuorumModeV3::WeightAtLeast => {
            signer_weight >= core.quorum.signer.threshold.unwrap_or(u64::MAX)
        }
    };
    let witnesses_ok = match core.quorum.witness.mode {
        WitnessQuorumModeV3::None => witness_count == 0,
        WitnessQuorumModeV3::All => witness_count == witness_participants.len() as u64,
        WitnessQuorumModeV3::CountAtLeast => {
            witness_count >= core.quorum.witness.threshold.unwrap_or(u64::MAX)
        }
        WitnessQuorumModeV3::WeightAtLeast => {
            witness_weight >= core.quorum.witness.threshold.unwrap_or(u64::MAX)
        }
    };
    Ok(signers_ok && witnesses_ok)
}

fn empty_verification_report() -> AgreementV3VerificationReport {
    AgreementV3VerificationReport {
        profile: "jacs-agreement-verification-report-v3".into(),
        verification_intent_digest: None,
        agreement_core_digest: None,
        agreement_digest: None,
        finalization_evidence_digest: None,
        terms_schema_valid: false,
        context_schema_valid: false,
        controller: None,
        consents: Vec::new(),
        witnesses: Vec::new(),
        notary: None,
        cryptographic_result: AgreementCryptographicResultV3::Invalid,
        policy_accepted: false,
        errors: Vec::new(),
        policy_errors: Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_finalization_inner(
    finalization: &AgreementFinalizationV3,
    intent: &AgreementVerificationIntentV3,
    keys: &[AgreementVerificationKeyV3],
    human_keys: &[HumanSealVerificationKeyV3],
    terms_bundle: &ResolvedSchemaBundleV3,
    context_bundle: &ResolvedSchemaBundleV3,
    predecessor: Option<&AgreementFinalizationV3>,
    exact_artifact: Option<&str>,
) -> AgreementV3VerificationReport {
    let mut report = empty_verification_report();

    let structural = (|| -> Result<(String, String), CoreError> {
        validate_finalization_shape(finalization)?;
        let core = &finalization.agreement_version.core;
        validate_amendment_lineage(core, predecessor)?;
        let core_hash = core_digest(core)?;
        let finalization_hash = finalization_evidence_digest(finalization)?;
        report.verification_intent_digest = Some(verification_intent_digest(intent)?);
        report.agreement_core_digest = Some(core_hash.clone());
        report.agreement_digest = Some(finalization.agreement_digest.clone());
        report.finalization_evidence_digest = Some(finalization_hash.clone());
        terms_bundle.validate(
            &finalization.agreement_version.terms.schema_id,
            &finalization.agreement_version.terms.schema_bundle_digest,
            &finalization.agreement_version.terms.value,
        )?;
        report.terms_schema_valid = true;
        context_bundle.validate(
            &finalization.agreement_version.context.schema_id,
            &finalization.agreement_version.context.schema_bundle_digest,
            &finalization.agreement_version.context.value,
        )?;
        report.context_schema_valid = true;
        validate_intent_against_finalization(
            intent,
            finalization,
            &core_hash,
            &finalization_hash,
            keys,
        )?;
        Ok((core_hash, finalization_hash))
    })();
    if let Err(error) = structural {
        report.errors.push(error.to_string());
        return report;
    }

    let core = &finalization.agreement_version.core;
    report.controller = Some(verify_role_evidence(
        &finalization.agreement_version.controller_evidence,
        EvidenceRoleV3::Controller,
        core,
        keys,
        human_keys,
        exact_artifact,
    ));
    report.consents = finalization
        .consents
        .iter()
        .map(|evidence| {
            verify_role_evidence(
                evidence,
                EvidenceRoleV3::Signer,
                core,
                keys,
                human_keys,
                exact_artifact,
            )
        })
        .collect();
    report.witnesses = finalization
        .witnesses
        .iter()
        .map(|evidence| {
            verify_role_evidence(
                evidence,
                EvidenceRoleV3::Witness,
                core,
                keys,
                human_keys,
                exact_artifact,
            )
        })
        .collect();
    report.notary = finalization.notary.as_ref().map(|evidence| {
        verify_role_evidence(
            evidence,
            EvidenceRoleV3::Notary,
            core,
            keys,
            human_keys,
            exact_artifact,
        )
    });

    let controller_valid = report
        .controller
        .as_ref()
        .is_some_and(|r| r.cryptographic_result == AgreementCryptographicResultV3::Valid);
    let all_supplied_valid = report
        .consents
        .iter()
        .chain(report.witnesses.iter())
        .chain(report.notary.iter())
        .all(|r| r.cryptographic_result == AgreementCryptographicResultV3::Valid);
    let notary_valid = if core.notary_required {
        report
            .notary
            .as_ref()
            .is_some_and(|r| r.cryptographic_result == AgreementCryptographicResultV3::Valid)
    } else {
        report.notary.is_none()
    };
    let quorum_valid =
        quorum_satisfied(core, &report.consents, &report.witnesses).unwrap_or_else(|error| {
            report.errors.push(error.to_string());
            false
        });
    for proof_report in report
        .controller
        .iter()
        .chain(report.consents.iter())
        .chain(report.witnesses.iter())
        .chain(report.notary.iter())
    {
        report.errors.extend(proof_report.errors.iter().cloned());
    }
    if controller_valid
        && all_supplied_valid
        && notary_valid
        && quorum_valid
        && report.errors.is_empty()
    {
        report.cryptographic_result = AgreementCryptographicResultV3::Valid;
        // A preselected key is not proof of identity, lifecycle, current trust,
        // revocation, or operation authorization.  Until the surrounding
        // verifier supplies and validates one complete TP-24/TP-26 report per
        // role proof, v3 intentionally remains mathematical evidence only.
        report.policy_errors.push(
            "full TP-24/TP-26 identity, lifecycle, trust, revocation, operation, and temporal reports are required before Agreement v3 policy acceptance"
                .into(),
        );
    }
    report
}

#[allow(clippy::too_many_arguments)]
pub fn verify_finalization(
    finalization: &AgreementFinalizationV3,
    intent: &AgreementVerificationIntentV3,
    keys: &[AgreementVerificationKeyV3],
    human_keys: &[HumanSealVerificationKeyV3],
    terms_bundle: &ResolvedSchemaBundleV3,
    context_bundle: &ResolvedSchemaBundleV3,
    predecessor: Option<&AgreementFinalizationV3>,
) -> AgreementV3VerificationReport {
    verify_finalization_inner(
        finalization,
        intent,
        keys,
        human_keys,
        terms_bundle,
        context_bundle,
        predecessor,
        None,
    )
}

/// Verify the complete portable request used by all bindings.
pub fn verify_input(input: &AgreementV3VerificationInput) -> AgreementV3VerificationReport {
    let finalization_bytes = match decode_base64url(
        "verificationInput.finalizationBase64url",
        &input.finalization_base64url,
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            let mut report = empty_verification_report();
            report.errors.push(error.to_string());
            return report;
        }
    };
    let finalization_raw = match std::str::from_utf8(&finalization_bytes) {
        Ok(raw) => raw,
        Err(_) => {
            let mut report = empty_verification_report();
            report
                .errors
                .push("agreement finalization must be UTF-8 JSON".into());
            return report;
        }
    };
    let finalization = match parse_finalization(&finalization_bytes) {
        Ok(finalization) => finalization,
        Err(error) => {
            let mut report = empty_verification_report();
            report.errors.push(error.to_string());
            return report;
        }
    };
    let predecessor = match input.predecessor_base64url.as_deref() {
        Some(encoded) => match decode_base64url("verificationInput.predecessorBase64url", encoded)
            .and_then(|bytes| parse_finalization(&bytes))
        {
            Ok(predecessor) => Some(predecessor),
            Err(error) => {
                let mut report = empty_verification_report();
                report.errors.push(error.to_string());
                return report;
            }
        },
        None => None,
    };
    verify_finalization_inner(
        &finalization,
        &input.intent,
        &input.keys,
        &input.human_keys,
        &input.terms_schema_bundle,
        &input.context_schema_bundle,
        predecessor.as_ref(),
        Some(finalization_raw),
    )
}

pub fn serialize_canonical<T: Serialize>(value: &T) -> Result<String, CoreError> {
    let value = serde_json::to_value(value)
        .map_err(|e| CoreError::MalformedDocument(format!("serialize agreement v3: {e}")))?;
    canonicalize_json_try(&value)
}
