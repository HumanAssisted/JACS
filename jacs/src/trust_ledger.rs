//! Crash-durable local trust, policy, and status authority ledger.
//!
//! Candidate discovery and key caches never write this store.  Every mutation
//! requires a fresh, explicitly supplied owner authorization, is serialized by
//! one persistent advisory lock, and commits through a recoverable journal.
//! Immutable entry files are the source of truth; `state.json` is a validated
//! high-water projection and cannot silently replace ledger history.

use crate::error::JacsError;
use jacs_core::identity::{
    AuthorityAnchor, IdentityAnchor, JacsTime, StatusAuthority, TrustStoreAnchor, digest_json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::{info, warn};

const STORE_PROFILE: &str = "jacs-local-trust-ledger-store-v1";
const STATE_PROFILE: &str = "jacs-local-trust-ledger-state-v1";
const ENTRY_PROFILE: &str = "jacs-local-trust-ledger-entry-v1";
const JOURNAL_PROFILE: &str = "jacs-local-trust-ledger-journal-v1";
const OWNER_ENROLLMENT_PROFILE: &str = "jacs-local-owner-enrollment-v1";
const OWNER_PROOF_PROFILE: &str = "jacs-control-actor-proof-v1";
const OWNER_PROOF_RECORD_PROFILE: &str = "jacs-local-control-actor-record-v1";
const TRUST_DECISION_PROFILE: &str = "jacs-trust-decision-evidence-v1";
const TRUST_LEDGER_PROFILE: &str = "jacs-trust-ledger-v1";
const TRUST_PROVENANCE_PROFILE: &str = "jacs-trust-provenance-v1";
const TRUST_TOMBSTONE_PROFILE: &str = "jacs-trust-tombstone-v1";
const POLICY_BUNDLE_PROFILE: &str = "jacs-policy-bundle-v1";
const POLICY_AUTH_PROFILE: &str = "jacs-policy-update-authorization-v1";
const POLICY_UPDATE_PROFILE: &str = "jacs-policy-update-v1";
const STATUS_ACCEPTANCE_PROFILE: &str = "jacs-status-checkpoint-acceptance-v1";
const MAX_LEDGER_FILE_BYTES: usize = 16 * 1024 * 1024;
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);

fn trust_error(message: impl Into<String>) -> JacsError {
    let message = message.into();
    warn!(
        event = "local_trust_ledger_rejected",
        reason = %message,
        "rejected local trust authority operation"
    );
    JacsError::TrustError(message)
}

fn map_io(path: &Path, error: std::io::Error) -> JacsError {
    warn!(
        event = "local_trust_ledger_read_failed",
        path = %path.display(),
        reason = %error,
        "failed to read local trust authority state"
    );
    JacsError::FileReadFailed {
        path: path.to_string_lossy().into_owned(),
        reason: error.to_string(),
    }
}

fn map_write(path: &Path, error: std::io::Error) -> JacsError {
    warn!(
        event = "local_trust_ledger_write_failed",
        path = %path.display(),
        reason = %error,
        "failed to commit local trust authority state"
    );
    JacsError::FileWriteFailed {
        path: path.to_string_lossy().into_owned(),
        reason: error.to_string(),
    }
}

fn digest<T: Serialize>(label: &str, value: &T) -> Result<String, JacsError> {
    let value = serde_json::to_value(value)
        .map_err(|error| trust_error(format!("failed to encode digest input: {error}")))?;
    digest_json(label, &value).map_err(|error| trust_error(error.to_string()))
}

fn require_digest(value: &str, field: &str) -> Result<(), JacsError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(trust_error(format!("{field} is not a sha256 digest")));
    };
    if hex.len() != 64
        || !hex
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(trust_error(format!(
            "{field} must contain 64 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn require_id(value: &str, field: &str) -> Result<(), JacsError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(trust_error(format!(
            "{field} is not a valid nonempty identifier"
        )));
    }
    Ok(())
}

fn parse_time(value: &JacsTime) -> Result<chrono::DateTime<chrono::Utc>, JacsError> {
    crate::time_utils::parse_rfc3339(value.as_str())
}

fn now_time() -> Result<JacsTime, JacsError> {
    JacsTime::from_unix_seconds(chrono::Utc::now().timestamp())
        .map_err(|error| trust_error(error.to_string()))
}

/// Explicit owner enrollment mode.  A legacy migration records the old store
/// as forensic input only; it never imports trust, policy, or tombstone state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnerEnrollmentMode {
    NewStore,
    LegacyMigration {
        #[serde(rename = "legacyStoreDigest")]
        legacy_store_digest: String,
        #[serde(rename = "legacyConfigDigest")]
        legacy_config_digest: String,
    },
}

/// Operator authorization needed to create a local authority store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnerEnrollmentRequest {
    pub confirmation_digest: String,
    pub mode: OwnerEnrollmentMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalOwnerStoreBootstrap {
    pub profile: String,
    pub canonical_store_id: String,
    pub owner_id: String,
    pub bootstrap_nonce: String,
    pub created_at: JacsTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalOwnerEnrollmentRecord {
    pub profile: String,
    pub bootstrap_digest: String,
    pub owner_id: String,
    pub confirmation_digest: String,
    pub mode: OwnerEnrollmentMode,
    pub committed_at: JacsTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoreBootstrapFile {
    profile: String,
    bootstrap: LocalOwnerStoreBootstrap,
    bootstrap_digest: String,
    source_anchor: TrustStoreAnchor,
    owner_enrollment: LocalOwnerEnrollmentRecord,
    owner_enrollment_digest: String,
}

/// Fresh local owner authorization. The proof is consumed in the same ledger
/// transaction and cannot be replayed for a second request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerAuthorization {
    decision_id: String,
    confirmation_digest: String,
    authenticated_at: JacsTime,
    expires_at: JacsTime,
}

impl OwnerAuthorization {
    /// Construct a five-minute owner authorization window starting now.
    pub fn fresh(
        decision_id: impl Into<String>,
        confirmation_digest: impl Into<String>,
    ) -> Result<Self, JacsError> {
        let decision_id = decision_id.into();
        let confirmation_digest = confirmation_digest.into();
        require_id(&decision_id, "decisionId")?;
        require_digest(&confirmation_digest, "confirmationDigest")?;
        let authenticated_at = chrono::Utc::now().timestamp();
        let expires_at = authenticated_at + 300;
        let authenticated_at = JacsTime::from_unix_seconds(authenticated_at)
            .map_err(|error| trust_error(error.to_string()))?;
        let expires_at = JacsTime::from_unix_seconds(expires_at)
            .map_err(|error| trust_error(error.to_string()))?;
        Ok(Self {
            decision_id,
            confirmation_digest,
            authenticated_at,
            expires_at,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OwnerProofScope {
    Trust,
    Policy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalOwnerProofPayload {
    profile: String,
    proof_id: String,
    source_anchor: TrustStoreAnchor,
    scope: OwnerProofScope,
    action: String,
    actor_class: String,
    actor_id: String,
    authentication_class: String,
    action_request_digest: String,
    authenticated_at: JacsTime,
    expires_at: JacsTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalOwnerProofRecord {
    profile: String,
    source_anchor: TrustStoreAnchor,
    record_id: String,
    sequence: u64,
    previous_record_digest: Option<String>,
    body_digest: String,
    authenticated_commit_time: JacsTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum LocalOwnerProofAuthentication {
    LocalOwnerStore { record: LocalOwnerProofRecord },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalOwnerProofEvidence {
    payload: LocalOwnerProofPayload,
    authentication: LocalOwnerProofAuthentication,
}

impl LocalOwnerProofEvidence {
    fn record(&self) -> &LocalOwnerProofRecord {
        match &self.authentication {
            LocalOwnerProofAuthentication::LocalOwnerStore { record } => record,
        }
    }

    fn evidence_digest(&self) -> Result<String, JacsError> {
        digest("JACS-CONTROL-ACTOR-PROOF-EVIDENCE-V1", self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustProvenanceMethod {
    AuthenticatedOutOfBand,
    ExplicitTofu,
    AuthorityRegistry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustProvenance {
    pub profile: String,
    pub method: TrustProvenanceMethod,
    pub source_authority_anchor: Option<AuthorityAnchor>,
    pub source_evidence_digest: String,
    pub candidate_material_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustEnrollment {
    pub policy_name: String,
    pub policy_version: u64,
    pub verification_policy_digest: String,
    pub identity_anchor: IdentityAnchor,
    pub status_authority: StatusAuthority,
    pub provenance: TrustProvenance,
    pub current_root_canonical_key_id: String,
    pub lifecycle_sequence: u64,
    pub lifecycle_record_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DistrustReason {
    AdministrativeWithdrawal,
    SuspectedCompromise,
    ConfirmedCompromise,
    PolicyViolation,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustTombstone {
    pub profile: String,
    pub tombstone_id: String,
    pub identity: String,
    pub denied_anchors: Vec<IdentityAnchor>,
    pub prior_trust_record_digests: Vec<String>,
    pub reason_category: DistrustReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReanchorMode {
    ContinuityProved,
    NewEnrollment,
}

/// High-level trust mutation. The store constructs the decision request,
/// owner proof, decision evidence, and immutable ledger row from this value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum TrustMutation {
    Enroll {
        enrollment: TrustEnrollment,
        underlying_independent_proof_digest: String,
    },
    AdvanceHead {
        identity_anchor: IdentityAnchor,
        prior_lifecycle_sequence: u64,
        prior_lifecycle_record_digest: String,
        new_root_canonical_key_id: String,
        new_lifecycle_sequence: u64,
        new_lifecycle_record_digest: String,
    },
    Reanchor {
        old_identity_anchor: IdentityAnchor,
        new_enrollment: TrustEnrollment,
        mode: ReanchorMode,
        continuity_evidence_digest: Option<String>,
    },
    Distrust {
        tombstone: TrustTombstone,
    },
    Reenroll {
        tombstone_id: String,
        tombstone_digest: String,
        new_enrollment: TrustEnrollment,
    },
    UpdateEnrollmentPolicy {
        identity_anchor: IdentityAnchor,
        old_policy_digest: String,
        new_policy_digest: String,
        policy_update_digest: String,
    },
    UpdateStatusAuthority {
        identity_anchor: IdentityAnchor,
        old_status_authority: StatusAuthority,
        new_status_authority: StatusAuthority,
        transition_evidence_digest: Option<String>,
    },
}

impl TrustMutation {
    fn action(&self) -> &'static str {
        match self {
            Self::Enroll { .. } => "enroll",
            Self::AdvanceHead { .. } => "advance_head",
            Self::Reanchor { .. } => "reanchor",
            Self::Distrust { .. } => "distrust",
            Self::Reenroll { .. } => "reenroll",
            Self::UpdateEnrollmentPolicy { .. } => "update_enrollment_policy",
            Self::UpdateStatusAuthority { .. } => "update_status_authority",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ControlActorReference {
    actor_class: String,
    actor_id: String,
    actor_proof_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ControlActorEvidence {
    actor_class: String,
    actor_id: String,
    actor_proof_type: String,
    actor_proof_evidence_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustDecisionRequest {
    decision_id: String,
    source_anchor: TrustStoreAnchor,
    action: String,
    actor: ControlActorReference,
    identity: String,
    prior_trust_record_digest: Option<String>,
    details: TrustMutation,
    decision_time: JacsTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustDecisionEvidence {
    profile: String,
    decision_id: String,
    source_anchor: TrustStoreAnchor,
    action: String,
    actor: ControlActorEvidence,
    identity: String,
    prior_trust_record_digest: Option<String>,
    details: TrustMutation,
    decision_request_digest: String,
    decision_time: JacsTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustLedgerActor {
    actor_class: String,
    actor_id: String,
    actor_proof_type: String,
    decision_evidence_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustLedgerRecord {
    profile: String,
    source_anchor: TrustStoreAnchor,
    record_id: String,
    sequence: u64,
    previous_record_digest: Option<String>,
    identity: String,
    event: TrustMutation,
    actor: TrustLedgerActor,
    authenticated_commit_time: JacsTime,
}

/// Closed policy bundle persisted by the local authority. Component objects
/// remain opaque here but their profile/version/digest cross-links are checked
/// before the bundle can advance the high-water record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyBundle {
    pub profile: String,
    pub bundle_version: u64,
    pub verification_policy: Value,
    pub schema_registry: Option<Value>,
    pub security_profile_registry: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyUpdateAuthorizationRequest {
    source_anchor: TrustStoreAnchor,
    decision_id: String,
    previous_bundle_digest: Option<String>,
    proposed_bundle_digest: String,
    actor: ControlActorReference,
    decided_at: JacsTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyUpdateAuthorization {
    profile: String,
    source_anchor: TrustStoreAnchor,
    decision_id: String,
    previous_bundle_digest: Option<String>,
    proposed_bundle_digest: String,
    actor: ControlActorEvidence,
    decided_at: JacsTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyUpdateRecord {
    profile: String,
    source_anchor: TrustStoreAnchor,
    sequence: u64,
    previous_update_digest: Option<String>,
    previous_bundle_digest: Option<String>,
    new_bundle: PolicyBundle,
    authorization_digest: String,
    authenticated_commit_time: JacsTime,
}

/// Complete local status statement accepted by the owner store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalStatusCheckpoint {
    pub profile: String,
    pub operation: String,
    pub purpose: String,
    pub identity_anchor: IdentityAnchor,
    pub status_authority: StatusAuthority,
    pub authority_scope: String,
    pub status_sequence: u64,
    pub checkpoint_time: JacsTime,
    pub complete_through: JacsTime,
    pub lifecycle_sequence: u64,
    pub lifecycle_record_digest: String,
    pub current_status_key_id: Option<String>,
    pub revocation_epoch: u64,
    pub previous_status_checkpoint_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StatusAcceptanceRequest {
    acceptance_id: String,
    source_anchor: TrustStoreAnchor,
    identity: String,
    status_checkpoint_digest: String,
    previous_acceptance_digest: Option<String>,
    accepted_at: JacsTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum AcceptedStatusEvidence {
    LocalStatusPayload { digest: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalStatusAcceptance {
    profile: String,
    trust_store_anchor: TrustStoreAnchor,
    identity_anchor: IdentityAnchor,
    status_authority: StatusAuthority,
    acceptance_sequence: u64,
    previous_acceptance_digest: Option<String>,
    status_checkpoint_digest: String,
    accepted_evidence: AcceptedStatusEvidence,
    status_sequence: u64,
    lifecycle_sequence: u64,
    lifecycle_record_digest: String,
    revocation_epoch: u64,
    complete_through: JacsTime,
    first_accepted_at: JacsTime,
}

/// Compare-and-swap heads supplied by a caller that prepared a trust change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustAppendGuard {
    pub expected_global_head: Option<String>,
    pub expected_identity_head: Option<String>,
}

/// Compare-and-swap heads supplied for a policy change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyAppendGuard {
    pub expected_policy_head: Option<String>,
    pub expected_bundle_digest: Option<String>,
}

/// Compare-and-swap heads supplied for status acceptance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatusAppendGuard {
    pub expected_acceptance_head: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LedgerAppendReceipt {
    pub entry_sequence: u64,
    pub entry_digest: String,
    pub logical_record_digest: String,
    pub state_digest: String,
    pub idempotent_replay: bool,
}

/// Authenticated retained heads exposed to verification without permitting a
/// caller to mutate or synthesize ledger state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LedgerHighWater {
    pub source_anchor: TrustStoreAnchor,
    pub trust_sequence: Option<u64>,
    pub trust_record_digest: Option<String>,
    pub policy_sequence: Option<u64>,
    pub policy_update_digest: Option<String>,
    pub policy_bundle_digest: Option<String>,
    pub tombstone_disposition_digest: String,
    pub blocking_tombstone_set_digest: String,
    pub greatest_accepted_utc_second: JacsTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalStatusHighWater {
    pub identity_anchor: IdentityAnchor,
    pub status_authority: StatusAuthority,
    pub acceptance_sequence: u64,
    pub acceptance_digest: String,
    pub status_sequence: u64,
    pub checkpoint_digest: String,
    pub checkpoint_time: JacsTime,
    pub complete_through: JacsTime,
    pub lifecycle_sequence: u64,
    pub lifecycle_record_digest: String,
    pub revocation_epoch: u64,
    pub first_accepted_at: JacsTime,
}

/// Opaque hand-off from the native trust/lifecycle verifier.
///
/// There is deliberately no constructor in this module. Until a reducer can
/// prove the candidate anchor, complete lifecycle chain, independent trust
/// proof, and action-specific continuity evidence, caller-provided lifecycle
/// counters or digests cannot reach durable authority state.
#[derive(Debug, Clone)]
pub struct VerifiedTrustMutation {
    identity: String,
    mutation: TrustMutation,
}

/// Opaque hand-off from the closed TP-25/registry policy parser.
#[derive(Debug, Clone)]
pub struct VerifiedPolicyBundle {
    bundle: PolicyBundle,
}

/// Opaque hand-off from the lifecycle/status verifier.
#[derive(Debug, Clone)]
pub struct VerifiedLocalStatusCheckpoint {
    identity: String,
    checkpoint: LocalStatusCheckpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConsumedDecision {
    request_digest: String,
    entry_sequence: u64,
    entry_digest: String,
    logical_record_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TombstoneState {
    tombstone: TrustTombstone,
    tombstone_digest: String,
    ledger_record_digest: String,
    superseded_by_record_digest: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TombstoneDispositionProjection<'a> {
    identity: &'a str,
    tombstone_id: &'a str,
    tombstone_digest: &'a str,
    disposition: &'static str,
    reenrollment_record_digest: Option<&'a str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BlockingTombstoneProjection<'a> {
    identity: &'a str,
    tombstone_id: &'a str,
    tombstone_digest: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IdentityTrustState {
    current_record_digest: String,
    active_enrollment: Option<TrustEnrollment>,
    superseded_anchors: Vec<IdentityAnchor>,
    tombstones: Vec<TombstoneState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyHighWater {
    sequence: u64,
    update_digest: String,
    bundle_version: u64,
    bundle_digest: String,
    policy_name: String,
    policy_version: u64,
    verification_policy_digest: String,
    schema_registry_version: Option<u64>,
    schema_registry_digest: Option<String>,
    security_profile_registry_version: u64,
    security_profile_registry_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StatusHighWater {
    identity_anchor: IdentityAnchor,
    status_authority: StatusAuthority,
    acceptance_sequence: u64,
    acceptance_digest: String,
    status_sequence: u64,
    checkpoint_digest: String,
    checkpoint_time: JacsTime,
    complete_through: JacsTime,
    lifecycle_sequence: u64,
    lifecycle_record_digest: String,
    revocation_epoch: u64,
    first_accepted_at: JacsTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LedgerState {
    profile: String,
    source_anchor: TrustStoreAnchor,
    bootstrap_digest: String,
    owner_enrollment_digest: String,
    global_head: Option<String>,
    entry_digests: Vec<String>,
    trust_sequence: Option<u64>,
    trust_head: Option<String>,
    owner_proof_sequence: Option<u64>,
    owner_proof_head: Option<String>,
    greatest_accepted_utc_second: JacsTime,
    policy: Option<PolicyHighWater>,
    identities: BTreeMap<String, IdentityTrustState>,
    status: BTreeMap<String, StatusHighWater>,
    tombstone_disposition_digest: String,
    blocking_tombstone_set_digest: String,
    consumed_decisions: BTreeMap<String, ConsumedDecision>,
}

impl LedgerState {
    fn initial(bootstrap: &StoreBootstrapFile) -> Result<Self, JacsError> {
        let identities = BTreeMap::new();
        let (tombstone_disposition_digest, blocking_tombstone_set_digest) =
            tombstone_projection_digests(&identities)?;
        Ok(Self {
            profile: STATE_PROFILE.to_string(),
            source_anchor: bootstrap.source_anchor.clone(),
            bootstrap_digest: bootstrap.bootstrap_digest.clone(),
            owner_enrollment_digest: bootstrap.owner_enrollment_digest.clone(),
            global_head: None,
            entry_digests: Vec::new(),
            trust_sequence: None,
            trust_head: None,
            owner_proof_sequence: None,
            owner_proof_head: None,
            greatest_accepted_utc_second: bootstrap.bootstrap.created_at.clone(),
            policy: None,
            identities,
            status: BTreeMap::new(),
            tombstone_disposition_digest,
            blocking_tombstone_set_digest,
            consumed_decisions: BTreeMap::new(),
        })
    }
}

fn tombstone_projection_digests(
    identities: &BTreeMap<String, IdentityTrustState>,
) -> Result<(String, String), JacsError> {
    let mut dispositions = Vec::new();
    let mut blocking = Vec::new();
    for (identity, state) in identities {
        for tombstone in &state.tombstones {
            let superseding = tombstone.superseded_by_record_digest.as_deref();
            dispositions.push(TombstoneDispositionProjection {
                identity,
                tombstone_id: &tombstone.tombstone.tombstone_id,
                tombstone_digest: &tombstone.tombstone_digest,
                disposition: if superseding.is_some() {
                    "superseded_by_reenroll"
                } else {
                    "effective"
                },
                reenrollment_record_digest: superseding,
            });
            if superseding.is_none() {
                blocking.push(BlockingTombstoneProjection {
                    identity,
                    tombstone_id: &tombstone.tombstone.tombstone_id,
                    tombstone_digest: &tombstone.tombstone_digest,
                });
            }
        }
    }
    dispositions.sort_by(|left, right| {
        (left.identity, left.tombstone_id).cmp(&(right.identity, right.tombstone_id))
    });
    blocking.sort_by(|left, right| {
        (left.identity, left.tombstone_id).cmp(&(right.identity, right.tombstone_id))
    });
    Ok((
        digest("JACS-TRUST-TOMBSTONE-DISPOSITIONS-V1", &dispositions)?,
        digest("JACS-BLOCKING-TRUST-TOMBSTONES-V1", &blocking)?,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum LedgerOperation {
    Trust {
        decision: TrustDecisionEvidence,
        record: TrustLedgerRecord,
    },
    Policy {
        authorization: PolicyUpdateAuthorization,
        record: PolicyUpdateRecord,
    },
    Status {
        request: StatusAcceptanceRequest,
        acceptance: LocalStatusAcceptance,
        checkpoint: LocalStatusCheckpoint,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LedgerEntry {
    profile: String,
    source_anchor: TrustStoreAnchor,
    entry_sequence: u64,
    previous_entry_digest: Option<String>,
    transaction_id: String,
    owner_proof: LocalOwnerProofEvidence,
    operation: LedgerOperation,
    committed_at: JacsTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum LedgerJournal {
    Clean {
        profile: String,
        state_digest: String,
    },
    Prepared {
        profile: String,
        base_state_digest: String,
        next_state_digest: String,
        entry_digest: String,
        entry: LedgerEntry,
        next_state: LedgerState,
    },
}

/// Owner-only local ledger rooted at an explicitly bootstrapped directory.
#[derive(Debug, Clone)]
pub struct LocalTrustLedger {
    root: PathBuf,
}

struct LedgerLock {
    _file: File,
}

impl LocalTrustLedger {
    pub fn initialize(
        root: impl AsRef<Path>,
        request: OwnerEnrollmentRequest,
    ) -> Result<Self, JacsError> {
        require_digest(&request.confirmation_digest, "confirmationDigest")?;
        if let OwnerEnrollmentMode::LegacyMigration {
            legacy_store_digest,
            legacy_config_digest,
        } = &request.mode
        {
            require_digest(legacy_store_digest, "legacyStoreDigest")?;
            require_digest(legacy_config_digest, "legacyConfigDigest")?;
        }

        let ledger = Self {
            root: root.as_ref().to_path_buf(),
        };
        crate::secure_io::ensure_owner_only_directory(&ledger.root)
            .map_err(|error| map_write(&ledger.root, error))?;
        crate::secure_io::ensure_owner_only_directory(ledger.entries_dir())
            .map_err(|error| map_write(&ledger.entries_dir(), error))?;
        let _lock = ledger.acquire_lock()?;

        for path in [
            ledger.bootstrap_path(),
            ledger.state_path(),
            ledger.journal_path(),
        ] {
            match std::fs::symlink_metadata(&path) {
                Ok(_) => {
                    return Err(trust_error(format!(
                        "local trust ledger is already or partially initialized at '{}'",
                        ledger.root.display()
                    )));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(map_io(&path, error)),
            }
        }

        let owner_id = effective_owner_id()?;
        let created_at = now_time()?;
        let bootstrap = LocalOwnerStoreBootstrap {
            profile: "jacs-local-owner-store-bootstrap-v1".to_string(),
            canonical_store_id: uuid::Uuid::new_v4().hyphenated().to_string(),
            owner_id: owner_id.clone(),
            bootstrap_nonce: hex::encode(rand::random::<[u8; 32]>()),
            created_at: created_at.clone(),
        };
        let bootstrap_digest = digest("JACS-LOCAL-OWNER-STORE-BOOTSTRAP-V1", &bootstrap)?;
        let source_anchor = local_source_anchor(&bootstrap, &bootstrap_digest);
        let owner_enrollment = LocalOwnerEnrollmentRecord {
            profile: OWNER_ENROLLMENT_PROFILE.to_string(),
            bootstrap_digest: bootstrap_digest.clone(),
            owner_id,
            confirmation_digest: request.confirmation_digest,
            mode: request.mode,
            committed_at: created_at,
        };
        let owner_enrollment_digest = digest("JACS-LOCAL-OWNER-ENROLLMENT-V1", &owner_enrollment)?;
        let bootstrap_file = StoreBootstrapFile {
            profile: STORE_PROFILE.to_string(),
            bootstrap,
            bootstrap_digest,
            source_anchor,
            owner_enrollment,
            owner_enrollment_digest,
        };
        validate_bootstrap(&bootstrap_file)?;
        let state = LedgerState::initial(&bootstrap_file)?;
        let state_digest = state_digest(&state)?;
        let journal = LedgerJournal::Clean {
            profile: JOURNAL_PROFILE.to_string(),
            state_digest,
        };

        ledger.write_new(&ledger.bootstrap_path(), &bootstrap_file)?;
        ledger.write_new(&ledger.state_path(), &state)?;
        ledger.write_new(&ledger.journal_path(), &journal)?;
        info!(
            event = "local_trust_ledger_initialized",
            path = %ledger.root.display(),
            store_id = %bootstrap_file.bootstrap.canonical_store_id,
            owner_id = %bootstrap_file.bootstrap.owner_id,
            "initialized owner-authenticated local trust ledger"
        );
        Ok(ledger)
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self, JacsError> {
        let ledger = Self {
            root: root.as_ref().to_path_buf(),
        };
        ledger.validate_store_directories()?;
        let _lock = ledger.acquire_lock()?;
        let bootstrap: StoreBootstrapFile = ledger.read(&ledger.bootstrap_path())?;
        validate_bootstrap(&bootstrap)?;
        ledger.recover_locked(&bootstrap)?;
        let state: LedgerState = ledger.read(&ledger.state_path())?;
        ledger.validate_state_and_history(&bootstrap, &state)?;
        Ok(ledger)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn global_head(&self) -> Result<Option<String>, JacsError> {
        self.with_state(|_, state| Ok(state.trust_head.clone()))
    }

    pub fn identity_head(&self, identity: &str) -> Result<Option<String>, JacsError> {
        require_id(identity, "identity")?;
        self.with_state(|_, state| {
            Ok(state
                .identities
                .get(identity)
                .map(|entry| entry.current_record_digest.clone()))
        })
    }

    pub fn policy_head(&self) -> Result<Option<String>, JacsError> {
        self.with_state(|_, state| {
            Ok(state
                .policy
                .as_ref()
                .map(|policy| policy.update_digest.clone()))
        })
    }

    pub fn active_policy_bundle(&self) -> Result<Option<PolicyBundle>, JacsError> {
        self.with_state(|_, state| self.resolve_policy_bundle(state))
    }

    pub fn status_acceptance_head(&self, identity: &str) -> Result<Option<String>, JacsError> {
        require_id(identity, "identity")?;
        self.with_state(|_, state| {
            Ok(state
                .status
                .get(identity)
                .map(|status| status.acceptance_digest.clone()))
        })
    }

    pub fn high_water(&self) -> Result<LedgerHighWater, JacsError> {
        self.with_state(|_, state| {
            Ok(LedgerHighWater {
                source_anchor: state.source_anchor.clone(),
                trust_sequence: state.trust_sequence,
                trust_record_digest: state.trust_head.clone(),
                policy_sequence: state.policy.as_ref().map(|value| value.sequence),
                policy_update_digest: state
                    .policy
                    .as_ref()
                    .map(|value| value.update_digest.clone()),
                policy_bundle_digest: state
                    .policy
                    .as_ref()
                    .map(|value| value.bundle_digest.clone()),
                tombstone_disposition_digest: state.tombstone_disposition_digest.clone(),
                blocking_tombstone_set_digest: state.blocking_tombstone_set_digest.clone(),
                greatest_accepted_utc_second: state.greatest_accepted_utc_second.clone(),
            })
        })
    }

    /// Return the current OS UTC second only when it is not below the durable
    /// owner-store time fence. This does not mutate or silently advance the
    /// fence; accepted transactions advance it atomically with their row.
    pub fn fenced_now(&self) -> Result<JacsTime, JacsError> {
        self.with_state(|_, state| {
            let current = now_time()?;
            if current < state.greatest_accepted_utc_second {
                return Err(trust_error(
                    "OS UTC clock is below the local trust-ledger high-water mark",
                ));
            }
            Ok(current)
        })
    }

    pub fn active_enrollment(&self, identity: &str) -> Result<Option<TrustEnrollment>, JacsError> {
        require_id(identity, "identity")?;
        self.with_state(|_, state| {
            Ok(state
                .identities
                .get(identity)
                .and_then(|value| value.active_enrollment.clone()))
        })
    }

    pub fn status_high_water(
        &self,
        identity: &str,
    ) -> Result<Option<LocalStatusHighWater>, JacsError> {
        require_id(identity, "identity")?;
        self.with_state(|_, state| {
            Ok(state
                .status
                .get(identity)
                .map(|value| LocalStatusHighWater {
                    identity_anchor: value.identity_anchor.clone(),
                    status_authority: value.status_authority.clone(),
                    acceptance_sequence: value.acceptance_sequence,
                    acceptance_digest: value.acceptance_digest.clone(),
                    status_sequence: value.status_sequence,
                    checkpoint_digest: value.checkpoint_digest.clone(),
                    checkpoint_time: value.checkpoint_time.clone(),
                    complete_through: value.complete_through.clone(),
                    lifecycle_sequence: value.lifecycle_sequence,
                    lifecycle_record_digest: value.lifecycle_record_digest.clone(),
                    revocation_epoch: value.revocation_epoch,
                    first_accepted_at: value.first_accepted_at.clone(),
                }))
        })
    }

    pub fn latest_local_status_checkpoint(
        &self,
        identity: &str,
    ) -> Result<Option<LocalStatusCheckpoint>, JacsError> {
        require_id(identity, "identity")?;
        self.with_state(|_, state| self.resolve_status_checkpoint(state, identity))
    }

    fn bootstrap_path(&self) -> PathBuf {
        self.root.join("bootstrap.json")
    }

    fn state_path(&self) -> PathBuf {
        self.root.join("state.json")
    }

    fn journal_path(&self) -> PathBuf {
        self.root.join("journal.json")
    }

    fn lock_path(&self) -> PathBuf {
        self.root.join(".ledger.lock")
    }

    fn entries_dir(&self) -> PathBuf {
        self.root.join("entries")
    }

    fn validate_store_directories(&self) -> Result<(), JacsError> {
        crate::secure_io::validate_owner_only_directory(&self.root)
            .map_err(|error| map_io(&self.root, error))?;
        let entries = self.entries_dir();
        crate::secure_io::validate_owner_only_directory(&entries)
            .map_err(|error| map_io(&entries, error))
    }

    fn resolve_policy_bundle(
        &self,
        state: &LedgerState,
    ) -> Result<Option<PolicyBundle>, JacsError> {
        for (index, digest) in state.entry_digests.iter().enumerate().rev() {
            let sequence = u64::try_from(index)
                .map_err(|_| trust_error("trust ledger entry count exceeds u64"))?;
            let entry: LedgerEntry = self.read(&self.entry_path(sequence, digest)?)?;
            if let LedgerOperation::Policy { record, .. } = entry.operation {
                return Ok(Some(record.new_bundle));
            }
        }
        Ok(None)
    }

    fn resolve_status_checkpoint(
        &self,
        state: &LedgerState,
        identity: &str,
    ) -> Result<Option<LocalStatusCheckpoint>, JacsError> {
        if !state.status.contains_key(identity) {
            return Ok(None);
        }
        for (index, digest) in state.entry_digests.iter().enumerate().rev() {
            let sequence = u64::try_from(index)
                .map_err(|_| trust_error("trust ledger entry count exceeds u64"))?;
            let entry: LedgerEntry = self.read(&self.entry_path(sequence, digest)?)?;
            if let LedgerOperation::Status {
                request,
                checkpoint,
                ..
            } = entry.operation
                && request.identity == identity
            {
                return Ok(Some(checkpoint));
            }
        }
        Ok(None)
    }

    fn entry_path(&self, sequence: u64, entry_digest: &str) -> Result<PathBuf, JacsError> {
        require_digest(entry_digest, "entryDigest")?;
        Ok(self.entries_dir().join(format!(
            "{sequence:020}-{}.json",
            entry_digest.trim_start_matches("sha256:")
        )))
    }

    fn acquire_lock(&self) -> Result<LedgerLock, JacsError> {
        let path = self.lock_path();
        let file = crate::secure_io::open_private_lock_file_no_follow(&path)
            .map_err(|error| map_write(&path, error))?;
        let deadline = Instant::now() + LOCK_TIMEOUT;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(LedgerLock { _file: file }),
                Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(trust_error(format!(
                        "timed out waiting for local trust ledger lock '{}'",
                        path.display()
                    )));
                }
                Err(std::fs::TryLockError::Error(error)) => {
                    return Err(map_write(&path, error));
                }
            }
        }
    }

    fn read<T: for<'de> Deserialize<'de>>(&self, path: &Path) -> Result<T, JacsError> {
        let bytes = crate::secure_io::read_no_follow_bounded(path, MAX_LEDGER_FILE_BYTES)
            .map_err(|error| map_io(path, error))?;
        let value = jacs_core::strict_json::parse_strict_json_slice(&bytes)
            .map_err(|error| trust_error(format!("invalid ledger JSON: {error}")))?;
        serde_json::from_value(value)
            .map_err(|error| trust_error(format!("invalid closed ledger record: {error}")))
    }

    fn encoded<T: Serialize>(&self, value: &T) -> Result<Vec<u8>, JacsError> {
        let bytes = serde_json::to_vec(value)
            .map_err(|error| trust_error(format!("failed to encode ledger record: {error}")))?;
        if bytes.len() > MAX_LEDGER_FILE_BYTES {
            return Err(trust_error(format!(
                "refusing local trust-ledger file larger than {MAX_LEDGER_FILE_BYTES} bytes"
            )));
        }
        Ok(bytes)
    }

    fn write_new<T: Serialize>(&self, path: &Path, value: &T) -> Result<(), JacsError> {
        let bytes = self.encoded(value)?;
        crate::secure_io::write_new_file(path, &bytes, 0o600)
            .map_err(|error| map_write(path, error))
    }

    fn replace<T: Serialize>(&self, path: &Path, value: &T) -> Result<(), JacsError> {
        let bytes = self.encoded(value)?;
        crate::secure_io::write_atomic_replace_no_symlink(path, &bytes, 0o600, true)
            .map_err(|error| map_write(path, error))
    }

    fn with_state<T>(
        &self,
        operation: impl FnOnce(&StoreBootstrapFile, &LedgerState) -> Result<T, JacsError>,
    ) -> Result<T, JacsError> {
        self.validate_store_directories()?;
        let _lock = self.acquire_lock()?;
        let bootstrap: StoreBootstrapFile = self.read(&self.bootstrap_path())?;
        validate_bootstrap(&bootstrap)?;
        self.recover_locked(&bootstrap)?;
        let state: LedgerState = self.read(&self.state_path())?;
        self.validate_state_and_history(&bootstrap, &state)?;
        operation(&bootstrap, &state)
    }

    pub fn append_trust(
        &self,
        verified: VerifiedTrustMutation,
        authorization: OwnerAuthorization,
        guard: TrustAppendGuard,
    ) -> Result<LedgerAppendReceipt, JacsError> {
        let VerifiedTrustMutation { identity, mutation } = verified;
        require_id(&identity, "identity")?;
        self.validate_store_directories()?;
        let _lock = self.acquire_lock()?;
        let bootstrap: StoreBootstrapFile = self.read(&self.bootstrap_path())?;
        validate_bootstrap(&bootstrap)?;
        self.recover_locked(&bootstrap)?;
        let state: LedgerState = self.read(&self.state_path())?;
        self.validate_state_and_history(&bootstrap, &state)?;

        let request = TrustDecisionRequest {
            decision_id: authorization.decision_id.clone(),
            source_anchor: bootstrap.source_anchor.clone(),
            action: mutation.action().to_string(),
            actor: ControlActorReference {
                actor_class: "owner".to_string(),
                actor_id: bootstrap.bootstrap.owner_id.clone(),
                actor_proof_type: "local_control_actor_proof".to_string(),
            },
            identity: identity.clone(),
            prior_trust_record_digest: guard.expected_identity_head.clone(),
            details: mutation.clone(),
            decision_time: authorization.authenticated_at.clone(),
        };
        let request_digest = digest("JACS-TRUST-DECISION-REQUEST-V1", &request)?;
        if let Some(receipt) =
            idempotent_receipt(&state, &authorization.decision_id, &request_digest)?
        {
            return Ok(receipt);
        }
        require_guard(
            "global trust ledger",
            &guard.expected_global_head,
            &state.trust_head,
        )?;
        let actual_identity_head = state
            .identities
            .get(&identity)
            .map(|entry| entry.current_record_digest.clone());
        require_guard(
            "identity",
            &guard.expected_identity_head,
            &actual_identity_head,
        )?;
        let owner_proof = build_owner_proof(
            &bootstrap,
            &state,
            &authorization,
            OwnerProofScope::Trust,
            mutation.action(),
            &request_digest,
        )?;
        let owner_proof_evidence_digest = owner_proof.evidence_digest()?;
        let decision = TrustDecisionEvidence {
            profile: TRUST_DECISION_PROFILE.to_string(),
            decision_id: request.decision_id,
            source_anchor: request.source_anchor,
            action: request.action,
            actor: ControlActorEvidence {
                actor_class: request.actor.actor_class,
                actor_id: request.actor.actor_id,
                actor_proof_type: request.actor.actor_proof_type,
                actor_proof_evidence_digest: owner_proof_evidence_digest,
            },
            identity: request.identity,
            prior_trust_record_digest: request.prior_trust_record_digest,
            details: request.details,
            decision_request_digest: request_digest,
            decision_time: request.decision_time,
        };
        let decision_digest = digest("JACS-TRUST-DECISION-EVIDENCE-V1", &decision)?;
        let record = TrustLedgerRecord {
            profile: TRUST_LEDGER_PROFILE.to_string(),
            source_anchor: bootstrap.source_anchor.clone(),
            record_id: authorization.decision_id.clone(),
            sequence: state.trust_sequence.map_or(0, |sequence| sequence + 1),
            previous_record_digest: state.trust_head.clone(),
            identity,
            event: mutation,
            actor: TrustLedgerActor {
                actor_class: "owner".to_string(),
                actor_id: bootstrap.bootstrap.owner_id.clone(),
                actor_proof_type: "local_control_actor_proof".to_string(),
                decision_evidence_digest: decision_digest,
            },
            authenticated_commit_time: authorization.authenticated_at.clone(),
        };
        let entry = LedgerEntry {
            profile: ENTRY_PROFILE.to_string(),
            source_anchor: bootstrap.source_anchor.clone(),
            entry_sequence: next_entry_sequence(&state)?,
            previous_entry_digest: state.global_head.clone(),
            transaction_id: authorization.decision_id,
            owner_proof,
            operation: LedgerOperation::Trust { decision, record },
            committed_at: authorization.authenticated_at,
        };
        let receipt = self.commit_locked(&state, entry)?;
        info!(
            event = "local_trust_ledger_appended",
            entry_sequence = receipt.entry_sequence,
            entry_digest = %receipt.entry_digest,
            "committed local trust decision"
        );
        Ok(receipt)
    }

    pub fn append_policy(
        &self,
        verified: VerifiedPolicyBundle,
        authorization: OwnerAuthorization,
        guard: PolicyAppendGuard,
    ) -> Result<LedgerAppendReceipt, JacsError> {
        let bundle = verified.bundle;
        self.validate_store_directories()?;
        let _lock = self.acquire_lock()?;
        let bootstrap: StoreBootstrapFile = self.read(&self.bootstrap_path())?;
        validate_bootstrap(&bootstrap)?;
        self.recover_locked(&bootstrap)?;
        let state: LedgerState = self.read(&self.state_path())?;
        self.validate_state_and_history(&bootstrap, &state)?;
        let proposed_bundle_digest = digest("JACS-POLICY-BUNDLE-V1", &bundle)?;
        let request = PolicyUpdateAuthorizationRequest {
            source_anchor: bootstrap.source_anchor.clone(),
            decision_id: authorization.decision_id.clone(),
            previous_bundle_digest: guard.expected_bundle_digest.clone(),
            proposed_bundle_digest,
            actor: ControlActorReference {
                actor_class: "owner".to_string(),
                actor_id: bootstrap.bootstrap.owner_id.clone(),
                actor_proof_type: "local_control_actor_proof".to_string(),
            },
            decided_at: authorization.authenticated_at.clone(),
        };
        let request_digest = digest("JACS-POLICY-UPDATE-AUTHORIZATION-REQUEST-V1", &request)?;
        if let Some(receipt) =
            idempotent_receipt(&state, &authorization.decision_id, &request_digest)?
        {
            return Ok(receipt);
        }
        let policy_head = state
            .policy
            .as_ref()
            .map(|value| value.update_digest.clone());
        require_guard("policy", &guard.expected_policy_head, &policy_head)?;
        let bundle_head = state
            .policy
            .as_ref()
            .map(|value| value.bundle_digest.clone());
        require_guard("policy bundle", &guard.expected_bundle_digest, &bundle_head)?;
        let owner_proof = build_owner_proof(
            &bootstrap,
            &state,
            &authorization,
            OwnerProofScope::Policy,
            "update_policy_bundle",
            &request_digest,
        )?;
        let owner_proof_evidence_digest = owner_proof.evidence_digest()?;
        let policy_authorization = PolicyUpdateAuthorization {
            profile: POLICY_AUTH_PROFILE.to_string(),
            source_anchor: request.source_anchor,
            decision_id: request.decision_id,
            previous_bundle_digest: request.previous_bundle_digest,
            proposed_bundle_digest: request.proposed_bundle_digest,
            actor: ControlActorEvidence {
                actor_class: request.actor.actor_class,
                actor_id: request.actor.actor_id,
                actor_proof_type: request.actor.actor_proof_type,
                actor_proof_evidence_digest: owner_proof_evidence_digest,
            },
            decided_at: request.decided_at,
        };
        let authorization_digest =
            digest("JACS-POLICY-UPDATE-AUTHORIZATION-V1", &policy_authorization)?;
        let record = PolicyUpdateRecord {
            profile: POLICY_UPDATE_PROFILE.to_string(),
            source_anchor: bootstrap.source_anchor.clone(),
            sequence: state
                .policy
                .as_ref()
                .map_or(0, |policy| policy.sequence + 1),
            previous_update_digest: state
                .policy
                .as_ref()
                .map(|policy| policy.update_digest.clone()),
            previous_bundle_digest: state
                .policy
                .as_ref()
                .map(|policy| policy.bundle_digest.clone()),
            new_bundle: bundle,
            authorization_digest,
            authenticated_commit_time: authorization.authenticated_at.clone(),
        };
        let entry = LedgerEntry {
            profile: ENTRY_PROFILE.to_string(),
            source_anchor: bootstrap.source_anchor.clone(),
            entry_sequence: next_entry_sequence(&state)?,
            previous_entry_digest: state.global_head.clone(),
            transaction_id: authorization.decision_id,
            owner_proof,
            operation: LedgerOperation::Policy {
                authorization: policy_authorization,
                record,
            },
            committed_at: authorization.authenticated_at,
        };
        let receipt = self.commit_locked(&state, entry)?;
        info!(
            event = "local_policy_ledger_appended",
            entry_sequence = receipt.entry_sequence,
            entry_digest = %receipt.entry_digest,
            "committed local policy update"
        );
        Ok(receipt)
    }

    pub fn accept_local_status(
        &self,
        verified: VerifiedLocalStatusCheckpoint,
        authorization: OwnerAuthorization,
        guard: StatusAppendGuard,
    ) -> Result<LedgerAppendReceipt, JacsError> {
        let VerifiedLocalStatusCheckpoint {
            identity,
            checkpoint,
        } = verified;
        require_id(&identity, "identity")?;
        self.validate_store_directories()?;
        let _lock = self.acquire_lock()?;
        let bootstrap: StoreBootstrapFile = self.read(&self.bootstrap_path())?;
        validate_bootstrap(&bootstrap)?;
        self.recover_locked(&bootstrap)?;
        let state: LedgerState = self.read(&self.state_path())?;
        self.validate_state_and_history(&bootstrap, &state)?;
        let checkpoint_digest = digest("JACS-STATUS-CHECKPOINT-V1", &checkpoint)?;
        let prior_acceptance = state.status.get(&identity);
        let request = StatusAcceptanceRequest {
            acceptance_id: authorization.decision_id.clone(),
            source_anchor: bootstrap.source_anchor.clone(),
            identity: identity.clone(),
            status_checkpoint_digest: checkpoint_digest.clone(),
            previous_acceptance_digest: guard.expected_acceptance_head.clone(),
            accepted_at: authorization.authenticated_at.clone(),
        };
        let request_digest = digest("JACS-STATUS-ACCEPTANCE-REQUEST-V1", &request)?;
        if let Some(receipt) =
            idempotent_receipt(&state, &authorization.decision_id, &request_digest)?
        {
            return Ok(receipt);
        }
        let acceptance_head = prior_acceptance.map(|value| value.acceptance_digest.clone());
        require_guard(
            "status acceptance",
            &guard.expected_acceptance_head,
            &acceptance_head,
        )?;
        let owner_proof = build_owner_proof(
            &bootstrap,
            &state,
            &authorization,
            OwnerProofScope::Trust,
            "accept_status_checkpoint",
            &request_digest,
        )?;
        let acceptance = LocalStatusAcceptance {
            profile: STATUS_ACCEPTANCE_PROFILE.to_string(),
            trust_store_anchor: bootstrap.source_anchor.clone(),
            identity_anchor: checkpoint.identity_anchor.clone(),
            status_authority: checkpoint.status_authority.clone(),
            acceptance_sequence: prior_acceptance.map_or(0, |value| value.acceptance_sequence + 1),
            previous_acceptance_digest: acceptance_head,
            status_checkpoint_digest: checkpoint_digest.clone(),
            accepted_evidence: AcceptedStatusEvidence::LocalStatusPayload {
                digest: checkpoint_digest,
            },
            status_sequence: checkpoint.status_sequence,
            lifecycle_sequence: checkpoint.lifecycle_sequence,
            lifecycle_record_digest: checkpoint.lifecycle_record_digest.clone(),
            revocation_epoch: checkpoint.revocation_epoch,
            complete_through: checkpoint.complete_through.clone(),
            first_accepted_at: authorization.authenticated_at.clone(),
        };
        let entry = LedgerEntry {
            profile: ENTRY_PROFILE.to_string(),
            source_anchor: bootstrap.source_anchor.clone(),
            entry_sequence: next_entry_sequence(&state)?,
            previous_entry_digest: state.global_head.clone(),
            transaction_id: authorization.decision_id,
            owner_proof,
            operation: LedgerOperation::Status {
                request,
                acceptance,
                checkpoint,
            },
            committed_at: authorization.authenticated_at,
        };
        let receipt = self.commit_locked(&state, entry)?;
        info!(
            event = "local_status_ledger_appended",
            entry_sequence = receipt.entry_sequence,
            entry_digest = %receipt.entry_digest,
            identity,
            "committed local status acceptance"
        );
        Ok(receipt)
    }
}

fn require_guard(
    name: &str,
    expected: &Option<String>,
    actual: &Option<String>,
) -> Result<(), JacsError> {
    if expected != actual {
        return Err(trust_error(format!(
            "stale {name} compare-and-swap head: expected {expected:?}, current {actual:?}"
        )));
    }
    Ok(())
}

fn next_entry_sequence(state: &LedgerState) -> Result<u64, JacsError> {
    u64::try_from(state.entry_digests.len())
        .map_err(|_| trust_error("trust ledger entry count exceeds u64"))
}

fn idempotent_receipt(
    state: &LedgerState,
    transaction_id: &str,
    request_digest: &str,
) -> Result<Option<LedgerAppendReceipt>, JacsError> {
    let Some(consumed) = state.consumed_decisions.get(transaction_id) else {
        return Ok(None);
    };
    if consumed.request_digest != request_digest {
        return Err(trust_error(
            "decision or acceptance ID was reused for different content",
        ));
    }
    Ok(Some(LedgerAppendReceipt {
        entry_sequence: consumed.entry_sequence,
        entry_digest: consumed.entry_digest.clone(),
        logical_record_digest: consumed.logical_record_digest.clone(),
        state_digest: state_digest(state)?,
        idempotent_replay: true,
    }))
}

fn effective_owner_id() -> Result<String, JacsError> {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions.
        return Ok(format!("posix-uid:{}", unsafe { libc::geteuid() }));
    }

    #[cfg(not(unix))]
    {
        Err(trust_error(
            "local owner-authenticated trust stores are unsupported on this platform; use an authenticated authority store",
        ))
    }
}

fn local_source_anchor(
    bootstrap: &LocalOwnerStoreBootstrap,
    bootstrap_digest: &str,
) -> TrustStoreAnchor {
    TrustStoreAnchor::LocalTrustStore {
        local_owner_store: StatusAuthority::LocalOwnerStore {
            canonical_store_id: bootstrap.canonical_store_id.clone(),
            owner_id: bootstrap.owner_id.clone(),
            bootstrap_digest: bootstrap_digest.to_string(),
        },
    }
}

fn validate_bootstrap(store: &StoreBootstrapFile) -> Result<(), JacsError> {
    if store.profile != STORE_PROFILE
        || store.bootstrap.profile != "jacs-local-owner-store-bootstrap-v1"
        || store.owner_enrollment.profile != OWNER_ENROLLMENT_PROFILE
    {
        return Err(trust_error("local trust store bootstrap profile mismatch"));
    }
    let parsed_store_id = uuid::Uuid::parse_str(&store.bootstrap.canonical_store_id)
        .map_err(|error| trust_error(format!("invalid canonicalStoreId: {error}")))?;
    if parsed_store_id.hyphenated().to_string() != store.bootstrap.canonical_store_id {
        return Err(trust_error(
            "canonicalStoreId is not canonical lowercase UUID text",
        ));
    }
    if store.bootstrap.bootstrap_nonce.len() != 64
        || !store
            .bootstrap
            .bootstrap_nonce
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(trust_error("bootstrapNonce must be 32 lowercase-hex bytes"));
    }
    let owner_id = effective_owner_id()?;
    if store.bootstrap.owner_id != owner_id || store.owner_enrollment.owner_id != owner_id {
        return Err(trust_error(
            "local trust store OS owner no longer matches bootstrap",
        ));
    }
    let expected_bootstrap = digest("JACS-LOCAL-OWNER-STORE-BOOTSTRAP-V1", &store.bootstrap)?;
    if expected_bootstrap != store.bootstrap_digest
        || store.owner_enrollment.bootstrap_digest != expected_bootstrap
        || store.owner_enrollment.committed_at != store.bootstrap.created_at
    {
        return Err(trust_error("local trust store bootstrap digest mismatch"));
    }
    require_digest(
        &store.owner_enrollment.confirmation_digest,
        "confirmationDigest",
    )?;
    if let OwnerEnrollmentMode::LegacyMigration {
        legacy_store_digest,
        legacy_config_digest,
    } = &store.owner_enrollment.mode
    {
        require_digest(legacy_store_digest, "legacyStoreDigest")?;
        require_digest(legacy_config_digest, "legacyConfigDigest")?;
    }
    let expected_enrollment = digest("JACS-LOCAL-OWNER-ENROLLMENT-V1", &store.owner_enrollment)?;
    if expected_enrollment != store.owner_enrollment_digest {
        return Err(trust_error("owner enrollment digest mismatch"));
    }
    let expected_anchor = local_source_anchor(&store.bootstrap, &store.bootstrap_digest);
    if expected_anchor != store.source_anchor {
        return Err(trust_error("local trust-store anchor mismatch"));
    }
    Ok(())
}

fn state_digest(state: &LedgerState) -> Result<String, JacsError> {
    digest("JACS-LOCAL-TRUST-LEDGER-STATE-V1", state)
}

fn entry_digest(entry: &LedgerEntry) -> Result<String, JacsError> {
    digest("JACS-LOCAL-TRUST-LEDGER-ENTRY-V1", entry)
}

impl LocalTrustLedger {
    fn recover_locked(&self, bootstrap: &StoreBootstrapFile) -> Result<(), JacsError> {
        let state: LedgerState = self.read(&self.state_path())?;
        let current_state_digest = state_digest(&state)?;
        let journal_path = self.journal_path();
        let journal = match std::fs::symlink_metadata(&journal_path) {
            Ok(_) => self.read::<LedgerJournal>(&journal_path)?,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && state.entry_digests.is_empty() =>
            {
                let clean = LedgerJournal::Clean {
                    profile: JOURNAL_PROFILE.to_string(),
                    state_digest: current_state_digest,
                };
                self.write_new(&journal_path, &clean)?;
                return Ok(());
            }
            Err(error) => return Err(map_io(&journal_path, error)),
        };
        match journal {
            LedgerJournal::Clean {
                profile,
                state_digest: expected,
            } => {
                if profile != JOURNAL_PROFILE || expected != current_state_digest {
                    return Err(trust_error(
                        "trust ledger clean journal does not match durable state",
                    ));
                }
            }
            LedgerJournal::Prepared {
                profile,
                base_state_digest,
                next_state_digest,
                entry_digest: expected_entry_digest,
                entry,
                next_state,
            } => {
                if profile != JOURNAL_PROFILE
                    || entry_digest(&entry)? != expected_entry_digest
                    || state_digest(&next_state)? != next_state_digest
                {
                    return Err(trust_error("trust ledger prepared journal digest mismatch"));
                }
                if next_state.bootstrap_digest != bootstrap.bootstrap_digest
                    || next_state.source_anchor != bootstrap.source_anchor
                {
                    return Err(trust_error("trust ledger journal belongs to another store"));
                }
                if current_state_digest != base_state_digest
                    && current_state_digest != next_state_digest
                {
                    return Err(trust_error(
                        "unresolvable mixed trust ledger state during journal recovery",
                    ));
                }
                if current_state_digest == base_state_digest {
                    self.validate_state_and_history(bootstrap, &state)?;
                    let mut derived_next = state.clone();
                    apply_entry(&mut derived_next, &entry, &expected_entry_digest)?;
                    if derived_next != next_state {
                        return Err(trust_error(
                            "prepared journal next state is not the exact result of its entry",
                        ));
                    }
                    self.ensure_immutable_entry(&entry, &expected_entry_digest)?;
                    self.replace(&self.state_path(), &next_state)?;
                } else {
                    if state != next_state {
                        return Err(trust_error(
                            "prepared journal next-state digest matched different state bytes",
                        ));
                    }
                    self.ensure_immutable_entry(&entry, &expected_entry_digest)?;
                    self.validate_state_and_history(bootstrap, &next_state)?;
                }
                let clean = LedgerJournal::Clean {
                    profile: JOURNAL_PROFILE.to_string(),
                    state_digest: next_state_digest,
                };
                self.replace(&self.journal_path(), &clean)?;
                info!(
                    event = "local_trust_ledger_recovered",
                    entry_sequence = entry.entry_sequence,
                    entry_digest = %expected_entry_digest,
                    "completed an interrupted local trust ledger transaction"
                );
            }
        }
        Ok(())
    }

    fn ensure_immutable_entry(
        &self,
        entry: &LedgerEntry,
        expected_digest: &str,
    ) -> Result<(), JacsError> {
        let path = self.entry_path(entry.entry_sequence, expected_digest)?;
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                let existing: LedgerEntry = self.read(&path)?;
                if existing != *entry || entry_digest(&existing)? != expected_digest {
                    return Err(trust_error(format!(
                        "immutable trust ledger entry conflict at '{}'",
                        path.display()
                    )));
                }
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.write_new(&path, entry)
            }
            Err(error) => Err(map_io(&path, error)),
        }
    }

    fn validate_state_and_history(
        &self,
        bootstrap: &StoreBootstrapFile,
        state: &LedgerState,
    ) -> Result<(), JacsError> {
        if state.profile != STATE_PROFILE
            || state.source_anchor != bootstrap.source_anchor
            || state.bootstrap_digest != bootstrap.bootstrap_digest
            || state.owner_enrollment_digest != bootstrap.owner_enrollment_digest
        {
            return Err(trust_error("trust ledger state/bootstrap mismatch"));
        }
        if state.global_head != state.entry_digests.last().cloned() {
            return Err(trust_error("trust ledger global high-water mismatch"));
        }

        let mut replayed = LedgerState::initial(bootstrap)?;
        for (index, expected_digest) in state.entry_digests.iter().enumerate() {
            require_digest(expected_digest, "entryDigest")?;
            let sequence = u64::try_from(index)
                .map_err(|_| trust_error("trust ledger entry count exceeds u64"))?;
            let path = self.entry_path(sequence, expected_digest)?;
            let entry: LedgerEntry = self.read(&path)?;
            let actual_digest = entry_digest(&entry)?;
            if actual_digest != *expected_digest {
                return Err(trust_error(format!(
                    "trust ledger entry digest mismatch at sequence {sequence}"
                )));
            }
            apply_entry(&mut replayed, &entry, &actual_digest)?;
        }
        if replayed != *state {
            return Err(trust_error(
                "trust ledger state projection does not equal immutable history",
            ));
        }
        Ok(())
    }

    fn commit_locked(
        &self,
        state: &LedgerState,
        entry: LedgerEntry,
    ) -> Result<LedgerAppendReceipt, JacsError> {
        let base_state_digest = state_digest(state)?;
        let computed_entry_digest = entry_digest(&entry)?;
        let mut next_state = state.clone();
        let (_, logical_record_digest) =
            apply_entry(&mut next_state, &entry, &computed_entry_digest)?;
        let next_state_digest = state_digest(&next_state)?;
        let prepared = LedgerJournal::Prepared {
            profile: JOURNAL_PROFILE.to_string(),
            base_state_digest,
            next_state_digest: next_state_digest.clone(),
            entry_digest: computed_entry_digest.clone(),
            entry: entry.clone(),
            next_state: next_state.clone(),
        };
        self.replace(&self.journal_path(), &prepared)?;
        self.ensure_immutable_entry(&entry, &computed_entry_digest)?;
        self.replace(&self.state_path(), &next_state)?;
        let clean = LedgerJournal::Clean {
            profile: JOURNAL_PROFILE.to_string(),
            state_digest: next_state_digest.clone(),
        };
        self.replace(&self.journal_path(), &clean)?;
        Ok(LedgerAppendReceipt {
            entry_sequence: entry.entry_sequence,
            entry_digest: computed_entry_digest,
            logical_record_digest,
            state_digest: next_state_digest,
            idempotent_replay: false,
        })
    }
}

fn build_owner_proof(
    bootstrap: &StoreBootstrapFile,
    state: &LedgerState,
    authorization: &OwnerAuthorization,
    scope: OwnerProofScope,
    action: &str,
    request_digest: &str,
) -> Result<LocalOwnerProofEvidence, JacsError> {
    require_id(&authorization.decision_id, "decisionId")?;
    require_digest(&authorization.confirmation_digest, "confirmationDigest")?;
    require_digest(request_digest, "actionRequestDigest")?;
    let authenticated_at = parse_time(&authorization.authenticated_at)?;
    let expires_at = parse_time(&authorization.expires_at)?;
    let retained_time = parse_time(&state.greatest_accepted_utc_second)?;
    if expires_at <= authenticated_at
        || expires_at - authenticated_at > chrono::Duration::seconds(300)
    {
        return Err(trust_error(
            "owner authorization validity must be within (0, 300] seconds",
        ));
    }
    if authenticated_at < retained_time {
        return Err(trust_error(
            "owner authorization time is below the retained local time high-water mark",
        ));
    }
    let now = chrono::Utc::now();
    if now < authenticated_at || now >= expires_at {
        return Err(trust_error("owner authorization is not currently fresh"));
    }
    let payload = LocalOwnerProofPayload {
        profile: OWNER_PROOF_PROFILE.to_string(),
        proof_id: authorization.decision_id.clone(),
        source_anchor: bootstrap.source_anchor.clone(),
        scope,
        action: action.to_string(),
        actor_class: "owner".to_string(),
        actor_id: bootstrap.bootstrap.owner_id.clone(),
        authentication_class: "local_os_owner".to_string(),
        action_request_digest: request_digest.to_string(),
        confirmation_digest: authorization.confirmation_digest.clone(),
        authenticated_at: authorization.authenticated_at.clone(),
        expires_at: authorization.expires_at.clone(),
    };
    let body_digest = digest("JACS-CONTROL-ACTOR-PROOF-V1", &payload)?;
    let record = LocalOwnerProofRecord {
        profile: OWNER_PROOF_RECORD_PROFILE.to_string(),
        source_anchor: bootstrap.source_anchor.clone(),
        record_id: authorization.decision_id.clone(),
        sequence: state
            .owner_proof_sequence
            .map_or(0, |sequence| sequence + 1),
        previous_record_digest: state.owner_proof_head.clone(),
        body_digest,
        authenticated_commit_time: authorization.authenticated_at.clone(),
    };
    let evidence_digest = digest(
        "JACS-CONTROL-ACTOR-PROOF-EVIDENCE-V1",
        &serde_json::json!({"payload": payload, "authentication": {
            "type": "local_owner_store", "record": record
        }}),
    )?;
    Ok(LocalOwnerProofEvidence {
        payload,
        record,
        evidence_digest,
    })
}

fn validate_owner_proof(state: &LedgerState, entry: &LedgerEntry) -> Result<String, JacsError> {
    let proof = &entry.owner_proof;
    if proof.payload.profile != OWNER_PROOF_PROFILE
        || proof.record.profile != OWNER_PROOF_RECORD_PROFILE
        || proof.payload.source_anchor != state.source_anchor
        || proof.record.source_anchor != state.source_anchor
        || proof.payload.proof_id != entry.transaction_id
        || proof.record.record_id != entry.transaction_id
        || proof.payload.actor_class != "owner"
        || proof.payload.actor_id != local_owner_id(&state.source_anchor)?
        || proof.payload.authentication_class != "local_os_owner"
        || proof.payload.authenticated_at != proof.record.authenticated_commit_time
        || proof.payload.authenticated_at != entry.committed_at
        || proof.record.sequence != state.owner_proof_sequence.map_or(0, |value| value + 1)
        || proof.record.previous_record_digest != state.owner_proof_head
    {
        return Err(trust_error("local owner proof/state mismatch"));
    }
    require_digest(
        &proof.payload.confirmation_digest,
        "ownerProof.confirmationDigest",
    )?;
    let expected_body = digest("JACS-CONTROL-ACTOR-PROOF-V1", &proof.payload)?;
    if expected_body != proof.record.body_digest {
        return Err(trust_error("local owner proof body digest mismatch"));
    }
    let expected_evidence = digest(
        "JACS-CONTROL-ACTOR-PROOF-EVIDENCE-V1",
        &serde_json::json!({"payload": proof.payload, "authentication": {
            "type": "local_owner_store", "record": proof.record
        }}),
    )?;
    if expected_evidence != proof.evidence_digest {
        return Err(trust_error("local owner proof evidence digest mismatch"));
    }
    let authenticated_at = parse_time(&proof.payload.authenticated_at)?;
    let expires_at = parse_time(&proof.payload.expires_at)?;
    if expires_at <= authenticated_at
        || expires_at - authenticated_at > chrono::Duration::seconds(300)
    {
        return Err(trust_error(
            "local owner proof has an invalid validity interval",
        ));
    }
    Ok(digest("JACS-LOCAL-CONTROL-ACTOR-RECORD-V1", &proof.record)?)
}

fn apply_entry(
    state: &mut LedgerState,
    entry: &LedgerEntry,
    computed_entry_digest: &str,
) -> Result<(String, String), JacsError> {
    let expected_sequence = u64::try_from(state.entry_digests.len())
        .map_err(|_| trust_error("trust ledger entry count exceeds u64"))?;
    if entry.profile != ENTRY_PROFILE
        || entry.source_anchor != state.source_anchor
        || entry.entry_sequence != expected_sequence
        || entry.previous_entry_digest != state.global_head
    {
        return Err(trust_error("trust ledger global entry chain mismatch"));
    }
    if entry.committed_at < state.greatest_accepted_utc_second {
        return Err(trust_error(
            "ledger commit time is below the retained local time high-water mark",
        ));
    }
    if state.consumed_decisions.contains_key(&entry.transaction_id) {
        return Err(trust_error(
            "decision or acceptance ID was already consumed",
        ));
    }
    let proof_record_digest = validate_owner_proof(state, entry)?;
    let (request_digest, logical_record_digest) = match &entry.operation {
        LedgerOperation::Trust { decision, record } => {
            apply_trust_operation(state, entry, decision, record)?
        }
        LedgerOperation::Policy {
            authorization,
            record,
        } => apply_policy_operation(state, entry, authorization, record)?,
        LedgerOperation::Status {
            request,
            acceptance,
            checkpoint,
        } => apply_status_operation(state, entry, request, acceptance, checkpoint)?,
    };
    if request_digest != entry.owner_proof.payload.action_request_digest {
        return Err(trust_error(
            "owner proof is not bound to the exact ledger request",
        ));
    }
    state.owner_proof_sequence = Some(entry.owner_proof.record.sequence);
    state.owner_proof_head = Some(proof_record_digest);
    state.consumed_decisions.insert(
        entry.transaction_id.clone(),
        ConsumedDecision {
            request_digest: request_digest.clone(),
            entry_sequence: entry.entry_sequence,
            entry_digest: computed_entry_digest.to_string(),
            logical_record_digest: logical_record_digest.clone(),
        },
    );
    state.entry_digests.push(computed_entry_digest.to_string());
    state.global_head = Some(computed_entry_digest.to_string());
    state.greatest_accepted_utc_second = entry.committed_at.clone();
    Ok((request_digest, logical_record_digest))
}

fn apply_trust_operation(
    state: &mut LedgerState,
    entry: &LedgerEntry,
    decision: &TrustDecisionEvidence,
    record: &TrustLedgerRecord,
) -> Result<(String, String), JacsError> {
    if decision.profile != TRUST_DECISION_PROFILE
        || record.profile != TRUST_LEDGER_PROFILE
        || decision.source_anchor != state.source_anchor
        || record.source_anchor != state.source_anchor
        || decision.decision_id != entry.transaction_id
        || record.record_id != entry.transaction_id
        || decision.actor.actor_class != "owner"
        || decision.actor.actor_id != entry.owner_proof.payload.actor_id
        || decision.actor.actor_proof_type != "local_control_actor_proof"
        || decision.actor.actor_proof_evidence_digest != entry.owner_proof.evidence_digest
        || decision.action != decision.details.action()
        || decision.identity != record.identity
        || decision.details != record.event
        || decision.decision_time != entry.committed_at
        || record.actor.actor_class != decision.actor.actor_class
        || record.actor.actor_id != decision.actor.actor_id
        || record.actor.actor_proof_type != decision.actor.actor_proof_type
        || record.authenticated_commit_time != entry.committed_at
        || entry.owner_proof.payload.scope != OwnerProofScope::Trust
        || entry.owner_proof.payload.action != decision.action
        || record.sequence != state.trust_sequence.map_or(0, |sequence| sequence + 1)
        || record.previous_record_digest != state.trust_head
    {
        return Err(trust_error("trust decision, proof, or ledger row mismatch"));
    }
    let request = TrustDecisionRequest {
        decision_id: decision.decision_id.clone(),
        source_anchor: decision.source_anchor.clone(),
        action: decision.action.clone(),
        actor: ControlActorReference {
            actor_class: decision.actor.actor_class.clone(),
            actor_id: decision.actor.actor_id.clone(),
            actor_proof_type: decision.actor.actor_proof_type.clone(),
        },
        identity: decision.identity.clone(),
        prior_trust_record_digest: decision.prior_trust_record_digest.clone(),
        details: decision.details.clone(),
        decision_time: decision.decision_time.clone(),
    };
    let expected_request = digest("JACS-TRUST-DECISION-REQUEST-V1", &request)?;
    if expected_request != decision.decision_request_digest {
        return Err(trust_error("trust decision request digest mismatch"));
    }
    let expected_decision = digest("JACS-TRUST-DECISION-EVIDENCE-V1", decision)?;
    if expected_decision != record.actor.decision_evidence_digest {
        return Err(trust_error("trust decision evidence digest mismatch"));
    }
    let logical_record_digest = digest("JACS-TRUST-LEDGER-RECORD-V1", record)?;
    apply_trust_mutation(
        state,
        &record.identity,
        &decision.prior_trust_record_digest,
        &record.event,
        &logical_record_digest,
    )?;
    let (tombstone_disposition_digest, blocking_tombstone_set_digest) =
        tombstone_projection_digests(&state.identities)?;
    state.tombstone_disposition_digest = tombstone_disposition_digest;
    state.blocking_tombstone_set_digest = blocking_tombstone_set_digest;
    state.trust_sequence = Some(record.sequence);
    state.trust_head = Some(logical_record_digest.clone());
    Ok((expected_request, logical_record_digest))
}

fn validate_enrollment(
    state: &LedgerState,
    identity: &str,
    enrollment: &TrustEnrollment,
) -> Result<(), JacsError> {
    if enrollment.provenance.profile != TRUST_PROVENANCE_PROFILE {
        return Err(trust_error("trust provenance profile mismatch"));
    }
    require_id(&enrollment.policy_name, "policyName")?;
    require_id(
        &enrollment.current_root_canonical_key_id,
        "currentRootCanonicalKeyId",
    )?;
    require_digest(
        &enrollment.verification_policy_digest,
        "verificationPolicyDigest",
    )?;
    require_digest(
        &enrollment.provenance.source_evidence_digest,
        "sourceEvidenceDigest",
    )?;
    require_digest(
        &enrollment.provenance.candidate_material_digest,
        "candidateMaterialDigest",
    )?;
    require_digest(&enrollment.lifecycle_record_digest, "lifecycleRecordDigest")?;
    if let IdentityAnchor::Portable { jacs_id, .. } = &enrollment.identity_anchor
        && jacs_id != identity
    {
        return Err(trust_error(
            "portable enrollment anchor does not match the trust-row identity",
        ));
    }
    if let StatusAuthority::PortableRootStatus { identity_anchor } = &enrollment.status_authority
        && identity_anchor != &enrollment.identity_anchor
    {
        return Err(trust_error(
            "portable status authority does not match the enrollment identity anchor",
        ));
    }
    match enrollment.provenance.method {
        TrustProvenanceMethod::ExplicitTofu
            if enrollment.provenance.source_authority_anchor.is_some() =>
        {
            return Err(trust_error("explicit TOFU cannot name a source authority"));
        }
        TrustProvenanceMethod::AuthorityRegistry
            if enrollment.provenance.source_authority_anchor.is_none() =>
        {
            return Err(trust_error(
                "authority-registry enrollment requires a preselected authority anchor",
            ));
        }
        _ => {}
    }
    let policy = state
        .policy
        .as_ref()
        .ok_or_else(|| trust_error("genesis policy must be committed before trust enrollment"))?;
    if enrollment.policy_name != policy.policy_name
        || enrollment.policy_version != policy.policy_version
        || enrollment.verification_policy_digest != policy.verification_policy_digest
    {
        return Err(trust_error(
            "trust enrollment does not name the active authenticated policy",
        ));
    }
    Ok(())
}

fn apply_trust_mutation(
    state: &mut LedgerState,
    identity: &str,
    stated_prior: &Option<String>,
    mutation: &TrustMutation,
    record_digest: &str,
) -> Result<(), JacsError> {
    let actual_prior = state
        .identities
        .get(identity)
        .map(|entry| entry.current_record_digest.clone());
    if stated_prior != &actual_prior {
        return Err(trust_error("trust decision used a stale identity prior"));
    }
    match mutation {
        TrustMutation::Enroll {
            enrollment,
            underlying_independent_proof_digest,
        } => {
            if state.identities.contains_key(identity) || stated_prior.is_some() {
                return Err(trust_error(
                    "Enroll is valid only when no prior identity row or tombstone exists",
                ));
            }
            validate_enrollment(state, identity, enrollment)?;
            require_digest(
                underlying_independent_proof_digest,
                "underlyingIndependentProofDigest",
            )?;
            if *underlying_independent_proof_digest != enrollment.provenance.source_evidence_digest
            {
                return Err(trust_error(
                    "enrollment provenance does not match its independent proof",
                ));
            }
            state.identities.insert(
                identity.to_string(),
                IdentityTrustState {
                    current_record_digest: record_digest.to_string(),
                    active_enrollment: Some(enrollment.clone()),
                    superseded_anchors: Vec::new(),
                    tombstones: Vec::new(),
                },
            );
        }
        TrustMutation::AdvanceHead {
            identity_anchor,
            prior_lifecycle_sequence,
            prior_lifecycle_record_digest,
            new_root_canonical_key_id,
            new_lifecycle_sequence,
            new_lifecycle_record_digest,
        } => {
            require_id(new_root_canonical_key_id, "newRootCanonicalKeyId")?;
            require_digest(prior_lifecycle_record_digest, "priorLifecycleRecordDigest")?;
            require_digest(new_lifecycle_record_digest, "newLifecycleRecordDigest")?;
            let current = state
                .identities
                .get_mut(identity)
                .ok_or_else(|| trust_error("AdvanceHead requires an enrolled identity"))?;
            let enrollment = current
                .active_enrollment
                .as_mut()
                .ok_or_else(|| trust_error("a tombstoned identity cannot advance its head"))?;
            if &enrollment.identity_anchor != identity_anchor
                || enrollment.lifecycle_sequence != *prior_lifecycle_sequence
                || enrollment.lifecycle_record_digest != *prior_lifecycle_record_digest
                || *new_lifecycle_sequence <= *prior_lifecycle_sequence
            {
                return Err(trust_error(
                    "AdvanceHead does not extend the exact active lifecycle head",
                ));
            }
            enrollment.lifecycle_sequence = *new_lifecycle_sequence;
            enrollment.lifecycle_record_digest = new_lifecycle_record_digest.clone();
            enrollment.current_root_canonical_key_id = new_root_canonical_key_id.clone();
            current.current_record_digest = record_digest.to_string();
            // A checkpoint for the prior lifecycle head can never attest the
            // newly accepted head. The verified reducer must append the new
            // local checkpoint before this identity can be Current again.
            state.status.remove(identity);
        }
        TrustMutation::Reanchor {
            old_identity_anchor,
            new_enrollment,
            mode,
            continuity_evidence_digest,
        } => {
            validate_enrollment(state, identity, new_enrollment)?;
            let current = state
                .identities
                .get_mut(identity)
                .ok_or_else(|| trust_error("Reanchor requires an enrolled identity"))?;
            if current
                .superseded_anchors
                .contains(&new_enrollment.identity_anchor)
            {
                return Err(trust_error(
                    "Reanchor cannot reactivate a previously superseded anchor",
                ));
            }
            let old = current
                .active_enrollment
                .as_ref()
                .ok_or_else(|| trust_error("a tombstoned identity requires Reenroll"))?;
            if &old.identity_anchor != old_identity_anchor
                || old.identity_anchor == new_enrollment.identity_anchor
            {
                return Err(trust_error("Reanchor old/new anchor mismatch"));
            }
            match (mode, continuity_evidence_digest) {
                (ReanchorMode::ContinuityProved, Some(value)) => {
                    require_digest(value, "continuityEvidenceDigest")?
                }
                (ReanchorMode::NewEnrollment, None) => {}
                _ => {
                    return Err(trust_error(
                        "continuity-proved reanchor requires evidence; new enrollment forbids it",
                    ));
                }
            }
            current.superseded_anchors.push(old_identity_anchor.clone());
            current.active_enrollment = Some(new_enrollment.clone());
            current.current_record_digest = record_digest.to_string();
            state.status.remove(identity);
        }
        TrustMutation::Distrust { tombstone } => {
            if tombstone.profile != TRUST_TOMBSTONE_PROFILE || tombstone.identity != identity {
                return Err(trust_error("trust tombstone profile or identity mismatch"));
            }
            require_id(&tombstone.tombstone_id, "tombstoneId")?;
            if state.identities.values().any(|value| {
                value
                    .tombstones
                    .iter()
                    .any(|prior| prior.tombstone.tombstone_id == tombstone.tombstone_id)
            }) {
                return Err(trust_error(
                    "trust tombstone ID is already used under this source anchor",
                ));
            }
            let current = state
                .identities
                .get_mut(identity)
                .ok_or_else(|| trust_error("Distrust requires an enrolled identity"))?;
            let enrollment = current
                .active_enrollment
                .as_ref()
                .ok_or_else(|| trust_error("identity is already tombstoned"))?;
            if tombstone.denied_anchors != vec![enrollment.identity_anchor.clone()]
                || tombstone.prior_trust_record_digests
                    != vec![current.current_record_digest.clone()]
            {
                return Err(trust_error(
                    "tombstone must name the complete active anchor and prior row",
                ));
            }
            let tombstone_digest = digest("JACS-TRUST-TOMBSTONE-V1", tombstone)?;
            current.tombstones.push(TombstoneState {
                tombstone: tombstone.clone(),
                tombstone_digest,
                ledger_record_digest: record_digest.to_string(),
                superseded_by_record_digest: None,
            });
            current.active_enrollment = None;
            current.current_record_digest = record_digest.to_string();
            state.status.remove(identity);
        }
        TrustMutation::Reenroll {
            tombstone_id,
            tombstone_digest,
            new_enrollment,
        } => {
            validate_enrollment(state, identity, new_enrollment)?;
            require_id(tombstone_id, "tombstoneId")?;
            require_digest(tombstone_digest, "tombstoneDigest")?;
            let current = state
                .identities
                .get_mut(identity)
                .ok_or_else(|| trust_error("Reenroll requires a tombstoned identity"))?;
            if current.active_enrollment.is_some() {
                return Err(trust_error("an active identity cannot be reenrolled"));
            }
            let tombstone = current
                .tombstones
                .iter_mut()
                .rev()
                .find(|value| value.superseded_by_record_digest.is_none())
                .ok_or_else(|| trust_error("no live tombstone is available for reenrollment"))?;
            if tombstone.tombstone.tombstone_id != *tombstone_id
                || tombstone.tombstone_digest != *tombstone_digest
            {
                return Err(trust_error(
                    "Reenroll does not name the exact live tombstone",
                ));
            }
            tombstone.superseded_by_record_digest = Some(record_digest.to_string());
            current.active_enrollment = Some(new_enrollment.clone());
            current.current_record_digest = record_digest.to_string();
        }
        TrustMutation::UpdateEnrollmentPolicy {
            identity_anchor,
            old_policy_digest,
            new_policy_digest,
            policy_update_digest,
        } => {
            for (value, field) in [
                (old_policy_digest, "oldPolicyDigest"),
                (new_policy_digest, "newPolicyDigest"),
                (policy_update_digest, "policyUpdateDigest"),
            ] {
                require_digest(value, field)?;
            }
            let policy = state
                .policy
                .as_ref()
                .ok_or_else(|| trust_error("no active policy exists"))?;
            if policy.verification_policy_digest != *new_policy_digest
                || policy.update_digest != *policy_update_digest
            {
                return Err(trust_error(
                    "policy migration does not name the active policy update",
                ));
            }
            let current = state
                .identities
                .get_mut(identity)
                .ok_or_else(|| trust_error("policy migration requires an enrollment"))?;
            let enrollment = current
                .active_enrollment
                .as_mut()
                .ok_or_else(|| trust_error("tombstoned identity cannot migrate policy"))?;
            if enrollment.identity_anchor != *identity_anchor
                || enrollment.verification_policy_digest != *old_policy_digest
            {
                return Err(trust_error("policy migration old enrollment mismatch"));
            }
            enrollment.policy_name = policy.policy_name.clone();
            enrollment.policy_version = policy.policy_version;
            enrollment.verification_policy_digest = policy.verification_policy_digest.clone();
            current.current_record_digest = record_digest.to_string();
        }
        TrustMutation::UpdateStatusAuthority {
            identity_anchor,
            old_status_authority,
            new_status_authority,
            transition_evidence_digest,
        } => {
            if let Some(value) = transition_evidence_digest {
                require_digest(value, "transitionEvidenceDigest")?;
            }
            if old_status_authority == new_status_authority {
                return Err(trust_error("status authority update must change authority"));
            }
            let current = state
                .identities
                .get_mut(identity)
                .ok_or_else(|| trust_error("status authority update requires enrollment"))?;
            let enrollment = current
                .active_enrollment
                .as_mut()
                .ok_or_else(|| trust_error("tombstoned identity has no status authority"))?;
            if enrollment.identity_anchor != *identity_anchor
                || enrollment.status_authority != *old_status_authority
            {
                return Err(trust_error(
                    "old status authority does not match enrollment",
                ));
            }
            enrollment.status_authority = new_status_authority.clone();
            current.current_record_digest = record_digest.to_string();
            // A new mode cannot inherit completeness merely from a resolver
            // fallback. The new authority must append its own initial status.
            state.status.remove(identity);
        }
    }
    Ok(())
}

fn apply_policy_operation(
    state: &mut LedgerState,
    entry: &LedgerEntry,
    authorization: &PolicyUpdateAuthorization,
    record: &PolicyUpdateRecord,
) -> Result<(String, String), JacsError> {
    if authorization.profile != POLICY_AUTH_PROFILE
        || record.profile != POLICY_UPDATE_PROFILE
        || authorization.source_anchor != state.source_anchor
        || record.source_anchor != state.source_anchor
        || authorization.decision_id != entry.transaction_id
        || authorization.actor.actor_class != "owner"
        || authorization.actor.actor_id != entry.owner_proof.payload.actor_id
        || authorization.actor.actor_proof_type != "local_control_actor_proof"
        || authorization.actor.actor_proof_evidence_digest != entry.owner_proof.evidence_digest
        || authorization.decided_at != entry.committed_at
        || entry.owner_proof.payload.scope != OwnerProofScope::Policy
        || entry.owner_proof.payload.action != "update_policy_bundle"
        || record.authenticated_commit_time != entry.committed_at
    {
        return Err(trust_error(
            "policy authorization, proof, or record mismatch",
        ));
    }
    let request = PolicyUpdateAuthorizationRequest {
        source_anchor: authorization.source_anchor.clone(),
        decision_id: authorization.decision_id.clone(),
        previous_bundle_digest: authorization.previous_bundle_digest.clone(),
        proposed_bundle_digest: authorization.proposed_bundle_digest.clone(),
        actor: ControlActorReference {
            actor_class: authorization.actor.actor_class.clone(),
            actor_id: authorization.actor.actor_id.clone(),
            actor_proof_type: authorization.actor.actor_proof_type.clone(),
        },
        decided_at: authorization.decided_at.clone(),
    };
    let expected_request = digest("JACS-POLICY-UPDATE-AUTHORIZATION-REQUEST-V1", &request)?;
    let authorization_digest = digest("JACS-POLICY-UPDATE-AUTHORIZATION-V1", authorization)?;
    if authorization_digest != record.authorization_digest {
        return Err(trust_error("policy update authorization digest mismatch"));
    }
    let bundle_digest = digest("JACS-POLICY-BUNDLE-V1", &record.new_bundle)?;
    if authorization.proposed_bundle_digest != bundle_digest
        || authorization.previous_bundle_digest != record.previous_bundle_digest
    {
        return Err(trust_error("policy bundle authorization linkage mismatch"));
    }
    let previous = state.policy.as_ref();
    let expected_sequence = previous.map_or(0, |value| value.sequence + 1);
    let expected_update = previous.map(|value| value.update_digest.clone());
    let expected_bundle = previous.map(|value| value.bundle_digest.clone());
    if record.sequence != expected_sequence
        || record.previous_update_digest != expected_update
        || record.previous_bundle_digest != expected_bundle
    {
        return Err(trust_error("policy update used a stale high-water record"));
    }
    let update_digest = digest("JACS-POLICY-UPDATE-V1", record)?;
    let high_water = policy_high_water(&record.new_bundle, &bundle_digest, &update_digest)?;
    if high_water.sequence != record.sequence {
        return Err(trust_error("policy high-water sequence mismatch"));
    }
    validate_policy_advance(previous, &high_water)?;
    state.policy = Some(high_water);
    Ok((expected_request, update_digest))
}

fn policy_high_water(
    bundle: &PolicyBundle,
    bundle_digest: &str,
    update_digest: &str,
) -> Result<PolicyHighWater, JacsError> {
    if bundle.profile != POLICY_BUNDLE_PROFILE || bundle.bundle_version == 0 {
        return Err(trust_error("policy bundle profile/version is invalid"));
    }
    let verification = value_object(&bundle.verification_policy, "verificationPolicy")?;
    require_value_literal(
        verification,
        "profile",
        "jacs-verification-policy-v1",
        "verificationPolicy",
    )?;
    let policy_name = value_string(verification, "policyName", "verificationPolicy")?;
    require_id(&policy_name, "policyName")?;
    let policy_version = value_u64(verification, "policyVersion", "verificationPolicy")?;
    if policy_version == 0 {
        return Err(trust_error("verification policy version must be positive"));
    }
    let verification_policy_digest =
        digest("JACS-VERIFICATION-POLICY-V1", &bundle.verification_policy)?;

    let profile_registry =
        value_object(&bundle.security_profile_registry, "securityProfileRegistry")?;
    require_value_literal(
        profile_registry,
        "profile",
        "jacs-security-profile-registry-v1",
        "securityProfileRegistry",
    )?;
    let security_profile_registry_version =
        value_u64(profile_registry, "version", "securityProfileRegistry")?;
    if value_string(profile_registry, "policyName", "securityProfileRegistry")? != policy_name
        || value_u64(profile_registry, "policyVersion", "securityProfileRegistry")?
            != policy_version
        || security_profile_registry_version != policy_version
    {
        return Err(trust_error(
            "security profile registry does not match verification policy name/version",
        ));
    }
    let security_profile_registry_digest = digest(
        "JACS-SECURITY-PROFILE-REGISTRY-V1",
        &bundle.security_profile_registry,
    )?;
    if value_string(
        verification,
        "securityProfileRegistryDigest",
        "verificationPolicy",
    )? != security_profile_registry_digest
    {
        return Err(trust_error(
            "verification policy security-profile registry digest mismatch",
        ));
    }

    let (schema_registry_version, schema_registry_digest) =
        if let Some(schema_registry) = &bundle.schema_registry {
            let schema = value_object(schema_registry, "schemaRegistry")?;
            require_value_literal(
                schema,
                "profile",
                "jacs-schema-registry-v1",
                "schemaRegistry",
            )?;
            let version = value_u64(schema, "version", "schemaRegistry")?;
            if version == 0 {
                return Err(trust_error("schema registry version must be positive"));
            }
            let digest = digest("JACS-SCHEMA-REGISTRY-V1", schema_registry)?;
            if verification
                .get("schemaRegistryDigest")
                .and_then(Value::as_str)
                != Some(digest.as_str())
            {
                return Err(trust_error(
                    "verification policy schema registry digest mismatch",
                ));
            }
            (Some(version), Some(digest))
        } else {
            if verification.get("schemaRegistryDigest") != Some(&Value::Null) {
                return Err(trust_error(
                    "null schema registry requires a null policy registry digest",
                ));
            }
            (None, None)
        };

    Ok(PolicyHighWater {
        sequence: bundle.bundle_version - 1,
        update_digest: update_digest.to_string(),
        bundle_version: bundle.bundle_version,
        bundle_digest: bundle_digest.to_string(),
        policy_name,
        policy_version,
        verification_policy_digest,
        schema_registry_version,
        schema_registry_digest,
        security_profile_registry_version,
        security_profile_registry_digest,
    })
}

fn validate_policy_advance(
    previous: Option<&PolicyHighWater>,
    next: &PolicyHighWater,
) -> Result<(), JacsError> {
    match previous {
        None => {
            if next.sequence != 0 || next.bundle_version != 1 || next.policy_version != 1 {
                return Err(trust_error(
                    "genesis policy must start at sequence 0 and bundle/policy version 1",
                ));
            }
            if next
                .schema_registry_version
                .is_some_and(|version| version != 1)
            {
                return Err(trust_error("genesis schema registry version must be 1"));
            }
        }
        Some(previous) => {
            if next.sequence != previous.sequence + 1
                || next.bundle_version != previous.bundle_version + 1
                || next.policy_version != previous.policy_version + 1
                || next.security_profile_registry_version
                    != previous.security_profile_registry_version + 1
            {
                return Err(trust_error(
                    "policy, bundle, and profile-registry versions must advance by one",
                ));
            }
            match (
                previous.schema_registry_version,
                next.schema_registry_version,
            ) {
                (Some(old), Some(new)) if new == old + 1 => {}
                (None, None) => {}
                (None, Some(1)) => {}
                (Some(_), None) => {}
                _ => {
                    return Err(trust_error(
                        "schema registry version must advance monotonically",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn value_object<'a>(
    value: &'a Value,
    field: &str,
) -> Result<&'a serde_json::Map<String, Value>, JacsError> {
    value
        .as_object()
        .ok_or_else(|| trust_error(format!("{field} must be an object")))
}

fn value_string(
    value: &serde_json::Map<String, Value>,
    field: &str,
    parent: &str,
) -> Result<String, JacsError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| trust_error(format!("{parent}.{field} must be a string")))
}

fn value_u64(
    value: &serde_json::Map<String, Value>,
    field: &str,
    parent: &str,
) -> Result<u64, JacsError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| trust_error(format!("{parent}.{field} must be an unsigned integer")))
}

fn require_value_literal(
    value: &serde_json::Map<String, Value>,
    field: &str,
    expected: &str,
    parent: &str,
) -> Result<(), JacsError> {
    if value.get(field).and_then(Value::as_str) != Some(expected) {
        return Err(trust_error(format!(
            "{parent}.{field} must equal '{expected}'"
        )));
    }
    Ok(())
}

fn apply_status_operation(
    state: &mut LedgerState,
    entry: &LedgerEntry,
    request: &StatusAcceptanceRequest,
    acceptance: &LocalStatusAcceptance,
    checkpoint: &LocalStatusCheckpoint,
) -> Result<(String, String), JacsError> {
    if acceptance.profile != STATUS_ACCEPTANCE_PROFILE
        || request.acceptance_id != entry.transaction_id
        || request.source_anchor != state.source_anchor
        || request.accepted_at != entry.committed_at
        || acceptance.trust_store_anchor != state.source_anchor
        || acceptance.first_accepted_at != entry.committed_at
        || entry.owner_proof.payload.scope != OwnerProofScope::Trust
        || entry.owner_proof.payload.action != "accept_status_checkpoint"
        || request.previous_acceptance_digest != acceptance.previous_acceptance_digest
    {
        return Err(trust_error("status acceptance, proof, or source mismatch"));
    }
    let expected_request = digest("JACS-STATUS-ACCEPTANCE-REQUEST-V1", request)?;
    let checkpoint_digest = digest("JACS-STATUS-CHECKPOINT-V1", checkpoint)?;
    if checkpoint_digest != request.status_checkpoint_digest
        || checkpoint_digest != acceptance.status_checkpoint_digest
        || acceptance.accepted_evidence
            != (AcceptedStatusEvidence::LocalStatusPayload {
                digest: checkpoint_digest.clone(),
            })
        || acceptance.identity_anchor != checkpoint.identity_anchor
        || acceptance.status_authority != checkpoint.status_authority
        || acceptance.status_sequence != checkpoint.status_sequence
        || acceptance.lifecycle_sequence != checkpoint.lifecycle_sequence
        || acceptance.lifecycle_record_digest != checkpoint.lifecycle_record_digest
        || acceptance.revocation_epoch != checkpoint.revocation_epoch
        || acceptance.complete_through != checkpoint.complete_through
    {
        return Err(trust_error("status checkpoint digest mismatch"));
    }
    if checkpoint.profile != "jacs-status-checkpoint-v1"
        || checkpoint.operation != "PublishStatusCheckpoint"
        || checkpoint.purpose != "status"
        || checkpoint.authority_scope != "local"
        || checkpoint.current_status_key_id.is_some()
        || checkpoint.revocation_epoch != checkpoint.lifecycle_sequence
    {
        return Err(trust_error(
            "invalid local status checkpoint profile or scope",
        ));
    }
    let identity = &request.identity;
    let trust = state
        .identities
        .get(identity)
        .and_then(|value| value.active_enrollment.as_ref())
        .ok_or_else(|| trust_error("status acceptance requires an active trust enrollment"))?;
    if checkpoint.identity_anchor != trust.identity_anchor
        || checkpoint.status_authority != trust.status_authority
        || checkpoint.lifecycle_sequence != trust.lifecycle_sequence
        || checkpoint.lifecycle_record_digest != trust.lifecycle_record_digest
        || checkpoint.status_authority != local_status_authority(&state.source_anchor)?
    {
        return Err(trust_error(
            "status checkpoint does not match the active local enrollment",
        ));
    }
    require_digest(&checkpoint.lifecycle_record_digest, "lifecycleRecordDigest")?;
    if parse_time(&checkpoint.complete_through)? > parse_time(&checkpoint.checkpoint_time)?
        || checkpoint.checkpoint_time != entry.committed_at
    {
        return Err(trust_error(
            "local status time must equal commit time and bound completeThrough",
        ));
    }

    let previous = state.status.get(identity);
    let expected_acceptance_sequence = previous.map_or(0, |value| value.acceptance_sequence + 1);
    let expected_acceptance_digest = previous.map(|value| value.acceptance_digest.clone());
    let expected_status_sequence = previous.map_or(0, |value| value.status_sequence + 1);
    let expected_checkpoint_digest = previous.map(|value| value.checkpoint_digest.clone());
    if acceptance.acceptance_sequence != expected_acceptance_sequence
        || acceptance.previous_acceptance_digest != expected_acceptance_digest
        || checkpoint.status_sequence != expected_status_sequence
        || checkpoint.previous_status_checkpoint_digest != expected_checkpoint_digest
    {
        return Err(trust_error(
            "status checkpoint or acceptance chain mismatch",
        ));
    }
    if let Some(previous) = previous {
        if parse_time(&checkpoint.checkpoint_time)? < parse_time(&previous.checkpoint_time)?
            || parse_time(&checkpoint.complete_through)? < parse_time(&previous.complete_through)?
            || checkpoint.lifecycle_sequence < previous.lifecycle_sequence
            || checkpoint.revocation_epoch < previous.revocation_epoch
            || (checkpoint.lifecycle_sequence == previous.lifecycle_sequence
                && checkpoint.lifecycle_record_digest != previous.lifecycle_record_digest)
        {
            return Err(trust_error(
                "status high-water state cannot decrease or fork",
            ));
        }
    }
    let acceptance_digest = digest("JACS-STATUS-CHECKPOINT-ACCEPTANCE-V1", acceptance)?;
    state.status.insert(
        identity.clone(),
        StatusHighWater {
            identity_anchor: checkpoint.identity_anchor.clone(),
            status_authority: checkpoint.status_authority.clone(),
            acceptance_sequence: acceptance.acceptance_sequence,
            acceptance_digest: acceptance_digest.clone(),
            status_sequence: checkpoint.status_sequence,
            checkpoint_digest,
            checkpoint_time: checkpoint.checkpoint_time.clone(),
            complete_through: checkpoint.complete_through.clone(),
            lifecycle_sequence: checkpoint.lifecycle_sequence,
            lifecycle_record_digest: checkpoint.lifecycle_record_digest.clone(),
            revocation_epoch: checkpoint.revocation_epoch,
            first_accepted_at: acceptance.first_accepted_at.clone(),
        },
    );
    Ok((expected_request, acceptance_digest))
}

fn local_status_authority(source: &TrustStoreAnchor) -> Result<StatusAuthority, JacsError> {
    match source {
        TrustStoreAnchor::LocalTrustStore { local_owner_store } => Ok(local_owner_store.clone()),
        TrustStoreAnchor::AuthorityTrustStore { .. } => Err(trust_error(
            "a local ledger cannot authenticate authority-backed status",
        )),
    }
}

fn local_owner_id(source: &TrustStoreAnchor) -> Result<&str, JacsError> {
    match source {
        TrustStoreAnchor::LocalTrustStore {
            local_owner_store: StatusAuthority::LocalOwnerStore { owner_id, .. },
        } => Ok(owner_id),
        _ => Err(trust_error(
            "local ledger source is not a local owner-store authority",
        )),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn test_digest(label: &str) -> String {
        digest(
            "JACS-TRUST-LEDGER-TEST-V1",
            &serde_json::json!({"label": label}),
        )
        .expect("test digest")
    }

    fn initialized_ledger() -> (tempfile::TempDir, LocalTrustLedger) {
        let temp = tempfile::tempdir().expect("private temp root");
        let root = temp
            .path()
            .canonicalize()
            .expect("canonical private temp root")
            .join("authority-store");
        let ledger = LocalTrustLedger::initialize(
            &root,
            OwnerEnrollmentRequest {
                confirmation_digest: test_digest("owner-enrollment"),
                mode: OwnerEnrollmentMode::NewStore,
            },
        )
        .expect("initialize ledger");
        (temp, ledger)
    }

    fn policy_bundle(version: u64) -> (PolicyBundle, String) {
        let profile_registry = serde_json::json!({
            "profile": "jacs-security-profile-registry-v1",
            "version": version,
            "policyName": "test-policy",
            "policyVersion": version,
            "profiles": []
        });
        let profile_registry_digest =
            digest("JACS-SECURITY-PROFILE-REGISTRY-V1", &profile_registry)
                .expect("profile registry digest");
        let verification_policy = serde_json::json!({
            "profile": "jacs-verification-policy-v1",
            "policyName": "test-policy",
            "policyVersion": version,
            "securityProfileRegistryDigest": profile_registry_digest,
            "schemaRegistryDigest": null
        });
        let verification_policy_digest =
            digest("JACS-VERIFICATION-POLICY-V1", &verification_policy)
                .expect("verification policy digest");
        (
            PolicyBundle {
                profile: POLICY_BUNDLE_PROFILE.to_string(),
                bundle_version: version,
                verification_policy,
                schema_registry: None,
                security_profile_registry: profile_registry,
            },
            verification_policy_digest,
        )
    }

    fn append_genesis_policy(ledger: &LocalTrustLedger) -> (LedgerAppendReceipt, String) {
        let (bundle, policy_digest) = policy_bundle(1);
        let receipt = ledger
            .append_policy(
                VerifiedPolicyBundle { bundle },
                OwnerAuthorization::fresh("policy-decision-1", test_digest("policy-1"))
                    .expect("owner authorization"),
                PolicyAppendGuard {
                    expected_policy_head: None,
                    expected_bundle_digest: None,
                },
            )
            .expect("append genesis policy");
        (receipt, policy_digest)
    }

    #[test]
    fn bootstrap_is_private_explicit_and_stable_across_open() {
        let (_temp, ledger) = initialized_ledger();
        for path in [ledger.root().to_path_buf(), ledger.entries_dir()] {
            assert_eq!(
                std::fs::metadata(path)
                    .expect("authority directory metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        for path in [
            ledger.bootstrap_path(),
            ledger.state_path(),
            ledger.journal_path(),
            ledger.lock_path(),
        ] {
            assert_eq!(
                std::fs::metadata(path)
                    .expect("authority file metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        let before = ledger.high_water().expect("initial high water");
        let reopened = LocalTrustLedger::open(ledger.root()).expect("reopen ledger");
        assert_eq!(reopened.high_water().expect("reopened high water"), before);
    }

    #[test]
    fn legacy_migration_is_explicit_forensic_input_not_imported_authority() {
        let temp = tempfile::tempdir().expect("private temp root");
        let root = temp
            .path()
            .canonicalize()
            .expect("canonical private temp root")
            .join("migrated-authority-store");
        let mode = OwnerEnrollmentMode::LegacyMigration {
            legacy_store_digest: test_digest("legacy-store"),
            legacy_config_digest: test_digest("legacy-config"),
        };
        let ledger = LocalTrustLedger::initialize(
            &root,
            OwnerEnrollmentRequest {
                confirmation_digest: test_digest("legacy-owner-confirmation"),
                mode: mode.clone(),
            },
        )
        .expect("explicit legacy migration");
        let bootstrap: StoreBootstrapFile = ledger
            .read(&ledger.bootstrap_path())
            .expect("bootstrap record");
        assert_eq!(bootstrap.owner_enrollment.mode, mode);
        let high_water = ledger.high_water().expect("empty migrated ledger");
        assert_eq!(high_water.trust_record_digest, None);
        assert_eq!(high_water.policy_update_digest, None);
        assert!(
            ledger
                .active_enrollment("legacy-principal")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn policy_append_is_cas_serialized_idempotent_and_time_fenced() {
        let (_temp, ledger) = initialized_ledger();
        let (bundle, _) = policy_bundle(1);
        let verified = VerifiedPolicyBundle { bundle };
        let authorization =
            OwnerAuthorization::fresh("policy-idempotent", test_digest("policy-idempotent"))
                .expect("owner authorization");
        let guard = PolicyAppendGuard {
            expected_policy_head: None,
            expected_bundle_digest: None,
        };
        let first = ledger
            .append_policy(verified.clone(), authorization.clone(), guard.clone())
            .expect("first append");
        let retry = ledger
            .append_policy(verified, authorization.clone(), guard)
            .expect("identical retry");
        assert!(retry.idempotent_replay);
        assert_eq!(retry.entry_digest, first.entry_digest);

        let current = ledger.high_water().expect("policy high water");
        let (second_bundle, _) = policy_bundle(2);
        assert!(
            ledger
                .append_policy(
                    VerifiedPolicyBundle {
                        bundle: second_bundle.clone(),
                    },
                    authorization,
                    PolicyAppendGuard {
                        expected_policy_head: current.policy_update_digest.clone(),
                        expected_bundle_digest: current.policy_bundle_digest.clone(),
                    },
                )
                .is_err(),
            "a consumed decision ID cannot authorize different content"
        );

        let retained = current.greatest_accepted_utc_second.unix_seconds();
        let rolled_back = retained - 1;
        let rollback_authorization = OwnerAuthorization {
            decision_id: "policy-clock-rollback".to_string(),
            confirmation_digest: test_digest("policy-clock-rollback"),
            authenticated_at: JacsTime::from_unix_seconds(rolled_back).expect("rollback timestamp"),
            expires_at: JacsTime::from_unix_seconds(rolled_back + 300).expect("rollback expiry"),
        };
        assert!(
            ledger
                .append_policy(
                    VerifiedPolicyBundle {
                        bundle: second_bundle,
                    },
                    rollback_authorization,
                    PolicyAppendGuard {
                        expected_policy_head: current.policy_update_digest,
                        expected_bundle_digest: current.policy_bundle_digest,
                    },
                )
                .is_err(),
            "local time below the retained high-water mark must fail"
        );
    }

    #[test]
    fn prepared_journal_recovers_only_the_exact_derived_next_state() {
        let (_temp, ledger) = initialized_ledger();
        let (receipt, _) = append_genesis_policy(&ledger);
        let bootstrap: StoreBootstrapFile = ledger
            .read(&ledger.bootstrap_path())
            .expect("bootstrap record");
        let next_state: LedgerState = ledger.read(&ledger.state_path()).expect("next state");
        let entry: LedgerEntry = ledger
            .read(
                &ledger
                    .entry_path(receipt.entry_sequence, &receipt.entry_digest)
                    .expect("entry path"),
            )
            .expect("immutable entry");
        let base_state = LedgerState::initial(&bootstrap).expect("base state");
        let prepared = LedgerJournal::Prepared {
            profile: JOURNAL_PROFILE.to_string(),
            base_state_digest: state_digest(&base_state).expect("base digest"),
            next_state_digest: state_digest(&next_state).expect("next digest"),
            entry_digest: receipt.entry_digest,
            entry,
            next_state: next_state.clone(),
        };
        ledger
            .replace(&ledger.state_path(), &base_state)
            .expect("simulate pre-state crash point");
        ledger
            .replace(&ledger.journal_path(), &prepared)
            .expect("persist prepared journal");

        let recovered = LocalTrustLedger::open(ledger.root()).expect("recover prepared commit");
        assert_eq!(
            recovered.high_water().expect("recovered high water"),
            ledger.high_water().expect("stable recovered high water")
        );
        let recovered_state: LedgerState = recovered
            .read(&recovered.state_path())
            .expect("recovered state");
        assert_eq!(recovered_state, next_state);
    }

    #[test]
    fn distrust_retains_tombstone_and_removes_status_without_discovery_fallback() {
        let (_temp, ledger) = initialized_ledger();
        let (_, policy_digest) = append_genesis_policy(&ledger);
        let initial_tombstone_heads = ledger.high_water().expect("initial heads");
        let identity = "test-principal".to_string();
        let identity_anchor = IdentityAnchor::Portable {
            jacs_id: identity.clone(),
            genesis_manifest_digest: test_digest("genesis-manifest"),
            genesis_root_canonical_key_id: "jacs-key-v1:ed25519:test-root".to_string(),
        };
        let enrollment = TrustEnrollment {
            policy_name: "test-policy".to_string(),
            policy_version: 1,
            verification_policy_digest: policy_digest,
            identity_anchor: identity_anchor.clone(),
            status_authority: local_status_authority(
                &ledger.high_water().expect("store anchor").source_anchor,
            )
            .expect("local status authority"),
            provenance: TrustProvenance {
                profile: TRUST_PROVENANCE_PROFILE.to_string(),
                method: TrustProvenanceMethod::ExplicitTofu,
                source_authority_anchor: None,
                source_evidence_digest: test_digest("independent-proof"),
                candidate_material_digest: test_digest("candidate-material"),
            },
            current_root_canonical_key_id: "jacs-key-v1:ed25519:test-root".to_string(),
            lifecycle_sequence: 0,
            lifecycle_record_digest: test_digest("lifecycle-zero"),
        };
        let enrollment_receipt = ledger
            .append_trust(
                VerifiedTrustMutation {
                    identity: identity.clone(),
                    mutation: TrustMutation::Enroll {
                        underlying_independent_proof_digest: enrollment
                            .provenance
                            .source_evidence_digest
                            .clone(),
                        enrollment: enrollment.clone(),
                    },
                },
                OwnerAuthorization::fresh("trust-enroll", test_digest("trust-enroll"))
                    .expect("owner authorization"),
                TrustAppendGuard {
                    expected_global_head: None,
                    expected_identity_head: None,
                },
            )
            .expect("enroll trust");

        let status_authorization =
            OwnerAuthorization::fresh("status-zero", test_digest("status-zero"))
                .expect("status authorization");
        let checkpoint_time = status_authorization.authenticated_at.clone();
        ledger
            .accept_local_status(
                VerifiedLocalStatusCheckpoint {
                    identity: identity.clone(),
                    checkpoint: LocalStatusCheckpoint {
                        profile: "jacs-status-checkpoint-v1".to_string(),
                        operation: "PublishStatusCheckpoint".to_string(),
                        purpose: "status".to_string(),
                        identity_anchor: identity_anchor.clone(),
                        status_authority: enrollment.status_authority.clone(),
                        authority_scope: "local".to_string(),
                        status_sequence: 0,
                        checkpoint_time: checkpoint_time.clone(),
                        complete_through: checkpoint_time,
                        lifecycle_sequence: enrollment.lifecycle_sequence,
                        lifecycle_record_digest: enrollment.lifecycle_record_digest.clone(),
                        current_status_key_id: None,
                        revocation_epoch: enrollment.lifecycle_sequence,
                        previous_status_checkpoint_digest: None,
                    },
                },
                status_authorization,
                StatusAppendGuard {
                    expected_acceptance_head: None,
                },
            )
            .expect("accept local status");
        assert!(
            ledger
                .status_high_water(&identity)
                .expect("status high water")
                .is_some()
        );

        let tombstone = TrustTombstone {
            profile: TRUST_TOMBSTONE_PROFILE.to_string(),
            tombstone_id: "tombstone-1".to_string(),
            identity: identity.clone(),
            denied_anchors: vec![identity_anchor],
            prior_trust_record_digests: vec![enrollment_receipt.logical_record_digest.clone()],
            reason_category: DistrustReason::AdministrativeWithdrawal,
        };
        ledger
            .append_trust(
                VerifiedTrustMutation {
                    identity: identity.clone(),
                    mutation: TrustMutation::Distrust { tombstone },
                },
                OwnerAuthorization::fresh("trust-distrust", test_digest("trust-distrust"))
                    .expect("owner authorization"),
                TrustAppendGuard {
                    expected_global_head: Some(enrollment_receipt.logical_record_digest.clone()),
                    expected_identity_head: Some(enrollment_receipt.logical_record_digest),
                },
            )
            .expect("append distrust");

        assert!(
            ledger
                .active_enrollment(&identity)
                .expect("active enrollment")
                .is_none()
        );
        assert!(
            ledger
                .status_high_water(&identity)
                .expect("status removed")
                .is_none()
        );
        let after = LocalTrustLedger::open(ledger.root())
            .expect("reopen tombstoned store")
            .high_water()
            .expect("retained tombstone heads");
        assert_ne!(
            after.tombstone_disposition_digest,
            initial_tombstone_heads.tombstone_disposition_digest
        );
        assert_ne!(
            after.blocking_tombstone_set_digest,
            initial_tombstone_heads.blocking_tombstone_set_digest
        );
    }
}
