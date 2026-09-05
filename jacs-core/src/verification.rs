//! Closed verification intent, policy, and report vocabulary (TP-24 through TP-27).
//! Decoding evidence never establishes trust. Integrity reports are deliberately
//! non-authorizing; only authenticated lifecycle/status engines may add authority.

use crate::identity::{
    AuthorityAnchor, IdentityAnchor, JacsTime, StatusAuthority, TrustStoreAnchor,
    canonical_algorithm, canonical_key_id, digest_bytes, digest_json, validate_digest,
};
use crate::signing::{PurposeIsolationAssurance, SigningOperation};
use crate::{CoreError, strict_json::parse_strict_json};
use serde::{Deserialize, Serialize, ser::SerializeMap};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub use crate::verification_registry::{
    ConformanceFixture, ConformanceFixtureBundle, ContextRuleId, MatcherDerived, ProfileKind,
    ResolvedSchemaBundle, SchemaRegistry, SchemaRegistryEntry, SecurityProfileEntry,
    SecurityProfileRegistry, SignatureFamilyId, ValidatedProfileSelection, WireRuleId,
};

fn invalid(message: impl Into<String>) -> CoreError {
    CoreError::MalformedDocument(message.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntentProfile {
    #[serde(rename = "jacs-verification-intent-v1")]
    V1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExactExpectation {
    Exact { value: String },
    NotApplicable { value: () },
}
impl ExactExpectation {
    pub fn exact(value: impl Into<String>) -> Self {
        Self::Exact {
            value: value.into(),
        }
    }
    pub fn not_applicable() -> Self {
        Self::NotApplicable { value: () }
    }
    pub fn value(&self) -> Option<&str> {
        match self {
            Self::Exact { value } => Some(value),
            Self::NotApplicable { .. } => None,
        }
    }
    fn validate(&self) -> Result<(), CoreError> {
        if self.value().is_some_and(str::is_empty) {
            return Err(invalid("exact expectation cannot be empty"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum VersionExpectation {
    Exact { value: String },
    CurrentAuthorized { value: () },
    NotApplicable { value: () },
}
impl VersionExpectation {
    pub fn exact(value: impl Into<String>) -> Self {
        Self::Exact {
            value: value.into(),
        }
    }
    pub fn not_applicable() -> Self {
        Self::NotApplicable { value: () }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum SchemaExpectation {
    Required {
        #[serde(rename = "schemaId")]
        schema_id: String,
        #[serde(rename = "schemaBundleDigest")]
        schema_bundle_digest: String,
    },
    Forbidden {
        #[serde(rename = "schemaId")]
        schema_id: (),
        #[serde(rename = "schemaBundleDigest")]
        schema_bundle_digest: (),
    },
    NotApplicable {
        #[serde(rename = "schemaId")]
        schema_id: (),
        #[serde(rename = "schemaBundleDigest")]
        schema_bundle_digest: (),
    },
}
impl SchemaExpectation {
    pub fn not_applicable() -> Self {
        Self::NotApplicable {
            schema_id: (),
            schema_bundle_digest: (),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContextExpectation {
    ExactFields { value: Value },
    ExactDigest { value: String },
    NotApplicable { value: () },
}
impl ContextExpectation {
    pub fn not_applicable() -> Self {
        Self::NotApplicable { value: () }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservationPolicy {
    RegisteredSignedObservation {
        #[serde(rename = "observerIdentityAnchor")]
        observer_identity_anchor: IdentityAnchor,
        #[serde(rename = "observerTrustRecordDigest")]
        observer_trust_record_digest: String,
        #[serde(rename = "observerKeyId")]
        observer_key_id: String,
        #[serde(rename = "receiptAuthorityTrustRecordDigest")]
        receipt_authority_trust_record_digest: String,
    },
    AuthorityReceipt {
        #[serde(rename = "authorityTrustRecordDigest")]
        authority_trust_record_digest: String,
    },
    TransparencyInclusion {
        #[serde(rename = "logTrustRecord")]
        log_trust_record: LogTrustRecord,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogTrustRecord {
    pub log_anchor: LogAnchor,
    pub initial_checkpoint_digest: String,
    pub trust_ledger_record_digest: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogAnchorProfile {
    #[serde(rename = "jacs-transparency-log-anchor-v1")]
    V1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InclusionProfile {
    #[serde(rename = "rfc6962-v1-sha256-jcs")]
    Rfc6962V1Sha256Jcs,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogAnchor {
    pub profile: LogAnchorProfile,
    pub log_service_id: String,
    pub inclusion_profile: InclusionProfile,
    pub bootstrap_checkpoint_signing_key_id: String,
    pub identity_anchor: IdentityAnchor,
    pub status_authority: StatusAuthority,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
#[allow(
    clippy::large_enum_variant,
    reason = "closed public verification expectation intentionally owns its observation policy by value; preserve the Rust construction API"
)]
pub enum TemporalExpectation {
    Current {
        #[serde(rename = "maxCheckpointAgeSeconds")]
        max_checkpoint_age_seconds: u64,
        #[serde(rename = "maxRevocationCheckpointAgeSeconds")]
        max_revocation_checkpoint_age_seconds: u64,
    },
    AsOf {
        #[serde(rename = "lifecycleCheckpointDigest")]
        lifecycle_checkpoint_digest: String,
    },
    Archival {
        #[serde(rename = "observationPolicy")]
        observation_policy: ObservationPolicy,
        #[serde(rename = "authorizationStatusCheckpointDigest")]
        authorization_status_checkpoint_digest: String,
        #[serde(rename = "maxRevocationCheckpointAgeSeconds")]
        max_revocation_checkpoint_age_seconds: u64,
    },
    NotApplicable,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvaluationTimeSource {
    LocalVerifierClock {
        #[serde(rename = "authorityAnchor")]
        authority_anchor: (),
    },
    AuthenticatedAuthorityClock {
        #[serde(rename = "authorityAnchor")]
        authority_anchor: AuthorityAnchor,
    },
    NotApplicable {
        #[serde(rename = "authorityAnchor")]
        authority_anchor: (),
    },
}
impl EvaluationTimeSource {
    pub fn not_applicable() -> Self {
        Self::NotApplicable {
            authority_anchor: (),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationIntent {
    pub profile: IntentProfile,
    pub expected_identity: ExactExpectation,
    pub expected_jacs_version: VersionExpectation,
    pub operation: SigningOperation,
    pub signature_profile: String,
    pub schema: SchemaExpectation,
    pub audience: ExactExpectation,
    pub context: ContextExpectation,
    pub temporal: TemporalExpectation,
    pub evaluation_time_source: EvaluationTimeSource,
}
impl VerificationIntent {
    pub fn document_integrity() -> Self {
        Self {
            profile: IntentProfile::V1,
            expected_identity: ExactExpectation::not_applicable(),
            expected_jacs_version: VersionExpectation::not_applicable(),
            operation: SigningOperation::SignDocument,
            signature_profile: "jacs-document-v2".into(),
            schema: SchemaExpectation::not_applicable(),
            audience: ExactExpectation::not_applicable(),
            context: ContextExpectation::not_applicable(),
            temporal: TemporalExpectation::NotApplicable,
            evaluation_time_source: EvaluationTimeSource::not_applicable(),
        }
    }
    pub fn from_json(raw: &str) -> Result<Self, CoreError> {
        let value = parse_strict_json(raw)?;
        let intent: Self = serde_json::from_value(value).map_err(|e| invalid(e.to_string()))?;
        intent.validate()?;
        Ok(intent)
    }
    pub fn validate(&self) -> Result<(), CoreError> {
        self.expected_identity.validate()?;
        self.audience.validate()?;
        if matches!(&self.expected_jacs_version, VersionExpectation::Exact { value } if value.is_empty())
            || self.signature_profile.is_empty()
        {
            return Err(invalid("version/profile expectation cannot be empty"));
        }
        if let SchemaExpectation::Required {
            schema_id,
            schema_bundle_digest,
        } = &self.schema
        {
            if !schema_id.contains(':') || schema_id.chars().any(char::is_whitespace) {
                return Err(invalid("schema ID must be an absolute URI"));
            }
            validate_digest(schema_bundle_digest)?;
        }
        match &self.context {
            ContextExpectation::ExactFields { value } if !value.is_object() => {
                return Err(invalid(
                    "expected context must be a closed operation object",
                ));
            }
            ContextExpectation::ExactDigest { value } => validate_digest(value)?,
            _ => {}
        }
        if let ContextExpectation::ExactFields { value } = &self.context {
            let context: crate::signing_context::SigningOperationContextV1 =
                serde_json::from_value(value.clone()).map_err(|e| invalid(e.to_string()))?;
            context.validate_for_intent(
                &self.operation,
                &self.signature_profile,
                self.audience.value(),
            )?;
        }
        match &self.temporal {
            TemporalExpectation::Current {
                max_checkpoint_age_seconds,
                max_revocation_checkpoint_age_seconds,
            } => {
                if *max_checkpoint_age_seconds == 0 || *max_revocation_checkpoint_age_seconds == 0 {
                    return Err(invalid("checkpoint ages must be positive"));
                }
            }
            TemporalExpectation::AsOf {
                lifecycle_checkpoint_digest,
            } => validate_digest(lifecycle_checkpoint_digest)?,
            TemporalExpectation::Archival {
                authorization_status_checkpoint_digest,
                max_revocation_checkpoint_age_seconds,
                ..
            } => {
                validate_digest(authorization_status_checkpoint_digest)?;
                if *max_revocation_checkpoint_age_seconds == 0 {
                    return Err(invalid("revocation checkpoint age must be positive"));
                }
            }
            TemporalExpectation::NotApplicable => {}
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String, CoreError> {
        self.validate()?;
        digest_json(
            "JACS-VERIFICATION-INTENT-V1",
            &serde_json::to_value(self).map_err(|e| invalid(e.to_string()))?,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyClass {
    IntegrityOnly,
    PinnedIdentity,
    AuthorityBacked,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackProtection {
    None,
    LocalHighWaterMark,
    AuthorityCheckpoint,
    MonotonicHardware,
}

/// Wire description of a selected head. This type alone is not authenticated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustLedgerSelectionHead {
    pub sequence: u64,
    pub record_digest: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleSelectionHead {
    pub sequence: u64,
    pub digest: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatusSelectionHead {
    pub sequence: u64,
    pub digest: String,
    pub lifecycle_sequence: u64,
    pub lifecycle_digest: String,
    pub revocation_epoch: u64,
    pub complete_through: JacsTime,
}

/// Exact TP-24 wire projection. Deserializing this object does not authenticate
/// it. A trusted host obtains it from one owner-ledger/authority transaction;
/// the native API exposes that selection only through an opaque locked token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustSelectionSnapshot {
    pub profile: String,
    pub trust_store_anchor: TrustStoreAnchor,
    pub expected_identity: String,
    pub identity_anchor: IdentityAnchor,
    pub trust_ledger_head: TrustLedgerSelectionHead,
    pub active_identity_trust_row: TrustLedgerSelectionHead,
    pub tombstone_disposition_digest: String,
    pub blocking_tombstone_set_digest: String,
    pub policy_sequence: u64,
    pub policy_update_digest: String,
    pub policy_bundle_digest: String,
    pub verification_policy_digest: String,
    pub status_authority: StatusAuthority,
    pub lifecycle_head: LifecycleSelectionHead,
    #[serde(deserialize_with = "required_nullable")]
    pub status_head: Option<StatusSelectionHead>,
    pub rollback_protection: RollbackProtection,
}
impl TrustSelectionSnapshot {
    pub fn validate_for(
        &self,
        intent: &VerificationIntent,
        policy: &VerificationPolicy,
    ) -> Result<(), CoreError> {
        policy.validate_intent(intent)?;
        if self.profile != "jacs-trust-selection-v1"
            || self.expected_identity.is_empty()
            || intent.expected_identity.value() != Some(self.expected_identity.as_str())
            || policy.trust_source_anchor.as_ref() != Some(&self.trust_store_anchor)
            || self.verification_policy_digest != policy.digest()?
            || self.rollback_protection != policy.required_rollback_protection
            || self.active_identity_trust_row.sequence > self.trust_ledger_head.sequence
        {
            return Err(invalid(
                "trust selection does not match exact policy/intent/head",
            ));
        }
        if let IdentityAnchor::Portable { jacs_id, .. } = &self.identity_anchor
            && jacs_id != &self.expected_identity
        {
            return Err(invalid("selected portable anchor names another identity"));
        }
        for digest in [
            &self.trust_ledger_head.record_digest,
            &self.active_identity_trust_row.record_digest,
            &self.tombstone_disposition_digest,
            &self.blocking_tombstone_set_digest,
            &self.policy_update_digest,
            &self.policy_bundle_digest,
            &self.verification_policy_digest,
            &self.lifecycle_head.digest,
        ] {
            validate_digest(digest)?;
        }
        if let Some(status) = &self.status_head {
            validate_digest(&status.digest)?;
            validate_digest(&status.lifecycle_digest)?;
            if status.lifecycle_sequence != self.lifecycle_head.sequence
                || status.lifecycle_digest != self.lifecycle_head.digest
                || status.revocation_epoch != self.lifecycle_head.sequence
            {
                return Err(invalid("selected status and lifecycle heads differ"));
            }
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String, CoreError> {
        digest_json(
            "JACS-TRUST-SELECTION-V1",
            &serde_json::to_value(self).map_err(|e| invalid(e.to_string()))?,
        )
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderAssurance {
    Unknown,
    OperatorAsserted,
    AuthorityEvidenced,
    Attested,
    NotApplicable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlgorithmRule {
    ExactAllowlist,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MinimumAlgorithmRule {
    AnyAllowed,
    Pq2025Only,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NumericProfile {
    #[serde(rename = "jacs-json-rfc8785-binary64-v1")]
    Rfc8785Binary64V1,
    #[serde(rename = "jacs-json-safe-binary64-v1")]
    SafeBinary64V1,
}
impl NumericProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rfc8785Binary64V1 => "jacs-json-rfc8785-binary64-v1",
            Self::SafeBinary64V1 => "jacs-json-safe-binary64-v1",
        }
    }
    pub(crate) fn parse_json(self, raw: &str) -> Result<Value, CoreError> {
        let selected = match self {
            Self::Rfc8785Binary64V1 => crate::strict_json::NumericProfile::Rfc8785CompatibleV1,
            Self::SafeBinary64V1 => crate::strict_json::NumericProfile::ExactDecimalV1,
        };
        crate::strict_json::parse_strict_json_with_numeric_profile(raw, selected)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyProfile {
    #[serde(rename = "jacs-verification-policy-v1")]
    V1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalMode {
    Current,
    AsOf,
    Archival,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationPolicy {
    pub profile: PolicyProfile,
    pub policy_name: String,
    pub policy_version: u64,
    pub policy_class: PolicyClass,
    pub instance_audience: String,
    #[serde(deserialize_with = "required_nullable")]
    pub trust_source_anchor: Option<TrustStoreAnchor>,
    pub security_profile_registry_digest: String,
    #[serde(deserialize_with = "required_nullable")]
    pub schema_registry_digest: Option<String>,
    pub allowed_algorithms: Vec<String>,
    pub algorithm_rule: AlgorithmRule,
    pub minimum_algorithm_rule: MinimumAlgorithmRule,
    pub numeric_profile: NumericProfile,
    pub allowed_temporal_modes: Vec<TemporalMode>,
    pub evaluation_time_source: EvaluationTimeSource,
    pub max_clock_skew_seconds: u64,
    #[serde(deserialize_with = "required_nullable")]
    pub default_checkpoint_age_seconds: Option<u64>,
    #[serde(deserialize_with = "required_nullable")]
    pub maximum_checkpoint_age_seconds: Option<u64>,
    #[serde(deserialize_with = "required_nullable")]
    pub default_revocation_horizon_age_seconds: Option<u64>,
    #[serde(deserialize_with = "required_nullable")]
    pub maximum_revocation_horizon_age_seconds: Option<u64>,
    pub required_rollback_protection: RollbackProtection,
    pub allowed_purpose_isolation_assurances: Vec<PurposeIsolationAssurance>,
    pub allowed_signer_provider_assurances: Vec<ProviderAssurance>,
    #[serde(deserialize_with = "required_nullable")]
    pub compatibility_cutoff: Option<JacsTime>,
    pub policy_acceptance_enabled: bool,
}

// Nullable members are still required members of the canonical policy object.
fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

impl VerificationPolicy {
    /// Construct the non-authorizing baseline with an explicitly selected registry.
    pub fn integrity_only(
        instance_audience: String,
        security_profile_registry_digest: String,
    ) -> Result<Self, CoreError> {
        let policy = Self {
            profile: PolicyProfile::V1,
            policy_name: "jacs-integrity-only-v1".into(),
            policy_version: 1,
            policy_class: PolicyClass::IntegrityOnly,
            instance_audience,
            trust_source_anchor: None,
            security_profile_registry_digest,
            schema_registry_digest: None,
            allowed_algorithms: vec!["ed25519".into(), "es256".into(), "pq2025".into()],
            algorithm_rule: AlgorithmRule::ExactAllowlist,
            minimum_algorithm_rule: MinimumAlgorithmRule::AnyAllowed,
            numeric_profile: NumericProfile::Rfc8785Binary64V1,
            allowed_temporal_modes: vec![TemporalMode::NotApplicable],
            evaluation_time_source: EvaluationTimeSource::not_applicable(),
            max_clock_skew_seconds: 0,
            default_checkpoint_age_seconds: None,
            maximum_checkpoint_age_seconds: None,
            default_revocation_horizon_age_seconds: None,
            maximum_revocation_horizon_age_seconds: None,
            required_rollback_protection: RollbackProtection::None,
            allowed_purpose_isolation_assurances: vec![PurposeIsolationAssurance::NotApplicable],
            allowed_signer_provider_assurances: vec![
                ProviderAssurance::NotApplicable,
                ProviderAssurance::Unknown,
            ],
            compatibility_cutoff: None,
            policy_acceptance_enabled: false,
        };
        policy.validate()?;
        Ok(policy)
    }
    pub fn from_json(raw: &str) -> Result<Self, CoreError> {
        let policy: Self =
            serde_json::from_value(parse_strict_json(raw)?).map_err(|e| invalid(e.to_string()))?;
        policy.validate()?;
        Ok(policy)
    }
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.policy_version != 1 || self.instance_audience.is_empty() {
            return Err(invalid("policy version/audience is invalid"));
        }
        if self.minimum_algorithm_rule != MinimumAlgorithmRule::AnyAllowed {
            return Err(invalid(
                "baseline policy names cannot be redefined as a hardened algorithm policy",
            ));
        }
        validate_digest(&self.security_profile_registry_digest)?;
        if let Some(digest) = &self.schema_registry_digest {
            validate_digest(digest)?;
        }
        if self.allowed_algorithms.is_empty()
            || self.allowed_algorithms.windows(2).any(|v| v[0] >= v[1])
            || self
                .allowed_algorithms
                .iter()
                .any(|v| canonical_algorithm(v).ok() != Some(v.as_str()))
        {
            return Err(invalid(
                "algorithm allowlist must be sorted unique canonical algorithms",
            ));
        }
        if self.allowed_temporal_modes.is_empty()
            || self.allowed_purpose_isolation_assurances.is_empty()
            || self.allowed_signer_provider_assurances.is_empty()
        {
            return Err(invalid("policy allowlists cannot be empty"));
        }
        let sorted = |value: Value| -> bool {
            let Some(items) = value.as_array() else {
                return false;
            };
            items
                .windows(2)
                .all(|items| items[0].as_str() < items[1].as_str())
        };
        for list in [
            serde_json::to_value(&self.allowed_temporal_modes),
            serde_json::to_value(&self.allowed_purpose_isolation_assurances),
            serde_json::to_value(&self.allowed_signer_provider_assurances),
        ] {
            if !sorted(list.map_err(|e| invalid(e.to_string()))?) {
                return Err(invalid("policy allowlists must be sorted and unique"));
            }
        }
        let local = matches!(
            self.policy_name.as_str(),
            "jacs-local-simple-v1" | "jacs-local-durable-v1"
        );
        let managed = matches!(
            self.policy_name.as_str(),
            "jacs-hai-managed-v1" | "jacs-hai-managed-compat-v1" | "jacs-browser-authority-v1"
        );
        if self.policy_name == "jacs-integrity-only-v1" {
            if self.policy_class != PolicyClass::IntegrityOnly
                || self.trust_source_anchor.is_some()
                || self.policy_acceptance_enabled
                || self.max_clock_skew_seconds != 0
                || self.required_rollback_protection != RollbackProtection::None
                || self.allowed_temporal_modes != [TemporalMode::NotApplicable]
                || !matches!(
                    self.evaluation_time_source,
                    EvaluationTimeSource::NotApplicable { .. }
                )
                || self.default_checkpoint_age_seconds.is_some()
                || self.maximum_checkpoint_age_seconds.is_some()
                || self.default_revocation_horizon_age_seconds.is_some()
                || self.maximum_revocation_horizon_age_seconds.is_some()
                || self.compatibility_cutoff.is_some()
                || self.allowed_purpose_isolation_assurances
                    != [PurposeIsolationAssurance::NotApplicable]
                || self.allowed_signer_provider_assurances
                    != [ProviderAssurance::NotApplicable, ProviderAssurance::Unknown]
            {
                return Err(invalid(
                    "integrity-only policy must not claim authority or time",
                ));
            }
        } else if local || managed {
            let expected_isolation = match self.policy_name.as_str() {
                "jacs-hai-managed-v1" => vec![PurposeIsolationAssurance::SeparatePurposeKey],
                "jacs-local-durable-v1" | "jacs-browser-authority-v1" => vec![
                    PurposeIsolationAssurance::ClosedMultiPurposeSharedKey,
                    PurposeIsolationAssurance::SeparatePurposeKey,
                ],
                _ => vec![
                    PurposeIsolationAssurance::ClosedMultiPurposeSharedKey,
                    PurposeIsolationAssurance::SeparatePurposeKey,
                    PurposeIsolationAssurance::SharedRawCapable,
                ],
            };
            let (class, default_age, max_age, rollback) = if local {
                (
                    PolicyClass::PinnedIdentity,
                    86400,
                    604800,
                    RollbackProtection::LocalHighWaterMark,
                )
            } else {
                (
                    PolicyClass::AuthorityBacked,
                    300,
                    3600,
                    RollbackProtection::AuthorityCheckpoint,
                )
            };
            if self.policy_class != class
                || self.trust_source_anchor.is_none()
                || !self.policy_acceptance_enabled
                || self.max_clock_skew_seconds != 300
                || self.required_rollback_protection != rollback
                || self.default_checkpoint_age_seconds != Some(default_age)
                || self.maximum_checkpoint_age_seconds != Some(max_age)
                || self.default_revocation_horizon_age_seconds != Some(default_age)
                || self.maximum_revocation_horizon_age_seconds != Some(max_age)
                || self.allowed_temporal_modes
                    != [
                        TemporalMode::Archival,
                        TemporalMode::AsOf,
                        TemporalMode::Current,
                    ]
                || (local
                    && !matches!(
                        self.evaluation_time_source,
                        EvaluationTimeSource::LocalVerifierClock { .. }
                    ))
                || (managed
                    && !matches!(
                        self.evaluation_time_source,
                        EvaluationTimeSource::AuthenticatedAuthorityClock { .. }
                    ))
                || ((self.policy_name == "jacs-hai-managed-compat-v1")
                    != self.compatibility_cutoff.is_some())
                || self.allowed_purpose_isolation_assurances != expected_isolation
                || self.allowed_signer_provider_assurances
                    != [
                        ProviderAssurance::Attested,
                        ProviderAssurance::AuthorityEvidenced,
                        ProviderAssurance::OperatorAsserted,
                        ProviderAssurance::Unknown,
                    ]
            {
                return Err(invalid("policy differs from its named baseline constants"));
            }
        } else {
            return Err(invalid("unknown named policy"));
        }
        Ok(())
    }
    pub fn validate_intent(&self, intent: &VerificationIntent) -> Result<(), CoreError> {
        self.validate()?;
        intent.validate()?;
        if intent.evaluation_time_source != self.evaluation_time_source {
            return Err(invalid("intent and policy time sources differ"));
        }
        if self.schema_registry_digest.is_none()
            && matches!(intent.schema, SchemaExpectation::Required { .. })
        {
            return Err(invalid("required schema has no selected registry"));
        }
        let mode = match &intent.temporal {
            TemporalExpectation::Current {
                max_checkpoint_age_seconds,
                max_revocation_checkpoint_age_seconds,
            } => {
                if Some(*max_checkpoint_age_seconds) > self.maximum_checkpoint_age_seconds
                    || Some(*max_revocation_checkpoint_age_seconds)
                        > self.maximum_revocation_horizon_age_seconds
                {
                    return Err(invalid("intent exceeds policy checkpoint age limits"));
                }
                TemporalMode::Current
            }
            TemporalExpectation::AsOf { .. } => TemporalMode::AsOf,
            TemporalExpectation::Archival {
                max_revocation_checkpoint_age_seconds,
                ..
            } => {
                if Some(*max_revocation_checkpoint_age_seconds)
                    > self.maximum_revocation_horizon_age_seconds
                {
                    return Err(invalid("intent exceeds revocation horizon age"));
                }
                TemporalMode::Archival
            }
            TemporalExpectation::NotApplicable => TemporalMode::NotApplicable,
        };
        if !self.allowed_temporal_modes.contains(&mode) {
            return Err(invalid("temporal mode is not allowed by policy"));
        }
        if self.policy_class != PolicyClass::IntegrityOnly
            && intent.expected_identity.value().is_none()
        {
            return Err(invalid(
                "trust-bearing verification requires an exact expected identity",
            ));
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String, CoreError> {
        self.validate()?;
        digest_json(
            "JACS-VERIFICATION-POLICY-V1",
            &serde_json::to_value(self).map_err(|e| invalid(e.to_string()))?,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldStatus {
    Present,
    Valid,
    Invalid,
    NotRequested,
    NotComputed,
    NotApplicable,
    Unknown,
    Missing,
    Stale,
    Conflict,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    NotRequestedByIntent,
    BlockedByParse,
    BlockedByCanonicalization,
    BlockedByPriorStage,
    MissingEvidence,
    MalformedEvidence,
    UnsupportedProfile,
    CryptographicFailure,
    ClaimMismatch,
    PolicyMismatch,
    Unauthorized,
    Revoked,
    StaleEvidence,
    ConflictingEvidence,
    RollbackDetected,
    InternalFailure,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldResult {
    pub status: FieldStatus,
    pub value: Value,
    pub reason_code: Option<ReasonCode>,
}
impl FieldResult {
    fn present(value: impl Into<Value>) -> Self {
        Self {
            status: FieldStatus::Present,
            value: value.into(),
            reason_code: None,
        }
    }
    fn predicate(value: bool) -> Self {
        Self {
            status: FieldStatus::Valid,
            value: Value::Bool(value),
            reason_code: None,
        }
    }
    fn failure(status: FieldStatus, reason: ReasonCode) -> Self {
        Self {
            status,
            value: Value::Null,
            reason_code: Some(reason),
        }
    }
    fn not_applicable() -> Self {
        Self::failure(FieldStatus::NotApplicable, ReasonCode::NotRequestedByIntent)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ReportField {
    #[serde(rename = "parse_valid")]
    ParseValid,
    #[serde(rename = "canonicalization_profile")]
    CanonicalizationProfile,
    #[serde(rename = "submitted_artifact_digest")]
    SubmittedArtifactDigest,
    #[serde(rename = "canonical_envelope_digest_or_not_applicable")]
    CanonicalEnvelopeDigestOrNotApplicable,
    #[serde(rename = "signature_input_digest")]
    SignatureInputDigest,
    #[serde(rename = "verification_intent_digest")]
    VerificationIntentDigest,
    #[serde(rename = "signature_valid")]
    SignatureValid,
    #[serde(rename = "content_hash_valid")]
    ContentHashValid,
    #[serde(rename = "referenced_content_valid_or_not_applicable")]
    ReferencedContentValidOrNotApplicable,
    #[serde(rename = "legacy_integrity_valid_or_not_applicable")]
    LegacyIntegrityValidOrNotApplicable,
    #[serde(rename = "actual_canonical_key_id")]
    ActualCanonicalKeyId,
    #[serde(rename = "signed_legacy_key_reference_or_not_applicable")]
    SignedLegacyKeyReferenceOrNotApplicable,
    #[serde(rename = "actual_algorithm")]
    ActualAlgorithm,
    #[serde(rename = "algorithm_policy_valid")]
    AlgorithmPolicyValid,
    #[serde(rename = "claimed_identity")]
    ClaimedIdentity,
    #[serde(rename = "expected_identity_mode_and_value")]
    ExpectedIdentityModeAndValue,
    #[serde(rename = "claimed_jacs_version_or_not_applicable")]
    ClaimedJacsVersionOrNotApplicable,
    #[serde(rename = "expected_jacs_version_mode_and_value")]
    ExpectedJacsVersionModeAndValue,
    #[serde(rename = "authorized_jacs_version_or_not_applicable")]
    AuthorizedJacsVersionOrNotApplicable,
    #[serde(rename = "claimed_signer_lookup_id_or_not_applicable")]
    ClaimedSignerLookupIdOrNotApplicable,
    #[serde(rename = "legacy_binding_authorized_or_not_applicable")]
    LegacyBindingAuthorizedOrNotApplicable,
    #[serde(rename = "identity_bound")]
    IdentityBound,
    #[serde(rename = "identity_anchor_confirmed_or_not_applicable")]
    IdentityAnchorConfirmedOrNotApplicable,
    #[serde(rename = "key_purpose_authorized")]
    KeyPurposeAuthorized,
    #[serde(rename = "purpose_isolation_assurance")]
    PurposeIsolationAssurance,
    #[serde(rename = "signer_provider_enforcement_assurance")]
    SignerProviderEnforcementAssurance,
    #[serde(rename = "hai_signer_completion_evidence_or_not_applicable")]
    HaiSignerCompletionEvidenceOrNotApplicable,
    #[serde(rename = "claimed_operation")]
    ClaimedOperation,
    #[serde(rename = "expected_operation")]
    ExpectedOperation,
    #[serde(rename = "operation_profile_bound")]
    OperationProfileBound,
    #[serde(rename = "claimed_signature_profile")]
    ClaimedSignatureProfile,
    #[serde(rename = "expected_signature_profile")]
    ExpectedSignatureProfile,
    #[serde(rename = "claimed_schema_id_and_digest_or_not_applicable")]
    ClaimedSchemaIdAndDigestOrNotApplicable,
    #[serde(rename = "selected_schema_id_and_bundle_digest_or_not_applicable")]
    SelectedSchemaIdAndBundleDigestOrNotApplicable,
    #[serde(rename = "claimed_audience_and_context_or_not_applicable")]
    ClaimedAudienceAndContextOrNotApplicable,
    #[serde(rename = "expected_audience_and_context_or_not_applicable")]
    ExpectedAudienceAndContextOrNotApplicable,
    #[serde(rename = "audience_context_bound_or_not_applicable")]
    AudienceContextBoundOrNotApplicable,
    #[serde(rename = "a2a_interaction_allowed_or_not_applicable")]
    A2aInteractionAllowedOrNotApplicable,
    #[serde(rename = "agent_card_assurance_or_not_applicable")]
    AgentCardAssuranceOrNotApplicable,
    #[serde(rename = "a2a_wrapper_and_card_key_results_or_not_applicable")]
    A2aWrapperAndCardKeyResultsOrNotApplicable,
    #[serde(rename = "trust_status_and_tombstone_or_not_applicable")]
    TrustStatusAndTombstoneOrNotApplicable,
    #[serde(rename = "trust_ledger_head_and_active_row_or_not_applicable")]
    TrustLedgerHeadAndActiveRowOrNotApplicable,
    #[serde(rename = "trust_selection_digest_or_not_applicable")]
    TrustSelectionDigestOrNotApplicable,
    #[serde(rename = "policy_bundle_sequence_and_digest")]
    PolicyBundleSequenceAndDigest,
    #[serde(rename = "key_status")]
    KeyStatus,
    #[serde(rename = "continuity_valid")]
    ContinuityValid,
    #[serde(rename = "lifecycle_sequence_and_record_digest")]
    LifecycleSequenceAndRecordDigest,
    #[serde(rename = "structural_history_or_not_requested")]
    StructuralHistoryOrNotRequested,
    #[serde(rename = "revocation_status")]
    RevocationStatus,
    #[serde(rename = "freshness_valid_or_not_applicable")]
    FreshnessValidOrNotApplicable,
    #[serde(rename = "current_authorization")]
    CurrentAuthorization,
    #[serde(rename = "authorization_history_valid")]
    AuthorizationHistoryValid,
    #[serde(rename = "authorization_as_of_checkpoint_and_time")]
    AuthorizationAsOfCheckpointAndTime,
    #[serde(rename = "authorization_status_checkpoint_digest_and_time_or_not_applicable")]
    AuthorizationStatusCheckpointDigestAndTimeOrNotApplicable,
    #[serde(rename = "revocation_horizon_status")]
    RevocationHorizonStatus,
    #[serde(rename = "revocation_horizon_checks_by_subject")]
    RevocationHorizonChecksBySubject,
    #[serde(rename = "observation_required")]
    ObservationRequired,
    #[serde(rename = "observation_status")]
    ObservationStatus,
    #[serde(rename = "observation_policy_and_evidence_chain_or_not_applicable")]
    ObservationPolicyAndEvidenceChainOrNotApplicable,
    #[serde(rename = "observation_artifact_digest_or_not_applicable")]
    ObservationArtifactDigestOrNotApplicable,
    #[serde(rename = "observation_commit_digest_or_not_applicable")]
    ObservationCommitDigestOrNotApplicable,
    #[serde(rename = "trusted_observation_time_or_not_applicable")]
    TrustedObservationTimeOrNotApplicable,
    #[serde(rename = "split_view_assurance_or_not_applicable")]
    SplitViewAssuranceOrNotApplicable,
    #[serde(rename = "independent_compromise_recovery")]
    IndependentCompromiseRecovery,
    #[serde(rename = "recovery_threshold_currently_satisfiable")]
    RecoveryThresholdCurrentlySatisfiable,
    #[serde(rename = "recovery_storage_assurance")]
    RecoveryStorageAssurance,
    #[serde(rename = "event_evaluation_time_and_source_or_not_applicable")]
    EventEvaluationTimeAndSourceOrNotApplicable,
    #[serde(rename = "verification_evaluation_time_and_source_or_not_applicable")]
    VerificationEvaluationTimeAndSourceOrNotApplicable,
    #[serde(rename = "rollback_protection")]
    RollbackProtection,
    #[serde(rename = "schema_valid_or_not_applicable")]
    SchemaValidOrNotApplicable,
    #[serde(rename = "source_and_anchor")]
    SourceAndAnchor,
    #[serde(rename = "base_authority_scope")]
    BaseAuthorityScope,
    #[serde(rename = "policy_name_and_version")]
    PolicyNameAndVersion,
    #[serde(rename = "verification_policy_digest")]
    VerificationPolicyDigest,
    #[serde(rename = "compatibility_mode_or_not_applicable")]
    CompatibilityModeOrNotApplicable,
    #[serde(rename = "policy_accepted")]
    PolicyAccepted,
}
pub const REPORT_FIELDS: &[ReportField] = &[
    ReportField::ParseValid,
    ReportField::CanonicalizationProfile,
    ReportField::SubmittedArtifactDigest,
    ReportField::CanonicalEnvelopeDigestOrNotApplicable,
    ReportField::SignatureInputDigest,
    ReportField::VerificationIntentDigest,
    ReportField::SignatureValid,
    ReportField::ContentHashValid,
    ReportField::ReferencedContentValidOrNotApplicable,
    ReportField::LegacyIntegrityValidOrNotApplicable,
    ReportField::ActualCanonicalKeyId,
    ReportField::SignedLegacyKeyReferenceOrNotApplicable,
    ReportField::ActualAlgorithm,
    ReportField::AlgorithmPolicyValid,
    ReportField::ClaimedIdentity,
    ReportField::ExpectedIdentityModeAndValue,
    ReportField::ClaimedJacsVersionOrNotApplicable,
    ReportField::ExpectedJacsVersionModeAndValue,
    ReportField::AuthorizedJacsVersionOrNotApplicable,
    ReportField::ClaimedSignerLookupIdOrNotApplicable,
    ReportField::LegacyBindingAuthorizedOrNotApplicable,
    ReportField::IdentityBound,
    ReportField::IdentityAnchorConfirmedOrNotApplicable,
    ReportField::KeyPurposeAuthorized,
    ReportField::PurposeIsolationAssurance,
    ReportField::SignerProviderEnforcementAssurance,
    ReportField::HaiSignerCompletionEvidenceOrNotApplicable,
    ReportField::ClaimedOperation,
    ReportField::ExpectedOperation,
    ReportField::OperationProfileBound,
    ReportField::ClaimedSignatureProfile,
    ReportField::ExpectedSignatureProfile,
    ReportField::ClaimedSchemaIdAndDigestOrNotApplicable,
    ReportField::SelectedSchemaIdAndBundleDigestOrNotApplicable,
    ReportField::ClaimedAudienceAndContextOrNotApplicable,
    ReportField::ExpectedAudienceAndContextOrNotApplicable,
    ReportField::AudienceContextBoundOrNotApplicable,
    ReportField::A2aInteractionAllowedOrNotApplicable,
    ReportField::AgentCardAssuranceOrNotApplicable,
    ReportField::A2aWrapperAndCardKeyResultsOrNotApplicable,
    ReportField::TrustStatusAndTombstoneOrNotApplicable,
    ReportField::TrustLedgerHeadAndActiveRowOrNotApplicable,
    ReportField::TrustSelectionDigestOrNotApplicable,
    ReportField::PolicyBundleSequenceAndDigest,
    ReportField::KeyStatus,
    ReportField::ContinuityValid,
    ReportField::LifecycleSequenceAndRecordDigest,
    ReportField::StructuralHistoryOrNotRequested,
    ReportField::RevocationStatus,
    ReportField::FreshnessValidOrNotApplicable,
    ReportField::CurrentAuthorization,
    ReportField::AuthorizationHistoryValid,
    ReportField::AuthorizationAsOfCheckpointAndTime,
    ReportField::AuthorizationStatusCheckpointDigestAndTimeOrNotApplicable,
    ReportField::RevocationHorizonStatus,
    ReportField::RevocationHorizonChecksBySubject,
    ReportField::ObservationRequired,
    ReportField::ObservationStatus,
    ReportField::ObservationPolicyAndEvidenceChainOrNotApplicable,
    ReportField::ObservationArtifactDigestOrNotApplicable,
    ReportField::ObservationCommitDigestOrNotApplicable,
    ReportField::TrustedObservationTimeOrNotApplicable,
    ReportField::SplitViewAssuranceOrNotApplicable,
    ReportField::IndependentCompromiseRecovery,
    ReportField::RecoveryThresholdCurrentlySatisfiable,
    ReportField::RecoveryStorageAssurance,
    ReportField::EventEvaluationTimeAndSourceOrNotApplicable,
    ReportField::VerificationEvaluationTimeAndSourceOrNotApplicable,
    ReportField::RollbackProtection,
    ReportField::SchemaValidOrNotApplicable,
    ReportField::SourceAndAnchor,
    ReportField::BaseAuthorityScope,
    ReportField::PolicyNameAndVersion,
    ReportField::VerificationPolicyDigest,
    ReportField::CompatibilityModeOrNotApplicable,
    ReportField::PolicyAccepted,
];
#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UntrustedDiagnostic {
    pub code: String,
    pub stage: ReportField,
    pub detail: Option<String>,
}

/// Immutable report: acceptance has no public setter and no deserializer.
/// Report JSON received from elsewhere remains untrusted evidence.
#[derive(Debug, Clone)]
pub struct VerificationReport {
    fields: BTreeMap<ReportField, FieldResult>,
    diagnostics: Vec<UntrustedDiagnostic>,
}
impl Serialize for VerificationReport {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(REPORT_FIELDS.len() + 2))?;
        map.serialize_entry("profile", "jacs-verification-report-v1")?;
        for field in REPORT_FIELDS {
            map.serialize_entry(field, &self.fields[field])?;
        }
        map.serialize_entry("untrusted_diagnostics", &self.diagnostics)?;
        map.end()
    }
}
impl VerificationReport {
    pub fn field(&self, field: ReportField) -> &FieldResult {
        &self.fields[&field]
    }
    pub fn policy_accepted(&self) -> bool {
        let result = self.field(ReportField::PolicyAccepted);
        result.status == FieldStatus::Valid && result.value == Value::Bool(true)
    }
    pub fn digest(&self) -> Result<String, CoreError> {
        let mut value = serde_json::to_value(self).map_err(|e| invalid(e.to_string()))?;
        value["untrusted_diagnostics"] = json!([]);
        digest_json("JACS-VERIFICATION-REPORT-V1", &value)
    }
    fn for_intent(
        raw: &[u8],
        intent: &VerificationIntent,
        policy: &VerificationPolicy,
    ) -> Result<Self, CoreError> {
        let mut report = Self::initial(raw);
        report.set(
            ReportField::VerificationIntentDigest,
            FieldResult::present(intent.digest()?),
        );
        report.set(
            ReportField::VerificationPolicyDigest,
            FieldResult::present(policy.digest()?),
        );
        report.set(
            ReportField::PolicyNameAndVersion,
            FieldResult::present(
                json!({"name":policy.policy_name,"version":policy.policy_version}),
            ),
        );
        report.set(
            ReportField::ExpectedIdentityModeAndValue,
            FieldResult::present(
                serde_json::to_value(&intent.expected_identity)
                    .map_err(|e| invalid(e.to_string()))?,
            ),
        );
        report.set(
            ReportField::ExpectedJacsVersionModeAndValue,
            FieldResult::present(
                serde_json::to_value(&intent.expected_jacs_version)
                    .map_err(|e| invalid(e.to_string()))?,
            ),
        );
        report.set(
            ReportField::ExpectedOperation,
            FieldResult::present(
                serde_json::to_value(&intent.operation).map_err(|e| invalid(e.to_string()))?,
            ),
        );
        report.set(
            ReportField::ExpectedSignatureProfile,
            FieldResult::present(intent.signature_profile.clone()),
        );
        Ok(report)
    }
    fn initial(bytes: &[u8]) -> Self {
        let mut fields = REPORT_FIELDS
            .iter()
            .map(|field| {
                (
                    *field,
                    FieldResult::failure(FieldStatus::NotComputed, ReasonCode::BlockedByPriorStage),
                )
            })
            .collect::<BTreeMap<_, _>>();
        fields.insert(
            ReportField::SubmittedArtifactDigest,
            FieldResult::present(digest_bytes("JACS-VERIFICATION-ARTIFACT-V1", bytes)),
        );
        fields.insert(
            ReportField::PolicyAccepted,
            FieldResult {
                status: FieldStatus::Invalid,
                value: Value::Bool(false),
                reason_code: Some(ReasonCode::MissingEvidence),
            },
        );
        Self {
            fields,
            diagnostics: Vec::new(),
        }
    }
    fn set(&mut self, field: ReportField, result: FieldResult) {
        self.fields.insert(field, result);
    }
    fn deny(&mut self, reason: ReasonCode) {
        self.fields.insert(
            ReportField::PolicyAccepted,
            FieldResult {
                status: FieldStatus::Invalid,
                value: Value::Bool(false),
                reason_code: Some(reason),
            },
        );
    }
}

/// Native callers run their built-in header and referenced-content validation
/// on the same strict input before providing these compatibility checks.
/// They cannot grant identity authorization through this structure.
#[derive(Debug, Clone, Copy)]
pub struct DocumentIntegrityChecks {
    pub header_valid: bool,
    pub content_hash_valid: bool,
    pub public_key_hash_valid: bool,
    pub referenced_content_valid: Option<bool>,
}

/// Build a complete TP-26 document-v2 or contextual response-v2 integrity report.
/// Signature math and signature-input
/// reconstruction run here using the exact selected key. Any trust-bearing
/// policy lacks an authenticated snapshot in this entry point and is denied.
pub fn document_integrity_report(
    raw: &str,
    public_key: &[u8],
    algorithm: &str,
    intent: &VerificationIntent,
    policy: &VerificationPolicy,
    checks: DocumentIntegrityChecks,
) -> Result<VerificationReport, CoreError> {
    policy.validate_intent(intent)?;
    let response_profile = matches!(
        intent.operation,
        SigningOperation::SignBoundResponse | SigningOperation::SignAsyncEvent
    );
    let mut report = VerificationReport::for_intent(raw.as_bytes(), intent, policy)?;
    let value = match policy.numeric_profile.parse_json(raw) {
        Ok(value) => value,
        Err(error) => {
            for field in REPORT_FIELDS {
                if report.field(*field).status == FieldStatus::NotComputed {
                    report.set(
                        *field,
                        FieldResult::failure(FieldStatus::NotComputed, ReasonCode::BlockedByParse),
                    );
                }
            }
            report.set(
                ReportField::ParseValid,
                FieldResult::failure(FieldStatus::Invalid, ReasonCode::MalformedEvidence),
            );
            report.diagnostics.push(UntrustedDiagnostic {
                code: "strict_parse_failed".into(),
                stage: ReportField::ParseValid,
                detail: Some(error.to_string()),
            });
            report.deny(ReasonCode::MalformedEvidence);
            return Ok(report);
        }
    };
    report.set(ReportField::ParseValid, FieldResult::predicate(true));
    report.set(
        ReportField::CanonicalizationProfile,
        FieldResult::present(policy.numeric_profile.as_str()),
    );
    report.set(
        ReportField::CanonicalEnvelopeDigestOrNotApplicable,
        FieldResult::present(digest_json("JACS-CANONICAL-ENVELOPE-V1", &value)?),
    );
    let algorithm = canonical_algorithm(algorithm)?;
    let key_id = canonical_key_id(algorithm, public_key)?;
    report.set(
        ReportField::ActualCanonicalKeyId,
        FieldResult::present(key_id.clone()),
    );
    let response_context = if response_profile {
        crate::response_context::inspect_response_context(&value)
            .ok()
            .flatten()
    } else {
        None
    };
    let signed_lookup = value
        .pointer("/jacsSignature/agentID")
        .and_then(Value::as_str);
    let response_lookup = if response_profile {
        signed_lookup.and_then(|lookup| lookup.split_once(':'))
    } else {
        None
    };
    let claimed_identity = response_lookup
        .map(|(identity, _)| identity)
        .or(signed_lookup);
    let claimed_version = response_lookup.map(|(_, version)| version).or_else(|| {
        value
            .pointer("/jacsSignature/agentVersion")
            .and_then(Value::as_str)
    });
    for (field, path) in [
        (ReportField::ClaimedIdentity, "/jacsSignature/agentID"),
        (
            ReportField::ClaimedJacsVersionOrNotApplicable,
            "/jacsSignature/agentVersion",
        ),
        (
            ReportField::SignedLegacyKeyReferenceOrNotApplicable,
            "/jacsSignature/publicKeyHash",
        ),
    ] {
        report.set(
            field,
            match value.pointer(path).and_then(Value::as_str) {
                Some(claim) => FieldResult::present(claim),
                None => FieldResult::failure(FieldStatus::Missing, ReasonCode::MissingEvidence),
            },
        );
    }
    if let (Some(identity), Some(version)) = (claimed_identity, claimed_version) {
        report.set(ReportField::ClaimedIdentity, FieldResult::present(identity));
        report.set(
            ReportField::ClaimedJacsVersionOrNotApplicable,
            FieldResult::present(version),
        );
        report.set(
            ReportField::ClaimedSignerLookupIdOrNotApplicable,
            FieldResult::present(format!("{identity}:{version}")),
        );
    }
    let actual_profile = response_context
        .as_ref()
        .map(|data| match data.operation() {
            crate::response_context::ResponseOperation::SignBoundResponse => {
                "jacs-response-v2/direct-response"
            }
            crate::response_context::ResponseOperation::SignAsyncEvent => {
                "jacs-response-v2/async-event"
            }
        });
    let actual_operation = response_context
        .as_ref()
        .map(|data| match data.operation() {
            crate::response_context::ResponseOperation::SignBoundResponse => {
                SigningOperation::SignBoundResponse
            }
            crate::response_context::ResponseOperation::SignAsyncEvent => {
                SigningOperation::SignAsyncEvent
            }
        });
    let profile_matches = if response_profile {
        value
            .pointer("/jacsSignature/signatureContentVersion")
            .and_then(Value::as_str)
            == Some("jacs-response-v2")
            && actual_profile == Some(intent.signature_profile.as_str())
            && actual_operation.as_ref() == Some(&intent.operation)
    } else {
        value
            .pointer("/jacsSignature/signatureContentVersion")
            .and_then(Value::as_str)
            == Some(crate::verify::SIGNATURE_CONTENT_VERSION_V2)
            && intent.signature_profile == "jacs-document-v2"
            && intent.operation == SigningOperation::SignDocument
    };
    report.set(
        ReportField::ClaimedOperation,
        if response_profile {
            match &actual_operation {
                Some(operation) => FieldResult::present(
                    serde_json::to_value(operation).map_err(|e| invalid(e.to_string()))?,
                ),
                None => FieldResult::failure(FieldStatus::Missing, ReasonCode::UnsupportedProfile),
            }
        } else {
            FieldResult::present("SignDocument")
        },
    );
    report.set(
        ReportField::ClaimedSignatureProfile,
        if response_profile {
            match actual_profile {
                Some(profile) => FieldResult::present(profile),
                None => FieldResult::failure(FieldStatus::Missing, ReasonCode::UnsupportedProfile),
            }
        } else {
            FieldResult::present("jacs-document-v2")
        },
    );
    report.set(
        ReportField::OperationProfileBound,
        if profile_matches {
            FieldResult::predicate(true)
        } else {
            FieldResult::failure(FieldStatus::Invalid, ReasonCode::UnsupportedProfile)
        },
    );
    let requested_algorithm = crate::sign::SigningAlgorithm::from_wire_str(algorithm)
        .ok_or_else(|| CoreError::UnsupportedAlgorithm(algorithm.into()))?;
    let algorithm_matches = value
        .pointer("/jacsSignature/signingAlgorithm")
        .and_then(Value::as_str)
        .and_then(|value| canonical_algorithm(value).ok())
        == Some(algorithm);
    let algorithm_allowed = algorithm_matches
        && policy
            .allowed_algorithms
            .iter()
            .any(|allowed| allowed == algorithm)
        && (policy.minimum_algorithm_rule == MinimumAlgorithmRule::AnyAllowed
            || algorithm == "pq2025");
    report.set(
        ReportField::AlgorithmPolicyValid,
        if algorithm_allowed {
            FieldResult::predicate(true)
        } else {
            FieldResult::failure(FieldStatus::Invalid, ReasonCode::PolicyMismatch)
        },
    );
    let outcome = if response_profile {
        response_signature_outcome(&value, public_key, requested_algorithm)
    } else {
        crate::verify::verify_document(&value, public_key, requested_algorithm, "jacsSignature")
    };
    let signature_valid = outcome.as_ref().is_ok_and(|outcome| outcome.valid);
    report.set(
        ReportField::SignatureValid,
        if signature_valid {
            FieldResult::predicate(true)
        } else {
            FieldResult::failure(FieldStatus::Invalid, ReasonCode::CryptographicFailure)
        },
    );
    if outcome.is_ok() {
        report.set(
            ReportField::ActualAlgorithm,
            FieldResult::present(algorithm),
        );
    }
    if response_profile && outcome.is_ok() {
        report.set(
            ReportField::SignatureInputDigest,
            FieldResult::present(digest_bytes(
                "JACS-VERIFIED-SIGNATURE-INPUT-V1",
                crate::response_context::response_signing_input(&value)?.as_bytes(),
            )),
        );
    } else if outcome.is_ok()
        && let Some(fields) = value
            .pointer("/jacsSignature/fields")
            .and_then(Value::as_array)
    {
        let fields = fields
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect::<Vec<_>>();
        if let Ok(input) = crate::verify::build_signature_content_v2(
            &value,
            &fields,
            "jacsSignature",
            &value["jacsSignature"],
        ) {
            report.set(
                ReportField::SignatureInputDigest,
                FieldResult::present(digest_bytes(
                    "JACS-VERIFIED-SIGNATURE-INPUT-V1",
                    input.as_bytes(),
                )),
            );
        }
    }
    report.set(
        ReportField::ContentHashValid,
        if checks.content_hash_valid {
            FieldResult::predicate(true)
        } else {
            FieldResult::failure(FieldStatus::Invalid, ReasonCode::CryptographicFailure)
        },
    );
    report.set(
        ReportField::ReferencedContentValidOrNotApplicable,
        match checks.referenced_content_valid {
            Some(true) => FieldResult::predicate(true),
            Some(false) => {
                FieldResult::failure(FieldStatus::Invalid, ReasonCode::CryptographicFailure)
            }
            None => FieldResult::not_applicable(),
        },
    );
    let legacy_valid = checks.header_valid
        && checks.content_hash_valid
        && checks.public_key_hash_valid
        && checks.referenced_content_valid != Some(false)
        && signature_valid;
    report.set(
        ReportField::LegacyIntegrityValidOrNotApplicable,
        if legacy_valid {
            FieldResult::predicate(true)
        } else {
            FieldResult::failure(FieldStatus::Invalid, ReasonCode::CryptographicFailure)
        },
    );
    for field in [
        ReportField::IdentityBound,
        ReportField::CurrentAuthorization,
        ReportField::KeyPurposeAuthorized,
        ReportField::IndependentCompromiseRecovery,
        ReportField::RecoveryThresholdCurrentlySatisfiable,
        ReportField::ObservationRequired,
    ] {
        report.set(field, FieldResult::predicate(false));
    }
    for field in [
        ReportField::IdentityAnchorConfirmedOrNotApplicable,
        ReportField::AuthorizedJacsVersionOrNotApplicable,
        ReportField::LegacyBindingAuthorizedOrNotApplicable,
        ReportField::HaiSignerCompletionEvidenceOrNotApplicable,
        ReportField::A2aInteractionAllowedOrNotApplicable,
        ReportField::AgentCardAssuranceOrNotApplicable,
        ReportField::A2aWrapperAndCardKeyResultsOrNotApplicable,
        ReportField::TrustStatusAndTombstoneOrNotApplicable,
        ReportField::TrustLedgerHeadAndActiveRowOrNotApplicable,
        ReportField::TrustSelectionDigestOrNotApplicable,
        ReportField::PolicyBundleSequenceAndDigest,
        ReportField::LifecycleSequenceAndRecordDigest,
        ReportField::AuthorizationAsOfCheckpointAndTime,
        ReportField::AuthorizationStatusCheckpointDigestAndTimeOrNotApplicable,
        ReportField::ObservationPolicyAndEvidenceChainOrNotApplicable,
        ReportField::ObservationArtifactDigestOrNotApplicable,
        ReportField::ObservationCommitDigestOrNotApplicable,
        ReportField::TrustedObservationTimeOrNotApplicable,
        ReportField::SplitViewAssuranceOrNotApplicable,
        ReportField::EventEvaluationTimeAndSourceOrNotApplicable,
        ReportField::VerificationEvaluationTimeAndSourceOrNotApplicable,
        ReportField::FreshnessValidOrNotApplicable,
    ] {
        report.set(field, FieldResult::not_applicable());
    }
    report.set(
        ReportField::StructuralHistoryOrNotRequested,
        FieldResult::failure(FieldStatus::NotRequested, ReasonCode::NotRequestedByIntent),
    );
    report.set(
        ReportField::KeyStatus,
        FieldResult::failure(FieldStatus::Unknown, ReasonCode::MissingEvidence),
    );
    report.set(ReportField::ContinuityValid, FieldResult::not_applicable());
    report.set(
        ReportField::AuthorizationHistoryValid,
        FieldResult::not_applicable(),
    );
    report.set(
        ReportField::RevocationStatus,
        FieldResult::present("not_checked"),
    );
    report.set(
        ReportField::RevocationHorizonStatus,
        FieldResult::present("not_requested"),
    );
    report.set(
        ReportField::RevocationHorizonChecksBySubject,
        FieldResult::present(json!([])),
    );
    report.set(
        ReportField::ObservationStatus,
        FieldResult::present("not_required"),
    );
    report.set(
        ReportField::PurposeIsolationAssurance,
        FieldResult::present("not_applicable"),
    );
    report.set(
        ReportField::SignerProviderEnforcementAssurance,
        FieldResult::present("unknown"),
    );
    report.set(
        ReportField::RecoveryStorageAssurance,
        FieldResult::present("not_applicable"),
    );
    report.set(
        ReportField::RollbackProtection,
        FieldResult::present("none"),
    );
    report.set(
        ReportField::BaseAuthorityScope,
        FieldResult::present("not_applicable"),
    );
    report.set(
        ReportField::CompatibilityModeOrNotApplicable,
        FieldResult::present("not_applicable"),
    );
    let schema_forbidden = matches!(intent.schema, SchemaExpectation::Forbidden { .. })
        && value.get("$schema").is_some();
    report.set(
        ReportField::SchemaValidOrNotApplicable,
        match &intent.schema {
            SchemaExpectation::Required { .. } => {
                FieldResult::failure(FieldStatus::Missing, ReasonCode::MissingEvidence)
            }
            _ if schema_forbidden => {
                FieldResult::failure(FieldStatus::Invalid, ReasonCode::ClaimMismatch)
            }
            _ => FieldResult::not_applicable(),
        },
    );
    report.set(
        ReportField::ClaimedSchemaIdAndDigestOrNotApplicable,
        FieldResult::not_applicable(),
    );
    report.set(
        ReportField::SelectedSchemaIdAndBundleDigestOrNotApplicable,
        FieldResult::not_applicable(),
    );
    let context_requested = !matches!(intent.context, ContextExpectation::NotApplicable { .. })
        || intent.audience.value().is_some();
    let mut context_matches = !context_requested;
    for field in [
        ReportField::ClaimedAudienceAndContextOrNotApplicable,
        ReportField::ExpectedAudienceAndContextOrNotApplicable,
        ReportField::AudienceContextBoundOrNotApplicable,
    ] {
        report.set(
            field,
            if context_requested {
                FieldResult::failure(FieldStatus::Invalid, ReasonCode::UnsupportedProfile)
            } else {
                FieldResult::not_applicable()
            },
        );
    }
    if context_requested && let Some(data) = response_context.as_ref() {
        let data_context = data.operation_context()?;
        let audience = data_context.get("audience").and_then(Value::as_str);
        let actual = json!({"type":"response_context_v2","value":data_context});
        let audience_matches = intent
            .audience
            .value()
            .is_none_or(|expected| audience == Some(expected));
        let expected_matches = match &intent.context {
            ContextExpectation::ExactFields { value } => *value == actual,
            ContextExpectation::ExactDigest { value } => {
                *value
                    == digest_json(
                        "JACS-VERIFICATION-CONTEXT-V1",
                        &json!({
                            "operation":intent.operation,"signatureProfile":intent.signature_profile,"context":actual,
                        }),
                    )?
            }
            ContextExpectation::NotApplicable { .. } => true,
        };
        context_matches = audience_matches && expected_matches;
        report.set(
            ReportField::ClaimedAudienceAndContextOrNotApplicable,
            FieldResult::present(json!({"audience":audience,"context":actual})),
        );
        report.set(
            ReportField::ExpectedAudienceAndContextOrNotApplicable,
            FieldResult::present(json!({"audience":intent.audience,"context":intent.context})),
        );
        report.set(
            ReportField::AudienceContextBoundOrNotApplicable,
            if context_matches {
                FieldResult::predicate(true)
            } else {
                FieldResult::failure(FieldStatus::Invalid, ReasonCode::ClaimMismatch)
            },
        );
    }
    report.set(ReportField::SourceAndAnchor,FieldResult::present(json!({
        "policySourceType":"integrity_only","artifactSource":{"type":"submitted_bytes","storeRecordDigest":null},
        "verificationMaterialSource":{"type":"caller_supplied","sourceReferenceDigest":digest_bytes("JACS-CALLER-KEY-MATERIAL-V1",public_key)},
        "actualCanonicalKeyId":key_id,"identityAnchor":null,"trustSourceAnchor":null,"trustSelection":null,"trustSelectionDigest":null,
        "lifecycleRecordDigest":null,"currentBindingsDigest":null
    })));
    if policy.policy_class != PolicyClass::IntegrityOnly {
        for field in [
            ReportField::IdentityBound,
            ReportField::IdentityAnchorConfirmedOrNotApplicable,
            ReportField::KeyPurposeAuthorized,
            ReportField::CurrentAuthorization,
            ReportField::LegacyBindingAuthorizedOrNotApplicable,
            ReportField::AuthorizedJacsVersionOrNotApplicable,
            ReportField::TrustStatusAndTombstoneOrNotApplicable,
            ReportField::TrustLedgerHeadAndActiveRowOrNotApplicable,
            ReportField::TrustSelectionDigestOrNotApplicable,
            ReportField::PolicyBundleSequenceAndDigest,
            ReportField::ContinuityValid,
            ReportField::LifecycleSequenceAndRecordDigest,
            ReportField::AuthorizationHistoryValid,
            ReportField::KeyStatus,
            ReportField::AuthorizationStatusCheckpointDigestAndTimeOrNotApplicable,
            ReportField::FreshnessValidOrNotApplicable,
            ReportField::VerificationEvaluationTimeAndSourceOrNotApplicable,
            ReportField::SourceAndAnchor,
            ReportField::RollbackProtection,
            ReportField::BaseAuthorityScope,
            ReportField::PurposeIsolationAssurance,
            ReportField::SignerProviderEnforcementAssurance,
        ] {
            report.set(
                field,
                FieldResult::failure(FieldStatus::Missing, ReasonCode::MissingEvidence),
            );
        }
        report.set(
            ReportField::RevocationStatus,
            FieldResult::present("unknown"),
        );
        report.set(
            ReportField::RevocationHorizonStatus,
            FieldResult::present("missing"),
        );
        report.set(
            ReportField::RevocationHorizonChecksBySubject,
            FieldResult::failure(FieldStatus::Missing, ReasonCode::MissingEvidence),
        );
    }
    // This entry point has no authenticated trust selection, time fence, registry
    // bundle, or lifecycle source. A policy name can never manufacture them.
    let claim_matches = intent
        .expected_identity
        .value()
        .is_none_or(|expected| claimed_identity == Some(expected))
        && match &intent.expected_jacs_version {
            VersionExpectation::Exact { value: expected } => {
                claimed_version == Some(expected.as_str())
            }
            VersionExpectation::NotApplicable { .. } => true,
            VersionExpectation::CurrentAuthorized { .. } => false,
        };
    let first_failure = if !checks.header_valid {
        ReasonCode::MalformedEvidence
    } else if !signature_valid
        || !checks.content_hash_valid
        || !checks.public_key_hash_valid
        || checks.referenced_content_valid == Some(false)
    {
        ReasonCode::CryptographicFailure
    } else if !algorithm_allowed {
        ReasonCode::PolicyMismatch
    } else if !claim_matches || schema_forbidden || (context_requested && !context_matches) {
        ReasonCode::ClaimMismatch
    } else if !profile_matches {
        ReasonCode::UnsupportedProfile
    } else if policy.policy_class == PolicyClass::IntegrityOnly {
        ReasonCode::PolicyMismatch
    } else {
        ReasonCode::MissingEvidence
    };
    report.deny(first_failure);
    Ok(report)
}

/// Internal adapters are called only after the agreement evaluator has selected
/// this proof from the exact submitted artifact. They do not accept a claimed
/// signature result or an externally supplied authorizing report.
pub(crate) enum DetachedProofInput<'a> {
    AgreementV2 {
        context: &'a Value,
    },
    AgreementV3 {
        proof: &'a crate::agreements::v3::AgreementProofV3,
    },
}

/// Preserve per-proof coverage when no exact preselected verification key exists.
pub(crate) fn missing_proof_integrity_report(
    raw: &str,
    intent: &VerificationIntent,
    policy: &VerificationPolicy,
) -> Result<VerificationReport, CoreError> {
    policy.validate_intent(intent)?;
    let mut report = VerificationReport::for_intent(raw.as_bytes(), intent, policy)?;
    match policy.numeric_profile.parse_json(raw) {
        Ok(value) => {
            report.set(ReportField::ParseValid, FieldResult::predicate(true));
            report.set(
                ReportField::CanonicalizationProfile,
                FieldResult::present(policy.numeric_profile.as_str()),
            );
            report.set(
                ReportField::CanonicalEnvelopeDigestOrNotApplicable,
                FieldResult::present(digest_json("JACS-CANONICAL-ENVELOPE-V1", &value)?),
            );
            report.set(
                ReportField::ActualCanonicalKeyId,
                FieldResult::failure(FieldStatus::Missing, ReasonCode::MissingEvidence),
            );
            report.deny(ReasonCode::MissingEvidence);
        }
        Err(_) => {
            report.set(
                ReportField::ParseValid,
                FieldResult::failure(FieldStatus::Invalid, ReasonCode::MalformedEvidence),
            );
            report.deny(ReasonCode::MalformedEvidence);
        }
    }
    Ok(report)
}

/// Build the full immutable TP-26 report for one profile-owned proof. This
/// mathematical-evidence adapter never grants lifecycle or policy authority.
pub(crate) fn detached_proof_integrity_report(
    raw: &str,
    public_key: &[u8],
    algorithm: &str,
    intent: &VerificationIntent,
    policy: &VerificationPolicy,
    proof: DetachedProofInput<'_>,
) -> Result<VerificationReport, CoreError> {
    use base64::Engine as _;
    policy.validate_intent(intent)?;
    let mut report = VerificationReport::for_intent(raw.as_bytes(), intent, policy)?;
    let parsed = match policy.numeric_profile.parse_json(raw) {
        Ok(value) => value,
        Err(error) => {
            report.set(
                ReportField::ParseValid,
                FieldResult::failure(FieldStatus::Invalid, ReasonCode::MalformedEvidence),
            );
            report.diagnostics.push(UntrustedDiagnostic {
                code: "strict_parse_failed".into(),
                stage: ReportField::ParseValid,
                detail: Some(error.to_string()),
            });
            report.deny(ReasonCode::MalformedEvidence);
            return Ok(report);
        }
    };
    for field in REPORT_FIELDS {
        if report.field(*field).status == FieldStatus::NotComputed {
            report.set(*field, FieldResult::not_applicable());
        }
    }
    report.set(ReportField::ParseValid, FieldResult::predicate(true));
    report.set(
        ReportField::CanonicalizationProfile,
        FieldResult::present(policy.numeric_profile.as_str()),
    );
    report.set(
        ReportField::CanonicalEnvelopeDigestOrNotApplicable,
        FieldResult::present(digest_json("JACS-CANONICAL-ENVELOPE-V1", &parsed)?),
    );
    // Input is recorded only after the selected primitive is actually invoked.
    report.set(
        ReportField::SignatureInputDigest,
        FieldResult::failure(FieldStatus::NotComputed, ReasonCode::BlockedByPriorStage),
    );
    report.set(
        ReportField::ActualAlgorithm,
        FieldResult::failure(FieldStatus::NotComputed, ReasonCode::BlockedByPriorStage),
    );
    let algorithm = canonical_algorithm(algorithm)?;
    let key_id = canonical_key_id(algorithm, public_key)?;
    report.set(
        ReportField::ActualCanonicalKeyId,
        FieldResult::present(key_id.clone()),
    );
    for field in [
        ReportField::IdentityBound,
        ReportField::CurrentAuthorization,
        ReportField::KeyPurposeAuthorized,
        ReportField::IndependentCompromiseRecovery,
        ReportField::RecoveryThresholdCurrentlySatisfiable,
        ReportField::ObservationRequired,
    ] {
        report.set(field, FieldResult::predicate(false));
    }
    for (field, value) in [
        (ReportField::RevocationStatus, "not_checked"),
        (ReportField::RevocationHorizonStatus, "not_requested"),
        (ReportField::ObservationStatus, "not_required"),
        (ReportField::PurposeIsolationAssurance, "not_applicable"),
        (ReportField::SignerProviderEnforcementAssurance, "unknown"),
        (ReportField::RecoveryStorageAssurance, "not_applicable"),
        (ReportField::RollbackProtection, "none"),
        (ReportField::BaseAuthorityScope, "not_applicable"),
        (
            ReportField::CompatibilityModeOrNotApplicable,
            "not_applicable",
        ),
    ] {
        report.set(field, FieldResult::present(value));
    }
    report.set(
        ReportField::KeyStatus,
        FieldResult::failure(FieldStatus::Unknown, ReasonCode::MissingEvidence),
    );
    report.set(
        ReportField::RevocationHorizonChecksBySubject,
        FieldResult::present(json!([])),
    );
    report.set(
        ReportField::StructuralHistoryOrNotRequested,
        FieldResult::failure(FieldStatus::NotRequested, ReasonCode::NotRequestedByIntent),
    );
    report.set(ReportField::SourceAndAnchor, FieldResult::present(json!({
        "policySourceType":"integrity_only", "artifactSource":{"type":"submitted_bytes","storeRecordDigest":null},
        "verificationMaterialSource":{"type":"caller_supplied","sourceReferenceDigest":digest_bytes("JACS-CALLER-KEY-MATERIAL-V1", public_key)},
        "actualCanonicalKeyId":key_id,"identityAnchor":null,"trustSourceAnchor":null,"trustSelection":null,"trustSelectionDigest":null,"lifecycleRecordDigest":null,"currentBindingsDigest":null
    })));
    let evaluated = (|| -> Result<(Vec<u8>, Vec<u8>, bool, bool), CoreError> {
        match proof {
            DetachedProofInput::AgreementV2 { context } => {
                let object = context
                    .as_object()
                    .ok_or_else(|| invalid("agreement proof context must be an object"))?;
                if object.keys().any(|key| {
                    !matches!(
                        key.as_str(),
                        "jacsId"
                            | "jacsAgreementHash"
                            | "agreementSignature"
                            | "signedTranscriptHash"
                    )
                }) || context.get("jacsId").and_then(Value::as_str).is_none()
                    || context
                        .get("jacsAgreementHash")
                        .and_then(Value::as_str)
                        .is_none()
                {
                    return Err(invalid("agreement v2 proof context is not closed"));
                }
                let signature = &context["agreementSignature"];
                let claimed = signature
                    .get("agentID")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("agreement signer claim missing"))?;
                report.set(ReportField::ClaimedIdentity, FieldResult::present(claimed));
                if let Some(version) = signature.get("agentVersion").and_then(Value::as_str) {
                    report.set(
                        ReportField::ClaimedJacsVersionOrNotApplicable,
                        FieldResult::present(version),
                    );
                    report.set(
                        ReportField::ClaimedSignerLookupIdOrNotApplicable,
                        FieldResult::present(format!("{claimed}:{version}")),
                    );
                }
                if let Some(hash) = signature.get("publicKeyHash").and_then(Value::as_str) {
                    report.set(
                        ReportField::SignedLegacyKeyReferenceOrNotApplicable,
                        FieldResult::present(hash),
                    );
                }
                report.set(
                    ReportField::ClaimedOperation,
                    FieldResult::present("SignAgreementConsent"),
                );
                report.set(
                    ReportField::ClaimedSignatureProfile,
                    FieldResult::present("jacs-signature-v2"),
                );
                if signature
                    .get("signatureContentVersion")
                    .and_then(Value::as_str)
                    != Some(crate::verify::SIGNATURE_CONTENT_VERSION_V2)
                    || signature
                        .get("signingAlgorithm")
                        .and_then(Value::as_str)
                        .and_then(|a| canonical_algorithm(a).ok())
                        != Some(algorithm)
                {
                    return Err(invalid("agreement v2 signature profile/algorithm mismatch"));
                }
                let fields = signature
                    .get("fields")
                    .and_then(Value::as_array)
                    .ok_or_else(|| invalid("agreement signature fields missing"))?
                    .iter()
                    .map(|field| {
                        field
                            .as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| invalid("agreement field name is not a string"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let input = crate::verify::build_signature_content_v2(
                    context,
                    &fields,
                    "agreementSignature",
                    signature,
                )?
                .into_bytes();
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(
                        signature
                            .get("signature")
                            .and_then(Value::as_str)
                            .ok_or_else(|| invalid("agreement signature missing"))?,
                    )
                    .map_err(|e| invalid(e.to_string()))?;
                let claims_match = intent
                    .expected_identity
                    .value()
                    .is_none_or(|expected| expected == claimed)
                    && match &intent.expected_jacs_version {
                        VersionExpectation::Exact { value } => {
                            signature.get("agentVersion").and_then(Value::as_str)
                                == Some(value.as_str())
                        }
                        VersionExpectation::NotApplicable { .. } => true,
                        VersionExpectation::CurrentAuthorized { .. } => false,
                    };
                // V2 lacks a signed role/purpose discriminator, regardless of the
                // agreement evaluator's mathematical-consent interpretation.
                Ok((input, bytes, false, claims_match))
            }
            DetachedProofInput::AgreementV3 { proof } => {
                crate::agreements::v3::validate_proof_shape(proof)?;
                let operation: SigningOperation = serde_json::from_value(
                    serde_json::to_value(proof.operation).map_err(|e| invalid(e.to_string()))?,
                )
                .map_err(|e| invalid(e.to_string()))?;
                report.set(
                    ReportField::ClaimedOperation,
                    FieldResult::present(
                        serde_json::to_value(&operation).map_err(|e| invalid(e.to_string()))?,
                    ),
                );
                report.set(
                    ReportField::ClaimedSignatureProfile,
                    FieldResult::present(proof.profile.as_str()),
                );
                report.set(
                    ReportField::ClaimedIdentity,
                    match &proof.signer_identity_anchor {
                        IdentityAnchor::Portable { jacs_id, .. } => {
                            FieldResult::present(jacs_id.clone())
                        }
                        // An authority enrollment handle is not the stable
                        // identity; resolving it requires authenticated evidence.
                        IdentityAnchor::AuthorityBacked { .. } => {
                            FieldResult::failure(FieldStatus::Missing, ReasonCode::MissingEvidence)
                        }
                    },
                );
                if proof.signature.algorithm.as_str() != algorithm
                    || proof.canonical_key_id != key_id
                    || proof.signature.key_id != key_id
                {
                    return Err(invalid("agreement proof key/algorithm mismatch"));
                }
                let input = crate::agreements::v3::proof_signature_input(proof)?;
                let bytes = crate::identity::decode_binary(&proof.signature.value)?;
                let operation_bound = intent.operation == operation
                    && intent.signature_profile == proof.profile.as_str();
                let claims_match = match &proof.signer_identity_anchor {
                    IdentityAnchor::Portable { jacs_id, .. } => intent
                        .expected_identity
                        .value()
                        .is_none_or(|expected| expected == jacs_id),
                    IdentityAnchor::AuthorityBacked { .. } => {
                        intent.expected_identity.value().is_none()
                    }
                };
                Ok((input, bytes, operation_bound, claims_match))
            }
        }
    })();
    match evaluated {
        Ok((input, signature, operation_bound, claims_match)) => {
            let result =
                crate::identity::verify_signature(algorithm, public_key, &input, &signature);
            report.set(
                ReportField::ActualAlgorithm,
                FieldResult::present(algorithm),
            );
            report.set(
                ReportField::SignatureInputDigest,
                FieldResult::present(digest_bytes("JACS-VERIFIED-SIGNATURE-INPUT-V1", &input)),
            );
            report.set(
                ReportField::SignatureValid,
                if result.is_ok() {
                    FieldResult::predicate(true)
                } else {
                    FieldResult::failure(FieldStatus::Invalid, ReasonCode::CryptographicFailure)
                },
            );
            let allowed = policy
                .allowed_algorithms
                .iter()
                .any(|allowed| allowed == algorithm);
            report.set(
                ReportField::AlgorithmPolicyValid,
                if allowed {
                    FieldResult::predicate(true)
                } else {
                    FieldResult::failure(FieldStatus::Invalid, ReasonCode::PolicyMismatch)
                },
            );
            report.set(
                ReportField::OperationProfileBound,
                if operation_bound {
                    FieldResult::predicate(true)
                } else {
                    FieldResult::failure(FieldStatus::Invalid, ReasonCode::UnsupportedProfile)
                },
            );
            report.deny(if result.is_err() {
                ReasonCode::CryptographicFailure
            } else if !allowed {
                ReasonCode::PolicyMismatch
            } else if !claims_match {
                ReasonCode::ClaimMismatch
            } else if !operation_bound {
                ReasonCode::UnsupportedProfile
            } else {
                ReasonCode::MissingEvidence
            });
        }
        Err(error) => {
            report.set(
                ReportField::SignatureValid,
                FieldResult::failure(FieldStatus::Invalid, ReasonCode::MalformedEvidence),
            );
            report.diagnostics.push(UntrustedDiagnostic {
                code: "proof_validation_failed".into(),
                stage: ReportField::SignatureValid,
                detail: Some(error.to_string()),
            });
            report.deny(ReasonCode::MalformedEvidence);
        }
    }
    if policy.policy_class != PolicyClass::IntegrityOnly {
        for field in [
            ReportField::IdentityBound,
            ReportField::IdentityAnchorConfirmedOrNotApplicable,
            ReportField::CurrentAuthorization,
            ReportField::KeyPurposeAuthorized,
            ReportField::SourceAndAnchor,
            ReportField::TrustSelectionDigestOrNotApplicable,
            ReportField::LifecycleSequenceAndRecordDigest,
            ReportField::ContinuityValid,
            ReportField::AuthorizationHistoryValid,
            ReportField::AuthorizationStatusCheckpointDigestAndTimeOrNotApplicable,
            ReportField::VerificationEvaluationTimeAndSourceOrNotApplicable,
            ReportField::FreshnessValidOrNotApplicable,
        ] {
            report.set(
                field,
                FieldResult::failure(FieldStatus::Missing, ReasonCode::MissingEvidence),
            );
        }
    }
    Ok(report)
}

fn response_signature_outcome(
    value: &Value,
    public_key: &[u8],
    algorithm: crate::sign::SigningAlgorithm,
) -> Result<crate::verify::VerificationOutcome, CoreError> {
    use base64::Engine as _;
    let claimed = value
        .pointer("/jacsSignature/signingAlgorithm")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("response signature algorithm is missing"))?;
    if canonical_algorithm(claimed)? != algorithm.as_str() {
        return Err(CoreError::AlgorithmMismatch {
            expected: algorithm.as_str().into(),
            actual: claimed.into(),
        });
    }
    if value
        .pointer("/jacsSignature/signatureContentVersion")
        .and_then(Value::as_str)
        != Some("jacs-response-v2")
    {
        return Err(invalid("response signature profile mismatch"));
    }
    let signature = value
        .pointer("/jacsSignature/signature")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("response signature missing"))?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(signature)
        .map_err(|e| invalid(e.to_string()))?;
    let input = crate::response_context::response_signing_input(value)?;
    let result = crate::identity::verify_signature(
        algorithm.as_str(),
        public_key,
        input.as_bytes(),
        &signature,
    );
    Ok(crate::verify::VerificationOutcome {
        valid: result.is_ok(),
        signer_id: String::new(),
        timestamp: String::new(),
        data: Value::Null,
        errors: result
            .err()
            .map(|error| vec![error.to_string()])
            .unwrap_or_default(),
    })
}
