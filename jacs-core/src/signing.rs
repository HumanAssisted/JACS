//! Restricted, purpose-aware signing primitives.
//!
//! This module is the portable signing facade for callers that need more than
//! a raw cryptographic primitive.  A [`RestrictedSigningProvider`] owns the
//! private key and exposes named operations.  Callers receive signatures or
//! signed envelopes, never private-key bytes.
//!
//! The document preparation API deliberately separates two moments:
//!
//! 1. [`prepare_message_v2`] or [`prepare_document_v2`] freezes every value
//!    that affects the JACS v2 signature input, including `date`, `iat`, and
//!    `jti`.
//! 2. [`RestrictedSigningProvider::sign_prepared_document`] later signs those
//!    exact bytes after revalidating the envelope, key, operation, purpose,
//!    and digest.  It inserts the signature, derives the compatibility
//!    `jacsSha256` checksum, and post-verifies the result.
//!
//! This is suitable for approval flows: the bytes approved by a user are the
//! bytes eventually signed.  Finalization never generates a new identifier or
//! timestamp.  The provider is one-shot by design, so decrypted key material
//! is cleared before the operation returns (and on every error path via
//! `Drop`).

use crate::CoreError;
use crate::agent::CoreAgent;
use crate::material::{AgentMaterial, UnlockSecret};
use crate::sign::SigningAlgorithm;
use crate::signing_context::{
    AuthoritySigningClassificationV1, SigningContextSelectionV1, SigningRequestContextV1,
    local_document_v2_selection,
};
use crate::verification_registry::SecurityProfileEntry;
use crate::verify::{
    build_signature_content_v2, build_signature_metadata, default_signed_fields, sha256_hex,
    verify_detached, verify_document,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Value, json};
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::str::FromStr;

/// Semantic profile for the frozen JACS document-v2 wire rule.
pub const DOCUMENT_V2_SIGNATURE_PROFILE: &str = "jacs-document-v2";
/// The only placement accepted by the document-v2 restricted facade.
pub const DOCUMENT_V2_PLACEMENT_KEY: &str = "jacsSignature";
/// Serializable profile identifying a frozen, not-yet-signed envelope.
pub const PREPARED_DOCUMENT_V2_PROFILE: &str = "jacs-prepared-document-signature-v1";
/// Serialized profile for an unchanged primary JACS signature plus its
/// separate TP-31 authority interpretation.
pub const AUTHORITY_CLASSIFIED_PREPARED_DOCUMENT_V1_PROFILE: &str =
    "jacs-authority-classified-prepared-document-v1";
/// Domain label used by HAI approval flows for the exact signature input.
pub const HAI_SIGNATURE_INPUT_DIGEST_DOMAIN: &str = "JACS-HAI-SIGNATURE-INPUT-V1";
/// Canonical header schema used by native `Agent::create_document_and_load`.
pub const HEADER_V1_SCHEMA_ID: &str = "https://hai.ai/schemas/header/v1/header.schema.json";
/// Closed standard media-claim profile used by the existing image verifier.
pub const MEDIA_V1_SIGNATURE_PROFILE: &str = "jacs-media-v1";
/// Closed robust/LSB media-claim profile used by the existing image verifier.
pub const MEDIA_V1_ROBUST_SIGNATURE_PROFILE: &str = "jacs-media-v1-robust";
const LEGACY_RAW_INPUT_DIGEST_DOMAIN: &str = "JACS-LEGACY-RAW-INPUT-V1";
const LEGACY_RAW_SIGNATURE_DIGEST_DOMAIN: &str = "JACS-LEGACY-RAW-SIGNATURE-V1";

/// Closed TP-18 signing-purpose vocabulary.
///
/// `EcosystemExport` is not a free-form escape hatch.  Its profile ID must be
/// canonical and the complete resulting purpose must already be present in a
/// provider's immutable [`SigningKeyScope`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SigningPurpose {
    IdentityRoot,
    Recovery,
    Status,
    AuthorityTime,
    Document,
    InlineText,
    FileMedia,
    Email,
    ApiRequest,
    Response,
    AgreementProposal,
    AgreementConsent,
    AgreementWitness,
    AgreementAmendment,
    AgreementNotary,
    A2aArtifact,
    Attestation,
    ArchivalObservation,
    LegacyRaw,
    EcosystemExport(String),
}

impl SigningPurpose {
    /// Exact purpose token used by manifests, policies, and verification.
    pub fn to_wire(&self) -> Cow<'_, str> {
        match self {
            Self::IdentityRoot => Cow::Borrowed("identity_root"),
            Self::Recovery => Cow::Borrowed("recovery"),
            Self::Status => Cow::Borrowed("status"),
            Self::AuthorityTime => Cow::Borrowed("authority_time"),
            Self::Document => Cow::Borrowed("document"),
            Self::InlineText => Cow::Borrowed("inline_text"),
            Self::FileMedia => Cow::Borrowed("file_media"),
            Self::Email => Cow::Borrowed("email"),
            Self::ApiRequest => Cow::Borrowed("api_request"),
            Self::Response => Cow::Borrowed("response"),
            Self::AgreementProposal => Cow::Borrowed("agreement_proposal"),
            Self::AgreementConsent => Cow::Borrowed("agreement_consent"),
            Self::AgreementWitness => Cow::Borrowed("agreement_witness"),
            Self::AgreementAmendment => Cow::Borrowed("agreement_amendment"),
            Self::AgreementNotary => Cow::Borrowed("agreement_notary"),
            Self::A2aArtifact => Cow::Borrowed("a2a_artifact"),
            Self::Attestation => Cow::Borrowed("attestation"),
            Self::ArchivalObservation => Cow::Borrowed("archival_observation"),
            Self::LegacyRaw => Cow::Borrowed("legacy_raw"),
            Self::EcosystemExport(profile_id) => {
                Cow::Owned(format!("ecosystem_export:{profile_id}"))
            }
        }
    }

    /// Validate programmatically constructed dynamic purpose components.
    pub fn validate(&self) -> Result<(), CoreError> {
        if let Self::EcosystemExport(profile_id) = self {
            validate_profile_id(profile_id)?;
        }
        Ok(())
    }
}

impl std::fmt::Display for SigningPurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_wire())
    }
}

impl FromStr for SigningPurpose {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let purpose = match value {
            "identity_root" => Self::IdentityRoot,
            "recovery" => Self::Recovery,
            "status" => Self::Status,
            "authority_time" => Self::AuthorityTime,
            "document" => Self::Document,
            "inline_text" => Self::InlineText,
            "file_media" => Self::FileMedia,
            "email" => Self::Email,
            "api_request" => Self::ApiRequest,
            "response" => Self::Response,
            "agreement_proposal" => Self::AgreementProposal,
            "agreement_consent" => Self::AgreementConsent,
            "agreement_witness" => Self::AgreementWitness,
            "agreement_amendment" => Self::AgreementAmendment,
            "agreement_notary" => Self::AgreementNotary,
            "a2a_artifact" => Self::A2aArtifact,
            "attestation" => Self::Attestation,
            "archival_observation" => Self::ArchivalObservation,
            "legacy_raw" => Self::LegacyRaw,
            _ if value.starts_with("ecosystem_export:") => {
                let profile_id = &value["ecosystem_export:".len()..];
                validate_profile_id(profile_id)?;
                Self::EcosystemExport(profile_id.to_owned())
            }
            _ => {
                return Err(CoreError::MalformedDocument(format!(
                    "unknown signing purpose '{value}'"
                )));
            }
        };
        Ok(purpose)
    }
}

impl Serialize for SigningPurpose {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_wire())
    }
}

impl<'de> Deserialize<'de> for SigningPurpose {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Closed TP-28 signing-operation vocabulary.
///
/// The wire form is one exact string.  There is intentionally no
/// `Custom(String)` variant: a caller cannot relabel raw bytes as a protected
/// operation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SigningOperation {
    SignDocument,
    SignInlineTextCreate,
    SignInlineTextUpdate,
    SignFileOrMediaManifest,
    SignEmail,
    AuthenticateHttpRequest,
    SignBoundResponse,
    SignAsyncEvent,
    SignAgreementProposal,
    SignAgreementConsent,
    SignAgreementWitness,
    SignAgreementAmendment,
    SignAgreementNotary,
    SignA2aArtifact,
    SignAttestation,
    RecordArchivalObservation,
    AuthorizeKeyEvent,
    PublishStatusCheckpoint,
    IssueAuthorityTime,
    AuthorizeRevocationCutoff,
    LegacyRawSign,
    ExportEcosystem(String),
}

impl SigningOperation {
    /// Exact operation identifier used in signing and verification contexts.
    pub fn to_wire(&self) -> Cow<'_, str> {
        match self {
            Self::SignDocument => Cow::Borrowed("SignDocument"),
            Self::SignInlineTextCreate => Cow::Borrowed("SignInlineTextCreate"),
            Self::SignInlineTextUpdate => Cow::Borrowed("SignInlineTextUpdate"),
            Self::SignFileOrMediaManifest => Cow::Borrowed("SignFileOrMediaManifest"),
            Self::SignEmail => Cow::Borrowed("SignEmail"),
            Self::AuthenticateHttpRequest => Cow::Borrowed("AuthenticateHttpRequest"),
            Self::SignBoundResponse => Cow::Borrowed("SignBoundResponse"),
            Self::SignAsyncEvent => Cow::Borrowed("SignAsyncEvent"),
            Self::SignAgreementProposal => Cow::Borrowed("SignAgreementProposal"),
            Self::SignAgreementConsent => Cow::Borrowed("SignAgreementConsent"),
            Self::SignAgreementWitness => Cow::Borrowed("SignAgreementWitness"),
            Self::SignAgreementAmendment => Cow::Borrowed("SignAgreementAmendment"),
            Self::SignAgreementNotary => Cow::Borrowed("SignAgreementNotary"),
            Self::SignA2aArtifact => Cow::Borrowed("SignA2AArtifact"),
            Self::SignAttestation => Cow::Borrowed("SignAttestation"),
            Self::RecordArchivalObservation => Cow::Borrowed("RecordArchivalObservation"),
            Self::AuthorizeKeyEvent => Cow::Borrowed("AuthorizeKeyEvent"),
            Self::PublishStatusCheckpoint => Cow::Borrowed("PublishStatusCheckpoint"),
            Self::IssueAuthorityTime => Cow::Borrowed("IssueAuthorityTime"),
            Self::AuthorizeRevocationCutoff => Cow::Borrowed("AuthorizeRevocationCutoff"),
            Self::LegacyRawSign => Cow::Borrowed("LegacyRawSign"),
            Self::ExportEcosystem(profile_id) => {
                Cow::Owned(format!("ExportEcosystem:{profile_id}"))
            }
        }
    }

    /// Validate programmatically constructed dynamic operation components.
    pub fn validate(&self) -> Result<(), CoreError> {
        if let Self::ExportEcosystem(profile_id) = self {
            validate_profile_id(profile_id)?;
        }
        Ok(())
    }

    /// Whether `purpose` is one of the exact TP-28 mappings for this operation.
    ///
    /// Key-event and status-checkpoint operations have deliberately explicit
    /// multi-purpose cases; their named protocol constructors must enforce the
    /// narrower event-specific rule before calling a signer.
    pub fn accepts_purpose(&self, purpose: &SigningPurpose) -> bool {
        match self {
            Self::SignDocument => purpose == &SigningPurpose::Document,
            Self::SignInlineTextCreate | Self::SignInlineTextUpdate => {
                purpose == &SigningPurpose::InlineText
            }
            Self::SignFileOrMediaManifest => purpose == &SigningPurpose::FileMedia,
            Self::SignEmail => purpose == &SigningPurpose::Email,
            Self::AuthenticateHttpRequest => purpose == &SigningPurpose::ApiRequest,
            Self::SignBoundResponse | Self::SignAsyncEvent => purpose == &SigningPurpose::Response,
            Self::SignAgreementProposal => purpose == &SigningPurpose::AgreementProposal,
            Self::SignAgreementConsent => purpose == &SigningPurpose::AgreementConsent,
            Self::SignAgreementWitness => purpose == &SigningPurpose::AgreementWitness,
            Self::SignAgreementAmendment => purpose == &SigningPurpose::AgreementAmendment,
            Self::SignAgreementNotary => purpose == &SigningPurpose::AgreementNotary,
            Self::SignA2aArtifact => purpose == &SigningPurpose::A2aArtifact,
            Self::SignAttestation => purpose == &SigningPurpose::Attestation,
            Self::RecordArchivalObservation => purpose == &SigningPurpose::ArchivalObservation,
            Self::AuthorizeKeyEvent => {
                matches!(
                    purpose,
                    SigningPurpose::IdentityRoot | SigningPurpose::Recovery
                )
            }
            Self::PublishStatusCheckpoint => {
                matches!(
                    purpose,
                    SigningPurpose::Status | SigningPurpose::IdentityRoot
                )
            }
            Self::IssueAuthorityTime => purpose == &SigningPurpose::AuthorityTime,
            Self::AuthorizeRevocationCutoff => purpose == &SigningPurpose::IdentityRoot,
            Self::LegacyRawSign => purpose == &SigningPurpose::LegacyRaw,
            Self::ExportEcosystem(operation_profile) => matches!(
                purpose,
                SigningPurpose::EcosystemExport(purpose_profile)
                    if operation_profile == purpose_profile
            ),
        }
    }
}

impl std::fmt::Display for SigningOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_wire())
    }
}

impl FromStr for SigningOperation {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let operation = match value {
            "SignDocument" => Self::SignDocument,
            "SignInlineTextCreate" => Self::SignInlineTextCreate,
            "SignInlineTextUpdate" => Self::SignInlineTextUpdate,
            "SignFileOrMediaManifest" => Self::SignFileOrMediaManifest,
            "SignEmail" => Self::SignEmail,
            "AuthenticateHttpRequest" => Self::AuthenticateHttpRequest,
            "SignBoundResponse" => Self::SignBoundResponse,
            "SignAsyncEvent" => Self::SignAsyncEvent,
            "SignAgreementProposal" => Self::SignAgreementProposal,
            "SignAgreementConsent" => Self::SignAgreementConsent,
            "SignAgreementWitness" => Self::SignAgreementWitness,
            "SignAgreementAmendment" => Self::SignAgreementAmendment,
            "SignAgreementNotary" => Self::SignAgreementNotary,
            "SignA2AArtifact" => Self::SignA2aArtifact,
            "SignAttestation" => Self::SignAttestation,
            "RecordArchivalObservation" => Self::RecordArchivalObservation,
            "AuthorizeKeyEvent" => Self::AuthorizeKeyEvent,
            "PublishStatusCheckpoint" => Self::PublishStatusCheckpoint,
            "IssueAuthorityTime" => Self::IssueAuthorityTime,
            "AuthorizeRevocationCutoff" => Self::AuthorizeRevocationCutoff,
            "LegacyRawSign" => Self::LegacyRawSign,
            _ if value.starts_with("ExportEcosystem:") => {
                let profile_id = &value["ExportEcosystem:".len()..];
                validate_profile_id(profile_id)?;
                Self::ExportEcosystem(profile_id.to_owned())
            }
            _ => {
                return Err(CoreError::MalformedDocument(format!(
                    "unknown signing operation '{value}'"
                )));
            }
        };
        Ok(operation)
    }
}

impl Serialize for SigningOperation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_wire())
    }
}

impl<'de> Deserialize<'de> for SigningOperation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Closed report values for signing-key purpose isolation.
///
/// This describes authenticated key history in a verification report.  A
/// provider carrying the value does not, by itself, prove the assurance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PurposeIsolationAssurance {
    SharedRawCapable,
    ClosedMultiPurposeSharedKey,
    SeparatePurposeKey,
    NotApplicable,
}

/// One authenticated operation/purpose/semantic-profile binding selected for
/// a signing key. The full registry row remains separately typed; keeping this
/// minimal projection in the scope prevents an untrusted prepared record from
/// selecting a different otherwise well-formed profile at key-use time.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SigningProfileBindingV1 {
    operation: SigningOperation,
    purpose: SigningPurpose,
    signature_profile: String,
}

impl SigningProfileBindingV1 {
    pub fn new(
        operation: SigningOperation,
        purpose: SigningPurpose,
        signature_profile: impl Into<String>,
    ) -> Result<Self, CoreError> {
        operation.validate()?;
        purpose.validate()?;
        if !operation.accepts_purpose(&purpose) {
            return Err(CoreError::MalformedKey(format!(
                "profile binding operation '{}' does not accept purpose '{}'",
                operation, purpose
            )));
        }
        let binding = Self {
            operation,
            purpose,
            signature_profile: signature_profile.into(),
        };
        validate_semantic_profile_id(&binding.signature_profile)?;
        Ok(binding)
    }

    pub fn operation(&self) -> &SigningOperation {
        &self.operation
    }

    pub fn purpose(&self) -> &SigningPurpose {
        &self.purpose
    }

    pub fn signature_profile(&self) -> &str {
        &self.signature_profile
    }

    fn validate(&self) -> Result<(), CoreError> {
        Self::new(
            self.operation.clone(),
            self.purpose.clone(),
            self.signature_profile.clone(),
        )
        .map(|_| ())
    }
}

/// Public, non-secret context that a restricted provider binds to one key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SigningKeyScope {
    identity: String,
    agent_version: String,
    canonical_key_id: String,
    algorithm: SigningAlgorithm,
    public_key_hash: String,
    authorized_purposes: BTreeSet<SigningPurpose>,
    #[serde(default)]
    authorized_profile_bindings: BTreeSet<SigningProfileBindingV1>,
    purpose_isolation_assurance: PurposeIsolationAssurance,
}

/// Compatibility alias for integrations that call the same public value a
/// signing-key context.
pub type SigningKeyContext = SigningKeyScope;

impl SigningKeyScope {
    /// Construct a scope from trusted identity/key history and the public key.
    ///
    /// The canonical key ID and public-key hash are derived here; a caller
    /// cannot provide inconsistent aliases for the same public key.
    pub fn from_public_key(
        identity: impl Into<String>,
        agent_version: impl Into<String>,
        algorithm: SigningAlgorithm,
        public_key: &[u8],
        authorized_purposes: impl IntoIterator<Item = SigningPurpose>,
        purpose_isolation_assurance: PurposeIsolationAssurance,
    ) -> Result<Self, CoreError> {
        let authorized_purposes = authorized_purposes.into_iter().collect::<BTreeSet<_>>();
        let mut bindings = BTreeSet::new();
        if authorized_purposes.contains(&SigningPurpose::Document) {
            bindings.insert(SigningProfileBindingV1::new(
                SigningOperation::SignDocument,
                SigningPurpose::Document,
                DOCUMENT_V2_SIGNATURE_PROFILE,
            )?);
        }
        if authorized_purposes.contains(&SigningPurpose::LegacyRaw) {
            bindings.insert(SigningProfileBindingV1::new(
                SigningOperation::LegacyRawSign,
                SigningPurpose::LegacyRaw,
                "jacs-legacy-raw-v1",
            )?);
        }
        Self::from_public_key_with_bindings(
            identity,
            agent_version,
            algorithm,
            public_key,
            authorized_purposes,
            bindings,
            purpose_isolation_assurance,
        )
    }

    /// Construct a scope from authenticated lifecycle purposes and exact
    /// profile-registry binding projections.
    #[allow(clippy::too_many_arguments)]
    pub fn from_public_key_with_bindings(
        identity: impl Into<String>,
        agent_version: impl Into<String>,
        algorithm: SigningAlgorithm,
        public_key: &[u8],
        authorized_purposes: impl IntoIterator<Item = SigningPurpose>,
        authorized_profile_bindings: impl IntoIterator<Item = SigningProfileBindingV1>,
        purpose_isolation_assurance: PurposeIsolationAssurance,
    ) -> Result<Self, CoreError> {
        let scope = Self {
            identity: identity.into(),
            agent_version: agent_version.into(),
            canonical_key_id: crate::identity::canonical_key_id(algorithm.as_str(), public_key)?,
            algorithm,
            public_key_hash: sha256_hex(public_key),
            authorized_purposes: authorized_purposes.into_iter().collect(),
            authorized_profile_bindings: authorized_profile_bindings.into_iter().collect(),
            purpose_isolation_assurance,
        };
        scope.validate_public_key(public_key)?;
        scope.validate_assurance()?;
        Ok(scope)
    }

    pub fn identity(&self) -> &str {
        &self.identity
    }

    pub fn agent_version(&self) -> &str {
        &self.agent_version
    }

    pub fn canonical_key_id(&self) -> &str {
        &self.canonical_key_id
    }

    pub fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    pub fn public_key_hash(&self) -> &str {
        &self.public_key_hash
    }

    pub fn authorized_purposes(&self) -> &BTreeSet<SigningPurpose> {
        &self.authorized_purposes
    }

    pub fn authorized_profile_bindings(&self) -> &BTreeSet<SigningProfileBindingV1> {
        &self.authorized_profile_bindings
    }

    pub fn purpose_isolation_assurance(&self) -> PurposeIsolationAssurance {
        self.purpose_isolation_assurance
    }

    /// Enforce both the operation mapping and this key's immutable purpose set.
    pub fn authorize(
        &self,
        operation: &SigningOperation,
        purpose: &SigningPurpose,
    ) -> Result<(), CoreError> {
        operation.validate()?;
        purpose.validate()?;
        if !operation.accepts_purpose(purpose) {
            return Err(CoreError::MalformedDocument(format!(
                "operation '{}' does not accept purpose '{}'",
                operation, purpose
            )));
        }
        if !self.authorized_purposes.contains(purpose) {
            return Err(CoreError::MalformedKey(format!(
                "key '{}' is not authorized for purpose '{}'",
                self.canonical_key_id, purpose
            )));
        }
        Ok(())
    }

    /// Enforce the exact semantic profile selected for this key in addition
    /// to the operation-to-purpose mapping.
    pub fn authorize_profile(
        &self,
        operation: &SigningOperation,
        purpose: &SigningPurpose,
        signature_profile: &str,
    ) -> Result<(), CoreError> {
        self.authorize(operation, purpose)?;
        let binding =
            SigningProfileBindingV1::new(operation.clone(), purpose.clone(), signature_profile)?;
        if !self.authorized_profile_bindings.contains(&binding) {
            return Err(CoreError::MalformedKey(format!(
                "key '{}' is not bound to operation '{}', purpose '{}', profile '{}'",
                self.canonical_key_id, operation, purpose, signature_profile
            )));
        }
        Ok(())
    }

    /// Recompute every public-key-derived identifier.
    pub fn validate_public_key(&self, public_key: &[u8]) -> Result<(), CoreError> {
        if self.identity.trim().is_empty() || self.agent_version.trim().is_empty() {
            return Err(CoreError::MalformedKey(
                "signing scope identity and agent version must be nonempty".into(),
            ));
        }
        let expected_key_id =
            crate::identity::canonical_key_id(self.algorithm.as_str(), public_key)?;
        if self.canonical_key_id != expected_key_id {
            return Err(CoreError::MalformedKey(format!(
                "canonical key ID mismatch: expected '{expected_key_id}', got '{}'",
                self.canonical_key_id
            )));
        }
        let expected_hash = sha256_hex(public_key);
        if self.public_key_hash != expected_hash {
            return Err(CoreError::MalformedKey(format!(
                "public-key hash mismatch: expected '{expected_hash}', got '{}'",
                self.public_key_hash
            )));
        }
        Ok(())
    }

    fn validate_assurance(&self) -> Result<(), CoreError> {
        for purpose in &self.authorized_purposes {
            purpose.validate()?;
        }
        for binding in &self.authorized_profile_bindings {
            binding.validate()?;
            if !self.authorized_purposes.contains(binding.purpose()) {
                return Err(CoreError::MalformedKey(format!(
                    "profile binding purpose '{}' is absent from the key purpose set",
                    binding.purpose()
                )));
            }
        }
        let purpose_count = self.authorized_purposes.len();
        let has_raw = self
            .authorized_purposes
            .contains(&SigningPurpose::LegacyRaw);
        let valid = match self.purpose_isolation_assurance {
            PurposeIsolationAssurance::SharedRawCapable => has_raw && purpose_count > 1,
            PurposeIsolationAssurance::ClosedMultiPurposeSharedKey => !has_raw && purpose_count > 1,
            PurposeIsolationAssurance::SeparatePurposeKey => purpose_count == 1,
            PurposeIsolationAssurance::NotApplicable => purpose_count == 0,
        };
        if !valid {
            return Err(CoreError::MalformedKey(format!(
                "purpose set is inconsistent with purpose-isolation assurance {:?}",
                self.purpose_isolation_assurance
            )));
        }
        Ok(())
    }
}

/// Values frozen into the JACS v2 signature metadata before approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SignatureMetadataV2 {
    pub date: String,
    pub iat: i64,
    pub jti: String,
}

impl SignatureMetadataV2 {
    /// Generate timestamp and identifier once, at preparation time.
    pub fn now() -> Self {
        let now = chrono::Utc::now();
        Self {
            date: now.to_rfc3339(),
            iat: now.timestamp(),
            jti: uuid::Uuid::now_v7().to_string(),
        }
    }

    fn validate(&self) -> Result<(), CoreError> {
        let parsed = chrono::DateTime::parse_from_rfc3339(&self.date).map_err(|e| {
            CoreError::MalformedDocument(format!("signature date is not RFC3339: {e}"))
        })?;
        if parsed.timestamp() != self.iat {
            return Err(CoreError::MalformedDocument(
                "signature date and iat identify different UTC seconds".into(),
            ));
        }
        if self.jti.trim().is_empty() {
            return Err(CoreError::MalformedDocument(
                "signature jti must be nonempty".into(),
            ));
        }
        Ok(())
    }
}

/// Header values generated once when a native-compatible message is prepared.
///
/// Native JACS creation assigns a document UUID, a version UUID, and matching
/// creation/version timestamps before signing.  Keeping those values in this
/// portable type lets an approval service freeze them before WebAuthn instead
/// of allowing the final signing call to silently generate replacements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NativeMessageHeaderV1 {
    jacs_id: String,
    jacs_version: String,
    jacs_version_date: String,
    jacs_original_version: String,
    jacs_original_date: String,
}

/// General name for the same frozen native creation header. The original
/// `NativeMessageHeaderV1` name remains source-compatible for early adopters.
pub type NativeDocumentHeaderV1 = NativeMessageHeaderV1;

impl NativeMessageHeaderV1 {
    /// Generate the complete native message header once, including its ID.
    pub fn now() -> Self {
        let now = Utc::now().to_rfc3339();
        let version = uuid::Uuid::new_v4().to_string();
        Self {
            jacs_id: uuid::Uuid::new_v4().to_string(),
            jacs_version: version.clone(),
            jacs_version_date: now.clone(),
            jacs_original_version: version,
            jacs_original_date: now,
        }
    }

    /// Generate the native version/timestamp fields while using an
    /// authoritative operation UUID as the JACS document ID.
    pub fn now_with_id(jacs_id: impl Into<String>) -> Result<Self, CoreError> {
        let now = Utc::now().to_rfc3339();
        let version = uuid::Uuid::new_v4().to_string();
        Self::from_parts(jacs_id, version.clone(), now.clone(), version, now)
    }

    /// Rehydrate explicitly frozen header values at a persistence boundary.
    pub fn from_parts(
        jacs_id: impl Into<String>,
        jacs_version: impl Into<String>,
        jacs_version_date: impl Into<String>,
        jacs_original_version: impl Into<String>,
        jacs_original_date: impl Into<String>,
    ) -> Result<Self, CoreError> {
        let header = Self {
            jacs_id: jacs_id.into(),
            jacs_version: jacs_version.into(),
            jacs_version_date: jacs_version_date.into(),
            jacs_original_version: jacs_original_version.into(),
            jacs_original_date: jacs_original_date.into(),
        };
        header.validate()?;
        Ok(header)
    }

    pub fn jacs_id(&self) -> &str {
        &self.jacs_id
    }

    pub fn jacs_version(&self) -> &str {
        &self.jacs_version
    }

    pub fn jacs_version_date(&self) -> &str {
        &self.jacs_version_date
    }

    pub fn jacs_original_version(&self) -> &str {
        &self.jacs_original_version
    }

    pub fn jacs_original_date(&self) -> &str {
        &self.jacs_original_date
    }

    fn validate(&self) -> Result<(), CoreError> {
        for (field, value) in [
            ("jacsId", &self.jacs_id),
            ("jacsVersion", &self.jacs_version),
            ("jacsOriginalVersion", &self.jacs_original_version),
        ] {
            uuid::Uuid::parse_str(value).map_err(|_| {
                CoreError::MalformedDocument(format!(
                    "native message header '{field}' must be a UUID"
                ))
            })?;
        }
        for (field, value) in [
            ("jacsVersionDate", &self.jacs_version_date),
            ("jacsOriginalDate", &self.jacs_original_date),
        ] {
            DateTime::parse_from_rfc3339(value).map_err(|error| {
                CoreError::MalformedDocument(format!(
                    "native message header '{field}' is not RFC3339: {error}"
                ))
            })?;
        }
        if self.jacs_version != self.jacs_original_version
            || self.jacs_version_date != self.jacs_original_date
        {
            return Err(CoreError::MalformedDocument(
                "new native message version/original header values must match".into(),
            ));
        }
        Ok(())
    }

    fn into_document(self, content: &Value) -> Value {
        json!({
            "$schema": HEADER_V1_SCHEMA_ID,
            "jacsId": self.jacs_id,
            "jacsVersion": self.jacs_version,
            "jacsVersionDate": self.jacs_version_date,
            "jacsOriginalVersion": self.jacs_original_version,
            "jacsOriginalDate": self.jacs_original_date,
            "jacsType": "message",
            "jacsLevel": "raw",
            "content": content,
        })
    }

    fn into_artifact_document(self, source: &Value) -> Result<Value, CoreError> {
        let mut document = source.as_object().cloned().ok_or_else(|| {
            CoreError::MalformedDocument("native artifact source must be a JSON object".into())
        })?;
        if document.contains_key("$schema") {
            return Err(CoreError::MalformedDocument(format!(
                "native artifact source must not supply reserved header field '$schema'"
            )));
        }
        if let Some(field) = document.keys().find(|field| {
            field.starts_with("jacs")
                && !matches!(field.as_str(), "jacsLevel" | "jacsType" | "jacsVisibility")
        }) {
            return Err(CoreError::MalformedDocument(format!(
                "native artifact source must not supply reserved header field '{field}'"
            )));
        }
        if document
            .get("jacsLevel")
            .is_some_and(|value| value.as_str() != Some("artifact"))
        {
            return Err(CoreError::MalformedDocument(
                "native artifact source must use jacsLevel=artifact when supplied".into(),
            ));
        }
        if document
            .get("jacsType")
            .is_some_and(|value| value.as_str() != Some("artifact"))
        {
            return Err(CoreError::MalformedDocument(
                "native artifact source must use jacsType=artifact when supplied".into(),
            ));
        }
        document.insert("$schema".into(), Value::String(HEADER_V1_SCHEMA_ID.into()));
        document.insert("jacsId".into(), Value::String(self.jacs_id));
        document.insert("jacsVersion".into(), Value::String(self.jacs_version));
        document.insert(
            "jacsVersionDate".into(),
            Value::String(self.jacs_version_date),
        );
        document.insert(
            "jacsOriginalVersion".into(),
            Value::String(self.jacs_original_version),
        );
        document.insert(
            "jacsOriginalDate".into(),
            Value::String(self.jacs_original_date),
        );
        document.insert("jacsType".into(), Value::String("artifact".into()));
        document.insert("jacsLevel".into(), Value::String("artifact".into()));
        Ok(Value::Object(document))
    }
}

/// Image formats supported by the existing JACS media claim wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MediaClaimFormatV1 {
    Png,
    Jpeg,
    Webp,
}

/// Exact content canonicalization declared by a media claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MediaCanonicalizationV1 {
    #[serde(rename = "jacs-media-v1")]
    Standard,
    #[serde(rename = "jacs-media-v1-robust")]
    Robust,
}

/// Actual channel into which the signed envelope will be embedded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MediaEmbeddingChannelV1 {
    Metadata,
    Lsb,
}

/// Closed, wire-compatible media claim signed by the current JACS image flow.
///
/// Construction is limited to standard metadata embedding or robust LSB
/// embedding. Hash fields are exact 32-byte base64url values; the native
/// adapter computes them with `jacs-media` rather than trusting caller input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MediaClaimV1 {
    media_signature_version: u8,
    format: MediaClaimFormatV1,
    canonicalization: MediaCanonicalizationV1,
    hash_algorithm: String,
    content_hash: String,
    public_key_hash: String,
    embedding_channels: Vec<MediaEmbeddingChannelV1>,
    robust: bool,
    pixel_hash: Option<String>,
}

impl MediaClaimV1 {
    /// Construct a metadata-only claim from hashes computed by `jacs-media`.
    pub fn standard(
        format: MediaClaimFormatV1,
        content_hash_base64url: impl Into<String>,
        public_key_hash: impl Into<String>,
    ) -> Result<Self, CoreError> {
        let claim = Self {
            media_signature_version: 1,
            format,
            canonicalization: MediaCanonicalizationV1::Standard,
            hash_algorithm: "sha256".into(),
            content_hash: content_hash_base64url.into(),
            public_key_hash: public_key_hash.into(),
            embedding_channels: vec![MediaEmbeddingChannelV1::Metadata],
            robust: false,
            pixel_hash: None,
        };
        claim.validate()?;
        Ok(claim)
    }

    /// Construct a robust LSB claim from hashes computed by `jacs-media`.
    pub fn robust(
        format: MediaClaimFormatV1,
        content_hash_base64url: impl Into<String>,
        public_key_hash: impl Into<String>,
        pixel_hash: impl Into<String>,
    ) -> Result<Self, CoreError> {
        let claim = Self {
            media_signature_version: 1,
            format,
            canonicalization: MediaCanonicalizationV1::Robust,
            hash_algorithm: "sha256".into(),
            content_hash: content_hash_base64url.into(),
            public_key_hash: public_key_hash.into(),
            embedding_channels: vec![MediaEmbeddingChannelV1::Lsb],
            robust: true,
            pixel_hash: Some(pixel_hash.into()),
        };
        claim.validate()?;
        Ok(claim)
    }

    pub fn format(&self) -> MediaClaimFormatV1 {
        self.format
    }

    pub fn canonicalization(&self) -> MediaCanonicalizationV1 {
        self.canonicalization
    }

    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }

    pub fn public_key_hash(&self) -> &str {
        &self.public_key_hash
    }

    pub fn signature_profile(&self) -> &'static str {
        match self.canonicalization {
            MediaCanonicalizationV1::Standard => MEDIA_V1_SIGNATURE_PROFILE,
            MediaCanonicalizationV1::Robust => MEDIA_V1_ROBUST_SIGNATURE_PROFILE,
        }
    }

    pub fn to_value(&self) -> Result<Value, CoreError> {
        serde_json::to_value(self).map_err(|error| {
            CoreError::MalformedDocument(format!("media claim serialization failed: {error}"))
        })
    }

    fn validate(&self) -> Result<(), CoreError> {
        if self.media_signature_version != 1 || self.hash_algorithm != "sha256" {
            return Err(CoreError::MalformedDocument(
                "media claim requires version 1 and sha256".into(),
            ));
        }
        validate_sha256_base64url(&self.content_hash, "contentHash", false)?;
        validate_sha256_base64url(&self.public_key_hash, "publicKeyHash", true)?;
        match self.canonicalization {
            MediaCanonicalizationV1::Standard
                if !self.robust
                    && self.embedding_channels == [MediaEmbeddingChannelV1::Metadata]
                    && self.pixel_hash.is_none() => {}
            MediaCanonicalizationV1::Robust
                if self.robust
                    && self.embedding_channels == [MediaEmbeddingChannelV1::Lsb]
                    && self.pixel_hash.is_some()
                    && self.format != MediaClaimFormatV1::Webp =>
            {
                validate_sha256_base64url(
                    self.pixel_hash.as_deref().expect("guarded above"),
                    "pixelHash",
                    true,
                )?;
            }
            _ => {
                return Err(CoreError::MalformedDocument(
                    "media canonicalization, robust flag, format, channels, and pixel hash are inconsistent"
                        .into(),
                ));
            }
        }
        Ok(())
    }
}

/// Whether a failed bounded signing call is known to have avoided private-key
/// use.  Once dispatch begins, an error is deliberately reported as
/// `key_use_may_have_occurred`; callers must not infer that a failed primitive
/// left the nonce or authorization reusable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparedSigningFailurePhase {
    BeforeKeyUse,
    KeyUseMayHaveOccurred,
}

/// Successful bounded prepared signing with an observation taken immediately
/// before dispatch to the private-key primitive.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PreparedSigningOutcome {
    pub envelope: Value,
    pub key_use_began_at: DateTime<Utc>,
}

/// Failure from a prepared signing operation with conservative key-use state.
#[derive(Debug)]
pub struct PreparedSigningError {
    phase: PreparedSigningFailurePhase,
    key_use_began_at: Option<DateTime<Utc>>,
    source: CoreError,
}

impl PreparedSigningError {
    /// Wrap setup/validation failure for which the private primitive was not
    /// dispatched.  Native adapters use this when local keystore unlock fails.
    pub fn before_key_use(source: CoreError) -> Self {
        Self {
            phase: PreparedSigningFailurePhase::BeforeKeyUse,
            key_use_began_at: None,
            source,
        }
    }

    fn after_key_use_dispatch(source: CoreError, began_at: DateTime<Utc>) -> Self {
        Self {
            phase: PreparedSigningFailurePhase::KeyUseMayHaveOccurred,
            key_use_began_at: Some(began_at),
            source,
        }
    }

    pub fn phase(&self) -> PreparedSigningFailurePhase {
        self.phase
    }

    pub fn key_use_began_at(&self) -> Option<DateTime<Utc>> {
        self.key_use_began_at
    }

    pub fn core_error(&self) -> &CoreError {
        &self.source
    }

    pub fn into_core_error(self) -> CoreError {
        self.source
    }
}

impl std::fmt::Display for PreparedSigningError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "prepared signing failed in phase {:?}: {}",
            self.phase, self.source
        )
    }
}

impl std::error::Error for PreparedSigningError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Frozen unsigned JACS v2 envelope plus the exact bytes that must be signed.
///
/// Fields are private so in-process callers cannot mutate a prepared value.
/// Serialized values are treated as untrusted and revalidated before signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PreparedDocumentV2 {
    profile: String,
    operation: SigningOperation,
    purpose: SigningPurpose,
    identity: String,
    agent_version: String,
    canonical_key_id: String,
    algorithm: SigningAlgorithm,
    public_key_hash: String,
    wire_profile: String,
    profile_entry: SecurityProfileEntry,
    signing_request_context: SigningRequestContextV1,
    signing_request_context_digest: String,
    placement_key: String,
    envelope: Value,
    #[serde(with = "base64_bytes")]
    signature_input: Vec<u8>,
    signature_input_digest: String,
}

impl PreparedDocumentV2 {
    pub fn operation(&self) -> &SigningOperation {
        &self.operation
    }

    pub fn purpose(&self) -> &SigningPurpose {
        &self.purpose
    }

    pub fn identity(&self) -> &str {
        &self.identity
    }

    pub fn canonical_key_id(&self) -> &str {
        &self.canonical_key_id
    }

    pub fn signature_profile(&self) -> &str {
        self.signing_request_context.signature_profile()
    }

    pub fn profile_entry(&self) -> &SecurityProfileEntry {
        &self.profile_entry
    }

    pub fn signing_request_context(&self) -> &SigningRequestContextV1 {
        &self.signing_request_context
    }

    pub fn signing_request_context_digest(&self) -> &str {
        &self.signing_request_context_digest
    }

    /// Exact final signature-input bytes.  Approval flows hash these bytes;
    /// they must store this value alongside the frozen envelope.
    pub fn signature_input(&self) -> &[u8] {
        &self.signature_input
    }

    /// Domain-separated digest of [`Self::signature_input`].
    pub fn signature_input_digest(&self) -> &str {
        &self.signature_input_digest
    }

    /// The complete envelope with an empty signature value.  Finalization
    /// fills that value and derives `jacsSha256`; neither step changes the
    /// signature input returned above.
    pub fn unsigned_envelope(&self) -> &Value {
        &self.envelope
    }

    /// Recompute the exact signature input and all operation/key bindings.
    pub fn validate(&self, scope: &SigningKeyScope, public_key: &[u8]) -> Result<(), CoreError> {
        scope.validate_public_key(public_key)?;
        scope.validate_profile_entry(&self.profile_entry)?;

        if &self.operation != &self.profile_entry.operation
            || &self.purpose != &self.profile_entry.purpose
            || &self.operation != self.signing_request_context.operation()
            || &self.purpose != self.signing_request_context.purpose()
        {
            return Err(CoreError::MalformedDocument(
                "prepared operation/purpose differs from its registry/context binding".into(),
            ));
        }

        let closed_profile = self.profile_entry.signature_family_id
            == crate::verification_registry::SignatureFamilyId::SignatureV2
            && self.profile_entry.wire_rule_id
                == crate::verification_registry::WireRuleId::DocumentV2
            && self.operation == SigningOperation::SignDocument
            && self.purpose == SigningPurpose::Document
            && self.wire_profile == DOCUMENT_V2_SIGNATURE_PROFILE;
        if self.profile != PREPARED_DOCUMENT_V2_PROFILE
            || !closed_profile
            || self.placement_key != DOCUMENT_V2_PLACEMENT_KEY
        {
            return Err(CoreError::MalformedDocument(
                "prepared document does not use a closed operation/purpose/signature profile"
                    .into(),
            ));
        }
        if self.identity != scope.identity
            || self.agent_version != scope.agent_version
            || self.canonical_key_id != scope.canonical_key_id
            || self.algorithm != scope.algorithm
            || self.public_key_hash != scope.public_key_hash
        {
            return Err(CoreError::MalformedDocument(
                "prepared document signing identity/key does not match the provider".into(),
            ));
        }

        let envelope = self.envelope.as_object().ok_or_else(|| {
            CoreError::MalformedDocument("prepared envelope must be a JSON object".into())
        })?;
        if envelope.contains_key("jacsSha256") {
            return Err(CoreError::MalformedDocument(
                "prepared unsigned envelope must not contain a precomputed jacsSha256".into(),
            ));
        }
        let signature_metadata = envelope
            .get(DOCUMENT_V2_PLACEMENT_KEY)
            .and_then(Value::as_object)
            .ok_or_else(|| {
                CoreError::MalformedDocument(
                    "prepared envelope must contain a jacsSignature object".into(),
                )
            })?;
        if signature_metadata.get("signature") != Some(&Value::String(String::new())) {
            return Err(CoreError::MalformedDocument(
                "prepared envelope signature must be the empty string".into(),
            ));
        }

        let fields = signature_metadata
            .get("fields")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                CoreError::MalformedDocument("prepared signature fields must be an array".into())
            })?
            .iter()
            .map(|value| {
                value.as_str().map(str::to_owned).ok_or_else(|| {
                    CoreError::MalformedDocument(
                        "prepared signature fields must contain only strings".into(),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if fields != default_signed_fields(&self.envelope, DOCUMENT_V2_PLACEMENT_KEY) {
            return Err(CoreError::MalformedDocument(
                "prepared signature fields do not equal the complete sorted document field set"
                    .into(),
            ));
        }

        let metadata = SignatureMetadataV2 {
            date: required_metadata_string(signature_metadata, "date")?,
            iat: signature_metadata
                .get("iat")
                .and_then(Value::as_i64)
                .ok_or_else(|| {
                    CoreError::MalformedDocument("prepared signature iat must be an integer".into())
                })?,
            jti: required_metadata_string(signature_metadata, "jti")?,
        };
        metadata.validate()?;
        let expected_metadata = build_signature_metadata(
            &scope.identity,
            &scope.agent_version,
            &metadata.date,
            metadata.iat,
            &metadata.jti,
            scope.algorithm,
            &scope.public_key_hash,
            &fields,
        );
        if Value::Object(signature_metadata.clone()) != expected_metadata {
            return Err(CoreError::MalformedDocument(
                "prepared signature metadata contains changed or unknown fields".into(),
            ));
        }

        let canonical = build_signature_content_v2(
            &self.envelope,
            &fields,
            DOCUMENT_V2_PLACEMENT_KEY,
            &expected_metadata,
        )?;
        if canonical.as_bytes() != self.signature_input {
            return Err(CoreError::MalformedDocument(
                "prepared envelope no longer reconstructs the frozen signature input".into(),
            ));
        }
        let expected_digest =
            labeled_digest(HAI_SIGNATURE_INPUT_DIGEST_DOMAIN, canonical.as_bytes());
        if self.signature_input_digest != expected_digest {
            return Err(CoreError::MalformedDocument(format!(
                "prepared signature-input digest mismatch: expected '{expected_digest}', got '{}'",
                self.signature_input_digest
            )));
        }
        self.signing_request_context
            .validate(scope, &self.profile_entry, &self.signature_input)?;
        let expected_context_digest = self.signing_request_context.digest()?;
        if self.signing_request_context_digest != expected_context_digest {
            return Err(CoreError::MalformedDocument(format!(
                "signing request context digest mismatch: expected '{expected_context_digest}', got '{}'",
                self.signing_request_context_digest
            )));
        }
        validate_native_header_if_declared(&self.envelope)?;
        Ok(())
    }

    /// Validate the complete prepared value and its exact TP-29 digest against
    /// an independently authenticated authorization record.
    pub fn validate_authorized_context(
        &self,
        scope: &SigningKeyScope,
        public_key: &[u8],
        expected_context_digest: &str,
    ) -> Result<(), CoreError> {
        self.validate(scope, public_key)?;
        crate::identity::validate_digest(expected_context_digest)?;
        if self.signing_request_context_digest != expected_context_digest {
            return Err(CoreError::MalformedDocument(
                "prepared signing context does not equal the authorized context digest".into(),
            ));
        }
        Ok(())
    }

    /// Insert a detached signature after cryptographically verifying it over
    /// the frozen bytes, then verify the completed JACS envelope again.
    pub fn complete_with_signature(
        mut self,
        scope: &SigningKeyScope,
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<Value, CoreError> {
        self.validate(scope, public_key)?;
        verify_detached(
            scope.algorithm,
            public_key,
            &self.signature_input,
            signature,
        )?;

        let signature_object = self
            .envelope
            .get_mut(DOCUMENT_V2_PLACEMENT_KEY)
            .and_then(Value::as_object_mut)
            .ok_or_else(|| {
                CoreError::MalformedDocument(
                    "prepared envelope lost its jacsSignature object".into(),
                )
            })?;
        signature_object.insert(
            "signature".into(),
            Value::String(STANDARD.encode(signature)),
        );

        let outcome = verify_document(
            &self.envelope,
            public_key,
            scope.algorithm,
            DOCUMENT_V2_PLACEMENT_KEY,
        )?;
        if !outcome.valid {
            return Err(CoreError::SignatureInvalid(outcome.errors.join("; ")));
        }

        // Native JACS computes this compatibility checksum only after the
        // signature exists.  It is excluded from the signature field set, so
        // deriving it here cannot change the approved signature input.
        let checksum = document_hash_v1(&self.envelope)?;
        self.envelope
            .as_object_mut()
            .expect("prepared envelope object was validated")
            .insert("jacsSha256".into(), Value::String(checksum));
        validate_native_header_if_declared(&self.envelope)?;
        let final_outcome = verify_document(
            &self.envelope,
            public_key,
            scope.algorithm,
            DOCUMENT_V2_PLACEMENT_KEY,
        )?;
        if !final_outcome.valid {
            return Err(CoreError::SignatureInvalid(final_outcome.errors.join("; ")));
        }
        Ok(self.envelope)
    }
}

/// One frozen generic JACS document signature and the separate authenticated
/// authority edge that classifies it as a more specific managed operation.
///
/// Keeping both values in one closed serialized object prevents a staging row
/// from pairing an approved TP-31 context with different signature-input
/// bytes. It does not change the primary document's signature family, wire
/// profile, or operation interpretation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthorityClassifiedPreparedDocumentV1 {
    profile: String,
    prepared_document: PreparedDocumentV2,
    authority_classification: AuthoritySigningClassificationV1,
}

impl AuthorityClassifiedPreparedDocumentV1 {
    pub fn prepare(
        scope: &SigningKeyScope,
        public_key: &[u8],
        prepared_document: PreparedDocumentV2,
        authority_selection: SigningContextSelectionV1,
    ) -> Result<Self, CoreError> {
        let authority_classification =
            AuthoritySigningClassificationV1::build_for_prepared_document(
                scope,
                public_key,
                &prepared_document,
                authority_selection,
            )?;
        Ok(Self {
            profile: AUTHORITY_CLASSIFIED_PREPARED_DOCUMENT_V1_PROFILE.into(),
            prepared_document,
            authority_classification,
        })
    }

    pub fn prepared_document(&self) -> &PreparedDocumentV2 {
        &self.prepared_document
    }

    pub fn authority_classification(&self) -> &AuthoritySigningClassificationV1 {
        &self.authority_classification
    }

    pub fn signature_input(&self) -> &[u8] {
        self.prepared_document.signature_input()
    }

    pub fn signature_input_digest(&self) -> &str {
        self.prepared_document.signature_input_digest()
    }

    pub fn authority_signing_request_context_digest(&self) -> &str {
        self.authority_classification
            .authority_signing_request_context_digest()
    }

    pub fn validate_authorized(
        &self,
        scope: &SigningKeyScope,
        public_key: &[u8],
        expected_authority_context_digest: &str,
    ) -> Result<(), CoreError> {
        if self.profile != AUTHORITY_CLASSIFIED_PREPARED_DOCUMENT_V1_PROFILE {
            return Err(CoreError::MalformedDocument(
                "authority-classified prepared document profile mismatch".into(),
            ));
        }
        self.authority_classification.validate_authorized(
            scope,
            public_key,
            &self.prepared_document,
            expected_authority_context_digest,
        )
    }

    pub fn into_prepared_document(
        self,
        scope: &SigningKeyScope,
        public_key: &[u8],
        expected_authority_context_digest: &str,
    ) -> Result<PreparedDocumentV2, CoreError> {
        self.validate_authorized(scope, public_key, expected_authority_context_digest)?;
        Ok(self.prepared_document)
    }
}

/// Freeze a complete unsigned document under the `SignDocument/document`
/// JACS-v2 rule.  The document must not already contain `jacsSignature`.
pub fn prepare_document_v2(
    scope: &SigningKeyScope,
    document: &Value,
    metadata: SignatureMetadataV2,
) -> Result<PreparedDocumentV2, CoreError> {
    let selection = local_document_v2_selection(scope.algorithm())?;
    prepare_document_v2_for_context(scope, document, metadata, selection)
}

/// Freeze document-v2 bytes under an authenticated semantic profile and the
/// caller-owned, typed TP-29 operation context.
pub fn prepare_document_v2_for_context(
    scope: &SigningKeyScope,
    document: &Value,
    metadata: SignatureMetadataV2,
    selection: SigningContextSelectionV1,
) -> Result<PreparedDocumentV2, CoreError> {
    prepare_profiled_document_v2(scope, document, metadata, selection)
}

fn prepare_profiled_document_v2(
    scope: &SigningKeyScope,
    document: &Value,
    metadata: SignatureMetadataV2,
    selection: SigningContextSelectionV1,
) -> Result<PreparedDocumentV2, CoreError> {
    let profile_entry = selection.profile_entry().clone();
    scope.validate_profile_entry(&profile_entry)?;
    scope.validate_assurance()?;
    metadata.validate()?;

    let mut envelope = document.clone();
    let envelope_object = envelope.as_object_mut().ok_or_else(|| {
        CoreError::MalformedDocument("document-v2 input must be a JSON object".into())
    })?;
    if envelope_object.contains_key(DOCUMENT_V2_PLACEMENT_KEY) {
        return Err(CoreError::MalformedDocument(
            "document-v2 input already contains jacsSignature".into(),
        ));
    }
    if envelope_object.contains_key("jacsSha256") {
        return Err(CoreError::MalformedDocument(
            "document-v2 input must not contain a precomputed jacsSha256".into(),
        ));
    }
    validate_native_header_if_declared(&envelope)?;

    let fields = default_signed_fields(&envelope, DOCUMENT_V2_PLACEMENT_KEY);
    let signature_metadata = build_signature_metadata(
        &scope.identity,
        &scope.agent_version,
        &metadata.date,
        metadata.iat,
        &metadata.jti,
        scope.algorithm,
        &scope.public_key_hash,
        &fields,
    );
    envelope
        .as_object_mut()
        .expect("envelope object checked above")
        .insert(DOCUMENT_V2_PLACEMENT_KEY.into(), signature_metadata.clone());

    let signature_input = build_signature_content_v2(
        &envelope,
        &fields,
        DOCUMENT_V2_PLACEMENT_KEY,
        &signature_metadata,
    )?
    .into_bytes();
    let signature_input_digest =
        labeled_digest(HAI_SIGNATURE_INPUT_DIGEST_DOMAIN, &signature_input);
    let signing_request_context =
        SigningRequestContextV1::build_for_prepared_document(scope, &selection, &signature_input)?;
    let signing_request_context_digest = signing_request_context.digest()?;
    let prepared = PreparedDocumentV2 {
        profile: PREPARED_DOCUMENT_V2_PROFILE.into(),
        operation: profile_entry.operation.clone(),
        purpose: profile_entry.purpose.clone(),
        identity: scope.identity.clone(),
        agent_version: scope.agent_version.clone(),
        canonical_key_id: scope.canonical_key_id.clone(),
        algorithm: scope.algorithm,
        public_key_hash: scope.public_key_hash.clone(),
        wire_profile: DOCUMENT_V2_SIGNATURE_PROFILE.into(),
        profile_entry,
        signing_request_context,
        signing_request_context_digest,
        placement_key: DOCUMENT_V2_PLACEMENT_KEY.into(),
        envelope,
        signature_input,
        signature_input_digest,
    };
    Ok(prepared)
}

/// Freeze a full native-compatible message envelope with fresh header values.
///
/// The generated document/version UUIDs and timestamps are part of the
/// returned frozen signature input.  They are never regenerated at signing.
pub fn prepare_message_v2(
    scope: &SigningKeyScope,
    content: &Value,
    metadata: SignatureMetadataV2,
) -> Result<PreparedDocumentV2, CoreError> {
    prepare_native_message_v2(scope, content, NativeMessageHeaderV1::now(), metadata)
}

/// Freeze a native-compatible message whose `jacsId` is an authoritative
/// operation UUID while JACS generates and freezes its version/timestamps.
pub fn prepare_message_v2_with_id(
    scope: &SigningKeyScope,
    content: &Value,
    jacs_id: impl Into<String>,
    metadata: SignatureMetadataV2,
) -> Result<PreparedDocumentV2, CoreError> {
    prepare_native_message_v2(
        scope,
        content,
        NativeMessageHeaderV1::now_with_id(jacs_id)?,
        metadata,
    )
}

/// Freeze a native-compatible message from explicitly persisted header
/// values.  This is the deterministic rehydration entry point for staging
/// tables; ordinary callers should use [`prepare_message_v2_with_id`].
pub fn prepare_native_message_v2(
    scope: &SigningKeyScope,
    content: &Value,
    header: NativeMessageHeaderV1,
    metadata: SignatureMetadataV2,
) -> Result<PreparedDocumentV2, CoreError> {
    header.validate()?;
    prepare_document_v2(scope, &header.into_document(content), metadata)
}

/// Freeze an unchanged native message signature and attach its separate
/// registry-selected TP-31 authority classification candidate.
pub fn prepare_authority_classified_native_message_v2(
    scope: &SigningKeyScope,
    public_key: &[u8],
    content: &Value,
    header: NativeMessageHeaderV1,
    metadata: SignatureMetadataV2,
    authority_selection: SigningContextSelectionV1,
) -> Result<AuthorityClassifiedPreparedDocumentV1, CoreError> {
    let prepared = prepare_native_message_v2(scope, content, header, metadata)?;
    AuthorityClassifiedPreparedDocumentV1::prepare(scope, public_key, prepared, authority_selection)
}

/// Convenience preflight that freezes a caller-authoritative operation UUID
/// and freshly generated native version/timestamps exactly once.
pub fn prepare_authority_classified_message_v2_with_id(
    scope: &SigningKeyScope,
    public_key: &[u8],
    content: &Value,
    jacs_id: impl Into<String>,
    metadata: SignatureMetadataV2,
    authority_selection: SigningContextSelectionV1,
) -> Result<AuthorityClassifiedPreparedDocumentV1, CoreError> {
    prepare_authority_classified_native_message_v2(
        scope,
        public_key,
        content,
        NativeMessageHeaderV1::now_with_id(jacs_id)?,
        metadata,
        authority_selection,
    )
}

/// Context-aware native message constructor for authority-backed named
/// operations that retain the frozen document-v2 wire.
pub fn prepare_native_message_v2_for_context(
    scope: &SigningKeyScope,
    content: &Value,
    header: NativeMessageHeaderV1,
    metadata: SignatureMetadataV2,
    selection: SigningContextSelectionV1,
) -> Result<PreparedDocumentV2, CoreError> {
    header.validate()?;
    prepare_document_v2_for_context(scope, &header.into_document(content), metadata, selection)
}

/// Context-aware message constructor using an authoritative operation UUID.
pub fn prepare_message_v2_with_id_for_context(
    scope: &SigningKeyScope,
    content: &Value,
    jacs_id: impl Into<String>,
    metadata: SignatureMetadataV2,
    selection: SigningContextSelectionV1,
) -> Result<PreparedDocumentV2, CoreError> {
    prepare_native_message_v2_for_context(
        scope,
        content,
        NativeMessageHeaderV1::now_with_id(jacs_id)?,
        metadata,
        selection,
    )
}

/// Freeze an application artifact in the root-level shape produced by native
/// `Agent::create_document_and_load`.
///
/// `source` contains application fields and may retain the existing
/// `jacsVisibility` access-control field. Exact `jacsType=artifact` and
/// `jacsLevel=artifact` values are also accepted for serializer compatibility;
/// every other caller-supplied `$schema`/`jacs*` field is rejected. JACS then
/// installs the frozen header and fixed artifact type/level before constructing
/// the signature input.
pub fn prepare_native_artifact_v2(
    scope: &SigningKeyScope,
    source: &Value,
    header: NativeMessageHeaderV1,
    metadata: SignatureMetadataV2,
) -> Result<PreparedDocumentV2, CoreError> {
    header.validate()?;
    prepare_document_v2(scope, &header.into_artifact_document(source)?, metadata)
}

/// Freeze an unchanged root-level native artifact and attach its separate
/// registry-selected TP-31 authority classification candidate.
pub fn prepare_authority_classified_native_artifact_v2(
    scope: &SigningKeyScope,
    public_key: &[u8],
    source: &Value,
    header: NativeMessageHeaderV1,
    metadata: SignatureMetadataV2,
    authority_selection: SigningContextSelectionV1,
) -> Result<AuthorityClassifiedPreparedDocumentV1, CoreError> {
    let prepared = prepare_native_artifact_v2(scope, source, header, metadata)?;
    AuthorityClassifiedPreparedDocumentV1::prepare(scope, public_key, prepared, authority_selection)
}

/// Convenience artifact preflight using an authoritative operation UUID.
pub fn prepare_authority_classified_artifact_v2_with_id(
    scope: &SigningKeyScope,
    public_key: &[u8],
    source: &Value,
    jacs_id: impl Into<String>,
    metadata: SignatureMetadataV2,
    authority_selection: SigningContextSelectionV1,
) -> Result<AuthorityClassifiedPreparedDocumentV1, CoreError> {
    prepare_authority_classified_native_artifact_v2(
        scope,
        public_key,
        source,
        NativeMessageHeaderV1::now_with_id(jacs_id)?,
        metadata,
        authority_selection,
    )
}

/// Context-aware application-artifact constructor. Header ownership and
/// compatibility field rules are identical to [`prepare_native_artifact_v2`].
pub fn prepare_native_artifact_v2_for_context(
    scope: &SigningKeyScope,
    source: &Value,
    header: NativeMessageHeaderV1,
    metadata: SignatureMetadataV2,
    selection: SigningContextSelectionV1,
) -> Result<PreparedDocumentV2, CoreError> {
    header.validate()?;
    prepare_document_v2_for_context(
        scope,
        &header.into_artifact_document(source)?,
        metadata,
        selection,
    )
}

/// Freeze the existing JACS v1 media claim in a native-compatible message.
///
/// `jacs-media` must compute the claim hashes from the actual image bytes
/// before calling this function. The closed [`MediaClaimV1`] prevents a caller
/// from changing canonicalization, robust mode, or embedding channels while
/// retaining the media signature profile. The unchanged inner JACS wire is a
/// generic `SignDocument/document` signature; a managed caller attaches the
/// separate TP-31 authority classification in `PreparedMediaV2`.
pub fn prepare_media_claim_v2(
    scope: &SigningKeyScope,
    claim: &MediaClaimV1,
    header: NativeMessageHeaderV1,
    metadata: SignatureMetadataV2,
) -> Result<PreparedDocumentV2, CoreError> {
    claim.validate()?;
    header.validate()?;
    prepare_document_v2(scope, &header.into_document(&claim.to_value()?), metadata)
}

/// One-operation signer whose private key never leaves the facade.
///
/// Every signing method consumes `self`.  Encrypted material is decrypted by
/// the existing JACS envelope reader, used for exactly one named operation,
/// then zeroized.  The caller's password is borrowed through [`UnlockSecret`]
/// and is never stored in the provider.
pub struct RestrictedSigningProvider {
    scope: SigningKeyScope,
    agent: CoreAgent,
}

impl std::fmt::Debug for RestrictedSigningProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestrictedSigningProvider")
            .field("identity", &self.scope.identity)
            .field("canonical_key_id", &self.scope.canonical_key_id)
            .field("algorithm", &self.scope.algorithm)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl RestrictedSigningProvider {
    /// Unlock existing encrypted material for one operation.
    pub fn unlock_for_one_operation(
        material: AgentMaterial,
        secret: UnlockSecret<'_>,
        scope: SigningKeyScope,
    ) -> Result<Self, CoreError> {
        scope.validate_public_key(&material.public_key)?;
        scope.validate_assurance()?;
        let material_identity = required_agent_string(&material.agent, "jacsId")?;
        let material_version = required_agent_string(&material.agent, "jacsVersion")?;
        if material_identity != scope.identity || material_version != scope.agent_version {
            return Err(CoreError::MalformedKey(
                "encrypted material identity/version does not match signing scope".into(),
            ));
        }
        if material.algorithm != scope.algorithm {
            return Err(CoreError::AlgorithmMismatch {
                expected: scope.algorithm.to_string(),
                actual: material.algorithm.to_string(),
            });
        }
        let agent = CoreAgent::from_encrypted_material(material, secret)?;
        Ok(Self { scope, agent })
    }

    pub fn scope(&self) -> &SigningKeyScope {
        &self.scope
    }

    /// Sign a previously frozen document.  No metadata is regenerated.
    pub fn sign_prepared_document(self, prepared: PreparedDocumentV2) -> Result<Value, CoreError> {
        self.sign_prepared_document_observed(prepared, None)
            .map(|outcome| outcome.envelope)
            .map_err(PreparedSigningError::into_core_error)
    }

    /// Sign a frozen envelope only if private-key dispatch begins before an
    /// absolute UTC deadline.
    ///
    /// All envelope, schema, key, operation, purpose, and digest checks happen
    /// before the clock check.  `key_use_began_at` is captured immediately
    /// before the call to the underlying private-key primitive.  Any error
    /// after that point is conservatively classified as
    /// `key_use_may_have_occurred` so a caller cannot safely reuse a claimed
    /// nonce merely because the primitive or post-verification returned an
    /// error.
    pub fn sign_prepared_document_before(
        self,
        prepared: PreparedDocumentV2,
        deadline: DateTime<Utc>,
    ) -> Result<PreparedSigningOutcome, PreparedSigningError> {
        self.sign_prepared_document_observed(prepared, Some(deadline))
    }

    /// Validate an independently authorized TP-31 classification, then sign
    /// the exact unchanged primary JACS input before the absolute deadline.
    pub fn sign_authority_classified_document_before(
        self,
        prepared: AuthorityClassifiedPreparedDocumentV1,
        expected_authority_context_digest: &str,
        deadline: DateTime<Utc>,
    ) -> Result<PreparedSigningOutcome, PreparedSigningError> {
        let prepared_document = prepared
            .into_prepared_document(
                &self.scope,
                self.agent.public_key(),
                expected_authority_context_digest,
            )
            .map_err(PreparedSigningError::before_key_use)?;
        self.sign_prepared_document_before(prepared_document, deadline)
    }

    fn sign_prepared_document_observed(
        mut self,
        prepared: PreparedDocumentV2,
        deadline: Option<DateTime<Utc>>,
    ) -> Result<PreparedSigningOutcome, PreparedSigningError> {
        prepared
            .validate(&self.scope, self.agent.public_key())
            .map_err(PreparedSigningError::before_key_use)?;

        // This is intentionally the last work before private-key dispatch.
        let key_use_began_at = Utc::now();
        if deadline.is_some_and(|deadline| key_use_began_at >= deadline) {
            return Err(PreparedSigningError::before_key_use(
                CoreError::SignatureInvalid(
                    "prepared signing deadline elapsed before private-key use".into(),
                ),
            ));
        }

        let signature = self
            .agent
            .sign_raw_bytes(prepared.signature_input())
            .map_err(|error| {
                PreparedSigningError::after_key_use_dispatch(error, key_use_began_at)
            })?;
        let envelope = prepared
            .complete_with_signature(&self.scope, self.agent.public_key(), &signature)
            .map_err(|error| {
                PreparedSigningError::after_key_use_dispatch(error, key_use_began_at)
            })?;
        self.agent.clear_secrets();
        Ok(PreparedSigningOutcome {
            envelope,
            key_use_began_at,
        })
    }

    /// Prepare and sign one document immediately under the named document-v2
    /// operation.  Approval flows should call `prepare_document_v2` earlier and
    /// later use [`Self::sign_prepared_document`] instead.
    pub fn sign_document_v2(
        self,
        document: &Value,
        metadata: SignatureMetadataV2,
    ) -> Result<Value, CoreError> {
        let prepared = prepare_document_v2(&self.scope, document, metadata)?;
        self.sign_prepared_document(prepared)
    }

    /// Prepare and sign one compatibility message immediately.
    pub fn sign_message_v2(
        self,
        content: &Value,
        metadata: SignatureMetadataV2,
    ) -> Result<Value, CoreError> {
        let prepared = prepare_message_v2(&self.scope, content, metadata)?;
        self.sign_prepared_document(prepared)
    }

    /// Compatibility-only exact-octet signing.
    ///
    /// This operation never infers a protocol from the bytes and can run only
    /// when this key's scope explicitly contains `legacy_raw`.
    pub fn legacy_raw_sign(mut self, input: &[u8]) -> Result<LegacyRawSignature, CoreError> {
        self.scope
            .authorize(&SigningOperation::LegacyRawSign, &SigningPurpose::LegacyRaw)?;
        let signature = self.agent.sign_raw_bytes(input)?;
        let verified = CoreAgent::verify_raw_bytes_with_key(
            self.agent.public_key(),
            self.scope.algorithm,
            input,
            &signature,
        )?;
        if !verified {
            return Err(CoreError::SignatureInvalid(
                "legacy raw signature failed provider post-verification".into(),
            ));
        }
        let result = LegacyRawSignature {
            operation: SigningOperation::LegacyRawSign,
            purpose: SigningPurpose::LegacyRaw,
            identity: self.scope.identity.clone(),
            canonical_key_id: self.scope.canonical_key_id.clone(),
            algorithm: self.scope.algorithm,
            input_digest: labeled_digest(LEGACY_RAW_INPUT_DIGEST_DOMAIN, input),
            signature_digest: labeled_digest(LEGACY_RAW_SIGNATURE_DIGEST_DOMAIN, &signature),
            signature,
            purpose_isolation_assurance: self.scope.purpose_isolation_assurance,
        };
        self.agent.clear_secrets();
        Ok(result)
    }
}

impl Drop for RestrictedSigningProvider {
    fn drop(&mut self) {
        self.agent.clear_secrets();
    }
}

/// Result of the explicitly lower-assurance `LegacyRawSign` operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LegacyRawSignature {
    pub operation: SigningOperation,
    pub purpose: SigningPurpose,
    pub identity: String,
    pub canonical_key_id: String,
    pub algorithm: SigningAlgorithm,
    pub input_digest: String,
    pub signature_digest: String,
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
    pub purpose_isolation_assurance: PurposeIsolationAssurance,
}

/// Domain-separated SHA-256 used by signing approval records.
pub fn labeled_digest(label: &str, bytes: &[u8]) -> String {
    crate::identity::digest_bytes(label, bytes)
}

/// Compatibility checksum used by native JACS documents.  The checksum field
/// itself is omitted and every other field, including the signature, is
/// canonicalized before SHA-256.
pub fn document_hash_v1(document: &Value) -> Result<String, CoreError> {
    let mut unhashed = document.clone();
    let object = unhashed.as_object_mut().ok_or_else(|| {
        CoreError::MalformedDocument("JACS checksum input must be an object".into())
    })?;
    object.remove("jacsSha256");
    let canonical = crate::canonical::canonicalize_json_try(&unhashed)?;
    Ok(sha256_hex(canonical.as_bytes()))
}

fn validate_native_header_if_declared(document: &Value) -> Result<(), CoreError> {
    if document.get("$schema").and_then(Value::as_str) != Some(HEADER_V1_SCHEMA_ID) {
        return Ok(());
    }

    let mut schema_input = document.clone();
    // Signature metadata is validated against the stricter closed v2 profile
    // in `PreparedDocumentV2::validate`.  Remove it for the header pass so the
    // historical schema's narrower algorithm spelling cannot reject the
    // portable `ed25519` wire token.
    schema_input
        .as_object_mut()
        .ok_or_else(|| CoreError::SchemaInvalid("native JACS header must be an object".into()))?
        .remove(DOCUMENT_V2_PLACEMENT_KEY);
    let schema =
        crate::schema::EmbeddedSchemaResolver::resolve("schemas/header/v1/header.schema.json")?;
    let validator = jsonschema::Validator::options()
        .with_draft(jsonschema::Draft::Draft7)
        .with_retriever(crate::schema::EmbeddedSchemaResolver::new())
        .should_validate_formats(true)
        .build(&schema)
        .map_err(|error| {
            CoreError::SchemaInvalid(format!(
                "failed to compile embedded native header schema: {error}"
            ))
        })?;
    validator.validate(&schema_input).map_err(|error| {
        CoreError::SchemaInvalid(format!(
            "native header schema validation failed at '{}': {}",
            error.instance_path, error
        ))
    })
}

fn validate_profile_id(profile_id: &str) -> Result<(), CoreError> {
    if profile_id.is_empty()
        || profile_id.len() > 256
        || profile_id.trim() != profile_id
        || profile_id.contains(':')
        || profile_id.chars().any(char::is_control)
    {
        return Err(CoreError::MalformedDocument(
            "ecosystem export profile ID must be 1-256 non-control characters without ':' or surrounding whitespace"
                .into(),
        ));
    }
    Ok(())
}

fn validate_semantic_profile_id(profile_id: &str) -> Result<(), CoreError> {
    if profile_id.is_empty()
        || profile_id.len() > 256
        || profile_id.trim() != profile_id
        || profile_id.chars().any(char::is_control)
    {
        return Err(CoreError::MalformedDocument(
            "semantic signature profile must be 1-256 non-control characters without surrounding whitespace"
                .into(),
        ));
    }
    Ok(())
}

fn validate_sha256_base64url(value: &str, field: &str, prefixed: bool) -> Result<(), CoreError> {
    let encoded = if prefixed {
        value.strip_prefix("sha256-b64url:").ok_or_else(|| {
            CoreError::MalformedDocument(format!(
                "media claim '{field}' must use the sha256-b64url prefix"
            ))
        })?
    } else {
        value
    };
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|error| {
            CoreError::MalformedDocument(format!(
                "media claim '{field}' is not unpadded base64url: {error}"
            ))
        })?;
    if decoded.len() != 32
        || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&decoded) != encoded
    {
        return Err(CoreError::MalformedDocument(format!(
            "media claim '{field}' must encode exactly one canonical SHA-256 digest"
        )));
    }
    Ok(())
}

fn required_metadata_string(
    metadata: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<String, CoreError> {
    metadata
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            CoreError::MalformedDocument(format!(
                "prepared signature metadata '{field}' must be a nonempty string"
            ))
        })
}

fn required_agent_string(agent: &Value, field: &str) -> Result<String, CoreError> {
    agent
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            CoreError::MalformedKey(format!(
                "agent material '{field}' must be a nonempty string"
            ))
        })
}

mod base64_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        STANDARD
            .decode(encoded.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::{DetachedSigner, Ed25519DalekSigner};
    use secrecy::SecretBox;

    fn material_and_scope(
        purposes: impl IntoIterator<Item = SigningPurpose>,
        assurance: PurposeIsolationAssurance,
    ) -> (AgentMaterial, SigningKeyScope, Vec<u8>) {
        let signer = Ed25519DalekSigner::generate().expect("keypair");
        let private_key = signer.export_private_key_bytes().expect("private key");
        let public_key = signer.public_key().to_vec();
        let agent = json!({"jacsId":"agent-1","jacsVersion":"v1"});
        let scope = SigningKeyScope::from_public_key(
            "agent-1",
            "v1",
            SigningAlgorithm::Ed25519,
            &public_key,
            purposes,
            assurance,
        )
        .expect("scope");
        let material = AgentMaterial {
            config: json!({}),
            agent,
            public_key,
            // RawPrivateKey is selected by these tests, so the encrypted
            // field is deliberately not interpreted.
            encrypted_private_key: Vec::new(),
            algorithm: SigningAlgorithm::Ed25519,
        };
        (material, scope, private_key)
    }

    #[test]
    fn operation_and_purpose_use_exact_string_wire_forms() {
        let operation = SigningOperation::ExportEcosystem("did-web-v1".into());
        let purpose = SigningPurpose::EcosystemExport("did-web-v1".into());
        assert_eq!(
            serde_json::to_string(&operation).unwrap(),
            "\"ExportEcosystem:did-web-v1\""
        );
        assert_eq!(
            serde_json::to_string(&purpose).unwrap(),
            "\"ecosystem_export:did-web-v1\""
        );
        assert!(operation.accepts_purpose(&purpose));
        assert!(
            "ExportEcosystem:free:form"
                .parse::<SigningOperation>()
                .is_err()
        );
        assert!("SignSomethingElse".parse::<SigningOperation>().is_err());
    }

    #[test]
    fn prepared_document_freezes_and_post_verifies_exact_input() {
        let (material, scope, private_key) = material_and_scope(
            [SigningPurpose::Document],
            PurposeIsolationAssurance::SeparatePurposeKey,
        );
        let metadata = SignatureMetadataV2 {
            date: "2026-09-04T12:00:00Z".into(),
            iat: 1_788_523_200,
            jti: "prepared-1".into(),
        };
        let prepared =
            prepare_message_v2(&scope, &json!({"approved": true}), metadata).expect("prepare");
        for field in [
            "$schema",
            "jacsId",
            "jacsVersion",
            "jacsVersionDate",
            "jacsOriginalVersion",
            "jacsOriginalDate",
        ] {
            assert!(prepared.unsigned_envelope().get(field).is_some(), "{field}");
        }
        let frozen_input = prepared.signature_input().to_vec();
        let frozen_digest = prepared.signature_input_digest().to_owned();

        let public_key = material.public_key.clone();
        let provider = RestrictedSigningProvider::unlock_for_one_operation(
            material,
            UnlockSecret::RawPrivateKey(SecretBox::new(Box::new(private_key))),
            scope.clone(),
        )
        .expect("unlock");
        let signed = provider
            .sign_prepared_document(prepared.clone())
            .expect("sign frozen document");
        let outcome = verify_document(
            &signed,
            &public_key,
            SigningAlgorithm::Ed25519,
            DOCUMENT_V2_PLACEMENT_KEY,
        )
        .expect("verify signed envelope");
        assert!(outcome.valid);
        assert!(signed.get("jacsSha256").and_then(Value::as_str).is_some());

        // Serialize/deserialize to model a database staging boundary.  The
        // preimage remains byte-for-byte stable and validation is mandatory.
        let serialized = serde_json::to_vec(&prepared).expect("serialize");
        let round_trip: PreparedDocumentV2 =
            serde_json::from_slice(&serialized).expect("deserialize");
        assert_eq!(round_trip.signature_input(), frozen_input);
        assert_eq!(round_trip.signature_input_digest(), frozen_digest);
    }

    #[test]
    fn expired_deadline_is_provably_before_private_key_use() {
        let (material, scope, private_key) = material_and_scope(
            [SigningPurpose::Document],
            PurposeIsolationAssurance::SeparatePurposeKey,
        );
        let prepared = prepare_message_v2(
            &scope,
            &json!({"approved": true}),
            SignatureMetadataV2::now(),
        )
        .expect("prepare");
        let provider = RestrictedSigningProvider::unlock_for_one_operation(
            material,
            UnlockSecret::RawPrivateKey(SecretBox::new(Box::new(private_key))),
            scope,
        )
        .expect("unlock");
        let error = provider
            .sign_prepared_document_before(prepared, Utc::now() - chrono::Duration::seconds(1))
            .expect_err("expired deadline");
        assert_eq!(error.phase(), PreparedSigningFailurePhase::BeforeKeyUse);
        assert!(error.key_use_began_at().is_none());
    }

    #[test]
    fn authoritative_document_id_is_frozen_into_signature_input() {
        let (_material, scope, _private_key) = material_and_scope(
            [SigningPurpose::Document],
            PurposeIsolationAssurance::SeparatePurposeKey,
        );
        let document_id = "00000000-0000-4000-8000-000000000123";
        let prepared = prepare_message_v2_with_id(
            &scope,
            &json!({"approved": true}),
            document_id,
            SignatureMetadataV2::now(),
        )
        .expect("prepare");
        assert_eq!(prepared.unsigned_envelope()["jacsId"], document_id);
        assert!(String::from_utf8_lossy(prepared.signature_input()).contains(document_id));
    }

    #[test]
    fn native_artifact_preserves_only_approved_application_header_fields() {
        let (_material, scope, _private_key) = material_and_scope(
            [SigningPurpose::Document],
            PurposeIsolationAssurance::SeparatePurposeKey,
        );
        let header = NativeMessageHeaderV1::from_parts(
            "00000000-0000-4000-8000-000000000123",
            "00000000-0000-4000-8000-000000000124",
            "2026-09-04T12:00:00Z",
            "00000000-0000-4000-8000-000000000124",
            "2026-09-04T12:00:00Z",
        )
        .expect("header");
        let metadata = SignatureMetadataV2 {
            date: "2026-09-04T12:00:00Z".into(),
            iat: 1_788_523_200,
            jti: "prepared-artifact-1".into(),
        };
        let prepared = prepare_native_artifact_v2(
            &scope,
            &json!({
                "kind": "task",
                "jacsType": "artifact",
                "jacsLevel": "artifact",
                "jacsVisibility": {"restricted": ["agent-2"]}
            }),
            header.clone(),
            metadata.clone(),
        )
        .expect("prepare artifact");
        assert_eq!(prepared.unsigned_envelope()["kind"], "task");
        assert_eq!(
            prepared.unsigned_envelope()["jacsVisibility"],
            json!({"restricted": ["agent-2"]})
        );

        let forbidden = prepare_native_artifact_v2(
            &scope,
            &json!({"kind": "task", "jacsVersion": "caller-selected"}),
            header,
            metadata,
        )
        .expect_err("caller-selected native headers must fail");
        assert!(forbidden.to_string().contains("jacsVersion"));
    }

    #[test]
    fn prepared_document_rejects_changed_envelope_after_deserialization() {
        let (material, scope, _private_key) = material_and_scope(
            [SigningPurpose::Document],
            PurposeIsolationAssurance::SeparatePurposeKey,
        );
        let mut prepared = prepare_message_v2(
            &scope,
            &json!({"amount": 10}),
            SignatureMetadataV2 {
                date: "2026-09-04T12:00:00Z".into(),
                iat: 1_788_523_200,
                jti: "prepared-2".into(),
            },
        )
        .expect("prepare");
        prepared.envelope["content"]["amount"] = json!(11);
        assert!(prepared.validate(&scope, &material.public_key).is_err());
    }

    #[test]
    fn local_combined_scope_is_explicitly_shared_raw_capable() {
        let (material, scope, _private_key) = material_and_scope(
            [SigningPurpose::Document, SigningPurpose::LegacyRaw],
            PurposeIsolationAssurance::SharedRawCapable,
        );
        assert_eq!(
            scope.purpose_isolation_assurance(),
            PurposeIsolationAssurance::SharedRawCapable
        );
        scope
            .authorize(&SigningOperation::SignDocument, &SigningPurpose::Document)
            .expect("document allowed");
        scope
            .authorize(&SigningOperation::LegacyRawSign, &SigningPurpose::LegacyRaw)
            .expect("legacy raw allowed");

        let raw_only = SigningKeyScope::from_public_key(
            "agent-1",
            "v1",
            scope.algorithm(),
            &material.public_key,
            [SigningPurpose::LegacyRaw],
            PurposeIsolationAssurance::SeparatePurposeKey,
        )
        .expect("a dedicated raw-only key is a separate-purpose key");
        raw_only
            .authorize(&SigningOperation::LegacyRawSign, &SigningPurpose::LegacyRaw)
            .expect("raw-only purpose remains available");
    }

    #[test]
    fn rust_signature_input_matches_shared_browser_fixture() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/prepared_document_v2.json"))
                .expect("fixture JSON");
        let envelope = &fixture["envelope"];
        let metadata = &envelope[DOCUMENT_V2_PLACEMENT_KEY];
        let fields = metadata["fields"]
            .as_array()
            .expect("fields")
            .iter()
            .map(|value| value.as_str().expect("field string").to_owned())
            .collect::<Vec<_>>();
        let actual =
            build_signature_content_v2(envelope, &fields, DOCUMENT_V2_PLACEMENT_KEY, metadata)
                .expect("build signature input");
        assert_eq!(actual, fixture["signatureInputUtf8"]);
        assert_eq!(
            labeled_digest(HAI_SIGNATURE_INPUT_DIGEST_DOMAIN, actual.as_bytes()),
            fixture["signatureInputDigest"]
        );
    }
}
