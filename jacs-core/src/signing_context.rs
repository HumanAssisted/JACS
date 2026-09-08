//! Portable TP-29 restricted-signing request context.
//!
//! Callers select one authenticated profile-registry entry and supply only
//! the operation-specific authority context, audience, and referenced-content
//! set they actually own. [`SigningRequestContextV1::build_for_prepared_document`]
//! derives every repeated operation/key/profile/schema/input field and both
//! context digests from that selection, the trusted key scope, and the exact
//! bytes prepared for the private-key primitive.

use crate::identity::{digest_bytes, digest_json, validate_digest};
use crate::response_context::{ResponseData, ResponseOperation};
use crate::sign::SigningAlgorithm;
use crate::signing::{
    DOCUMENT_V2_SIGNATURE_PROFILE, PreparedDocumentV2, PurposeIsolationAssurance, SigningKeyScope,
    SigningOperation, SigningProfileBindingV1, SigningPurpose,
};
use crate::verification_registry::{
    ContextRuleId, ProfileKind, SecurityProfileEntry, SignatureFamilyId, WireRuleId,
};
use crate::{CoreError, canonical::canonicalize_json_try, strict_json::parse_strict_json};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const SIGNING_REQUEST_CONTEXT_V1_PROFILE: &str = "jacs-signing-request-context-v1";
pub const SIGNING_OPERATION_CONTEXT_DIGEST_DOMAIN: &str = "JACS-SIGNING-OPERATION-CONTEXT-V1";
pub const SIGNING_REQUEST_CONTEXT_DIGEST_DOMAIN: &str = "JACS-SIGNING-REQUEST-CONTEXT-V1";
pub const AUTHORITY_SIGNING_CLASSIFICATION_V1_PROFILE: &str =
    "jacs-authority-signing-classification-v1";
const SIGNING_INPUT_DIGEST_DOMAIN_PREFIX: &str = "JACS-SIGNING-INPUT-V1:";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
// Local compatibility only: this marker is never a policy-pinned registry or
// an AuthorityBacked conformance-bundle claim.
const LOCAL_DOCUMENT_V2_NON_AUTHORIZING_MARKER: &[u8] =
    br#"{"signatureContentVersion":"jacs-signature-v2","wireRuleId":"document_v2"}"#;

fn invalid(message: impl Into<String>) -> CoreError {
    CoreError::MalformedDocument(message.into())
}

fn required_nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningInputEncodingV1 {
    ExactOctets,
    StrictJsonJcs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningKeyRoleV1 {
    Operational,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SigningSchemaBindingV1 {
    #[serde(deserialize_with = "required_nullable")]
    pub schema_id: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub schema_bundle_digest: Option<String>,
}

impl SigningSchemaBindingV1 {
    fn from_entry(entry: &SecurityProfileEntry) -> Result<Self, CoreError> {
        match (&entry.schema_id, &entry.schema_bundle_digest) {
            (Some(schema_id), Some(schema_bundle_digest)) => {
                if !schema_id.contains(':') || schema_id.chars().any(char::is_whitespace) {
                    return Err(invalid("signing schema ID must be an absolute URI"));
                }
                validate_digest(schema_bundle_digest)?;
            }
            (None, None) => {}
            _ => {
                return Err(invalid(
                    "signing schema ID and bundle digest must both be null or present",
                ));
            }
        }
        Ok(Self {
            schema_id: entry.schema_id.clone(),
            schema_bundle_digest: entry.schema_bundle_digest.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SigningInputBindingV1 {
    pub encoding: SigningInputEncodingV1,
    pub byte_length: u64,
    pub digest: String,
}

/// Complete closed request-auth v2 claims used by `request_auth_v2` context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SigningRequestAuthClaimsV2 {
    pub version: String,
    pub key_id: String,
    pub issued_at: u64,
    pub nonce: String,
    pub method: String,
    pub scheme: String,
    pub authority: String,
    pub target: String,
    pub content_digest: String,
    pub audience: String,
    pub signing_algorithm: String,
    pub public_key_hash: String,
}

impl SigningRequestAuthClaimsV2 {
    fn validate(&self) -> Result<(), CoreError> {
        if self.version != "jacs-request-v2"
            || self.issued_at > MAX_SAFE_INTEGER
            || !matches!(self.scheme.as_str(), "http" | "https")
            || self.method.is_empty()
            || self.method != self.method.to_ascii_uppercase()
            || self.target.is_empty()
            || !self.target.starts_with('/')
            || [
                &self.key_id,
                &self.nonce,
                &self.authority,
                &self.content_digest,
                &self.audience,
                &self.signing_algorithm,
                &self.public_key_hash,
            ]
            .into_iter()
            .any(|value| value.is_empty())
        {
            return Err(invalid(
                "request_auth_v2 context contains invalid or incomplete claims",
            ));
        }
        Ok(())
    }
}

/// Exact TP-29 operation-context union. There is no custom/free-form arm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SigningOperationContextV1 {
    NoneV1 {},
    RequestAuthV2 {
        claims: SigningRequestAuthClaimsV2,
    },
    ResponseContextV2 {
        value: Value,
    },
    AgreementProofV3 {
        agreement_core_digest: String,
        participant_id: String,
        role: String,
        #[serde(deserialize_with = "required_nullable")]
        ceremony_context_digest: Option<String>,
    },
    A2aArtifactV1 {
        wrapper_artifact_digest: String,
        agent_card_digest: String,
        interaction_context_digest: String,
    },
    LegacyRawV1 {
        byte_length: u64,
    },
    HaiExactReceiptV1 {
        preauthorization_request_digest: String,
    },
    RegistrySchemaV1 {
        value: Value,
    },
}

impl SigningOperationContextV1 {
    pub fn context_rule_id(&self) -> &'static str {
        match self {
            Self::NoneV1 {} => "none_v1",
            Self::RequestAuthV2 { .. } => "request_auth_v2",
            Self::ResponseContextV2 { .. } => "response_context_v2",
            Self::AgreementProofV3 { .. } => "agreement_proof_v3",
            Self::A2aArtifactV1 { .. } => "a2a_artifact_v1",
            Self::LegacyRawV1 { .. } => "legacy_raw_v1",
            Self::HaiExactReceiptV1 { .. } => "hai_exact_receipt_v1",
            Self::RegistrySchemaV1 { .. } => "registry_schema_v1",
        }
    }

    /// Validate this exact tagged context against one authenticated profile
    /// entry. Verifiers use the same function after reconstructing audience
    /// and input length from the signed wire.
    pub fn validate_for_profile(
        &self,
        entry: &SecurityProfileEntry,
        target_audience: Option<&str>,
        input_length: u64,
    ) -> Result<(), CoreError> {
        entry.validate()?;
        if entry.context_rule_id.as_str() != self.context_rule_id() {
            return Err(invalid("profile entry and operation context rule differ"));
        }
        validate_target_audience(target_audience)?;
        self.validate(
            &entry.operation,
            &entry.purpose,
            &entry.profile_id,
            &SigningSchemaBindingV1::from_entry(entry)?,
            target_audience,
            input_length,
        )
    }

    /// Syntax/operation check used by TP-24 intent validation before an
    /// authenticated registry has been selected. This never establishes
    /// profile authority; [`Self::validate_for_profile`] performs that join.
    pub fn validate_for_intent(
        &self,
        operation: &SigningOperation,
        signature_profile: &str,
        target_audience: Option<&str>,
    ) -> Result<(), CoreError> {
        operation.validate()?;
        if signature_profile.is_empty()
            || signature_profile.trim() != signature_profile
            || signature_profile.chars().any(char::is_control)
        {
            return Err(invalid("intent signature profile is not a canonical token"));
        }
        validate_target_audience(target_audience)?;
        let purpose = intent_operation_purpose(operation)?;
        if let Self::RegistrySchemaV1 { value } = self {
            canonicalize_json_try(value)?;
            return Ok(());
        }
        let schema = SigningSchemaBindingV1 {
            schema_id: None,
            schema_bundle_digest: None,
        };
        let input_length = match self {
            Self::LegacyRawV1 { byte_length } => *byte_length,
            _ => 0,
        };
        self.validate(
            operation,
            &purpose,
            signature_profile,
            &schema,
            target_audience,
            input_length,
        )
    }

    fn validate(
        &self,
        operation: &SigningOperation,
        purpose: &SigningPurpose,
        signature_profile: &str,
        schema: &SigningSchemaBindingV1,
        target_audience: Option<&str>,
        input_length: u64,
    ) -> Result<(), CoreError> {
        match self {
            Self::NoneV1 {}
                if operation == &SigningOperation::SignDocument
                    && purpose == &SigningPurpose::Document
                    && signature_profile == "jacs-document-v2"
                    && target_audience.is_none() => {}
            Self::RequestAuthV2 { claims }
                if operation == &SigningOperation::AuthenticateHttpRequest
                    && purpose == &SigningPurpose::ApiRequest
                    && target_audience == Some(claims.audience.as_str()) =>
            {
                claims.validate()?
            }
            Self::ResponseContextV2 { value }
                if matches!(
                    operation,
                    SigningOperation::SignBoundResponse | SigningOperation::SignAsyncEvent
                ) =>
            {
                let mut data = value.clone();
                let object = data
                    .as_object_mut()
                    .ok_or_else(|| invalid("response_context_v2 value must be a closed object"))?;
                let audience = object
                    .get("audience")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("response_context_v2 audience must be nonempty"))?;
                if target_audience != Some(audience) {
                    return Err(invalid(
                        "response_context_v2 audience differs from targetAudience",
                    ));
                }
                if object.contains_key("payload") {
                    return Err(invalid("response_context_v2 excludes payload"));
                }
                object.insert("payload".into(), Value::Null);
                let data: ResponseData = serde_json::from_value(data)
                    .map_err(|error| invalid(format!("invalid response context: {error}")))?;
                data.validate()?;
                let expected = match data.operation() {
                    ResponseOperation::SignBoundResponse => SigningOperation::SignBoundResponse,
                    ResponseOperation::SignAsyncEvent => SigningOperation::SignAsyncEvent,
                };
                if operation != &expected {
                    return Err(invalid("response context class and operation differ"));
                }
            }
            Self::AgreementProofV3 {
                agreement_core_digest,
                participant_id,
                role,
                ceremony_context_digest,
            } if matches!(
                operation,
                SigningOperation::SignAgreementProposal
                    | SigningOperation::SignAgreementConsent
                    | SigningOperation::SignAgreementWitness
                    | SigningOperation::SignAgreementAmendment
                    | SigningOperation::SignAgreementNotary
            ) =>
            {
                validate_digest(agreement_core_digest)?;
                if let Some(ceremony_context_digest) = ceremony_context_digest {
                    validate_digest(ceremony_context_digest)?;
                }
                if participant_id.is_empty() || role.is_empty() {
                    return Err(invalid(
                        "agreement proof participant and role must be nonempty",
                    ));
                }
                let expected_role = match operation {
                    SigningOperation::SignAgreementProposal
                    | SigningOperation::SignAgreementAmendment => "controller",
                    SigningOperation::SignAgreementConsent => "signer",
                    SigningOperation::SignAgreementWitness => "witness",
                    SigningOperation::SignAgreementNotary => "notary",
                    _ => unreachable!("match guard restricts agreement operations"),
                };
                if role != expected_role {
                    return Err(invalid("agreement proof role does not match its operation"));
                }
            }
            Self::A2aArtifactV1 {
                wrapper_artifact_digest,
                agent_card_digest,
                interaction_context_digest,
            } if operation == &SigningOperation::SignA2aArtifact
                && purpose == &SigningPurpose::A2aArtifact =>
            {
                validate_digest(wrapper_artifact_digest)?;
                validate_digest(agent_card_digest)?;
                validate_digest(interaction_context_digest)?;
            }
            Self::LegacyRawV1 { byte_length }
                if operation == &SigningOperation::LegacyRawSign
                    && purpose == &SigningPurpose::LegacyRaw
                    && *byte_length == input_length
                    && target_audience.is_none() => {}
            Self::HaiExactReceiptV1 {
                preauthorization_request_digest,
            } => validate_digest(preauthorization_request_digest)?,
            Self::RegistrySchemaV1 { value } if schema.schema_id.is_some() => {
                // Schema-bundle validation is performed by the authenticated
                // registry resolver. This portable layer still enforces strict
                // canonicalizable JSON and the non-null schema pair.
                canonicalize_json_try(value)?;
            }
            _ => {
                return Err(invalid(
                    "operation context does not match its closed TP-29 rule",
                ));
            }
        }
        Ok(())
    }
}

/// Nonredundant caller selection used to build the complete TP-29 context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SigningContextSelectionV1 {
    profile_entry: SecurityProfileEntry,
    #[serde(deserialize_with = "required_nullable")]
    target_audience: Option<String>,
    referenced_content_digests: Vec<String>,
    operation_context: SigningOperationContextV1,
}

impl SigningContextSelectionV1 {
    pub fn new(
        profile_entry: SecurityProfileEntry,
        operation_context: SigningOperationContextV1,
        target_audience: Option<String>,
        mut referenced_content_digests: Vec<String>,
    ) -> Result<Self, CoreError> {
        profile_entry.validate()?;
        validate_target_audience(target_audience.as_deref())?;
        for digest in &referenced_content_digests {
            validate_digest(digest)?;
        }
        referenced_content_digests.sort();
        if referenced_content_digests
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(invalid("referenced content digests must be unique"));
        }
        if profile_entry.context_rule_id.as_str() != operation_context.context_rule_id() {
            return Err(invalid("profile entry and operation context rule differ"));
        }
        Ok(Self {
            profile_entry,
            target_audience,
            referenced_content_digests,
            operation_context,
        })
    }

    pub fn profile_entry(&self) -> &SecurityProfileEntry {
        &self.profile_entry
    }

    pub fn operation_context(&self) -> &SigningOperationContextV1 {
        &self.operation_context
    }
}

/// Hardwired local-SDK profile used by compatibility document entry points.
/// Authority-backed services must supply the exact policy-pinned registry row
/// instead of calling this helper.
pub fn local_document_v2_profile_entry(
    algorithm: SigningAlgorithm,
) -> Result<SecurityProfileEntry, CoreError> {
    let entry = SecurityProfileEntry {
        profile_id: "jacs-document-v2".into(),
        profile_kind: ProfileKind::BuiltIn,
        operation: SigningOperation::SignDocument,
        purpose: SigningPurpose::Document,
        signature_family_id: SignatureFamilyId::SignatureV2,
        wire_rule_id: WireRuleId::DocumentV2,
        context_rule_id: ContextRuleId::NoneV1,
        allowed_algorithms: vec![algorithm.as_str().into()],
        schema_id: None,
        schema_bundle_digest: None,
        conformance_fixture_digest: digest_bytes(
            "JACS-CONFORMANCE-FIXTURE-V1",
            LOCAL_DOCUMENT_V2_NON_AUTHORIZING_MARKER,
        ),
    };
    entry.validate()?;
    Ok(entry)
}

pub fn local_document_v2_selection(
    algorithm: SigningAlgorithm,
) -> Result<SigningContextSelectionV1, CoreError> {
    SigningContextSelectionV1::new(
        local_document_v2_profile_entry(algorithm)?,
        SigningOperationContextV1::NoneV1 {},
        None,
        Vec::new(),
    )
}

/// Complete, derived TP-29 signing request context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SigningRequestContextV1 {
    profile: String,
    operation: SigningOperation,
    identity: String,
    canonical_key_id: String,
    key_role: SigningKeyRoleV1,
    purpose: SigningPurpose,
    signature_profile: String,
    signature_family_id: String,
    wire_rule_id: String,
    context_rule_id: String,
    schema: SigningSchemaBindingV1,
    #[serde(deserialize_with = "required_nullable")]
    target_audience: Option<String>,
    input: SigningInputBindingV1,
    referenced_content_digests: Vec<String>,
    operation_context: SigningOperationContextV1,
    operation_context_digest: String,
}

impl SigningRequestContextV1 {
    /// Build every redundant field and digest from trusted inputs.
    pub fn build_for_prepared_document(
        scope: &SigningKeyScope,
        selection: &SigningContextSelectionV1,
        exact_signature_input: &[u8],
    ) -> Result<Self, CoreError> {
        let entry = selection.profile_entry();
        let context = Self::build_unchecked(
            scope,
            selection,
            exact_signature_input,
            SignatureFamilyId::SignatureV2,
            WireRuleId::DocumentV2,
        )?;
        context.validate(scope, entry, exact_signature_input)?;
        Ok(context)
    }

    /// Rebuild the entire context and compare it byte-for-byte after a
    /// persistence boundary.
    pub fn validate(
        &self,
        scope: &SigningKeyScope,
        entry: &SecurityProfileEntry,
        exact_signature_input: &[u8],
    ) -> Result<(), CoreError> {
        if self.profile != SIGNING_REQUEST_CONTEXT_V1_PROFILE {
            return Err(invalid("signing request context profile mismatch"));
        }
        let selection = SigningContextSelectionV1::new(
            entry.clone(),
            self.operation_context.clone(),
            self.target_audience.clone(),
            self.referenced_content_digests.clone(),
        )?;
        let expected = Self::build_unchecked(
            scope,
            &selection,
            exact_signature_input,
            SignatureFamilyId::SignatureV2,
            WireRuleId::DocumentV2,
        )?;
        if self != &expected {
            return Err(invalid("signing request context changed after preparation"));
        }
        Ok(())
    }

    fn build_unchecked(
        scope: &SigningKeyScope,
        selection: &SigningContextSelectionV1,
        exact_signature_input: &[u8],
        expected_family: SignatureFamilyId,
        expected_wire: WireRuleId,
    ) -> Result<Self, CoreError> {
        let entry = selection.profile_entry();
        entry.validate()?;
        scope.validate_profile_entry(entry)?;
        if entry.signature_family_id != expected_family || entry.wire_rule_id != expected_wire {
            return Err(invalid("signing context profile family/wire mismatch"));
        }
        let input = build_input(
            &entry.operation,
            SigningInputEncodingV1::StrictJsonJcs,
            exact_signature_input,
        )?;
        let schema = SigningSchemaBindingV1::from_entry(entry)?;
        selection.operation_context.validate(
            &entry.operation,
            &entry.purpose,
            &entry.profile_id,
            &schema,
            selection.target_audience.as_deref(),
            input.byte_length,
        )?;
        if let SigningOperationContextV1::RequestAuthV2 { claims } = &selection.operation_context {
            let signer_lookup_id = format!("{}:{}", scope.identity(), scope.agent_version());
            if claims.key_id != signer_lookup_id
                || crate::identity::canonical_algorithm(&claims.signing_algorithm)?
                    != scope.algorithm().as_str()
                || claims.public_key_hash != scope.public_key_hash()
            {
                return Err(invalid(
                    "request_auth_v2 key fields differ from the selected signing scope",
                ));
            }
        }
        let operation_context_digest = digest_json(
            SIGNING_OPERATION_CONTEXT_DIGEST_DOMAIN,
            &json!({
                "operation": &entry.operation,
                "signatureProfile": &entry.profile_id,
                "contextRuleId": entry.context_rule_id.as_str(),
                "context": &selection.operation_context,
            }),
        )?;
        Ok(Self {
            profile: SIGNING_REQUEST_CONTEXT_V1_PROFILE.into(),
            operation: entry.operation.clone(),
            identity: scope.identity().into(),
            canonical_key_id: scope.canonical_key_id().into(),
            key_role: SigningKeyRoleV1::Operational,
            purpose: entry.purpose.clone(),
            signature_profile: entry.profile_id.clone(),
            signature_family_id: entry.signature_family_id.as_str().into(),
            wire_rule_id: entry.wire_rule_id.as_str().into(),
            context_rule_id: entry.context_rule_id.as_str().into(),
            schema,
            target_audience: selection.target_audience.clone(),
            input,
            referenced_content_digests: selection.referenced_content_digests.clone(),
            operation_context: selection.operation_context.clone(),
            operation_context_digest,
        })
    }

    fn build_for_authority_classification(
        scope: &SigningKeyScope,
        selection: &SigningContextSelectionV1,
        exact_primary_signature_input: &[u8],
    ) -> Result<Self, CoreError> {
        let context = Self::build_unchecked(
            scope,
            selection,
            exact_primary_signature_input,
            SignatureFamilyId::AuthorityReceiptV1,
            WireRuleId::AuthorityBackedExactReceiptV1,
        )?;
        context.validate_for_authority_classification(
            scope,
            selection.profile_entry(),
            exact_primary_signature_input,
        )?;
        Ok(context)
    }

    fn validate_for_authority_classification(
        &self,
        scope: &SigningKeyScope,
        entry: &SecurityProfileEntry,
        exact_primary_signature_input: &[u8],
    ) -> Result<(), CoreError> {
        if self.profile != SIGNING_REQUEST_CONTEXT_V1_PROFILE {
            return Err(invalid(
                "authority signing request context profile mismatch",
            ));
        }
        let selection = SigningContextSelectionV1::new(
            entry.clone(),
            self.operation_context.clone(),
            self.target_audience.clone(),
            self.referenced_content_digests.clone(),
        )?;
        let expected = Self::build_unchecked(
            scope,
            &selection,
            exact_primary_signature_input,
            SignatureFamilyId::AuthorityReceiptV1,
            WireRuleId::AuthorityBackedExactReceiptV1,
        )?;
        if self != &expected {
            return Err(invalid(
                "authority signing request context changed after preparation",
            ));
        }
        Ok(())
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

    pub fn input(&self) -> &SigningInputBindingV1 {
        &self.input
    }

    pub fn operation_context_digest(&self) -> &str {
        &self.operation_context_digest
    }

    pub fn operation_context(&self) -> &SigningOperationContextV1 {
        &self.operation_context
    }

    pub fn digest(&self) -> Result<String, CoreError> {
        digest_json(
            SIGNING_REQUEST_CONTEXT_DIGEST_DOMAIN,
            &serde_json::to_value(self)
                .map_err(|error| invalid(format!("serialize signing context: {error}")))?,
        )
    }
}

/// Authenticated TP-31 interpretation of one unchanged primary JACS signature.
///
/// The primary signature remains `jacs.signature.v2` / `SignDocument`. This
/// value is a separate candidate authority dependency edge: it classifies the
/// exact frozen primary input under one caller-supplied, policy-authenticated
/// authority-receipt registry row without relabeling the bytes or primitive
/// that JACS actually signs. It is not a completed or signed authority receipt
/// and cannot authorize verification by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthoritySigningClassificationV1 {
    profile: String,
    authority_profile_entry: SecurityProfileEntry,
    authority_signing_request_context: SigningRequestContextV1,
    authority_signing_request_context_digest: String,
    primary_signature_profile: String,
    primary_signature_family_id: SignatureFamilyId,
    primary_wire_rule_id: WireRuleId,
    primary_signature_input_digest: String,
    primary_signing_request_context_digest: String,
}

impl AuthoritySigningClassificationV1 {
    /// Build the complete authority-layer TP-29 context from a trusted key
    /// scope, one frozen primary document, and the nonredundant selected
    /// authority row/context. The caller never supplies duplicate operation,
    /// purpose, key, family, wire, schema, or input-digest fields.
    pub fn build_for_prepared_document(
        scope: &SigningKeyScope,
        public_key: &[u8],
        prepared: &PreparedDocumentV2,
        selection: SigningContextSelectionV1,
    ) -> Result<Self, CoreError> {
        prepared.validate(scope, public_key)?;
        validate_primary_document(prepared)?;
        let entry = selection.profile_entry();
        if entry.signature_family_id != SignatureFamilyId::AuthorityReceiptV1
            || entry.wire_rule_id != WireRuleId::AuthorityBackedExactReceiptV1
            || entry.context_rule_id != ContextRuleId::HaiExactReceiptV1
        {
            return Err(invalid(
                "authority classification requires an exact authority-receipt profile row",
            ));
        }
        let authority_signing_request_context =
            SigningRequestContextV1::build_for_authority_classification(
                scope,
                &selection,
                prepared.signature_input(),
            )?;
        let authority_signing_request_context_digest =
            authority_signing_request_context.digest()?;
        let classification = Self {
            profile: AUTHORITY_SIGNING_CLASSIFICATION_V1_PROFILE.into(),
            authority_profile_entry: entry.clone(),
            authority_signing_request_context,
            authority_signing_request_context_digest,
            primary_signature_profile: DOCUMENT_V2_SIGNATURE_PROFILE.into(),
            primary_signature_family_id: SignatureFamilyId::SignatureV2,
            primary_wire_rule_id: WireRuleId::DocumentV2,
            primary_signature_input_digest: prepared.signature_input_digest().into(),
            primary_signing_request_context_digest: prepared
                .signing_request_context_digest()
                .into(),
        };
        classification.validate_internal(scope, public_key, prepared)?;
        Ok(classification)
    }

    pub fn operation(&self) -> &SigningOperation {
        self.authority_signing_request_context.operation()
    }

    pub fn purpose(&self) -> &SigningPurpose {
        self.authority_signing_request_context.purpose()
    }

    pub fn authority_profile_entry(&self) -> &SecurityProfileEntry {
        &self.authority_profile_entry
    }

    pub fn authority_signing_request_context(&self) -> &SigningRequestContextV1 {
        &self.authority_signing_request_context
    }

    pub fn authority_signing_request_context_digest(&self) -> &str {
        &self.authority_signing_request_context_digest
    }

    pub fn primary_signature_input_digest(&self) -> &str {
        &self.primary_signature_input_digest
    }

    /// Recompute both layers without asserting that an external authority has
    /// accepted this context. This is an integrity check only; managed key use
    /// must call [`Self::validate_authorized`] with the independently stored
    /// digest.
    pub fn validate_structure(
        &self,
        scope: &SigningKeyScope,
        public_key: &[u8],
        prepared: &PreparedDocumentV2,
    ) -> Result<(), CoreError> {
        self.validate_internal(scope, public_key, prepared)
    }

    /// Recompute both layers and require the independently persisted authority
    /// context digest. This is the persistence/key-use boundary check.
    pub fn validate_authorized(
        &self,
        scope: &SigningKeyScope,
        public_key: &[u8],
        prepared: &PreparedDocumentV2,
        expected_authority_context_digest: &str,
    ) -> Result<(), CoreError> {
        validate_digest(expected_authority_context_digest)?;
        if self.authority_signing_request_context_digest != expected_authority_context_digest {
            return Err(invalid(
                "authority signing context does not equal the independently authorized digest",
            ));
        }
        self.validate_internal(scope, public_key, prepared)
    }

    fn validate_internal(
        &self,
        scope: &SigningKeyScope,
        public_key: &[u8],
        prepared: &PreparedDocumentV2,
    ) -> Result<(), CoreError> {
        if self.profile != AUTHORITY_SIGNING_CLASSIFICATION_V1_PROFILE {
            return Err(invalid("authority signing classification profile mismatch"));
        }
        prepared.validate(scope, public_key)?;
        validate_primary_document(prepared)?;
        if self.primary_signature_profile != DOCUMENT_V2_SIGNATURE_PROFILE
            || self.primary_signature_family_id != SignatureFamilyId::SignatureV2
            || self.primary_wire_rule_id != WireRuleId::DocumentV2
            || self.primary_signature_input_digest != prepared.signature_input_digest()
            || self.primary_signing_request_context_digest
                != prepared.signing_request_context_digest()
        {
            return Err(invalid(
                "authority classification no longer identifies the exact primary signature input",
            ));
        }
        self.authority_profile_entry.validate()?;
        scope.validate_profile_entry(&self.authority_profile_entry)?;
        if self.authority_profile_entry.signature_family_id != SignatureFamilyId::AuthorityReceiptV1
            || self.authority_profile_entry.wire_rule_id
                != WireRuleId::AuthorityBackedExactReceiptV1
            || self.authority_profile_entry.context_rule_id != ContextRuleId::HaiExactReceiptV1
            || &self.authority_profile_entry.operation
                != self.authority_signing_request_context.operation()
            || &self.authority_profile_entry.purpose
                != self.authority_signing_request_context.purpose()
        {
            return Err(invalid(
                "authority classification registry/context binding mismatch",
            ));
        }
        self.authority_signing_request_context
            .validate_for_authority_classification(
                scope,
                &self.authority_profile_entry,
                prepared.signature_input(),
            )?;
        let expected = self.authority_signing_request_context.digest()?;
        if self.authority_signing_request_context_digest != expected {
            return Err(invalid(
                "authority signing request context digest changed after preparation",
            ));
        }
        Ok(())
    }
}

fn validate_primary_document(prepared: &PreparedDocumentV2) -> Result<(), CoreError> {
    if prepared.operation() != &SigningOperation::SignDocument
        || prepared.purpose() != &SigningPurpose::Document
        || prepared.signature_profile() != DOCUMENT_V2_SIGNATURE_PROFILE
        || prepared.profile_entry().signature_family_id != SignatureFamilyId::SignatureV2
        || prepared.profile_entry().wire_rule_id != WireRuleId::DocumentV2
    {
        return Err(invalid(
            "authority classification requires an unchanged generic document-v2 primary signature",
        ));
    }
    Ok(())
}

fn build_input(
    operation: &SigningOperation,
    encoding: SigningInputEncodingV1,
    exact_input: &[u8],
) -> Result<SigningInputBindingV1, CoreError> {
    let byte_length = u64::try_from(exact_input.len())
        .map_err(|_| invalid("signing input length does not fit u64"))?;
    if byte_length > MAX_SAFE_INTEGER {
        return Err(invalid(
            "signing input length exceeds the JSON safe integer range",
        ));
    }
    if encoding == SigningInputEncodingV1::StrictJsonJcs {
        let text = std::str::from_utf8(exact_input)
            .map_err(|_| invalid("strict_json_jcs input is not UTF-8"))?;
        let value = parse_strict_json(text)?;
        if canonicalize_json_try(&value)?.as_bytes() != exact_input {
            return Err(invalid("strict_json_jcs input is not canonical JSON"));
        }
    }
    let domain = format!(
        "{SIGNING_INPUT_DIGEST_DOMAIN_PREFIX}{}",
        operation.to_wire()
    );
    Ok(SigningInputBindingV1 {
        encoding,
        byte_length,
        digest: digest_bytes(&domain, exact_input),
    })
}

fn validate_target_audience(audience: Option<&str>) -> Result<(), CoreError> {
    if audience.is_some_and(str::is_empty) {
        return Err(invalid("target audience must be nonempty or null"));
    }
    Ok(())
}

fn intent_operation_purpose(operation: &SigningOperation) -> Result<SigningPurpose, CoreError> {
    let purpose = match operation {
        SigningOperation::SignDocument => SigningPurpose::Document,
        SigningOperation::SignInlineTextCreate | SigningOperation::SignInlineTextUpdate => {
            SigningPurpose::InlineText
        }
        SigningOperation::SignFileOrMediaManifest => SigningPurpose::FileMedia,
        SigningOperation::SignEmail => SigningPurpose::Email,
        SigningOperation::AuthenticateHttpRequest => SigningPurpose::ApiRequest,
        SigningOperation::SignBoundResponse | SigningOperation::SignAsyncEvent => {
            SigningPurpose::Response
        }
        SigningOperation::SignAgreementProposal => SigningPurpose::AgreementProposal,
        SigningOperation::SignAgreementConsent => SigningPurpose::AgreementConsent,
        SigningOperation::SignAgreementWitness => SigningPurpose::AgreementWitness,
        SigningOperation::SignAgreementAmendment => SigningPurpose::AgreementAmendment,
        SigningOperation::SignAgreementNotary => SigningPurpose::AgreementNotary,
        SigningOperation::SignA2aArtifact => SigningPurpose::A2aArtifact,
        SigningOperation::SignAttestation => SigningPurpose::Attestation,
        SigningOperation::LegacyRawSign => SigningPurpose::LegacyRaw,
        SigningOperation::ExportEcosystem(profile_id) => {
            SigningPurpose::EcosystemExport(profile_id.clone())
        }
        SigningOperation::RecordArchivalObservation
        | SigningOperation::AuthorizeKeyEvent
        | SigningOperation::PublishStatusCheckpoint
        | SigningOperation::IssueAuthorityTime
        | SigningOperation::AuthorizeRevocationCutoff => {
            return Err(invalid(
                "control-plane operation requires its hardwired authority context",
            ));
        }
    };
    Ok(purpose)
}

impl SigningKeyScope {
    /// Construct a key scope and its exact authorized profile bindings from
    /// authenticated registry rows. No caller repeats operation/purpose/profile
    /// triples separately.
    #[allow(clippy::too_many_arguments)]
    pub fn from_public_key_with_profile_entries(
        identity: impl Into<String>,
        agent_version: impl Into<String>,
        algorithm: SigningAlgorithm,
        public_key: &[u8],
        profile_entries: &[SecurityProfileEntry],
        purpose_isolation_assurance: PurposeIsolationAssurance,
    ) -> Result<Self, CoreError> {
        let mut bindings = Vec::with_capacity(profile_entries.len());
        let mut authorized_purposes = Vec::with_capacity(profile_entries.len());
        for entry in profile_entries {
            entry.validate()?;
            if !entry
                .allowed_algorithms
                .iter()
                .any(|allowed| allowed == algorithm.as_str())
            {
                return Err(CoreError::AlgorithmMismatch {
                    expected: entry.allowed_algorithms.join("|"),
                    actual: algorithm.as_str().into(),
                });
            }
            bindings.push(SigningProfileBindingV1::new(
                entry.operation.clone(),
                entry.purpose.clone(),
                entry.profile_id.clone(),
            )?);
            authorized_purposes.push(entry.purpose.clone());
        }
        let scope = Self::from_public_key_with_bindings(
            identity,
            agent_version,
            algorithm,
            public_key,
            authorized_purposes,
            bindings,
            purpose_isolation_assurance,
        )?;
        for entry in profile_entries {
            scope.validate_profile_entry(entry)?;
        }
        Ok(scope)
    }

    /// Validate an authenticated profile-registry row against this exact key
    /// scope. This is the shared signer/verifier registry join.
    pub fn validate_profile_entry(&self, entry: &SecurityProfileEntry) -> Result<(), CoreError> {
        entry.validate()?;
        self.authorize_profile(&entry.operation, &entry.purpose, &entry.profile_id)?;
        if !entry
            .allowed_algorithms
            .iter()
            .any(|algorithm| algorithm == self.algorithm().as_str())
        {
            return Err(CoreError::AlgorithmMismatch {
                expected: entry.allowed_algorithms.join("|"),
                actual: self.algorithm().as_str().into(),
            });
        }
        Ok(())
    }
}
