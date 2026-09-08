//! Immutable, digest-pinned profile and schema registries. Parsing a registry
//! is not trust enrollment; its digest must come from authenticated policy.

use crate::canonical::canonicalize_json_try;
use crate::identity::{
    canonical_algorithm, decode_binary, digest_bytes, digest_json, validate_digest,
};
use crate::signing::{SigningOperation, SigningPurpose};
use crate::verification::{
    ContextExpectation, SchemaExpectation, VerificationIntent, VerificationPolicy,
};
use crate::{CoreError, strict_json::parse_strict_json};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub use crate::agreements::v3::ResolvedSchemaBundleV3 as ResolvedSchemaBundle;

fn invalid(message: impl Into<String>) -> CoreError {
    CoreError::MalformedDocument(message.into())
}
fn required_nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
fn absolute_uri(uri: &str) -> bool {
    uri.split_once(':').is_some_and(|(scheme, rest)| {
        !scheme.is_empty()
            && !rest.is_empty()
            && scheme.bytes().enumerate().all(|(i, b)| {
                b.is_ascii_alphabetic()
                    || (i > 0 && (b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'.')))
            })
    }) && !uri.chars().any(char::is_whitespace)
}
fn canonical_algorithms(algorithms: &[String]) -> Result<(), CoreError> {
    if algorithms.is_empty()
        || algorithms.windows(2).any(|pair| pair[0] >= pair[1])
        || algorithms
            .iter()
            .any(|a| canonical_algorithm(a).ok() != Some(a.as_str()))
    {
        return Err(invalid(
            "algorithm list must be sorted, unique, nonempty canonical tokens",
        ));
    }
    Ok(())
}

macro_rules! wire_enum {
    ($name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        pub enum $name { $(#[serde(rename=$wire)] $variant),+ }
        impl $name { pub const fn as_str(self) -> &'static str { match self { $(Self::$variant => $wire),+ } } }
    }
}
wire_enum!(ProfileKind { BuiltIn => "built_in", EcosystemExport => "ecosystem_export" });
wire_enum!(SignatureFamilyId {
    SignatureV2 => "jacs.signature.v2", DocumentV3 => "jacs.document.v3",
    RequestAuthV2 => "jacs.request-auth.v2", ResponseV2 => "jacs.response.v2",
    AgreementProofV3 => "jacs.agreement-proof.v3", AuthorityReceiptV1 => "jacs.authority-receipt.v1",
    A2aArtifactV1 => "jacs.a2a-artifact.v1", LegacyRawV0 => "jacs.legacy-raw.v0"
});
wire_enum!(WireRuleId {
    DocumentV2 => "document_v2", DocumentV3Named => "document_v3_named",
    RequestAuthV2 => "request_auth_v2", ResponseV2 => "response_v2",
    AgreementV3Proof => "agreement_v3_proof", AuthorityBackedExactReceiptV1 => "authority_backed_exact_receipt_v1",
    A2aArtifactV1 => "a2a_artifact_v1", LegacyRaw => "legacy_raw"
});
wire_enum!(ContextRuleId {
    NoneV1 => "none_v1", RequestAuthV2 => "request_auth_v2", ResponseContextV2 => "response_context_v2",
    AgreementProofV3 => "agreement_proof_v3", A2aArtifactV1 => "a2a_artifact_v1", LegacyRawV1 => "legacy_raw_v1",
    HaiExactReceiptV1 => "hai_exact_receipt_v1", RegistrySchemaV1 => "registry_schema_v1"
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecurityProfileEntry {
    pub profile_id: String,
    pub profile_kind: ProfileKind,
    pub operation: SigningOperation,
    pub purpose: SigningPurpose,
    pub signature_family_id: SignatureFamilyId,
    pub wire_rule_id: WireRuleId,
    pub context_rule_id: ContextRuleId,
    pub allowed_algorithms: Vec<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub schema_id: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub schema_bundle_digest: Option<String>,
    pub conformance_fixture_digest: String,
}
impl SecurityProfileEntry {
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.profile_id.is_empty() || self.profile_id.chars().any(char::is_whitespace) {
            return Err(invalid("profile ID must be nonempty token"));
        }
        validate_digest(&self.conformance_fixture_digest)?;
        canonical_algorithms(&self.allowed_algorithms)?;
        match (&self.schema_id, &self.schema_bundle_digest) {
            (None, None) => {}
            (Some(id), Some(digest)) if absolute_uri(id) => validate_digest(digest)?,
            _ => {
                return Err(invalid(
                    "profile schema pair must be both null or exact URI/digest",
                ));
            }
        }
        if !self.operation.accepts_purpose(&self.purpose) {
            return Err(invalid("profile operation/purpose mismatch"));
        }
        if self.allowed_algorithms.iter().any(|a| a == "es256")
            && self.wire_rule_id != WireRuleId::A2aArtifactV1
        {
            return Err(invalid(
                "ES256 application authentication is confined to strict A2A compatibility",
            ));
        }
        if self.profile_kind == ProfileKind::EcosystemExport {
            let SigningOperation::ExportEcosystem(operation_id) = &self.operation else {
                return Err(invalid("ecosystem operation mismatch"));
            };
            let SigningPurpose::EcosystemExport(purpose_id) = &self.purpose else {
                return Err(invalid("ecosystem purpose mismatch"));
            };
            if operation_id.is_empty()
                || !operation_id.is_ascii()
                || operation_id != purpose_id
                || self.profile_id != format!("ecosystem_export:{operation_id}")
                || self.context_rule_id != ContextRuleId::RegistrySchemaV1
                || self.schema_id.is_none()
                || self.wire_rule_id != WireRuleId::AuthorityBackedExactReceiptV1
                || self.signature_family_id != SignatureFamilyId::AuthorityReceiptV1
            {
                return Err(invalid(
                    "ecosystem row has no exact supported wire/context join",
                ));
            }
            return Ok(());
        }
        let exact = match self.wire_rule_id {
            WireRuleId::DocumentV2 => {
                self.profile_id == "jacs-document-v2"
                    && self.operation == SigningOperation::SignDocument
                    && self.purpose == SigningPurpose::Document
                    && self.signature_family_id == SignatureFamilyId::SignatureV2
                    && self.context_rule_id == ContextRuleId::NoneV1
            }
            WireRuleId::DocumentV3Named => false,
            WireRuleId::RequestAuthV2 => {
                self.profile_id == "jacs-request-auth-v2"
                    && self.operation == SigningOperation::AuthenticateHttpRequest
                    && self.purpose == SigningPurpose::ApiRequest
                    && self.signature_family_id == SignatureFamilyId::RequestAuthV2
                    && self.context_rule_id == ContextRuleId::RequestAuthV2
            }
            WireRuleId::ResponseV2 => {
                ((self.profile_id == "jacs-response-v2/direct-response"
                    && self.operation == SigningOperation::SignBoundResponse)
                    || (self.profile_id == "jacs-response-v2/async-event"
                        && self.operation == SigningOperation::SignAsyncEvent))
                    && self.purpose == SigningPurpose::Response
                    && self.signature_family_id == SignatureFamilyId::ResponseV2
                    && self.context_rule_id == ContextRuleId::ResponseContextV2
            }
            WireRuleId::AgreementV3Proof => {
                let profile = match self.profile_id.as_str() {
                    "jacs-agreement-proposal-proof-v3" => {
                        Some(crate::agreements::v3::AgreementProofProfileV3::Proposal)
                    }
                    "jacs-agreement-amendment-proof-v3" => {
                        Some(crate::agreements::v3::AgreementProofProfileV3::Amendment)
                    }
                    "jacs-agreement-consent-proof-v3" => {
                        Some(crate::agreements::v3::AgreementProofProfileV3::Consent)
                    }
                    "jacs-agreement-witness-proof-v3" => {
                        Some(crate::agreements::v3::AgreementProofProfileV3::Witness)
                    }
                    "jacs-agreement-notary-proof-v3" => {
                        Some(crate::agreements::v3::AgreementProofProfileV3::Notary)
                    }
                    _ => None,
                };
                profile.is_some_and(|profile| {
                    serde_json::to_value(profile.operation()).ok()
                        == serde_json::to_value(&self.operation).ok()
                        && serde_json::to_value(profile.purpose()).ok()
                            == serde_json::to_value(&self.purpose).ok()
                }) && self.signature_family_id == SignatureFamilyId::AgreementProofV3
                    && self.context_rule_id == ContextRuleId::AgreementProofV3
            }
            WireRuleId::AuthorityBackedExactReceiptV1 => {
                self.signature_family_id == SignatureFamilyId::AuthorityReceiptV1
                    && self.context_rule_id == ContextRuleId::HaiExactReceiptV1
                    && !matches!(
                        self.operation,
                        SigningOperation::AuthorizeKeyEvent
                            | SigningOperation::PublishStatusCheckpoint
                            | SigningOperation::IssueAuthorityTime
                            | SigningOperation::AuthorizeRevocationCutoff
                            | SigningOperation::RecordArchivalObservation
                            | SigningOperation::ExportEcosystem(_)
                    )
            }
            WireRuleId::A2aArtifactV1 => {
                self.profile_id == "jacs-a2a-artifact-v1"
                    && self.operation == SigningOperation::SignA2aArtifact
                    && self.purpose == SigningPurpose::A2aArtifact
                    && self.signature_family_id == SignatureFamilyId::A2aArtifactV1
                    && self.context_rule_id == ContextRuleId::A2aArtifactV1
            }
            WireRuleId::LegacyRaw => {
                self.profile_id == "jacs-legacy-raw-v1"
                    && self.operation == SigningOperation::LegacyRawSign
                    && self.purpose == SigningPurpose::LegacyRaw
                    && self.signature_family_id == SignatureFamilyId::LegacyRawV0
                    && self.context_rule_id == ContextRuleId::LegacyRawV1
                    && self.schema_id.is_none()
            }
        };
        if !exact {
            return Err(invalid(
                "profile does not match a closed built-in wire/context rule",
            ));
        }
        Ok(())
    }
    pub fn projection(&self) -> Result<Value, CoreError> {
        let mut value = serde_json::to_value(self).map_err(|e| invalid(e.to_string()))?;
        value
            .as_object_mut()
            .ok_or_else(|| invalid("entry projection"))?
            .remove("conformanceFixtureDigest");
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecurityProfileRegistry {
    pub profile: String,
    pub policy_name: String,
    pub policy_version: u64,
    pub entries: Vec<SecurityProfileEntry>,
}
impl SecurityProfileRegistry {
    pub fn from_value(value: &Value) -> Result<Self, CoreError> {
        let registry: Self =
            serde_json::from_value(value.clone()).map_err(|e| invalid(e.to_string()))?;
        registry.validate()?;
        Ok(registry)
    }
    pub fn from_json(raw: &str) -> Result<Self, CoreError> {
        Self::from_value(&parse_strict_json(raw)?)
    }
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.profile != "jacs-security-profile-registry-v1"
            || self.policy_name.is_empty()
            || self.policy_version == 0
        {
            return Err(invalid("security profile registry header mismatch"));
        }
        let mut ids = BTreeSet::new();
        let mut prior: Option<String> = None;
        for entry in &self.entries {
            entry.validate()?;
            if !ids.insert(&entry.profile_id) {
                return Err(invalid("duplicate semantic profile ID"));
            }
            let canonical = canonicalize_json_try(
                &serde_json::to_value(entry).map_err(|e| invalid(e.to_string()))?,
            )?;
            if prior.as_ref().is_some_and(|p| p >= &canonical) {
                return Err(invalid(
                    "profile registry entries must be JCS-byte sorted and unique",
                ));
            }
            prior = Some(canonical);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String, CoreError> {
        self.validate()?;
        digest_json(
            "JACS-SECURITY-PROFILE-REGISTRY-V1",
            &serde_json::to_value(self).map_err(|e| invalid(e.to_string()))?,
        )
    }
    pub fn validate_for_policy(&self, policy: &VerificationPolicy) -> Result<(), CoreError> {
        policy.validate()?;
        self.validate()?;
        if self.policy_name != policy.policy_name
            || self.policy_version != policy.policy_version
            || self.digest()? != policy.security_profile_registry_digest
        {
            return Err(invalid(
                "profile registry is not the exact policy-pinned registry",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SchemaRegistryEntry {
    pub schema_id: String,
    pub schema_bundle_digest: String,
    pub legacy_signed_schema_aliases: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SchemaRegistry {
    pub profile: String,
    pub registry_id: String,
    pub version: u64,
    pub entries: Vec<SchemaRegistryEntry>,
}
impl SchemaRegistry {
    pub fn from_value(value: &Value) -> Result<Self, CoreError> {
        let registry: Self =
            serde_json::from_value(value.clone()).map_err(|e| invalid(e.to_string()))?;
        registry.validate()?;
        Ok(registry)
    }
    pub fn from_json(raw: &str) -> Result<Self, CoreError> {
        Self::from_value(&parse_strict_json(raw)?)
    }
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.profile != "jacs-schema-registry-v1"
            || self.registry_id.is_empty()
            || self.version == 0
        {
            return Err(invalid("schema registry header mismatch"));
        }
        let mut ids = BTreeSet::new();
        let mut aliases = BTreeSet::new();
        let mut previous: Option<&str> = None;
        for entry in &self.entries {
            if !absolute_uri(&entry.schema_id)
                || previous.is_some_and(|prior| prior >= entry.schema_id.as_str())
                || !ids.insert(entry.schema_id.as_str())
            {
                return Err(invalid(
                    "schema registry entries must be unique URI-sorted absolute IDs",
                ));
            }
            previous = Some(&entry.schema_id);
            validate_digest(&entry.schema_bundle_digest)?;
            if entry
                .legacy_signed_schema_aliases
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            {
                return Err(invalid("schema aliases must be sorted and unique"));
            }
            for alias in &entry.legacy_signed_schema_aliases {
                if !absolute_uri(alias) || !aliases.insert(alias.as_str()) {
                    return Err(invalid(
                        "schema aliases must be globally unique absolute URIs",
                    ));
                }
            }
        }
        for entry in &self.entries {
            for alias in &entry.legacy_signed_schema_aliases {
                if ids.contains(alias.as_str()) && alias != &entry.schema_id {
                    return Err(invalid("schema alias conflicts with another schema ID"));
                }
            }
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String, CoreError> {
        self.validate()?;
        digest_json(
            "JACS-SCHEMA-REGISTRY-V1",
            &serde_json::to_value(self).map_err(|e| invalid(e.to_string()))?,
        )
    }
    pub fn validate_for_policy(&self, policy: &VerificationPolicy) -> Result<(), CoreError> {
        self.validate()?;
        if policy.schema_registry_digest.as_deref() != Some(self.digest()?.as_str()) {
            return Err(invalid(
                "schema registry is not the exact policy-pinned registry",
            ));
        }
        Ok(())
    }
    pub fn resolve(
        &self,
        schema_id: &str,
        digest: &str,
    ) -> Result<&SchemaRegistryEntry, CoreError> {
        self.validate()?;
        self.entries
            .iter()
            .find(|entry| entry.schema_id == schema_id && entry.schema_bundle_digest == digest)
            .ok_or_else(|| invalid("selected schema pair is absent from registry"))
    }
    pub fn validate_document_v2(
        &self,
        schema_id: &str,
        digest: &str,
        bundle: &ResolvedSchemaBundle,
        document: &Value,
    ) -> Result<(), CoreError> {
        let entry = self.resolve(schema_id, digest)?;
        let signed_uri = document
            .get("$schema")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("required signed schema URI is absent"))?;
        if !entry
            .legacy_signed_schema_aliases
            .iter()
            .any(|alias| alias == signed_uri)
        {
            return Err(invalid(
                "v2 schema URI lacks an authenticated registry alias",
            ));
        }
        bundle.validate(schema_id, digest, document)
    }
}

/// Complete matcher output. It describes signed wire meaning, not identity trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MatcherDerived {
    pub profile_id: String,
    pub operation: SigningOperation,
    pub purpose: SigningPurpose,
    pub signature_family_id: SignatureFamilyId,
    pub wire_rule_id: WireRuleId,
    pub context_rule_id: ContextRuleId,
    pub actual_algorithm: String,
    #[serde(deserialize_with = "required_nullable")]
    pub schema_id: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub schema_bundle_digest: Option<String>,
    pub operation_context: Value,
}

#[derive(Debug, Clone)]
pub struct ValidatedProfileSelection {
    entry: SecurityProfileEntry,
    derived: MatcherDerived,
}
impl ValidatedProfileSelection {
    pub fn entry(&self) -> &SecurityProfileEntry {
        &self.entry
    }
    pub fn derived(&self) -> &MatcherDerived {
        &self.derived
    }
}

/// Reconstruct only implemented built-in signed wire contexts. Unsupported
/// profiles never become accepting merely because their registry row parses.
pub fn match_builtin_wire(
    raw: &str,
    entry: &SecurityProfileEntry,
    schema_registry: Option<&SchemaRegistry>,
) -> Result<Option<MatcherDerived>, CoreError> {
    entry.validate()?;
    let value = parse_strict_json(raw)?;
    let (profile, operation, purpose, family, context_rule, context) = match entry.wire_rule_id {
        WireRuleId::DocumentV2 => {
            if value
                .pointer("/jacsSignature/signatureContentVersion")
                .and_then(Value::as_str)
                != Some(crate::verify::SIGNATURE_CONTENT_VERSION_V2)
            {
                return Ok(None);
            }
            let fields: Vec<String> = serde_json::from_value(
                value
                    .pointer("/jacsSignature/fields")
                    .cloned()
                    .ok_or_else(|| invalid("document signed fields missing"))?,
            )
            .map_err(|e| invalid(e.to_string()))?;
            if fields != crate::verify::default_signed_fields(&value, "jacsSignature") {
                return Err(invalid(
                    "document v2 signed fields do not cover exact complete field set",
                ));
            }
            crate::verify::build_signature_content_v2(
                &value,
                &fields,
                "jacsSignature",
                &value["jacsSignature"],
            )?;
            (
                "jacs-document-v2",
                SigningOperation::SignDocument,
                SigningPurpose::Document,
                SignatureFamilyId::SignatureV2,
                ContextRuleId::NoneV1,
                json!({"type":"none_v1"}),
            )
        }
        WireRuleId::ResponseV2 => {
            if value
                .pointer("/jacsSignature/signatureContentVersion")
                .and_then(Value::as_str)
                != Some("jacs-response-v2")
            {
                return Ok(None);
            }
            let Some(data) = crate::response_context::inspect_response_context(&value)? else {
                return Ok(None);
            };
            data.validate_envelope_metadata(&value)?;
            let (profile, operation) = match data.operation() {
                crate::response_context::ResponseOperation::SignBoundResponse => (
                    "jacs-response-v2/direct-response",
                    SigningOperation::SignBoundResponse,
                ),
                crate::response_context::ResponseOperation::SignAsyncEvent => (
                    "jacs-response-v2/async-event",
                    SigningOperation::SignAsyncEvent,
                ),
            };
            (
                profile,
                operation,
                SigningPurpose::Response,
                SignatureFamilyId::ResponseV2,
                ContextRuleId::ResponseContextV2,
                json!({"type":"response_context_v2","value":data.operation_context()?}),
            )
        }
        _ => {
            return Err(invalid(
                "built-in matcher is unavailable for selected wire rule",
            ));
        }
    };
    let actual_algorithm = canonical_algorithm(
        value
            .pointer("/jacsSignature/signingAlgorithm")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("signed algorithm missing"))?,
    )?
    .to_string();
    if entry.profile_id != profile
        || entry.operation != operation
        || entry.purpose != purpose
        || entry.signature_family_id != family
        || entry.context_rule_id != context_rule
        || !entry.allowed_algorithms.contains(&actual_algorithm)
    {
        return Ok(None);
    }
    match (&entry.schema_id, &entry.schema_bundle_digest) {
        (Some(id), Some(digest)) => {
            let registry = schema_registry.ok_or_else(|| invalid("schema registry unavailable"))?;
            let selected = registry.resolve(id, digest)?;
            let claimed = value.get("$schema").and_then(Value::as_str);
            if !claimed.is_some_and(|claim| {
                selected
                    .legacy_signed_schema_aliases
                    .iter()
                    .any(|alias| alias == claim)
            }) {
                return Ok(None);
            }
        }
        (None, None) if value.get("$schema").is_some() => return Ok(None),
        (None, None) => {}
        _ => return Err(invalid("partial schema pair")),
    }
    Ok(Some(MatcherDerived {
        profile_id: profile.into(),
        operation,
        purpose,
        signature_family_id: family,
        wire_rule_id: entry.wire_rule_id,
        context_rule_id: context_rule,
        actual_algorithm,
        schema_id: entry.schema_id.clone(),
        schema_bundle_digest: entry.schema_bundle_digest.clone(),
        operation_context: context,
    }))
}

wire_enum!(ConformanceStatus { Match => "match", NoMatch => "no_match", Invalid => "invalid" });
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConformanceExpected {
    pub status: ConformanceStatus,
    #[serde(deserialize_with = "required_nullable")]
    pub derived: Option<MatcherDerived>,
    #[serde(deserialize_with = "required_nullable")]
    pub error_code: Option<crate::verification::ReasonCode>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConformanceFixture {
    pub fixture_id: String,
    pub wire_bytes: String,
    pub registry_entry_projection: Value,
    pub intent: VerificationIntent,
    pub expected: ConformanceExpected,
    pub input_digest: String,
    pub expected_result_digest: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConformanceFixtureBundle {
    pub wire_rule_id: WireRuleId,
    pub signature_family_id: SignatureFamilyId,
    pub fixtures: Vec<ConformanceFixture>,
}
impl ConformanceFixtureBundle {
    pub fn digest(&self) -> Result<String, CoreError> {
        digest_json(
            "JACS-CONFORMANCE-FIXTURE-BUNDLE-V1",
            &serde_json::to_value(self).map_err(|e| invalid(e.to_string()))?,
        )
    }
    pub fn validate_for_entry(
        &self,
        entry: &SecurityProfileEntry,
        schema_registry: Option<&SchemaRegistry>,
    ) -> Result<(), CoreError> {
        if self.wire_rule_id != entry.wire_rule_id
            || self.signature_family_id != entry.signature_family_id
            || self.digest()? != entry.conformance_fixture_digest
            || self.fixtures.is_empty()
        {
            return Err(invalid(
                "fixture bundle does not match exact selected entry",
            ));
        }
        let mut prior: Option<&str> = None;
        for fixture in &self.fixtures {
            if fixture.fixture_id.is_empty()
                || prior.is_some_and(|prior| prior >= fixture.fixture_id.as_str())
                || fixture.registry_entry_projection != entry.projection()?
            {
                return Err(invalid("fixture identity/order/entry projection mismatch"));
            }
            prior = Some(&fixture.fixture_id);
            fixture.intent.validate()?;
            let bytes = decode_binary(&fixture.wire_bytes)?;
            if fixture.input_digest != digest_bytes("JACS-CONFORMANCE-FIXTURE-INPUT-V1", &bytes)
                || fixture.expected_result_digest
                    != digest_json(
                        "JACS-CONFORMANCE-FIXTURE-RESULT-V1",
                        &serde_json::to_value(&fixture.expected)
                            .map_err(|e| invalid(e.to_string()))?,
                    )?
            {
                return Err(invalid("fixture input/result digest mismatch"));
            }
            let observed = match std::str::from_utf8(&bytes)
                .map_err(|_| invalid("fixture wire is not UTF-8"))
                .and_then(|raw| match_builtin_wire(raw, entry, schema_registry))
            {
                Ok(Some(derived)) => ConformanceExpected {
                    status: ConformanceStatus::Match,
                    derived: Some(derived),
                    error_code: None,
                },
                Ok(None) => ConformanceExpected {
                    status: ConformanceStatus::NoMatch,
                    derived: None,
                    error_code: None,
                },
                Err(_) => ConformanceExpected {
                    status: ConformanceStatus::Invalid,
                    derived: None,
                    error_code: Some(crate::verification::ReasonCode::MalformedEvidence),
                },
            };
            if observed != fixture.expected {
                return Err(invalid(
                    "conformance fixture result differs from built-in matcher",
                ));
            }
        }
        Ok(())
    }
}
impl SecurityProfileRegistry {
    pub fn select(
        &self,
        raw: &str,
        intent: &VerificationIntent,
        policy: &VerificationPolicy,
        bundles: &[ConformanceFixtureBundle],
        schema_registry: Option<&SchemaRegistry>,
    ) -> Result<ValidatedProfileSelection, CoreError> {
        self.validate_for_policy(policy)?;
        policy.validate_intent(intent)?;
        policy.numeric_profile.parse_json(raw)?;
        if let Some(registry) = schema_registry {
            registry.validate_for_policy(policy)?;
        }
        let mut selected = None;
        for entry in &self.entries {
            let matching_bundles = bundles
                .iter()
                .filter(|bundle| {
                    bundle.digest().ok().as_deref()
                        == Some(entry.conformance_fixture_digest.as_str())
                })
                .collect::<Vec<_>>();
            if matching_bundles.len() != 1 {
                return Err(invalid(
                    "exact conformance fixture bundle unavailable or ambiguous",
                ));
            }
            matching_bundles[0].validate_for_entry(entry, schema_registry)?;
            let Some(derived) = match_builtin_wire(raw, entry, schema_registry)? else {
                continue;
            };
            if intent.operation != entry.operation || intent.signature_profile != entry.profile_id {
                continue;
            }
            let context: crate::signing_context::SigningOperationContextV1 =
                serde_json::from_value(derived.operation_context.clone())
                    .map_err(|e| invalid(e.to_string()))?;
            if context
                .validate_for_profile(entry, intent.audience.value(), raw.len() as u64)
                .is_err()
            {
                continue;
            }
            let schema_matches = match &intent.schema {
                SchemaExpectation::Required {
                    schema_id,
                    schema_bundle_digest,
                } => {
                    entry.schema_id.as_deref() == Some(schema_id)
                        && entry.schema_bundle_digest.as_deref() == Some(schema_bundle_digest)
                }
                SchemaExpectation::Forbidden { .. } => entry.schema_id.is_none(),
                SchemaExpectation::NotApplicable { .. } => true,
            };
            if !schema_matches
                || !policy
                    .allowed_algorithms
                    .contains(&derived.actual_algorithm)
            {
                continue;
            }
            let context_matches = match &intent.context {
                ContextExpectation::ExactFields { value } => value == &derived.operation_context,
                ContextExpectation::ExactDigest { value } => {
                    value
                        == &digest_json(
                            "JACS-VERIFICATION-CONTEXT-V1",
                            &json!({"operation":intent.operation,"signatureProfile":intent.signature_profile,"context":derived.operation_context}),
                        )?
                }
                ContextExpectation::NotApplicable { .. } => {
                    entry.context_rule_id == ContextRuleId::NoneV1
                }
            };
            if !context_matches {
                continue;
            }
            if selected.is_some() {
                return Err(invalid("multiple complete registry joins"));
            }
            selected = Some(ValidatedProfileSelection {
                entry: entry.clone(),
                derived,
            });
        }
        selected.ok_or_else(|| invalid("no complete authenticated registry join"))
    }
}
