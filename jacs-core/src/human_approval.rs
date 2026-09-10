//! Portable evidence for authority-mapped WebAuthn approval.
//!
//! The authenticator signs the standard WebAuthn challenge, NOT the intent
//! digest. A separately trusted enrollment/API authority authenticates their
//! association. An agent's envelope signature does not confer that authority.
//! Parsing these types establishes neither approval nor current authorization.
//! WebAuthn proof verification is available only in the native `jacs` facade's
//! optional `human-approval` feature; a wrapper signature alone is insufficient.

use crate::{
    CoreError,
    identity::{JacsTime, decode_binary, digest_json, validate_digest},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const HUMAN_APPROVAL_PROFILE_V1: &str = "jacs-human-approval-webauthn-mapped-v1";
pub const HUMAN_APPROVAL_BINDING_PROFILE_V1: &str = "jacs-human-approval-binding-v1";
pub const HUMAN_APPROVAL_STATE_PROFILE_V1: &str = "webauthn-rs-passkey-authentication-0.5.5-v1";
pub const HUMAN_APPROVAL_SUBJECT_PROFILE_V1: &str = "jacs-human-approved-document-v1";
pub const HUMAN_APPROVED_DOCUMENT_PROFILE_V1: &str = "jacs-human-approved-document-v1";
pub const MAX_HUMAN_APPROVED_DOCUMENT_BYTES: usize = 524_288;
pub const MAX_HUMAN_APPROVAL_EVIDENCE_BYTES: usize = 262_144;
pub const MAX_HUMAN_APPROVAL_STATE_BYTES: usize = 32_768;
pub const MAX_HUMAN_APPROVAL_ASSERTION_BYTES: usize = 32_768;
pub const MAX_HUMAN_APPROVAL_AUTHORITY_BYTES: usize = 131_072;
pub const MAX_HUMAN_APPROVAL_VALIDITY_SECONDS: i64 = 600;

fn invalid(message: &str) -> CoreError {
    CoreError::MalformedDocument(format!("human approval: {message}"))
}

fn text(value: &str) -> Result<(), CoreError> {
    if value.is_empty() || value.len() > 1_024 || value.chars().any(char::is_control) {
        return Err(invalid("missing, oversized, or control-containing context"));
    }
    Ok(())
}

fn binary(value: &str, minimum: usize, maximum: usize) -> Result<(), CoreError> {
    if value.len() > maximum.saturating_mul(2) {
        return Err(invalid("oversized binary field"));
    }
    let decoded = decode_binary(value)?;
    if !(minimum..=maximum).contains(&decoded.len()) {
        return Err(invalid("binary field length is outside the profile bounds"));
    }
    Ok(())
}

/// Bound serialized values without interpreting library-owned state.
pub fn bounded_value(value: &Value, maximum: usize) -> Result<(), CoreError> {
    let encoded = serde_json::to_vec(value).map_err(|_| invalid("JSON encoding failed"))?;
    if encoded.len() > maximum {
        return Err(invalid("evidence component exceeds the profile limit"));
    }
    crate::strict_json::validate_i_json_numbers(value)?;
    Ok(())
}

/// Digest the exact JSON value emitted by the pinned library, without editing
/// credentials, challenge, counters, policy, extensions, or other state.
pub fn authentication_state_digest_v1(state: &Value) -> Result<String, CoreError> {
    bounded_value(state, MAX_HUMAN_APPROVAL_STATE_BYTES)?;
    digest_json("JACS-HUMAN-APPROVAL-AUTHENTICATION-STATE-V1", state)
}

/// The native adapter obtains this JSON through `Passkey::get_public_key` and
/// the library's COSEKey serializer. This is a commitment, not a COSE verifier.
pub fn credential_public_key_digest_v1(public_key: &Value) -> Result<String, CoreError> {
    bounded_value(public_key, 16_384)?;
    digest_json("JACS-HUMAN-APPROVAL-COSE-KEY-V1", public_key)
}

/// Exact public Passkey-record digest for comparing the expected post-assertion
/// state with a protected persisted record. This does not confer enrollment or
/// current status and is not an additional field in the signed proof format.
pub fn credential_state_digest_v1(passkey: &Value) -> Result<String, CoreError> {
    bounded_value(passkey, MAX_HUMAN_APPROVAL_STATE_BYTES)?;
    digest_json("JACS-HUMAN-APPROVAL-CREDENTIAL-STATE-V1", passkey)
}

/// Commit to the existing exact v2 JACS signature input. Works both before
/// and after the document signature is attached: the existing input builder
/// excludes the signature value, not the signed metadata or reviewed content.
pub fn document_signature_input_digest_v1(document: &Value) -> Result<String, CoreError> {
    bounded_value(document, MAX_HUMAN_APPROVAL_EVIDENCE_BYTES)?;
    let metadata = document
        .get("jacsSignature")
        .ok_or_else(|| invalid("document signature metadata missing"))?;
    if metadata
        .get("signatureContentVersion")
        .and_then(Value::as_str)
        != Some(crate::verify::SIGNATURE_CONTENT_VERSION_V2)
    {
        return Err(invalid(
            "approved document must use the frozen JACS v2 signature input",
        ));
    }
    let fields: Vec<String> = serde_json::from_value(
        metadata
            .get("fields")
            .cloned()
            .ok_or_else(|| invalid("signed fields missing"))?,
    )
    .map_err(|_| invalid("invalid signed fields"))?;
    if fields != crate::verify::default_signed_fields(document, "jacsSignature") {
        return Err(invalid(
            "approved document must sign every non-reserved field exactly once",
        ));
    }
    let bytes =
        crate::verify::build_signature_content_v2(document, &fields, "jacsSignature", metadata)?;
    Ok(crate::identity::digest_bytes(
        "JACS-HUMAN-APPROVAL-DOCUMENT-SIGNATURE-INPUT-V1",
        bytes.as_bytes(),
    ))
}

/// The document and human proof are siblings in a compound artifact; the
/// document need not reciprocally sign the proof. Its exact input, selected
/// provenance key and the human's role are all part of the approved subject.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HumanApprovalSubjectV1 {
    pub profile: String,
    pub document_signature_input_digest: String,
    pub provenance_signer_id: String,
    pub provenance_signer_version: String,
    pub provenance_key_id: String,
    pub provenance_signing_algorithm: String,
    pub human_role: String,
}

impl HumanApprovalSubjectV1 {
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.profile != HUMAN_APPROVAL_SUBJECT_PROFILE_V1 {
            return Err(invalid("unsupported approved subject profile"));
        }
        validate_digest(&self.document_signature_input_digest)?;
        for value in [
            &self.provenance_signer_id,
            &self.provenance_signer_version,
            &self.provenance_key_id,
            &self.human_role,
        ] {
            text(value)?;
        }
        let algorithm = crate::identity::canonical_algorithm(&self.provenance_signing_algorithm)?;
        let prefix = format!("jacs-key-v1:{algorithm}:");
        binary(
            self.provenance_key_id
                .strip_prefix(&prefix)
                .ok_or_else(|| invalid("approved provenance key id has the wrong algorithm"))?,
            32,
            32,
        )?;
        Ok(())
    }
}

/// Construct the approved subject from a frozen unsigned/signed document and
/// the independently selected provenance key. This computes commitments only;
/// it does not authenticate the document, key, human role or other context.
pub fn subject_for_document_v1(
    document: &Value,
    provenance_public_key: &[u8],
    human_role: &str,
) -> Result<HumanApprovalSubjectV1, CoreError> {
    let metadata = document
        .get("jacsSignature")
        .ok_or_else(|| invalid("document signature metadata missing"))?;
    let field = |name| {
        metadata
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| invalid("document provenance field missing"))
    };
    let algorithm = field("signingAlgorithm")?;
    let subject = HumanApprovalSubjectV1 {
        profile: HUMAN_APPROVAL_SUBJECT_PROFILE_V1.into(),
        document_signature_input_digest: document_signature_input_digest_v1(document)?,
        provenance_signer_id: field("agentID")?,
        provenance_signer_version: field("agentVersion")?,
        provenance_key_id: crate::identity::canonical_key_id(&algorithm, provenance_public_key)?,
        provenance_signing_algorithm: algorithm,
        human_role: human_role.into(),
    };
    subject.validate()?;
    Ok(subject)
}

/// Signed as `/content` in an ordinary complete JACS v2 message by the
/// independently selected enrollment/API authority. Its key MUST NOT be
/// chosen from the enclosing agent artifact or from this untrusted payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HumanApprovalBindingV1 {
    pub profile: String,
    pub state_profile: String,
    pub human_id: String,
    pub prepared_intent_digest: String,
    pub subject: HumanApprovalSubjectV1,
    pub purpose: String,
    pub audience: String,
    pub operation_nonce: String,
    pub credential_id: String,
    pub credential_key_digest: String,
    pub credential_binding_digest: String,
    pub credential_generation: i64,
    pub rp_id: String,
    pub rp_origin: String,
    pub challenge: String,
    pub authentication_state_digest: String,
    pub issued_at: JacsTime,
    pub expires_at: JacsTime,
}

impl HumanApprovalBindingV1 {
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.profile != HUMAN_APPROVAL_BINDING_PROFILE_V1
            || self.state_profile != HUMAN_APPROVAL_STATE_PROFILE_V1
        {
            return Err(invalid("unsupported binding or retained-state profile"));
        }
        self.expectation().validate()?;
        binary(&self.challenge, 16, 128)?;
        validate_digest(&self.authentication_state_digest)?;
        let lifetime = self.expires_at.unix_seconds() - self.issued_at.unix_seconds();
        if !(1..=MAX_HUMAN_APPROVAL_VALIDITY_SECONDS).contains(&lifetime) {
            return Err(invalid("binding validity interval is invalid"));
        }
        Ok(())
    }

    /// Projection for comparisons, not a source of caller trust. A verifier
    /// must construct its expectation independently of submitted evidence.
    pub fn expectation(&self) -> HumanApprovalExpectationV1 {
        HumanApprovalExpectationV1 {
            human_id: self.human_id.clone(),
            prepared_intent_digest: self.prepared_intent_digest.clone(),
            subject: self.subject.clone(),
            purpose: self.purpose.clone(),
            audience: self.audience.clone(),
            operation_nonce: self.operation_nonce.clone(),
            credential_id: self.credential_id.clone(),
            credential_key_digest: self.credential_key_digest.clone(),
            credential_binding_digest: self.credential_binding_digest.clone(),
            credential_generation: self.credential_generation,
            rp_id: self.rp_id.clone(),
            rp_origin: self.rp_origin.clone(),
        }
    }

    pub fn digest(&self) -> Result<String, CoreError> {
        self.validate()?;
        let value = serde_json::to_value(self).map_err(|_| invalid("binding encoding failed"))?;
        digest_json("JACS-HUMAN-APPROVAL-BINDING-V1", &value)
    }

    /// This is the authority's challenge-issuance window. It does not establish
    /// when the authenticator signed; WebAuthn supplies no trusted timestamp.
    pub fn issuance_window_contains(&self, trusted_time: &JacsTime) -> bool {
        self.issued_at.unix_seconds() <= trusted_time.unix_seconds()
            && trusted_time.unix_seconds() < self.expires_at.unix_seconds()
    }
}

/// Independently selected expected intent and enrolled credential binding.
/// Populate from protected application state or authenticated enrollment
/// evidence under the relying party's own trust policy, NEVER by copying
/// fields from the artifact being verified. The intent digest must cover the
/// complete reviewed action/resource/key/context, excluding its own proof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HumanApprovalExpectationV1 {
    pub human_id: String,
    pub prepared_intent_digest: String,
    pub subject: HumanApprovalSubjectV1,
    pub purpose: String,
    pub audience: String,
    pub operation_nonce: String,
    pub credential_id: String,
    pub credential_key_digest: String,
    pub credential_binding_digest: String,
    pub credential_generation: i64,
    pub rp_id: String,
    pub rp_origin: String,
}

impl HumanApprovalExpectationV1 {
    pub fn validate(&self) -> Result<(), CoreError> {
        self.subject.validate()?;
        for value in [
            &self.human_id,
            &self.purpose,
            &self.audience,
            &self.rp_id,
            &self.rp_origin,
        ] {
            text(value)?;
        }
        for value in [
            &self.prepared_intent_digest,
            &self.credential_key_digest,
            &self.credential_binding_digest,
        ] {
            validate_digest(value)?;
        }
        binary(&self.operation_nonce, 16, 128)?;
        binary(&self.credential_id, 1, 1_024)?;
        if !(1..=9_007_199_254_740_991).contains(&self.credential_generation) {
            return Err(invalid(
                "credential generation must be a positive safe integer",
            ));
        }
        Ok(())
    }

    pub fn check_binding(&self, binding: &HumanApprovalBindingV1) -> Result<(), CoreError> {
        self.validate()?;
        binding.validate()?;
        if self != &binding.expectation() {
            return Err(invalid(
                "binding does not match independently expected intent and credential",
            ));
        }
        Ok(())
    }
}

/// Public evidence: it contains no unlock secret and relies on no secrecy of
/// the retained state. Issuers MUST create state with the standard library's
/// start method for exactly one selected enrolled credential, not redact or
/// alter state after creation. `authorityBinding` is a complete JACS message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HumanApprovalEvidenceV1 {
    pub profile: String,
    pub authority_binding: Value,
    pub authentication_state: Value,
    pub assertion: Value,
}

impl HumanApprovalEvidenceV1 {
    /// Strict bounded decoding only. This does not inspect WebAuthn state or
    /// authenticate anything. Native verification checks the authority first.
    pub fn parse_json(json: &str) -> Result<Self, CoreError> {
        if json.len() > MAX_HUMAN_APPROVAL_EVIDENCE_BYTES {
            return Err(invalid("evidence exceeds the profile limit"));
        }
        let parsed = crate::strict_json::parse_strict_json(json)?;
        let result: Self = serde_json::from_value(parsed)
            .map_err(|_| invalid("invalid closed evidence object"))?;
        if result.profile != HUMAN_APPROVAL_PROFILE_V1 {
            return Err(invalid("unsupported evidence profile"));
        }
        bounded_value(
            &result.authority_binding,
            MAX_HUMAN_APPROVAL_AUTHORITY_BYTES,
        )?;
        Ok(result)
    }

    /// Call only after the authority signature has authenticated the binding.
    /// Does not constitute WebAuthn proof verification.
    pub fn check_authenticated_components(
        &self,
        binding: &HumanApprovalBindingV1,
    ) -> Result<(), CoreError> {
        binding.validate()?;
        bounded_value(&self.assertion, MAX_HUMAN_APPROVAL_ASSERTION_BYTES)?;
        if authentication_state_digest_v1(&self.authentication_state)?
            != binding.authentication_state_digest
        {
            return Err(invalid(
                "retained authentication state digest differs from signed binding",
            ));
        }
        Ok(())
    }
}

/// One compound artifact: unchanged JACS provenance plus an independently
/// checked human proof that commits to that document's exact signature input.
/// The JACS document does not need a reciprocal signature over the proof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HumanApprovedDocumentV1 {
    pub profile: String,
    pub jacs_document: Value,
    pub human_approval: HumanApprovalEvidenceV1,
}

impl HumanApprovedDocumentV1 {
    pub fn parse_json(json: &str) -> Result<Self, CoreError> {
        if json.len() > MAX_HUMAN_APPROVED_DOCUMENT_BYTES {
            return Err(invalid("compound document exceeds the profile limit"));
        }
        let value = crate::strict_json::parse_strict_json(json)?;
        let result: Self = serde_json::from_value(value)
            .map_err(|_| invalid("invalid closed compound document"))?;
        result.validate_shape()?;
        Ok(result)
    }

    fn validate_shape(&self) -> Result<(), CoreError> {
        if self.profile != HUMAN_APPROVED_DOCUMENT_PROFILE_V1
            || self.human_approval.profile != HUMAN_APPROVAL_PROFILE_V1
        {
            return Err(invalid("unsupported compound approval profile"));
        }
        bounded_value(&self.jacs_document, MAX_HUMAN_APPROVAL_EVIDENCE_BYTES)?;
        let evidence = serde_json::to_value(&self.human_approval)
            .map_err(|_| invalid("approval evidence encoding failed"))?;
        bounded_value(&evidence, MAX_HUMAN_APPROVAL_EVIDENCE_BYTES)?;
        bounded_value(
            &self.human_approval.authority_binding,
            MAX_HUMAN_APPROVAL_AUTHORITY_BYTES,
        )?;
        Ok(())
    }

    /// The single frozen complete-bundle serialization used for persistence,
    /// countersigning and digest references. Validation here is not approval.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CoreError> {
        self.validate_shape()?;
        let value = serde_json::to_value(self).map_err(|_| invalid("compound encoding failed"))?;
        let bytes = crate::canonical::canonicalize_json_try(&value)?.into_bytes();
        if bytes.len() > MAX_HUMAN_APPROVED_DOCUMENT_BYTES {
            return Err(invalid("compound document exceeds the profile limit"));
        }
        Ok(bytes)
    }

    /// Hash the complete compound artifact, including the exact human proof,
    /// for a separate HAI witness/countersignature. Do not hash just its JACS arm.
    pub fn digest(&self) -> Result<String, CoreError> {
        Ok(crate::identity::digest_bytes(
            "JACS-HUMAN-APPROVED-DOCUMENT-V1",
            &self.canonical_bytes()?,
        ))
    }
}

/// The MVP does not implement a lifecycle/current-status oracle. A valid
/// retained proof must not be used as a substitute for live execution checks.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HumanApprovalCurrentStatusV1 {
    NotEvaluated,
}

/// Native success report. Neither issuance time nor a passkey counter proves
/// approval time, global one-use, present enrollment status, or honest display.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HumanApprovalVerificationV1 {
    pub profile: String,
    pub proof_valid: bool,
    pub authority_mapping_valid: bool,
    pub binding: HumanApprovalBindingV1,
    pub binding_digest: String,
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub signature_counter: u32,
    /// Derived via the standard Passkey update API after verification. This is
    /// an expected public-record digest, not a Current verdict or proof field.
    pub updated_credential_state_digest: String,
    pub current: HumanApprovalCurrentStatusV1,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HumanApprovedDocumentVerificationV1 {
    pub profile: String,
    pub bundle_digest: String,
    pub provenance_signature_valid: bool,
    pub approval: HumanApprovalVerificationV1,
    pub current: HumanApprovalCurrentStatusV1,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::encode_binary;
    use serde_json::json;

    fn binding() -> HumanApprovalBindingV1 {
        HumanApprovalBindingV1 {
            profile: HUMAN_APPROVAL_BINDING_PROFILE_V1.into(),
            state_profile: HUMAN_APPROVAL_STATE_PROFILE_V1.into(),
            human_id: "human-one".into(),
            prepared_intent_digest: format!("sha256:{}", "1".repeat(64)),
            subject: HumanApprovalSubjectV1 {
                profile: HUMAN_APPROVAL_SUBJECT_PROFILE_V1.into(),
                document_signature_input_digest: format!("sha256:{}", "4".repeat(64)),
                provenance_signer_id: "agent-one".into(),
                provenance_signer_version: "version-one".into(),
                provenance_key_id: format!("jacs-key-v1:ed25519:{}", encode_binary(&[5; 32])),
                provenance_signing_algorithm: "ed25519".into(),
                human_role: "approver".into(),
            },
            purpose: "agreement.confirm.v1".into(),
            audience: "https://api.example.test".into(),
            operation_nonce: encode_binary(&[1; 32]),
            credential_id: encode_binary(&[2; 32]),
            credential_key_digest: format!("sha256:{}", "2".repeat(64)),
            credential_binding_digest: format!("sha256:{}", "3".repeat(64)),
            credential_generation: 1,
            rp_id: "example.test".into(),
            rp_origin: "https://app.example.test".into(),
            challenge: encode_binary(&[3; 32]),
            authentication_state_digest: authentication_state_digest_v1(&json!({"ast": {}}))
                .unwrap(),
            issued_at: JacsTime::parse("2026-09-04T10:00:00Z").unwrap(),
            expires_at: JacsTime::parse("2026-09-04T10:02:00Z").unwrap(),
        }
    }

    #[test]
    fn mapped_intent_requires_independent_exact_context() {
        let original = binding();
        let expected = original.expectation();
        expected.check_binding(&original).unwrap();
        let mut other = original.clone();
        other.human_id = "another-human".into();
        assert!(expected.check_binding(&other).is_err());
        other = original.clone();
        other.operation_nonce = encode_binary(&[4; 32]);
        assert!(expected.check_binding(&other).is_err());
        other = original;
        other.purpose = "another.purpose".into();
        assert!(expected.check_binding(&other).is_err());
    }

    #[test]
    fn closed_profile_and_bounded_validity() {
        let mut value = serde_json::to_value(binding()).unwrap();
        value["extra"] = json!(true);
        assert!(serde_json::from_value::<HumanApprovalBindingV1>(value).is_err());
        let mut value = binding();
        value.state_profile = "future-or-custom-state".into();
        assert!(value.validate().is_err());
        value = binding();
        value.expires_at = JacsTime::parse("2026-09-04T10:11:00Z").unwrap();
        assert!(value.validate().is_err());
    }

    #[test]
    fn state_digest_is_canonical_and_domain_separated() {
        let state = json!({"ast": {"challenge": "example", "credentials": []}});
        assert_eq!(
            authentication_state_digest_v1(&state).unwrap(),
            authentication_state_digest_v1(&state.clone()).unwrap()
        );
        assert_ne!(
            authentication_state_digest_v1(&state).unwrap(),
            credential_public_key_digest_v1(&state).unwrap()
        );
        assert!(
            authentication_state_digest_v1(
                &json!({"oversized": "x".repeat(MAX_HUMAN_APPROVAL_STATE_BYTES)})
            )
            .is_err()
        );
    }

    #[test]
    fn duplicate_members_are_not_evidence() {
        let json = format!(
            r#"{{"profile":"{}","profile":"{}","authorityBinding":{{}},"authenticationState":{{}},"assertion":{{}}}}"#,
            HUMAN_APPROVAL_PROFILE_V1, HUMAN_APPROVAL_PROFILE_V1
        );
        assert!(HumanApprovalEvidenceV1::parse_json(&json).is_err());
    }

    #[test]
    fn compound_digest_covers_both_document_and_actual_proof() {
        let bundle = HumanApprovedDocumentV1 {
            profile: HUMAN_APPROVED_DOCUMENT_PROFILE_V1.into(),
            jacs_document: json!({"content":{"action":"reviewed"}}),
            human_approval: HumanApprovalEvidenceV1 {
                profile: HUMAN_APPROVAL_PROFILE_V1.into(),
                authority_binding: json!({"content":binding()}),
                authentication_state: json!({"ast":{}}),
                assertion: json!({"proof":"first"}),
            },
        };
        let original = bundle.digest().unwrap();
        let bytes = String::from_utf8(bundle.canonical_bytes().unwrap()).unwrap();
        assert_eq!(
            HumanApprovedDocumentV1::parse_json(&bytes)
                .unwrap()
                .digest()
                .unwrap(),
            original
        );
        let mut changed = bundle.clone();
        changed.human_approval.assertion = json!({"proof":"second"});
        assert_ne!(changed.digest().unwrap(), original);
        changed = bundle;
        changed.jacs_document["content"]["action"] = json!("another");
        assert_ne!(changed.digest().unwrap(), original);
        let mut value: Value = crate::strict_json::parse_strict_json(&bytes).unwrap();
        value["extra"] = json!(true);
        assert!(HumanApprovedDocumentV1::parse_json(&value.to_string()).is_err());
    }
}
