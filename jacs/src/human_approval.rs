//! Native verification of independently authority-mapped WebAuthn approval.
//!
//! This profile trusts the API/enrollment authority separately from the agent
//! signer. It does not protect against compromise of that authority or the
//! review application. The authenticator signs a standard random challenge;
//! it does not directly sign a JACS document or its digest.
//!
//! The retained 0.5.5 state is public, version-pinned, authenticated before
//! deserialization, and never edited. Current enrollment, recovery, revocation,
//! one-use execution and trusted approval time are outside this MVP result.

pub use jacs_core::human_approval::*;
use jacs_core::{
    CoreError,
    identity::{canonical_key_id, encode_binary},
    sign::SigningAlgorithm,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use webauthn_rs::prelude::{
    COSEKey, Passkey, PasskeyAuthentication, PublicKeyCredential, Url, Webauthn, WebauthnBuilder,
};

fn invalid(message: &str) -> CoreError {
    CoreError::MalformedDocument(format!("human approval: {message}"))
}

/// An independently pinned API/enrollment authority, NOT a key selected from
/// the submitted artifact or its enclosing agent signature. Application trust
/// policy must authorize this key to issue human-approval mappings. Its exact
/// registered hash is explicit to preserve the existing native JACS hash
/// contract; raw-key cryptography does not trust that hash as a substitute key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PinnedHumanApprovalAuthorityV1 {
    pub agent_id: String,
    pub agent_version: String,
    pub signing_algorithm: String,
    pub public_key_hash: String,
    pub public_key_raw: Vec<u8>,
}

impl PinnedHumanApprovalAuthorityV1 {
    pub fn validate(&self) -> Result<SigningAlgorithm, CoreError> {
        if [
            &self.agent_id,
            &self.agent_version,
            &self.signing_algorithm,
            &self.public_key_hash,
        ]
        .iter()
        .any(|field| field.is_empty() || field.len() > 1_024 || field.chars().any(char::is_control))
            || self.public_key_raw.len() > 16_384
        {
            return Err(invalid("invalid pinned authority"));
        }
        canonical_key_id(&self.signing_algorithm, &self.public_key_raw)?;
        SigningAlgorithm::from_wire_str(&self.signing_algorithm)
            .ok_or_else(|| CoreError::UnsupportedAlgorithm(self.signing_algorithm.clone()))
    }
}

/// Same exact public-key tuple, independently selected for the JACS document
/// provenance role. This is NOT the API authority unless policy explicitly
/// selected the same signer for that different role.
pub type PinnedJacsProvenanceV1 = PinnedHumanApprovalAuthorityV1;

/// The one reusable credential-key commitment. Callers obtain this key from
/// a registered Passkey through the standard library getter, not a hand-rolled
/// COSE decoder. The portable digest routine defines its frozen JSON input.
pub fn credential_key_digest_v1(public_key: &COSEKey) -> Result<String, CoreError> {
    let value =
        serde_json::to_value(public_key).map_err(|_| invalid("COSE key encoding failed"))?;
    credential_public_key_digest_v1(&value)
}

/// Selected-only ceremony produced by the ordinary safe library API. The API
/// can persist the original state and expose its exact public serialization;
/// do not redact a multi-credential state or rewrite the generated challenge.
#[derive(Debug, Clone)]
pub struct SelectedHumanApprovalCeremonyV1 {
    pub public_key: Value,
    pub authentication_state: Value,
    pub challenge: String,
    pub authentication_state_digest: String,
    pub credential_id: String,
    pub credential_key_digest: String,
}

pub fn start_selected_human_approval_v1(
    webauthn: &Webauthn,
    selected: &Passkey,
) -> Result<SelectedHumanApprovalCeremonyV1, CoreError> {
    let (options, state) = webauthn
        .start_passkey_authentication(std::slice::from_ref(selected))
        .map_err(|_| invalid("selected credential cannot start a WebAuthn ceremony"))?;
    let public_key =
        serde_json::to_value(options).map_err(|_| invalid("WebAuthn options encoding failed"))?;
    let authentication_state =
        serde_json::to_value(state).map_err(|_| invalid("WebAuthn state encoding failed"))?;
    let challenge = public_key
        .pointer("/publicKey/challenge")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("unsupported WebAuthn options profile"))?
        .to_owned();
    let credential_bytes: &[u8] = selected.cred_id().as_ref();
    Ok(SelectedHumanApprovalCeremonyV1 {
        public_key,
        challenge,
        authentication_state_digest: authentication_state_digest_v1(&authentication_state)?,
        authentication_state,
        credential_id: encode_binary(credential_bytes),
        credential_key_digest: credential_key_digest_v1(selected.get_public_key())?,
    })
}

/// Authenticate a mapping using the existing portable JACS v2 verifier over
/// the actual submitted value, with exact pinned identity/algorithm/hash and
/// complete signed fields. No storage lookup or attacker-selected key fetch.
fn verify_pinned_document(
    document: &Value,
    authority: &PinnedHumanApprovalAuthorityV1,
) -> Result<(), CoreError> {
    let algorithm = authority.validate()?;
    let metadata = document
        .get("jacsSignature")
        .ok_or_else(|| invalid("authority signature missing"))?;
    for (name, expected) in [
        ("agentID", authority.agent_id.as_str()),
        ("agentVersion", authority.agent_version.as_str()),
        ("signingAlgorithm", authority.signing_algorithm.as_str()),
        ("publicKeyHash", authority.public_key_hash.as_str()),
        (
            "signatureContentVersion",
            jacs_core::verify::SIGNATURE_CONTENT_VERSION_V2,
        ),
    ] {
        if metadata.get(name).and_then(Value::as_str) != Some(expected) {
            return Err(CoreError::SignatureInvalid(
                "approval authority does not match the independently pinned signer".into(),
            ));
        }
    }
    // This also rejects a partial-field or duplicate-field signature before
    // any retained WebAuthn state is interpreted.
    document_signature_input_digest_v1(document)?;
    let result = jacs_core::verify::verify_document(
        document,
        &authority.public_key_raw,
        algorithm,
        "jacsSignature",
    )?;
    if !result.valid {
        return Err(CoreError::SignatureInvalid(
            "approval mapping signature did not verify".into(),
        ));
    }
    if let Some(checksum) = document.get("jacsSha256") {
        let actual = jacs_core::signing::document_hash_v1(document)?;
        if checksum.as_str() != Some(actual.as_str()) {
            return Err(invalid(
                "authority document checksum differs from submitted bytes",
            ));
        }
    }
    Ok(())
}

fn verify_authority_binding(
    document: &Value,
    authority: &PinnedHumanApprovalAuthorityV1,
) -> Result<HumanApprovalBindingV1, CoreError> {
    if document.get("jacsType").and_then(Value::as_str) != Some("message") {
        return Err(invalid(
            "authority binding must be an ordinary JACS message",
        ));
    }
    verify_pinned_document(document, authority)?;
    let binding: HumanApprovalBindingV1 = serde_json::from_value(
        document
            .get("content")
            .cloned()
            .ok_or_else(|| invalid("signed authority content missing"))?,
    )
    .map_err(|_| invalid("invalid closed authority binding"))?;
    binding.validate()?;
    Ok(binding)
}

fn rp_verifier(expected: &HumanApprovalExpectationV1) -> Result<Webauthn, CoreError> {
    let origin =
        Url::parse(&expected.rp_origin).map_err(|_| invalid("invalid expected RP origin"))?;
    let local = matches!(expected.rp_id.as_str(), "localhost" | "127.0.0.1");
    if !(origin.scheme() == "https" || (local && origin.scheme() == "http"))
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err(invalid(
            "expected RP origin must be an exact HTTPS origin (HTTP only for explicit localhost)",
        ));
    }
    WebauthnBuilder::new(&expected.rp_id, &origin)
        .and_then(|builder| builder.rp_name("JACS human approval").build())
        .map_err(|_| invalid("invalid expected WebAuthn RP configuration"))
}

fn verify_inner(
    evidence_json: &str,
    expected: &HumanApprovalExpectationV1,
    authority: &PinnedHumanApprovalAuthorityV1,
) -> Result<HumanApprovalVerificationV1, CoreError> {
    expected.validate()?;
    let evidence = HumanApprovalEvidenceV1::parse_json(evidence_json)?;
    // Security boundary: authenticate exact issuer mapping before touching
    // library-owned state. Its signature is not an approval verdict.
    let binding = verify_authority_binding(&evidence.authority_binding, authority)?;
    expected.check_binding(&binding)?;
    evidence.check_authenticated_components(&binding)?;

    let state = &evidence.authentication_state;
    let credentials = state
        .pointer("/ast/credentials")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("unsupported retained WebAuthn state"))?;
    if credentials.len() != 1
        || state.pointer("/ast/challenge").and_then(Value::as_str)
            != Some(binding.challenge.as_str())
        || state.pointer("/ast/policy").and_then(Value::as_str) != Some("required")
        || state
            .pointer("/ast/appid")
            .is_none_or(|value| !value.is_null())
    {
        return Err(invalid(
            "state must bind the signed challenge and exactly one required-UV passkey without AppID fallback",
        ));
    }
    // Read the pinned serializer representation into the library's public
    // Passkey type. Neither the state nor its contained credential is changed.
    // This snapshot becomes usable only after the authority/state commitment
    // and caller's independent enrollment expectation have both been checked.
    let mut selected: Passkey = serde_json::from_value(json!({"cred": credentials[0]}))
        .map_err(|_| invalid("selected enrolled credential is not a supported Passkey"))?;
    let selected_id: &[u8] = selected.cred_id().as_ref();
    if encode_binary(selected_id) != expected.credential_id
        || credential_key_digest_v1(selected.get_public_key())? != expected.credential_key_digest
    {
        return Err(invalid(
            "state credential differs from independently enrolled key",
        ));
    }
    let authentication: PasskeyAuthentication = serde_json::from_value(state.clone())
        .map_err(|_| invalid("unsupported pinned WebAuthn state serialization"))?;
    let assertion: PublicKeyCredential = serde_json::from_value(evidence.assertion)
        .map_err(|_| invalid("malformed standard WebAuthn assertion"))?;
    let result = rp_verifier(expected)?
        .finish_passkey_authentication(&assertion, &authentication)
        .map_err(|_| {
            CoreError::SignatureInvalid("standard WebAuthn assertion did not verify".into())
        })?;
    if !result.user_verified() || result.cred_id() != selected.cred_id() {
        return Err(CoreError::SignatureInvalid(
            "assertion lacks required UV or used another credential".into(),
        ));
    }
    // Update a separate public credential projection using the safe library
    // API, never the retained ceremony state. Consumers may compare this exact
    // expected record digest to protected live storage without re-verifying.
    selected
        .update_credential(&result)
        .ok_or_else(|| invalid("verified credential update did not match selected key"))?;
    let updated = serde_json::to_value(&selected)
        .map_err(|_| invalid("verified credential encoding failed"))?;
    let updated_credential_state_digest = credential_state_digest_v1(&updated)?;
    Ok(HumanApprovalVerificationV1 {
        profile: HUMAN_APPROVAL_PROFILE_V1.into(),
        proof_valid: true,
        authority_mapping_valid: true,
        binding_digest: binding.digest()?,
        binding,
        user_verified: result.user_verified(),
        backup_eligible: result.backup_eligible(),
        backup_state: result.backup_state(),
        signature_counter: result.counter(),
        updated_credential_state_digest,
        current: HumanApprovalCurrentStatusV1::NotEvaluated,
    })
}

/// Verify retained human-approval evidence, NOT current execution authority.
///
/// `expected` must contain the caller-selected human, complete reviewed intent,
/// operation nonce, purpose, audience, RP and independently authenticated
/// credential binding. The public Passkey is obtained from the authenticated
/// selected-only state and checked against that exact expected enrolled key.
/// The separately pinned API authority cannot be supplied by the agent artifact.
///
/// Success leaves `current = not_evaluated`: a caller executing a live action
/// must additionally check a trusted current clock/window, lifecycle status,
/// session/action authorization and atomic one-use state. The mapped profile
/// proves neither an authenticator-signed intent digest nor a trusted timestamp.
/// It also does not verify the sibling JACS document: compound verification
/// must verify that document and compare its exact input/provenance to `subject`.
pub fn verify_human_approval_v1(
    evidence_json: &str,
    expected: &HumanApprovalExpectationV1,
    authority: &PinnedHumanApprovalAuthorityV1,
) -> Result<HumanApprovalVerificationV1, CoreError> {
    verify_inner(evidence_json, expected, authority).inspect_err(|error| {
        tracing::warn!(
            event = "jacs.human_approval.rejected",
            error_kind = error.code(),
            "Human approval evidence failed verification"
        );
    })
}

/// Verify both arms of the compound artifact using separately selected
/// authority and provenance pins. This confirms JACS signature integrity and
/// exact human-approved signing-input linkage, not schema/application policy,
/// referenced external media, lifecycle, global one-use, or trusted approval
/// time. Those checks must never be inferred from `provenance_signature_valid`.
pub fn verify_human_approved_document_v1(
    bundle_json: &str,
    expected: &HumanApprovalExpectationV1,
    authority: &PinnedHumanApprovalAuthorityV1,
    provenance: &PinnedJacsProvenanceV1,
) -> Result<HumanApprovedDocumentVerificationV1, CoreError> {
    let verify = || {
        expected.validate()?;
        let bundle = HumanApprovedDocumentV1::parse_json(bundle_json)?;
        verify_pinned_document(&bundle.jacs_document, provenance)?;
        let subject = subject_for_document_v1(
            &bundle.jacs_document,
            &provenance.public_key_raw,
            &expected.subject.human_role,
        )?;
        if subject != expected.subject {
            return Err(invalid(
                "document differs from the independently expected approved subject",
            ));
        }
        let evidence_json = serde_json::to_string(&bundle.human_approval)
            .map_err(|_| invalid("evidence encoding failed"))?;
        let approval = verify_inner(&evidence_json, expected, authority)?;
        Ok(HumanApprovedDocumentVerificationV1 {
            profile: HUMAN_APPROVED_DOCUMENT_PROFILE_V1.into(),
            bundle_digest: bundle.digest()?,
            provenance_signature_valid: true,
            approval,
            current: HumanApprovalCurrentStatusV1::NotEvaluated,
        })
    };
    verify().inspect_err(|error: &CoreError| {
        tracing::warn!(
            event = "jacs.human_approved_document.rejected",
            error_kind = error.code(),
            "Compound human-approved document failed verification"
        );
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use jacs_core::identity::{JacsTime, digest_json};
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};

    /// Test-only software authenticator fixture. The production verifier is
    /// still the standard WebAuthn library. No generated ceremony state is
    /// modified; the test signs the normal authentication transcript with an
    /// ephemeral registered P-256 key and does not use any external target.
    fn valid_bundle() -> (
        HumanApprovedDocumentV1,
        HumanApprovalExpectationV1,
        PinnedHumanApprovalAuthorityV1,
        PinnedJacsProvenanceV1,
    ) {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let point = key.verifying_key().to_encoded_point(false);
        let passkey: Passkey = serde_json::from_value(json!({"cred": {
            "cred_id": encode_binary(&[7;32]),
            "cred": {"type_":"ES256", "key":{"EC_EC2": {
                "curve":"SECP256R1", "x": point.x().unwrap().to_vec(), "y": point.y().unwrap().to_vec()
            }}},
            "counter": 0, "transports": null, "user_verified": true,
            "backup_eligible": false, "backup_state": false,
            "registration_policy": "required", "extensions": {},
            "attestation": {"data":"None", "metadata":"None"}, "attestation_format":"None"
        }})).unwrap();
        let origin = Url::parse("https://app.example.test").unwrap();
        let webauthn = WebauthnBuilder::new("example.test", &origin)
            .unwrap()
            .build()
            .unwrap();
        let ceremony = start_selected_human_approval_v1(&webauthn, &passkey).unwrap();
        assert_eq!(
            ceremony
                .authentication_state
                .pointer("/ast/credentials")
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            ceremony.authentication_state["ast"]["challenge"],
            json!(ceremony.challenge)
        );
        assert_eq!(
            ceremony.public_key["publicKey"]["userVerification"],
            json!("required")
        );
        let client_data = serde_json::to_vec(&json!({
            "type":"webauthn.get", "challenge":ceremony.challenge,
            "origin":"https://app.example.test", "crossOrigin":false
        }))
        .unwrap();
        let mut authenticator_data = crate::crypt::hash::hash_bytes_raw(b"example.test").to_vec();
        authenticator_data.push(0x05); // Standard UP + UV flags.
        authenticator_data.extend_from_slice(&1_u32.to_be_bytes());
        let mut transcript = authenticator_data.clone();
        transcript.extend_from_slice(&crate::crypt::hash::hash_bytes_raw(&client_data));
        let signature: Signature = key.sign(&transcript);
        let assertion = json!({
            "id":ceremony.credential_id, "rawId":ceremony.credential_id,
            "type":"public-key", "extensions":{},
            "response": {
                "authenticatorData":encode_binary(&authenticator_data),
                "clientDataJSON":encode_binary(&client_data),
                "signature":encode_binary(signature.to_der().as_bytes()), "userHandle":null
            }
        });
        let mut provenance_agent =
            jacs_core::CoreAgent::ephemeral(SigningAlgorithm::Ed25519).unwrap();
        let document = provenance_agent
            .sign_message(&json!({"action":"reviewed exact action"}))
            .unwrap();
        let provenance = authority(&provenance_agent, &document);
        let binding = HumanApprovalBindingV1 {
            profile: HUMAN_APPROVAL_BINDING_PROFILE_V1.into(),
            state_profile: HUMAN_APPROVAL_STATE_PROFILE_V1.into(),
            human_id: "enrolled-human".into(),
            prepared_intent_digest: digest_json(
                "TEST-REVIEWED-INTENT",
                &json!({"action":"reviewed exact action"}),
            )
            .unwrap(),
            subject: subject_for_document_v1(&document, &provenance.public_key_raw, "approver")
                .unwrap(),
            purpose: "document.approve.v1".into(),
            audience: "https://app.example.test".into(),
            operation_nonce: encode_binary(&[6; 32]),
            credential_id: ceremony.credential_id,
            credential_key_digest: ceremony.credential_key_digest,
            credential_binding_digest: digest_json(
                "TEST-INDEPENDENT-ENROLLMENT",
                &json!({"human":"enrolled-human"}),
            )
            .unwrap(),
            credential_generation: 1,
            rp_id: "example.test".into(),
            rp_origin: "https://app.example.test".into(),
            challenge: ceremony.challenge,
            authentication_state_digest: ceremony.authentication_state_digest,
            issued_at: JacsTime::parse("2026-09-04T10:00:00Z").unwrap(),
            expires_at: JacsTime::parse("2026-09-04T10:02:00Z").unwrap(),
        };
        let expected = binding.expectation(); // Trusted test fixture's issuance inputs.
        let mut issuer = jacs_core::CoreAgent::ephemeral(SigningAlgorithm::Ed25519).unwrap();
        let authority_binding = issuer
            .sign_message(&serde_json::to_value(binding).unwrap())
            .unwrap();
        let issuer_pin = authority(&issuer, &authority_binding);
        (
            HumanApprovedDocumentV1 {
                profile: HUMAN_APPROVED_DOCUMENT_PROFILE_V1.into(),
                jacs_document: document,
                human_approval: HumanApprovalEvidenceV1 {
                    profile: HUMAN_APPROVAL_PROFILE_V1.into(),
                    authority_binding,
                    authentication_state: ceremony.authentication_state,
                    assertion,
                },
            },
            expected,
            issuer_pin,
            provenance,
        )
    }

    #[test]
    fn standard_passkey_proof_and_jacs_provenance_verify_without_current_claim() {
        let (bundle, expected, issuer, provenance) = valid_bundle();
        let bytes = String::from_utf8(bundle.canonical_bytes().unwrap()).unwrap();
        let report =
            verify_human_approved_document_v1(&bytes, &expected, &issuer, &provenance).unwrap();
        assert!(report.provenance_signature_valid && report.approval.proof_valid);
        assert!(report.approval.authority_mapping_valid && report.approval.user_verified);
        assert_eq!(report.current, HumanApprovalCurrentStatusV1::NotEvaluated);
        assert_eq!(
            report.approval.current,
            HumanApprovalCurrentStatusV1::NotEvaluated
        );
        assert_eq!(report.bundle_digest, bundle.digest().unwrap());
        let state_credential = &bundle.human_approval.authentication_state["ast"]["credentials"][0];
        let expected_update: Passkey =
            serde_json::from_value(json!({"cred":state_credential})).unwrap();
        // The test's normal assertion increments its ephemeral credential from
        // zero to one; the adapter must expose a distinct derived public state.
        let before =
            credential_state_digest_v1(&serde_json::to_value(&expected_update).unwrap()).unwrap();
        assert_ne!(report.approval.updated_credential_state_digest, before);
        assert_eq!(report.approval.signature_counter, 1);
        // Read-only access remains possible; the signed retained state did not
        // change when the verifier updated its independent public projection.
        let initial_id: &[u8] = expected_update.cred_id().as_ref();
        assert_eq!(initial_id, &[7; 32]);
        assert!(
            !report
                .approval
                .binding
                .issuance_window_contains(&JacsTime::parse("2026-09-04T10:03:00Z").unwrap())
        );
    }

    #[test]
    fn valid_proof_requires_callers_exact_intent_and_enrollment() {
        let (bundle, expected, issuer, provenance) = valid_bundle();
        let bytes = String::from_utf8(bundle.canonical_bytes().unwrap()).unwrap();
        let mut other = expected.clone();
        other.human_id = "another-human".into();
        assert!(verify_human_approved_document_v1(&bytes, &other, &issuer, &provenance).is_err());
        other = expected.clone();
        other.operation_nonce = encode_binary(&[9; 32]);
        assert!(verify_human_approved_document_v1(&bytes, &other, &issuer, &provenance).is_err());
        other = expected.clone();
        other.subject.human_role = "different-role".into();
        assert!(verify_human_approved_document_v1(&bytes, &other, &issuer, &provenance).is_err());
        other = expected;
        other.credential_generation += 1;
        assert!(verify_human_approved_document_v1(&bytes, &other, &issuer, &provenance).is_err());
    }

    #[test]
    fn persisted_public_bundle_verifies_repeatedly_without_signing_key_storage() {
        let (bundle, expected, issuer, provenance) = valid_bundle();
        // The fixture's private signing keys have already been dropped. Only
        // public evidence goes to disk; verification is neither enrollment nor
        // a claim that the archived operation may execute again.
        let storage = tempfile::tempdir().unwrap();
        let path = storage.path().join("approved-document.json");
        let bytes = bundle.canonical_bytes().unwrap();
        std::fs::write(&path, &bytes).unwrap();
        let expected_digest = bundle.digest().unwrap();
        drop(bundle);

        for _ in 0..2 {
            let submitted = std::fs::read_to_string(&path).unwrap();
            let report =
                verify_human_approved_document_v1(&submitted, &expected, &issuer, &provenance)
                    .unwrap();
            assert!(report.provenance_signature_valid && report.approval.proof_valid);
            assert_eq!(report.bundle_digest, expected_digest);
            assert_eq!(report.current, HumanApprovalCurrentStatusV1::NotEvaluated);
            assert_eq!(
                report.approval.current,
                HumanApprovalCurrentStatusV1::NotEvaluated
            );
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
        assert_eq!(std::fs::read_dir(storage.path()).unwrap().count(), 1);
    }

    #[test]
    fn ordinary_provenance_is_not_a_compound_human_approval() {
        let (bundle, expected, issuer, provenance) = valid_bundle();
        // Prove the service document is genuine before checking the stronger
        // contract. Neither arm alone is a complete human-approved artifact.
        verify_pinned_document(&bundle.jacs_document, &provenance).unwrap();
        let evidence = serde_json::to_string(&bundle.human_approval).unwrap();
        assert!(
            verify_human_approval_v1(&evidence, &expected, &issuer)
                .unwrap()
                .proof_valid
        );
        for incomplete in [
            serde_json::to_string(&bundle.jacs_document).unwrap(),
            evidence,
        ] {
            assert!(
                verify_human_approved_document_v1(&incomplete, &expected, &issuer, &provenance)
                    .is_err()
            );
        }
    }

    #[test]
    fn caller_selected_pins_are_checked_for_each_approval_and_provenance_role() {
        let (bundle, expected, issuer, provenance) = valid_bundle();
        let bytes = String::from_utf8(bundle.canonical_bytes().unwrap()).unwrap();
        assert_ne!(issuer.public_key_raw, provenance.public_key_raw);
        verify_human_approved_document_v1(&bytes, &expected, &issuer, &provenance).unwrap();
        assert!(
            verify_human_approved_document_v1(&bytes, &expected, &provenance, &provenance).is_err()
        );
        assert!(verify_human_approved_document_v1(&bytes, &expected, &issuer, &issuer).is_err());
    }

    fn authority(agent: &jacs_core::CoreAgent, document: &Value) -> PinnedHumanApprovalAuthorityV1 {
        let metadata = &document["jacsSignature"];
        PinnedHumanApprovalAuthorityV1 {
            agent_id: metadata["agentID"].as_str().unwrap().into(),
            agent_version: metadata["agentVersion"].as_str().unwrap().into(),
            signing_algorithm: metadata["signingAlgorithm"].as_str().unwrap().into(),
            public_key_hash: metadata["publicKeyHash"].as_str().unwrap().into(),
            public_key_raw: agent.public_key().to_vec(),
        }
    }

    #[test]
    fn mapping_authentication_precedes_closed_binding_decode() {
        let mut agent = jacs_core::CoreAgent::ephemeral(SigningAlgorithm::Ed25519).unwrap();
        let mut message = agent.sign_message(&json!({"not": "a binding"})).unwrap();
        let pinned = authority(&agent, &message);
        message["content"] = json!({"tampered": true});
        let error = verify_authority_binding(&message, &pinned).unwrap_err();
        assert!(matches!(error, CoreError::SignatureInvalid(_)));
    }

    #[test]
    fn authority_identity_cannot_come_from_submitted_document() {
        let mut enrolled = jacs_core::CoreAgent::ephemeral(SigningAlgorithm::Ed25519).unwrap();
        let message = enrolled.sign_message(&json!({})).unwrap();
        let pinned = authority(&enrolled, &message);
        let mut unrelated = jacs_core::CoreAgent::ephemeral(SigningAlgorithm::Ed25519).unwrap();
        let other = unrelated.sign_message(&json!({})).unwrap();
        assert!(matches!(
            verify_authority_binding(&other, &pinned),
            Err(CoreError::SignatureInvalid(_))
        ));
    }

    #[test]
    fn proof_subject_is_unchanged_by_attaching_signature() {
        let mut agent = jacs_core::CoreAgent::ephemeral(SigningAlgorithm::Ed25519).unwrap();
        let document = agent.sign_message(&json!({"action": "reviewed"})).unwrap();
        let before = document_signature_input_digest_v1(&document).unwrap();
        let mut unsigned = document.clone();
        unsigned["jacsSignature"]
            .as_object_mut()
            .unwrap()
            .remove("signature");
        assert_eq!(
            before,
            document_signature_input_digest_v1(&unsigned).unwrap()
        );
        unsigned["content"]["action"] = json!("another action");
        assert_ne!(
            before,
            document_signature_input_digest_v1(&unsigned).unwrap()
        );
    }
}
