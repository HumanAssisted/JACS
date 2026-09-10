//! Regenerate the shared public verification fixture with the supported native
//! implementation. Run only during fixture maintenance, not in ordinary tests:
//! `cargo run -p jacs-binding-core --features human-approval --example generate_human_approval_fixture`
//! Stdout contains public evidence/pins/report only. The ephemeral private keys
//! are never serialized. The selected-only WebAuthn state is not edited.

use jacs::human_approval::*;
use jacs_core::{
    CoreAgent,
    identity::{JacsTime, digest_json, encode_binary},
    sign::SigningAlgorithm,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::{Value, json};
use webauthn_rs::prelude::{Passkey, Url, WebauthnBuilder};

fn pin(agent: &CoreAgent, document: &Value) -> PinnedHumanApprovalAuthorityV1 {
    let metadata = &document["jacsSignature"];
    PinnedHumanApprovalAuthorityV1 {
        agent_id: metadata["agentID"].as_str().unwrap().into(),
        agent_version: metadata["agentVersion"].as_str().unwrap().into(),
        signing_algorithm: metadata["signingAlgorithm"].as_str().unwrap().into(),
        public_key_hash: metadata["publicKeyHash"].as_str().unwrap().into(),
        public_key_raw: agent.public_key().to_vec(),
    }
}

fn main() {
    let key = SigningKey::random(&mut rand_core::OsRng);
    let point = key.verifying_key().to_encoded_point(false);
    // Public registered-credential fixture, matching the native verifier tests.
    // This does not exercise an enrollment UI, browser or physical authenticator.
    let passkey: Passkey = serde_json::from_value(json!({"cred": {
        "cred_id": encode_binary(&[7;32]),
        "cred": {"type_":"ES256", "key":{"EC_EC2": {
            "curve":"SECP256R1", "x": point.x().unwrap().to_vec(), "y": point.y().unwrap().to_vec()
        }}},
        "counter": 0, "transports": null, "user_verified": true,
        "backup_eligible": false, "backup_state": false,
        "registration_policy": "required", "extensions": {},
        "attestation": {"data":"None", "metadata":"None"}, "attestation_format":"None"
    }}))
    .unwrap();
    let origin = Url::parse("https://app.example.test").unwrap();
    let webauthn = WebauthnBuilder::new("example.test", &origin)
        .unwrap()
        .build()
        .unwrap();
    let ceremony = start_selected_human_approval_v1(&webauthn, &passkey).unwrap();
    let client_data = serde_json::to_vec(&json!({
        "type":"webauthn.get", "challenge":ceremony.challenge,
        "origin":"https://app.example.test", "crossOrigin":false
    }))
    .unwrap();
    let mut authenticator_data = jacs::crypt::hash::hash_bytes_raw(b"example.test").to_vec();
    authenticator_data.push(0x05); // Standard UP + UV flags.
    authenticator_data.extend_from_slice(&1_u32.to_be_bytes());
    let mut transcript = authenticator_data.clone();
    transcript.extend_from_slice(&jacs::crypt::hash::hash_bytes_raw(&client_data));
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
    let mut agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).unwrap();
    let document = agent
        .sign_message(&json!({"action":"reviewed exact action"}))
        .unwrap();
    let provenance = pin(&agent, &document);
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
    let expected = binding.expectation(); // Selected from trusted fixture issuance, never bundle discovery.
    let mut issuer = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).unwrap();
    let authority_binding = issuer
        .sign_message(&serde_json::to_value(binding).unwrap())
        .unwrap();
    let authority = pin(&issuer, &authority_binding);
    let bundle = HumanApprovedDocumentV1 {
        profile: HUMAN_APPROVED_DOCUMENT_PROFILE_V1.into(),
        jacs_document: document,
        human_approval: HumanApprovalEvidenceV1 {
            profile: HUMAN_APPROVAL_PROFILE_V1.into(),
            authority_binding,
            authentication_state: ceremony.authentication_state,
            assertion,
        },
    };
    let report = verify_human_approved_document_v1(
        &serde_json::to_string(&bundle).unwrap(),
        &expected,
        &authority,
        &provenance,
    )
    .unwrap();
    println!("{}", serde_json::to_string_pretty(&json!({
        "_description":"Public-only software-authenticator fixture. Caller-selected expectations/pins are test trust inputs, not discoverable authority. Current status is not evaluated.",
        "bundle":bundle, "expected":expected, "authority":authority, "provenance":provenance, "report":report,
    })).unwrap());
}
