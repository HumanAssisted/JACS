//! Real native fixture, authority refusals and legacy-card compatibility.
#![cfg(feature = "a2a")]
#[path = "../examples/support/a2a_v1.rs"]
mod support;
use jacs::agent::boilerplate::BoilerPlate;
use serde_json::{Value, json};

#[test]
fn v1_direct_pq_root_uses_detached_jws_and_explicit_trust() {
    use jacs::a2a::v1;
    let mut agent = jacs::agent::Agent::ephemeral("pq2025").unwrap();
    agent
        .create_agent_and_load(
            &json!({"jacsAgentType":"ai", "name":"v1-pq", "description":"Direct PQ v1 test"})
                .to_string(),
            true,
            Some("pq2025"),
        )
        .unwrap();
    let id = agent.get_id().unwrap();
    let version = agent.get_version().unwrap();
    let root = agent.get_public_key().unwrap().clone();
    let jwk = jacs_core::jose::mldsa87_public_jwk(&root).unwrap();
    let projection = v1::project_agent_card(&agent, "http://127.0.0.1:18080/a2a").unwrap();
    let card = v1::export_agent_card(&mut agent, "unused", projection).unwrap();
    assert!(card["signatures"][0]["protected"].is_string());
    assert!(card["signatures"][0]["signature"].is_string());
    assert!(card["signatures"][0].get("jws").is_none());
    assert_eq!(card["supportedInterfaces"][0]["protocolVersion"], "1.0");
    assert_eq!(
        card["capabilities"]["extensions"][0]["params"]
            .as_object()
            .unwrap()
            .len(),
        3
    );
    v1::verify_root_card(&card, &jwk, &id, &version, &root).unwrap();
    assert!(v1::verify_root_card(&card, &jwk, "other", &version, &root).is_err());
    assert!(v1::verify_root_card(&card, &jwk, &id, "other", &root).is_err());
    let wrong = jacs_core::Pq2025Signer::generate().unwrap();
    use jacs_core::DetachedSigner;
    assert!(v1::verify_root_card(&card, &jwk, &id, &version, wrong.public_key()).is_err());
    let mut tampered = card.clone();
    tampered["name"] = json!("tampered");
    assert!(v1::verify_root_card(&tampered, &jwk, &id, &version, &root).is_err());

    // A valid root signature cannot make unsupported profile fields valid.
    use base64::{
        Engine as _,
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    };
    use jacs::crypt::KeyManager;
    for (field, value) in [
        ("skills", json!([])),
        ("defaultInputModes", json!([])),
        ("supportedInterfaces", json!([])),
    ] {
        let mut invalid = card.clone();
        invalid.as_object_mut().unwrap().remove("signatures");
        invalid[field] = value;
        let payload = jacs_core::canonical::canonicalize_json_try(&invalid).unwrap();
        let input = jacs_core::jose::mldsa87_jws_signing_input(
            payload.as_bytes(),
            jwk["kid"].as_str().unwrap(),
        )
        .unwrap();
        let signature =
            URL_SAFE_NO_PAD.encode(STANDARD.decode(agent.sign_string(&input).unwrap()).unwrap());
        invalid["signatures"] =
            json!([{"protected": input.split('.').next().unwrap(), "signature":signature}]);
        assert!(
            v1::verify_root_card(&invalid, &jwk, &id, &version, &root).is_err(),
            "{field}"
        );
    }
}

#[test]
fn finite_v1_fixture_preserves_native_authority_and_legacy_contracts() {
    let fixture = support::fixture("http://127.0.0.1:18080/a2a").unwrap();
    let verdict = support::verify(&fixture).unwrap();
    assert_eq!(verdict["native_binding_valid"], true);
    assert_eq!(verdict["native_report_integrity_valid"], true);
    let mut wrong_algorithm = fixture.clone();
    wrong_algorithm["rootAlgorithm"] = json!("pq2025");
    assert_eq!(
        support::verify(&wrong_algorithm).unwrap()["native_report_integrity_valid"],
        false,
        "a mismatched explicit root algorithm must never fall back to Ed25519"
    );
    wrong_algorithm["rootAlgorithm"] = json!("unsupported");
    assert!(support::verify(&wrong_algorithm).is_err());
    assert_eq!(fixture["rejectedProfiles"].as_array().unwrap().len(), 7);
    for name in [
        "scalar_extension_params",
        "array_extension_params",
        "boolean_extension_params",
    ] {
        assert!(
            fixture["rejectedProfiles"]
                .as_array()
                .unwrap()
                .contains(&json!(name))
        );
    }
    assert!(fixture["card"].get("metadata").is_none());
    assert!(fixture["card"].get("protocolVersions").is_none());
    assert_eq!(
        fixture["card"]["supportedInterfaces"][0]["protocolVersion"],
        "1.0"
    );
    assert!(fixture["legacyCard"]["signatures"][0]["jws"].is_string());
    assert!(
        fixture["legacyCard"]["signatures"][0]
            .get("protected")
            .is_none()
    );
    assert!(fixture["legacyCard"]["metadata"]["jacsCompatBindingHash"].is_string());
    for vector in fixture["vectors"].as_array().unwrap() {
        let mut input = fixture.clone();
        input["card"] = vector["card"].clone();
        assert_eq!(
            support::verify(&input).unwrap()["native_binding_valid"],
            true
        );
    }
    for (name, binding) in fixture["negativeBindings"].as_object().unwrap() {
        let mut input = fixture.clone();
        input["binding"] = binding.clone();
        input["card"]["capabilities"]["extensions"][0]["params"]["jacsCompatBindingHash"] =
            binding["jacsSha256"].clone();
        assert_eq!(
            support::verify(&input).unwrap()["native_binding_valid"],
            false,
            "{name}"
        );
    }
    for case in [
        "wrong_root",
        "wrong_jwk",
        "missing_hash",
        "changed_hash",
        "duplicate_extension",
    ] {
        let mut input = fixture.clone();
        match case {
            "wrong_root" => input["trustedRoot"] = json!(vec![0_u8; 32]),
            "wrong_jwk" => input["jwk"]["x"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            "missing_hash" => {
                input["card"]["capabilities"]["extensions"][0]["params"]
                    .as_object_mut()
                    .unwrap()
                    .remove("jacsCompatBindingHash");
            }
            "changed_hash" => {
                input["card"]["capabilities"]["extensions"][0]["params"]["jacsCompatBindingHash"] =
                    json!("bad")
            }
            _ => {
                let duplicate = input["card"]["capabilities"]["extensions"][0].clone();
                input["card"]["capabilities"]["extensions"]
                    .as_array_mut()
                    .unwrap()
                    .push(duplicate);
            }
        }
        assert_eq!(
            support::verify(&input).unwrap()["native_binding_valid"],
            false,
            "{case}"
        );
    }
    let mut tampered = fixture.clone();
    let mut report: Value = serde_json::from_str(fixture["report"].as_str().unwrap()).unwrap();
    report["content"]["score"] = json!(8);
    tampered["report"] = json!(serde_json::to_string(&report).unwrap());
    assert_eq!(
        support::verify(&tampered).unwrap()["native_report_integrity_valid"],
        false
    );
}
