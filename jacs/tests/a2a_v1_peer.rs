//! Real native fixture, authority refusals and legacy-card compatibility.
#![cfg(feature = "a2a")]
#[path = "../examples/support/a2a_v1.rs"]
mod support;
use serde_json::{Value, json};

#[test]
fn finite_v1_fixture_preserves_native_authority_and_legacy_contracts() {
    let fixture = support::fixture("http://127.0.0.1:18080/a2a").unwrap();
    let verdict = support::verify(&fixture).unwrap();
    assert_eq!(verdict["native_binding_valid"], true);
    assert_eq!(verdict["native_report_integrity_valid"], true);
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
