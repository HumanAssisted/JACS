//! Stateless binding contract for the complete authority-mapped approval profile.
//! The shared fixture contains only public evidence and caller-selected trust
//! inputs. These archival checks do not authorize current execution.

#![cfg(feature = "human-approval")]

use jacs_binding_core::{BindingResult, ErrorKind, SimpleAgentWrapper};
use serde_json::Value;

fn fixture() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/human_approved_document_v1.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("shared public fixture"))
        .expect("fixture JSON")
}

fn verify(value: &Value) -> BindingResult<String> {
    SimpleAgentWrapper::verify_human_approved_document_json(
        &value["bundle"].to_string(),
        &value["expected"].to_string(),
        &value["authority"].to_string(),
        &value["provenance"].to_string(),
    )
}

#[test]
fn complete_public_report_matches_native_without_constructing_an_agent() {
    let value = fixture();
    let native = jacs::human_approval::verify_human_approved_document_v1(
        &value["bundle"].to_string(),
        &serde_json::from_value(value["expected"].clone()).unwrap(),
        &serde_json::from_value(value["authority"].clone()).unwrap(),
        &serde_json::from_value(value["provenance"].clone()).unwrap(),
    )
    .unwrap();
    for _ in 0..2 {
        let report: Value = serde_json::from_str(&verify(&value).unwrap()).unwrap();
        assert_eq!(report, serde_json::to_value(&native).unwrap());
        assert_eq!(report, value["report"]);
        assert_eq!(report["current"], "not_evaluated");
        assert_eq!(report["approval"]["current"], "not_evaluated");
        assert_eq!(report["approval"]["signatureCounter"], 1);
        assert_eq!(report["approval"]["userVerified"], true);
        assert!(report["approval"]["binding"].is_object());
        assert!(report["approval"]["updatedCredentialStateDigest"].is_string());
    }
}

#[test]
fn caller_supplies_exact_intent_and_independent_role_pins() {
    let value = fixture();
    for (field, replacement) in [
        ("humanId", Value::from("different-human")),
        ("purpose", Value::from("different-purpose")),
        ("audience", Value::from("https://other.example.test")),
        ("credentialGeneration", Value::from(2)),
    ] {
        let mut different = value.clone();
        different["expected"][field] = replacement;
        assert_eq!(
            verify(&different).unwrap_err().kind,
            ErrorKind::VerificationFailed
        );
    }
    for role in ["authority", "provenance"] {
        let mut different = value.clone();
        different[role] = value[if role == "authority" {
            "provenance"
        } else {
            "authority"
        }]
        .clone();
        assert_eq!(
            verify(&different).unwrap_err().kind,
            ErrorKind::VerificationFailed
        );
    }
}

#[test]
fn prior_success_never_substitutes_stored_bytes_or_one_component() {
    let value = fixture();
    verify(&value).unwrap();
    let mut changed = value.clone();
    changed["bundle"]["jacsDocument"]["content"]["action"] = Value::from("different action");
    assert_eq!(
        verify(&changed).unwrap_err().kind,
        ErrorKind::VerificationFailed
    );
    for component in ["jacsDocument", "humanApproval"] {
        changed = value.clone();
        changed["bundle"] = value["bundle"][component].clone();
        assert_eq!(
            verify(&changed).unwrap_err().kind,
            ErrorKind::VerificationFailed
        );
    }
    verify(&value).unwrap();
}

#[test]
fn policy_json_is_strict_and_never_defaults_missing_pins() {
    let value = fixture();
    let inputs =
        ["bundle", "expected", "authority", "provenance"].map(|field| value[field].to_string());
    for index in 1..4 {
        let field = if index == 1 { "humanId" } else { "agentId" };
        let original: Value = serde_json::from_str(&inputs[index]).unwrap();
        let duplicate = format!("{{\"{field}\":{},{}", original[field], &inputs[index][1..]);
        let mut unknown = original;
        unknown["unrecognizedPolicy"] = Value::Bool(true);
        for invalid in ["{}".into(), "null".into(), duplicate, unknown.to_string()] {
            let mut changed = inputs.clone();
            changed[index] = invalid;
            let error = SimpleAgentWrapper::verify_human_approved_document_json(
                &changed[0],
                &changed[1],
                &changed[2],
                &changed[3],
            )
            .unwrap_err();
            assert_eq!(error.kind, ErrorKind::InvalidArgument);
        }
    }
}

#[test]
#[serial_test::serial]
fn disk_evidence_is_read_only_and_no_private_key_directory_is_needed() {
    let original = std::env::current_dir().unwrap();
    struct Restore(std::path::PathBuf);
    impl Drop for Restore {
        fn drop(&mut self) {
            std::env::set_current_dir(&self.0).unwrap();
        }
    }
    let _restore = Restore(original);
    let value = fixture();
    let storage = tempfile::tempdir().unwrap();
    let path = storage.path().join("public-evidence.json");
    let original_bytes = value.to_string();
    std::fs::write(&path, &original_bytes).unwrap();
    std::env::set_current_dir(storage.path()).unwrap();
    for _ in 0..2 {
        let stored: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        verify(&stored).unwrap();
    }
    assert_eq!(std::fs::read_to_string(path).unwrap(), original_bytes);
    assert_eq!(std::fs::read_dir(storage.path()).unwrap().count(), 1);
}
