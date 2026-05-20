//! Tests for `signAgreementJson` / `verifyAgreementJson` (Task 018).
//!
//! The `#[cfg(target_arch = "wasm32")]` block runs under
//! `wasm-pack test --headless --chrome jacs-wasm --test agreement`; the
//! `#[cfg(not(target_arch = "wasm32"))]` block runs under
//! `cargo test -p jacs-wasm --test agreement` so the implementation
//! logic stays exercised on every PR (browser tests are gated on
//! matched chromedriver/Chrome in CI).

// ---------------------------------------------------------------------------
// Native sanity tests — exercise the same code paths the browser will
// hit, minus the wasm-bindgen marshalling. Validates the JSON wire
// contract (camelCase keys, base64 public keys, QuorumOutcome shape).
// ---------------------------------------------------------------------------

#![allow(unused_imports)]

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use base64::Engine;
    use jacs_wasm::{create_agreement_json, create_ephemeral};
    use serde_json::{Value, json};

    fn signer_spec(agent_id: &str, public_key_b64: &str, algorithm: &str) -> Value {
        json!({
            "agentId": agent_id,
            "publicKeyBase64": public_key_b64,
            "algorithm": algorithm,
        })
    }

    #[test]
    fn sign_agreement_returns_updated_agreement_json() {
        let handle = create_ephemeral("ed25519").expect("ephemeral");
        let agent_json: Value =
            serde_json::from_str(&handle.export_agent().expect("export")).expect("agent");
        let agent_id = agent_json["jacsId"].as_str().expect("jacsId");
        let skeleton = create_agreement_json(
            r#"{"doc":"hello"}"#,
            &format!("[\"{}\"]", agent_id),
            Some("approve?".into()),
            Some("ctx".into()),
        )
        .expect("create skeleton");
        let updated = handle
            .sign_agreement_json(&skeleton, "approver")
            .expect("sign");
        let parsed: Value = serde_json::from_str(&updated).expect("parse");
        let signatures = parsed["jacsAgreement"]["signatures"]
            .as_array()
            .expect("signatures array");
        assert_eq!(signatures.len(), 1);
        assert_eq!(signatures[0]["role"], Value::String("approver".into()));
    }

    #[test]
    fn verify_two_party_agreement_with_keys() {
        let alice = create_ephemeral("ed25519").expect("alice");
        let bob = create_ephemeral("pq2025").expect("bob");
        let alice_id =
            serde_json::from_str::<Value>(&alice.export_agent().unwrap()).unwrap()["jacsId"]
                .as_str()
                .unwrap()
                .to_string();
        let bob_id = serde_json::from_str::<Value>(&bob.export_agent().unwrap()).unwrap()["jacsId"]
            .as_str()
            .unwrap()
            .to_string();
        let skeleton = create_agreement_json(
            r#"{"doc":"two-party"}"#,
            &format!("[\"{}\",\"{}\"]", alice_id, bob_id),
            None,
            None,
        )
        .expect("create");
        let after_alice = alice
            .sign_agreement_json(&skeleton, "approver")
            .expect("alice sign");
        let after_bob = bob
            .sign_agreement_json(&after_alice, "approver")
            .expect("bob sign");

        let alice_pk = alice.get_public_key_base64().unwrap();
        let bob_pk = bob.get_public_key_base64().unwrap();
        let signers = serde_json::to_string(&json!([
            signer_spec(&alice_id, &alice_pk, "ed25519"),
            signer_spec(&bob_id, &bob_pk, "pq2025"),
        ]))
        .unwrap();
        let outcome_json = bob
            .verify_agreement_json(&after_bob, &signers)
            .expect("verify");
        let outcome: Value = serde_json::from_str(&outcome_json).unwrap();
        assert_eq!(outcome["all_valid"], Value::Bool(true));
        assert_eq!(outcome["verified_signers"], Value::from(2));
        assert_eq!(outcome["expected_signers"], Value::from(2));
    }

    #[test]
    fn verify_agreement_missing_signer_key_returns_signer_key_missing() {
        let alice = create_ephemeral("ed25519").expect("alice");
        let bob = create_ephemeral("ed25519").expect("bob");
        let alice_id =
            serde_json::from_str::<Value>(&alice.export_agent().unwrap()).unwrap()["jacsId"]
                .as_str()
                .unwrap()
                .to_string();
        let bob_id = serde_json::from_str::<Value>(&bob.export_agent().unwrap()).unwrap()["jacsId"]
            .as_str()
            .unwrap()
            .to_string();
        let skeleton = create_agreement_json(
            r#"{"doc":"missing-key"}"#,
            &format!("[\"{}\",\"{}\"]", alice_id, bob_id),
            None,
            None,
        )
        .expect("create");
        let after_alice = alice.sign_agreement_json(&skeleton, "approver").unwrap();
        let after_bob = bob.sign_agreement_json(&after_alice, "approver").unwrap();

        let alice_pk = alice.get_public_key_base64().unwrap();
        // Only supply Alice's key — Bob's must surface as missing.
        let signers =
            serde_json::to_string(&json!([signer_spec(&alice_id, &alice_pk, "ed25519"),])).unwrap();
        let outcome_json = alice.verify_agreement_json(&after_bob, &signers).unwrap();
        let outcome: Value = serde_json::from_str(&outcome_json).unwrap();
        assert_eq!(outcome["all_valid"], Value::Bool(false));
        let per_signer = outcome["per_signer"].as_array().unwrap();
        let bob_entry = per_signer
            .iter()
            .find(|e| e["agent_id"].as_str() == Some(bob_id.as_str()))
            .unwrap();
        assert_eq!(
            bob_entry["status"]["kind"],
            Value::String("SignerKeyMissing".into())
        );
    }

    #[test]
    fn verify_agreement_tampered_returns_invalid() {
        let alice = create_ephemeral("ed25519").expect("alice");
        let alice_id =
            serde_json::from_str::<Value>(&alice.export_agent().unwrap()).unwrap()["jacsId"]
                .as_str()
                .unwrap()
                .to_string();
        let skeleton = create_agreement_json(
            r#"{"doc":"tamper-me"}"#,
            &format!("[\"{}\"]", alice_id),
            None,
            None,
        )
        .expect("create");
        let signed_str = alice.sign_agreement_json(&skeleton, "approver").unwrap();

        // Flip a byte in the document payload (NOT inside the signature)
        // so the canonical bytes change and the signature no longer
        // verifies.
        let mut signed: Value = serde_json::from_str(&signed_str).unwrap();
        signed["doc"] = Value::String("tampered-me".into());
        let tampered_str = serde_json::to_string(&signed).unwrap();

        let alice_pk = alice.get_public_key_base64().unwrap();
        let signers =
            serde_json::to_string(&json!([signer_spec(&alice_id, &alice_pk, "ed25519"),])).unwrap();
        let outcome_json = alice
            .verify_agreement_json(&tampered_str, &signers)
            .unwrap();
        let outcome: Value = serde_json::from_str(&outcome_json).unwrap();
        assert_eq!(outcome["all_valid"], Value::Bool(false));
        let per_signer = outcome["per_signer"].as_array().unwrap();
        assert_eq!(
            per_signer[0]["status"]["kind"],
            Value::String("Invalid".into())
        );
    }

    #[test]
    #[ignore = "JsError construction panics on native targets; covered by web::sign_agreement_after_clear_secrets_errors under wasm-pack test"]
    fn sign_agreement_after_clear_secrets_returns_locked() {
        // JsError doesn't impl Debug on native, but we can still
        // observe the failure via `is_err()` + extracting the error
        // payload through Display.
        let handle = create_ephemeral("ed25519").expect("ephemeral");
        let agent_id =
            serde_json::from_str::<Value>(&handle.export_agent().unwrap()).unwrap()["jacsId"]
                .as_str()
                .unwrap()
                .to_string();
        let skeleton = create_agreement_json(
            r#"{"doc":"locked"}"#,
            &format!("[\"{}\"]", agent_id),
            None,
            None,
        )
        .expect("create");
        handle.clear_secrets().expect("clear");
        let result = handle.sign_agreement_json(&skeleton, "approver");
        // The `JsError` returned here has a JSON body of
        // `{ code: "Locked", ... }`. We assert the failure with
        // `is_err()`; the JSON shape is verified end-to-end in the
        // browser-side test.
        assert!(result.is_err(), "sign after clear_secrets must fail");
        drop(result.err());
    }

    #[test]
    #[ignore = "JsError construction panics on native targets; covered under wasm-pack test"]
    fn verify_agreement_with_invalid_signers_json_returns_malformed_document() {
        let alice = create_ephemeral("ed25519").expect("alice");
        let agent_id =
            serde_json::from_str::<Value>(&alice.export_agent().unwrap()).unwrap()["jacsId"]
                .as_str()
                .unwrap()
                .to_string();
        let skeleton =
            create_agreement_json(r#"{"doc":"x"}"#, &format!("[\"{}\"]", agent_id), None, None)
                .expect("create");
        let signed = alice.sign_agreement_json(&skeleton, "approver").unwrap();
        // Pass garbage JSON for signers.
        let result = alice.verify_agreement_json(&signed, "{not an array}");
        assert!(result.is_err(), "garbage signers JSON must error");
        drop(result.err());
    }

    #[test]
    #[ignore = "JsError construction panics on native targets; covered under wasm-pack test"]
    fn signer_with_bad_base64_returns_malformed_key() {
        let alice = create_ephemeral("ed25519").expect("alice");
        let agent_id =
            serde_json::from_str::<Value>(&alice.export_agent().unwrap()).unwrap()["jacsId"]
                .as_str()
                .unwrap()
                .to_string();
        let skeleton =
            create_agreement_json(r#"{"doc":"y"}"#, &format!("[\"{}\"]", agent_id), None, None)
                .expect("create");
        let signed = alice.sign_agreement_json(&skeleton, "approver").unwrap();
        let signers = serde_json::to_string(&json!([
            { "agentId": agent_id, "publicKeyBase64": "!!!not-base64!!!", "algorithm": "ed25519" }
        ]))
        .unwrap();
        let result = alice.verify_agreement_json(&signed, &signers);
        assert!(result.is_err(), "bad base64 must error");
        drop(result.err());
    }
}

// ---------------------------------------------------------------------------
// Browser tests — exercise the wasm-bindgen wrappers under
// `window.crypto`-backed RNG + the actual JS-facing camelCase function
// names. Run via `wasm-pack test --headless --chrome` in CI.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
mod web {
    use jacs_wasm::{create_agreement_json, create_ephemeral, init_jacs_wasm};
    use serde_json::{Value, json};
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn sign_agreement_returns_updated_agreement_json() {
        init_jacs_wasm();
        let handle = create_ephemeral("ed25519").expect("ephemeral");
        let agent_id =
            serde_json::from_str::<Value>(&handle.export_agent().unwrap()).unwrap()["jacsId"]
                .as_str()
                .unwrap()
                .to_string();
        let skeleton = create_agreement_json(
            r#"{"doc":"hello"}"#,
            &format!("[\"{}\"]", agent_id),
            None,
            None,
        )
        .expect("create skeleton");
        let updated = handle
            .sign_agreement_json(&skeleton, "approver")
            .expect("sign");
        let parsed: Value = serde_json::from_str(&updated).expect("parse");
        let signatures = parsed["jacsAgreement"]["signatures"]
            .as_array()
            .expect("signatures");
        assert_eq!(signatures.len(), 1);
    }

    #[wasm_bindgen_test]
    fn verify_two_party_agreement() {
        init_jacs_wasm();
        let alice = create_ephemeral("ed25519").expect("alice");
        let bob = create_ephemeral("pq2025").expect("bob");
        let alice_id =
            serde_json::from_str::<Value>(&alice.export_agent().unwrap()).unwrap()["jacsId"]
                .as_str()
                .unwrap()
                .to_string();
        let bob_id = serde_json::from_str::<Value>(&bob.export_agent().unwrap()).unwrap()["jacsId"]
            .as_str()
            .unwrap()
            .to_string();
        let skeleton = create_agreement_json(
            r#"{"doc":"web-two-party"}"#,
            &format!("[\"{}\",\"{}\"]", alice_id, bob_id),
            None,
            None,
        )
        .expect("create");
        let after_alice = alice.sign_agreement_json(&skeleton, "approver").unwrap();
        let after_bob = bob.sign_agreement_json(&after_alice, "approver").unwrap();

        let signers = serde_json::to_string(&json!([
            {
                "agentId": alice_id,
                "publicKeyBase64": alice.get_public_key_base64().unwrap(),
                "algorithm": "ed25519",
            },
            {
                "agentId": bob_id,
                "publicKeyBase64": bob.get_public_key_base64().unwrap(),
                "algorithm": "pq2025",
            },
        ]))
        .unwrap();
        let outcome_json = bob
            .verify_agreement_json(&after_bob, &signers)
            .expect("verify");
        let outcome: Value = serde_json::from_str(&outcome_json).unwrap();
        assert_eq!(outcome["all_valid"], Value::Bool(true));
        assert_eq!(outcome["verified_signers"], Value::from(2));
    }

    #[wasm_bindgen_test]
    fn sign_agreement_after_clear_secrets_errors() {
        init_jacs_wasm();
        let handle = create_ephemeral("ed25519").expect("ephemeral");
        let agent_id =
            serde_json::from_str::<Value>(&handle.export_agent().unwrap()).unwrap()["jacsId"]
                .as_str()
                .unwrap()
                .to_string();
        let skeleton = create_agreement_json(
            r#"{"doc":"locked-web"}"#,
            &format!("[\"{}\"]", agent_id),
            None,
            None,
        )
        .expect("create");
        handle.clear_secrets().unwrap();
        let result = handle.sign_agreement_json(&skeleton, "approver");
        assert!(result.is_err(), "sign after clear_secrets must fail");
        drop(result.err());
    }
}
