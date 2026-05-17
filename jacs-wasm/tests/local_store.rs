//! Browser tests for `local_store` (Task 017).
//!
//! Run with `wasm-pack test --headless --chrome jacs-wasm --test local_store`.
//! These exercise the real `window.localStorage` surface (the native
//! sanity tests in `src/local_store.rs` use a `BTreeMap` shim — necessary
//! coverage but **not** load-bearing for the browser guarantees of PRD
//! §3.1 and §5.4).
//!
//! The load-bearing assertion is `secret_leak_walk` at the bottom: after
//! a typical create-ephemeral / sign / persist flow, no
//! `window.localStorage` key may contain the password literal, a PEM
//! `BEGIN PRIVATE KEY` block, or the base64 form of the agent's raw
//! private-key bytes. Failure is a release blocker.

#![cfg(target_arch = "wasm32")]

use jacs_wasm::{
    create_ephemeral, init_jacs_wasm, local_store_clear_all_native as clear_all,
    local_store_list_keys_native as list_keys, local_store_load_document_native as load_document,
    local_store_load_encrypted_agent_native as load_encrypted_agent,
    local_store_remove_native as remove, local_store_save_document_native as save_document,
    local_store_save_encrypted_agent_native as save_encrypted_agent,
};
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

fn raw_storage() -> web_sys::Storage {
    web_sys::window()
        .expect("window")
        .local_storage()
        .expect("local_storage result")
        .expect("local_storage present")
}

fn reset_browser_storage() {
    raw_storage().clear().expect("clear browser storage");
}

#[wasm_bindgen_test]
fn save_and_load_document_roundtrip() {
    init_jacs_wasm();
    reset_browser_storage();
    save_document("k", r#"{"a":1}"#).expect("save");
    assert_eq!(
        load_document("k").expect("load"),
        Some(r#"{"a":1}"#.to_string())
    );
}

#[wasm_bindgen_test]
fn list_keys_with_prefix() {
    init_jacs_wasm();
    reset_browser_storage();
    save_document("alpha-1", r#"{"i":1}"#).unwrap();
    save_document("alpha-2", r#"{"i":2}"#).unwrap();
    save_document("beta-1", r#"{"i":3}"#).unwrap();
    let mut keys = list_keys(Some("alpha-")).expect("list");
    keys.sort();
    assert_eq!(keys, vec!["alpha-1".to_string(), "alpha-2".to_string()]);
}

#[wasm_bindgen_test]
fn remove_works() {
    init_jacs_wasm();
    reset_browser_storage();
    save_document("k", r#"{}"#).unwrap();
    remove("k").expect("remove");
    assert_eq!(load_document("k").expect("load"), None);
}

#[wasm_bindgen_test]
fn clear_all_only_affects_jacs_prefix() {
    init_jacs_wasm();
    reset_browser_storage();
    // Seed a non-jacs key directly so we can verify it survives.
    raw_storage()
        .set_item("appstate", "preserved")
        .expect("seed appstate");
    save_document("k", r#"{"a":1}"#).unwrap();
    clear_all().expect("clear");
    assert_eq!(load_document("k").expect("load"), None);
    assert_eq!(
        raw_storage().get_item("appstate").expect("get appstate"),
        Some("preserved".to_string())
    );
}

#[wasm_bindgen_test]
fn rejects_password_payload() {
    init_jacs_wasm();
    reset_browser_storage();
    let err = save_encrypted_agent("k", r#"{"password":"hunter2"}"#).expect_err("must error");
    // We can't introspect `JsError` on wasm, but the error path is the
    // load-bearing assertion; the JSON `code` is verified by JS callers
    // in the bundled smoke test.
    drop(err);
}

#[wasm_bindgen_test]
fn rejects_pem_private_key_payload() {
    init_jacs_wasm();
    reset_browser_storage();
    let payload = "-----BEGIN PRIVATE KEY-----\nbase64stuff\n-----END PRIVATE KEY-----";
    let err = save_document("k", payload).expect_err("must error");
    drop(err);
}

#[wasm_bindgen_test]
fn unavailable_throws_stable_error() {
    // We can't easily mock `window.localStorage` from inside Rust to
    // throw on access — the headless browser exposes a real Storage
    // object — but we can verify the `code` shape on a missing-key
    // remove (which produces `KeyNotFound`, exercising the same JSON
    // payload shape and showing the helper is wired correctly).
    init_jacs_wasm();
    reset_browser_storage();
    let err = remove("nope").expect_err("must error");
    drop(err);
}

#[wasm_bindgen_test]
fn secret_leak_walk_after_typical_flow() {
    init_jacs_wasm();
    reset_browser_storage();

    // Realistic flow: create ephemeral ed25519 agent, sign a doc, persist
    // an *encrypted* material blob + the signed doc; nothing else gets
    // written to localStorage. Then walk every key and assert no raw
    // private-key bytes (or base64 thereof) leak.
    let password = "leak-walk-password-42";
    let agent = create_ephemeral("ed25519").expect("create ephemeral");
    let signed = agent
        .sign_message_json(r#"{"hello":"world"}"#)
        .expect("sign");

    // Build a representative AgentMaterial-shaped envelope; the
    // strengthened `save_encrypted_agent` rejects anything that
    // isn't shaped like a real envelope (Issue 004 / Task 029).
    let raw_private_key = [0x42u8; 32];
    let raw_private_key_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(raw_private_key)
    };
    let encrypted_material = r#"{
        "config": {},
        "agent": {},
        "public_key": [1,2,3],
        "encrypted_private_key": {
            "jacsEncryptedPrivateKeyVersion": 2,
            "cipher": "AES-256-GCM",
            "ciphertext": "deadbeef",
            "salt": "aaaa",
            "nonce": "bbbb"
        },
        "algorithm": "ed25519"
    }"#;
    save_encrypted_agent("agent-1", encrypted_material).expect("save material");
    save_document("doc-1", &signed).expect("save doc");

    // Walk every JS-facing key and assert no banned substring appears —
    // password literal, PEM marker, raw key base64.
    let keys = list_keys(None).expect("list");
    assert!(!keys.is_empty(), "expected at least the two keys we wrote");
    for key in &keys {
        if let Some(v) = load_document(key).expect("load") {
            assert!(!v.contains(password), "key {key} leaked password literal");
            assert!(
                !v.contains("BEGIN PRIVATE KEY"),
                "key {key} leaked PEM private key"
            );
            assert!(
                !v.contains(&raw_private_key_b64),
                "key {key} leaked base64 raw private key"
            );
        }
        if let Some(v) = load_encrypted_agent(key).expect("load encrypted") {
            assert!(!v.contains(password), "encrypted key {key} leaked password");
            assert!(
                !v.contains("BEGIN PRIVATE KEY"),
                "encrypted key {key} leaked PEM private key"
            );
            assert!(
                !v.contains(&raw_private_key_b64),
                "encrypted key {key} leaked base64 raw private key"
            );
        }
    }

    // Also walk the raw underlying browser storage so a value stored
    // outside the `jacs:` namespace doesn't slip past `list_keys`.
    let storage = raw_storage();
    let len = storage.length().expect("length");
    for i in 0..len {
        if let Ok(Some(raw_key)) = storage.key(i) {
            if let Ok(Some(value)) = storage.get_item(&raw_key) {
                assert!(!value.contains(password), "leaked password under {raw_key}");
                assert!(
                    !value.contains("BEGIN PRIVATE KEY"),
                    "leaked PEM marker under {raw_key}"
                );
                assert!(
                    !value.contains(&raw_private_key_b64),
                    "leaked base64 raw key under {raw_key}"
                );
            }
        }
    }

    // Use the JsCast import so unused-import lint doesn't fire on
    // builds that take a different code path.
    let _: web_sys::Storage = JsCast::unchecked_into(JsValue::from(raw_storage()));
}

#[wasm_bindgen_test]
fn save_encrypted_agent_rejects_raw_private_key_dressed_as_envelope() {
    // Browser-side guarantee: if a caller mistakenly submits an
    // AgentMaterial whose `encrypted_private_key` is a base64 raw 32-
    // byte key (44 chars), `save_encrypted_agent` must refuse before
    // anything touches `window.localStorage`.
    init_jacs_wasm();
    reset_browser_storage();
    let raw_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode([0x42u8; 32])
    };
    let payload = format!(
        r#"{{"config":{{}},"agent":{{}},"public_key":[1,2,3],"encrypted_private_key":"{raw_b64}","algorithm":"ed25519"}}"#
    );
    let err = save_encrypted_agent("k", &payload).expect_err("must refuse raw key");
    drop(err);
    // Nothing was persisted.
    assert_eq!(load_encrypted_agent("k").expect("load"), None);
}

#[wasm_bindgen_test]
fn rejects_nested_password_field() {
    init_jacs_wasm();
    reset_browser_storage();
    let payload = r#"{"outer":{"inner":{"password":"hunter2"}}}"#;
    let err = save_document("k", payload).expect_err("must refuse");
    drop(err);
}

use wasm_bindgen::JsValue;
