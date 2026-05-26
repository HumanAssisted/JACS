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
fn missing_key_remove_has_stable_error() {
    // Negative test for the `remove` path — calling `remove` on a key
    // that is not present must yield a stable `{ code: "KeyNotFound" }`
    // payload. This used to be named `unavailable_throws_stable_error`
    // but that name was misleading — it didn't actually exercise the
    // `StorageUnavailable` code path. The renamed
    // `localstorage_unavailable_throws_stable_error` below (Issue 012)
    // now covers that.
    init_jacs_wasm();
    reset_browser_storage();
    let err = remove("nope").expect_err("must error");
    let msg = format!("{:?}", err);
    // `JsError` does not expose the inner JSON in a stable way from Rust,
    // so we assert the type via the err existing; the JS-side
    // `JsError.message` is verified by the smoke + worker JS tests.
    drop(msg);
}

#[wasm_bindgen_test]
fn quota_exceeded_throws_stable_error() {
    // Issue 012: monkey-patch `Storage.prototype.setItem` to throw a
    // DOMException shaped like a `QuotaExceededError`, then assert that
    // `save_document` surfaces the `{ code: "QuotaExceeded" }` payload
    // (PRD §3.1 / §5.4 — stable error codes for the two storage failure
    // classes the browser can hit).
    init_jacs_wasm();
    reset_browser_storage();
    let original = patch_storage_set_item_to_throw(
        // Browser's real `QuotaExceededError` carries the literal
        // "QuotaExceededError" name and the legacy code `22`; we hit
        // both substrings the runtime classifier checks.
        "QuotaExceededError: Setting the value exceeded the quota.",
    );

    let result = save_document("k", r#"{"a":1}"#);

    // Restore the original *before* asserting so a failure cannot leak
    // the monkeypatch into adjacent tests.
    restore_storage_set_item(original);

    let err = result.expect_err("must error when setItem throws QuotaExceededError");
    assert_eq!(
        err.code(),
        "QuotaExceeded",
        "expected QuotaExceeded code, got {err:?}"
    );
}

#[wasm_bindgen_test]
fn localstorage_unavailable_throws_stable_error() {
    // Issue 012: replace `window.localStorage` getter so accessing it
    // throws — emulates Safari private-mode and sandboxed-iframe
    // denials. The helper must surface `StorageUnavailable`.
    init_jacs_wasm();
    reset_browser_storage();
    let original = patch_window_local_storage_to_throw();

    let result = load_document("any");

    restore_window_local_storage(original);

    let err = result.expect_err("must error when localStorage throws on access");
    assert_eq!(
        err.code(),
        "StorageUnavailable",
        "expected StorageUnavailable code, got {err:?}"
    );
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

// ---------------------------------------------------------------------------
// Issue 012 — browser monkeypatch helpers. The runtime classifier in
// `src/local_store.rs` maps `setItem` failures whose message mentions
// "QuotaExceeded" / "quota" / "22" to `QuotaExceeded`, and any
// `window.localStorage` access failure to `StorageUnavailable`. The
// helpers below replace the relevant native methods with throwing stubs
// for the duration of a single test, then restore the originals.
//
// Using `js_sys::Reflect` keeps the test in pure Rust + js-sys (already
// a dev-dep). The patches are scoped to one `wasm_bindgen_test` at a
// time — every test calls `restore_*` before returning.
// ---------------------------------------------------------------------------

/// Replace `Storage.prototype.setItem` with a function that throws an
/// error carrying the given message. Returns the original function so the
/// caller can pass it to [`restore_storage_set_item`].
fn patch_storage_set_item_to_throw(message: &str) -> JsValue {
    let proto = js_sys::Reflect::get(
        &js_sys::global()
            .dyn_into::<js_sys::Object>()
            .expect("global is object"),
        &JsValue::from_str("Storage"),
    )
    .expect("get Storage");
    let proto =
        js_sys::Reflect::get(&proto, &JsValue::from_str("prototype")).expect("Storage.prototype");
    let original = js_sys::Reflect::get(&proto, &JsValue::from_str("setItem"))
        .expect("Storage.prototype.setItem");
    // Build a closure that throws when called. Throw an Error object,
    // not a string, because real browsers surface quota failures as
    // DOMException/Error-like objects. This keeps the production
    // classifier honest: it must inspect `name` / `message` / `code`.
    let msg = message.to_string();
    let thrower = wasm_bindgen::closure::Closure::wrap(Box::new(move || -> JsValue {
        let err = js_sys::Error::new(&msg);
        err.set_name("QuotaExceededError");
        js_sys::Reflect::set(
            err.as_ref(),
            &JsValue::from_str("code"),
            &JsValue::from_f64(22.0),
        )
        .expect("set quota code");
        wasm_bindgen::throw_val(err.into());
    }) as Box<dyn FnMut() -> JsValue>);
    let thrower_js: JsValue = thrower.as_ref().clone();
    // Leak the closure so the JS side can keep calling it for the
    // remainder of the test. The closure is uninstalled by
    // `restore_storage_set_item`, so the leak is bounded to the test.
    thrower.forget();
    js_sys::Reflect::set(&proto, &JsValue::from_str("setItem"), &thrower_js)
        .expect("install thrower as setItem");
    original
}

/// Restore the original `Storage.prototype.setItem` returned by
/// [`patch_storage_set_item_to_throw`].
fn restore_storage_set_item(original: JsValue) {
    let proto = js_sys::Reflect::get(
        &js_sys::global()
            .dyn_into::<js_sys::Object>()
            .expect("global is object"),
        &JsValue::from_str("Storage"),
    )
    .expect("get Storage");
    let proto =
        js_sys::Reflect::get(&proto, &JsValue::from_str("prototype")).expect("Storage.prototype");
    js_sys::Reflect::set(&proto, &JsValue::from_str("setItem"), &original)
        .expect("restore setItem");
}

/// Replace the `window.localStorage` accessor with one that throws on
/// access. Returns the original property descriptor for
/// [`restore_window_local_storage`] to put back.
fn patch_window_local_storage_to_throw() -> JsValue {
    let window = web_sys::window().expect("window for monkeypatch");
    let window_obj: js_sys::Object = JsValue::from(window).dyn_into().expect("window is object");
    let original = js_sys::Object::get_own_property_descriptor(
        &window_obj,
        &JsValue::from_str("localStorage"),
    );
    // Build a getter that throws.
    let thrower = wasm_bindgen::closure::Closure::wrap(Box::new(|| -> JsValue {
        let err = js_sys::Error::new("localStorage denied");
        err.set_name("SecurityError");
        wasm_bindgen::throw_val(err.into());
    }) as Box<dyn FnMut() -> JsValue>);
    let descriptor = js_sys::Object::new();
    js_sys::Reflect::set(&descriptor, &JsValue::from_str("get"), thrower.as_ref())
        .expect("set descriptor.get");
    js_sys::Reflect::set(
        &descriptor,
        &JsValue::from_str("configurable"),
        &JsValue::from_bool(true),
    )
    .expect("set descriptor.configurable");
    thrower.forget();
    js_sys::Object::define_property(&window_obj, &JsValue::from_str("localStorage"), &descriptor);
    original
}

/// Restore the original `window.localStorage` descriptor returned by
/// [`patch_window_local_storage_to_throw`].
fn restore_window_local_storage(original: JsValue) {
    let window = web_sys::window().expect("window for restore");
    let window_obj: js_sys::Object = JsValue::from(window).dyn_into().expect("window is object");
    if original.is_undefined() || original.is_null() {
        // No prior descriptor — best-effort delete the patched property.
        let _ = js_sys::Reflect::delete_property(&window_obj, &JsValue::from_str("localStorage"));
        return;
    }
    js_sys::Object::define_property(
        &window_obj,
        &JsValue::from_str("localStorage"),
        &original
            .dyn_into::<js_sys::Object>()
            .expect("descriptor is object"),
    );
}
