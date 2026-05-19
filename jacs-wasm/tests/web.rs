//! Browser-side smoke tests for the jacs-wasm skeleton (Task 015).
//!
//! Run with `wasm-pack test --headless --chrome jacs-wasm`. These tests
//! confirm that:
//!
//! - `initJacsWasm` is idempotent and exposes the JS name expected by
//!   the PRD §4.3 API contract.
//! - `SigningAlgorithm` round-trips through `serde_wasm_bindgen` as the
//!   lowercase strings `"ed25519"` / `"pq2025"` that the JS surface
//!   consumes.

#![cfg(target_arch = "wasm32")]

use jacs_wasm::{SigningAlgorithm, init_jacs_wasm, signing_algorithm_to_js};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn init_jacs_wasm_is_idempotent() {
    init_jacs_wasm();
    init_jacs_wasm(); // must not panic on second call
}

#[wasm_bindgen_test]
fn algorithm_enum_serializes_to_lowercase_string() {
    init_jacs_wasm();

    // Round-trip Ed25519.
    let js_ed = serde_wasm_bindgen::to_value(&SigningAlgorithm::Ed25519)
        .expect("ed25519 to JS");
    let ed_str: String = serde_wasm_bindgen::from_value(js_ed).expect("ed25519 from JS");
    assert_eq!(ed_str, "ed25519");

    // Round-trip Pq2025.
    let js_pq = serde_wasm_bindgen::to_value(&SigningAlgorithm::Pq2025)
        .expect("pq2025 to JS");
    let pq_str: String = serde_wasm_bindgen::from_value(js_pq).expect("pq2025 from JS");
    assert_eq!(pq_str, "pq2025");

    // The exported `signingAlgorithmToJs(str)` helper accepts both wire
    // forms and rejects unknowns with a typed error.
    let ok = signing_algorithm_to_js("ed25519").expect("ed25519 helper");
    let s: String = serde_wasm_bindgen::from_value(ok).expect("helper str");
    assert_eq!(s, "ed25519");

    // Native legacy alias resolves through `from_wire_str`.
    let ok_legacy = signing_algorithm_to_js("ring-Ed25519").expect("alias helper");
    let s_legacy: String = serde_wasm_bindgen::from_value(ok_legacy).expect("alias str");
    assert_eq!(s_legacy, "ed25519");

    // Unknown algorithm surfaces a typed error to JS.
    assert!(signing_algorithm_to_js("rsa").is_err());
}
