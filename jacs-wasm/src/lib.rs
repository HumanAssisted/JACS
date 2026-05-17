//! JACS browser bindings — wasm-bindgen wrapper around `jacs-core`.
//!
//! This is the V1 skeleton (Task 015): exports `initJacsWasm` and the
//! `SigningAlgorithm` enum so JS callers can wire up the panic hook + pick
//! an algorithm before the handle types in later tasks land.
//!
//! See `docs/jacs/JACS_WASM_PRD.md` §4.3 for the full JS surface and §3.1
//! for the security caveats (browser memory is JS-accessible by design).
//!
//! ## Crate layout
//!
//! - `lib.rs` — entry points (`init_jacs_wasm`, `SigningAlgorithm` re-export).
//! - `agent_handle.rs` — `CoreAgentHandle` + constructors (Task 016).
//! - `local_store.rs` — WebLocalStorage helpers (Task 017).
//! - `worker.rs` — Web Worker bridge (Task 019).

use wasm_bindgen::prelude::*;

pub mod agent_handle;
pub mod local_store;
pub mod worker;

pub use agent_handle::{
    CoreAgentHandle, create_agreement_json, create_ephemeral, create_verifier,
    import_encrypted_agent, import_encrypted_agent_files,
};

// `local_store` (Task 017) — JS-facing free functions are exported under
// the `localStore*` camelCase names via `#[wasm_bindgen]` attributes on
// each function; Rust callers can use the free functions directly via
// `jacs_wasm::local_store::*`.
pub use local_store::{
    LocalStoreError, clear_all as local_store_clear_all_native,
    list_keys as local_store_list_keys_native, load_document as local_store_load_document_native,
    load_encrypted_agent as local_store_load_encrypted_agent_native,
    remove as local_store_remove_native, save_document as local_store_save_document_native,
    save_encrypted_agent as local_store_save_encrypted_agent_native,
    validate_no_plaintext_secrets,
};

// ---------------------------------------------------------------------------
// initJacsWasm — idempotent panic-hook installer.
// ---------------------------------------------------------------------------

/// Initialise JACS WASM internals. Currently:
///
/// - installs `console_error_panic_hook` (so Rust panics surface in the
///   browser console instead of as a bare `RuntimeError`).
///
/// Idempotent — calling more than once is a no-op (the hook itself short-
/// circuits on subsequent installs). Safe to call from every entry point;
/// constructors in subsequent tasks invoke it implicitly.
///
/// The JS-facing name is `initJacsWasm` (PRD §4.3).
#[wasm_bindgen(js_name = initJacsWasm)]
pub fn init_jacs_wasm() {
    // `set_once` ensures the hook is installed at most once across calls.
    // No state needs to be returned — the function exists so JS can
    // explicitly await initialisation before constructing any handle.
    console_error_panic_hook::set_once();
}

// ---------------------------------------------------------------------------
// SigningAlgorithm — wire-form enum used by JS callers (`"ed25519"` /
// `"pq2025"`). The Rust enum is re-exported from `jacs_core` so there is
// only one definition in the workspace (DRY per PRD §4.2).
// ---------------------------------------------------------------------------

/// JACS signing algorithm — re-export of [`jacs_core::SigningAlgorithm`]
/// (PRD §4.2). JS callers receive / emit the lowercase string form via
/// `serde_wasm_bindgen`.
pub use jacs_core::SigningAlgorithm;

/// Project a `SigningAlgorithm` into a `JsValue`. Used by handle methods
/// in Task 016 to surface the algorithm tag on `CoreAgentHandle`. Kept
/// here so the conversion logic is single-sourced.
#[wasm_bindgen(js_name = signingAlgorithmToJs)]
pub fn signing_algorithm_to_js(algorithm: &str) -> Result<JsValue, JsError> {
    let parsed = jacs_core::SigningAlgorithm::from_wire_str(algorithm).ok_or_else(|| {
        JsError::new(&format!(
            "unsupported signing algorithm '{}' (expected one of: ed25519, pq2025)",
            algorithm
        ))
    })?;
    serde_wasm_bindgen::to_value(&parsed).map_err(|e| JsError::new(&format!("{}", e)))
}
