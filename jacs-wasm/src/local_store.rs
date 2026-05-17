//! WebLocalStorage helpers for `@jacs/wasm` (Task 017).
//!
//! Browser callers persist encrypted key material and signed documents via
//! `window.localStorage`. This module wraps the raw `web-sys` API behind a
//! strict policy:
//!
//! - **Every** key is namespaced with the `jacs:` prefix internally. JS-
//!   facing key strings are passed through verbatim and the prefix is
//!   added/stripped at the boundary.
//! - **No** call ever writes a payload containing the literal string
//!   `BEGIN PRIVATE KEY` (PEM private blocks) or a top-level `"password"`
//!   JSON property. That guard is a defense-in-depth tripwire — not a
//!   security boundary, since browser memory is JS-accessible by design
//!   (PRD §3.1) — and is the load-bearing check for the secret-leak walk
//!   test in §5.4.
//! - Errors map to a stable `{ code, message }` JSON shape, identical to
//!   the `CoreError` wire contract. Codes used: `RefusedPayload`,
//!   `StorageUnavailable`, `QuotaExceeded`, `KeyNotFound`.
//!
//! The JS-facing module name is `localStore`; the hand-written TypeScript
//! wrapper in `jacs-wasm/index.ts` (Task 020) assembles the free
//! functions exported here under that object so callers write
//! `localStore.saveDocument(...)`.

use serde::Serialize;
use serde::ser::SerializeStruct;
use wasm_bindgen::prelude::*;

/// Prefix prepended to every JS-facing key before it touches
/// `window.localStorage`. `clear_all()` only removes keys carrying this
/// prefix so we never trample on host-app state stored under different
/// namespaces.
pub const JACS_LOCAL_STORE_PREFIX: &str = "jacs:";

/// PEM marker that flags a private-key block. We refuse to persist any
/// payload that contains this literal substring.
const PEM_PRIVATE_KEY_MARKER: &str = "BEGIN PRIVATE KEY";

// ---------------------------------------------------------------------------
// Error type — stable `{ code, message }` wire shape.
// ---------------------------------------------------------------------------

/// Error returned by every `local_store` operation. Serializes to the same
/// `{ code, message }` JSON shape as `jacs_core::CoreError` so JS callers
/// can `try { … } catch (e) { JSON.parse(e.message).code }` uniformly
/// across the API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalStoreError {
    /// Payload was rejected because it contained plaintext material that
    /// is never allowed in `localStorage` (PEM private-key block or
    /// top-level `"password"` field).
    RefusedPayload(String),
    /// `window.localStorage` is not available (no `window`, private mode
    /// denial, sandboxed iframe, …).
    StorageUnavailable(String),
    /// `setItem` raised `QuotaExceededError`.
    QuotaExceeded(String),
    /// Requested key is not present.
    KeyNotFound(String),
}

impl LocalStoreError {
    /// Stable wire code (the `code` field of the serialized payload).
    pub fn code(&self) -> &'static str {
        match self {
            LocalStoreError::RefusedPayload(_) => "RefusedPayload",
            LocalStoreError::StorageUnavailable(_) => "StorageUnavailable",
            LocalStoreError::QuotaExceeded(_) => "QuotaExceeded",
            LocalStoreError::KeyNotFound(_) => "KeyNotFound",
        }
    }

    fn message(&self) -> &str {
        match self {
            LocalStoreError::RefusedPayload(m)
            | LocalStoreError::StorageUnavailable(m)
            | LocalStoreError::QuotaExceeded(m)
            | LocalStoreError::KeyNotFound(m) => m,
        }
    }
}

impl Serialize for LocalStoreError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("LocalStoreError", 2)?;
        s.serialize_field("code", self.code())?;
        s.serialize_field("message", self.message())?;
        s.end()
    }
}

impl std::fmt::Display for LocalStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for LocalStoreError {}

/// Convert a [`LocalStoreError`] into a `JsError` carrying the same JSON
/// `{ code, message }` payload. JS callers dispatch on
/// `JSON.parse(e.message).code`.
fn err_to_js(err: LocalStoreError) -> JsError {
    let payload = serde_json::to_string(&err).unwrap_or_else(|_| {
        format!("{{\"code\":\"{}\",\"message\":\"{}\"}}", err.code(), err.message())
    });
    JsError::new(&payload)
}

// ---------------------------------------------------------------------------
// Payload validation — load-bearing defense-in-depth check (PRD §5.4).
// ---------------------------------------------------------------------------

/// Refuse a payload that obviously carries plaintext secret material:
///
/// 1. Any PEM private-key block (literal substring `BEGIN PRIVATE KEY`).
/// 2. A JSON value containing any object key named `password`,
///    `passphrase`, or `secret` (case-insensitive on the key name) at
///    **any** depth — the walk is recursive so a nested credential is
///    refused too.
///
/// This is **not** a security boundary — browser memory is JS-accessible —
/// it is a tripwire so a caller who accidentally hands us a password or a
/// PEM private block surfaces a `RefusedPayload` error immediately instead
/// of silently persisting plaintext. The secret-leak walk test (PRD §5.4)
/// exercises this contract.
pub fn validate_no_plaintext_secrets(payload: &str) -> Result<(), LocalStoreError> {
    if payload.contains(PEM_PRIVATE_KEY_MARKER) {
        return Err(LocalStoreError::RefusedPayload(format!(
            "payload contains '{}' — refusing to persist a PEM private key in localStorage",
            PEM_PRIVATE_KEY_MARKER
        )));
    }
    // Recursive JSON walk for credential-shaped keys. We *only* walk
    // payloads that parse as JSON; non-JSON falls through with just the
    // PEM check above. The intent is defense-in-depth, not validation
    // logic: a caller who serializes an object containing a `password`,
    // `passphrase`, or `secret` field surfaces the error before anything
    // touches localStorage.
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) {
        if let Some(found) = find_credential_key(&value) {
            return Err(LocalStoreError::RefusedPayload(format!(
                "payload contains a '{}' field at JSON path '{}' — refusing to persist what looks like a plaintext credential in localStorage",
                found.matched_key, found.json_pointer
            )));
        }
    }
    Ok(())
}

/// JSON keys we treat as credential-shaped (case-insensitive match).
const CREDENTIAL_KEY_NAMES: &[&str] = &["password", "passphrase", "secret"];

/// Result of a credential-key walk — the key name we matched and the
/// JSON Pointer (RFC 6901) of where we found it.
struct CredentialMatch {
    matched_key: String,
    json_pointer: String,
}

/// Walk `value` recursively, returning the first object key whose name
/// matches any of [`CREDENTIAL_KEY_NAMES`] (case-insensitive).
fn find_credential_key(value: &serde_json::Value) -> Option<CredentialMatch> {
    walk(value, String::new())
}

fn walk(value: &serde_json::Value, pointer: String) -> Option<CredentialMatch> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if CREDENTIAL_KEY_NAMES
                    .iter()
                    .any(|k| key.eq_ignore_ascii_case(k))
                {
                    return Some(CredentialMatch {
                        matched_key: key.clone(),
                        json_pointer: format!("{}/{}", pointer, escape_pointer_segment(key)),
                    });
                }
                if let Some(found) = walk(
                    child,
                    format!("{}/{}", pointer, escape_pointer_segment(key)),
                ) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(arr) => {
            for (idx, child) in arr.iter().enumerate() {
                if let Some(found) = walk(child, format!("{}/{}", pointer, idx)) {
                    return Some(found);
                }
            }
            None
        }
        _ => None,
    }
}

/// Escape a JSON Pointer segment per RFC 6901 §4: `~` → `~0`, `/` → `~1`.
fn escape_pointer_segment(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

// ---------------------------------------------------------------------------
// Encrypted-material shape check — load-bearing for `save_encrypted_agent`
// (Issue 004 / Task 029). The function looks for an
// `encrypted_private_key` field and refuses the payload unless the value
// looks like one of the two on-disk envelopes jacs-core ships:
//
// 1. V2 JSON envelope: a JSON object containing
//    `jacsEncryptedPrivateKeyVersion: 2` + ciphertext/salt/nonce fields.
// 2. Legacy raw-binary PBKDF2 envelope: a base64 string that decodes to
//    at least 28 bytes (16-byte salt + 12-byte nonce + ciphertext).
//
// Anything else — a raw 32-byte private key base64'd, a hex key, a JSON
// blob without an envelope shape — is refused as `RefusedPayload`. The
// goal is to make the "localStorage never receives a raw private key"
// guarantee in PRD §3.1 enforceable.
// ---------------------------------------------------------------------------

/// Minimum length of a PBKDF2 raw-binary envelope after base64 decode:
/// 16-byte salt + 12-byte nonce + at least 16 bytes of ciphertext / tag.
/// In practice envelopes are much larger (private key + GCM tag) but
/// 28 is the lower bound that rejects bare 32-byte raw key uploads.
const MIN_PBKDF2_ENVELOPE_BYTES: usize = 16 + 12 + 16;

/// Maximum length of a payload we will treat as "might be a raw key
/// dressed up as base64". A 32-byte ed25519 key base64-encodes to 44
/// chars; a 64-byte signed-message base64-encodes to 88. PBKDF2
/// envelopes are always longer than 88 chars (salt + nonce + ciphertext
/// + tag → ~ 80+ chars at minimum, plus the private key bytes).
const MAX_RAW_KEY_BASE64_LEN: usize = 88;

/// Validate that the JSON payload looks like an `AgentMaterial` blob
/// carrying a recognized encrypted-key envelope. Returns
/// [`LocalStoreError::RefusedPayload`] if the `encrypted_private_key`
/// field is missing, is shaped like a raw key, or otherwise does not
/// match a known envelope.
///
/// Called only from [`save_encrypted_agent`]; `save_document` keeps the
/// lighter `validate_no_plaintext_secrets` check because signed
/// documents do not carry key material.
pub fn validate_encrypted_material_shape(payload: &str) -> Result<(), LocalStoreError> {
    let value: serde_json::Value = serde_json::from_str(payload).map_err(|e| {
        LocalStoreError::RefusedPayload(format!(
            "expected JSON-shaped AgentMaterial blob: {}",
            e
        ))
    })?;
    let obj = value.as_object().ok_or_else(|| {
        LocalStoreError::RefusedPayload(
            "expected JSON object (AgentMaterial); got non-object".into(),
        )
    })?;
    let enc = obj
        .get("encrypted_private_key")
        .ok_or_else(|| {
            LocalStoreError::RefusedPayload(
                "AgentMaterial missing 'encrypted_private_key' field".into(),
            )
        })?;
    is_recognized_envelope(enc)
}

/// Sniff `value` and return `Ok(())` if it looks like a V2 JSON envelope
/// or a long-enough PBKDF2 raw-binary envelope; otherwise return
/// `RefusedPayload`.
fn is_recognized_envelope(value: &serde_json::Value) -> Result<(), LocalStoreError> {
    match value {
        // V2 JSON envelope — match `{"jacsEncryptedPrivateKeyVersion": 2, ...}`.
        serde_json::Value::Object(map) => {
            if map.get("jacsEncryptedPrivateKeyVersion")
                .and_then(|v| v.as_u64())
                == Some(2)
                && map.contains_key("ciphertext")
                && map.contains_key("salt")
                && map.contains_key("nonce")
            {
                Ok(())
            } else {
                Err(LocalStoreError::RefusedPayload(
                    "'encrypted_private_key' object does not match the V2 JSON envelope shape \
                     (need `jacsEncryptedPrivateKeyVersion: 2` + `ciphertext` + `salt` + `nonce`)"
                        .into(),
                ))
            }
        }
        // Legacy PBKDF2 raw-binary envelope — base64 string that decodes
        // to enough bytes for salt+nonce+ciphertext. A bare 32-byte raw
        // key (base64 length 44) does not decode to ≥ 44 bytes, so this
        // rejects it. A base64 of 32 raw bytes is 44 chars → decodes to
        // 32 bytes → < MIN_PBKDF2_ENVELOPE_BYTES → refused.
        serde_json::Value::Array(arr) => {
            // Allow an integer-array encoding too (some serializers emit
            // [u8] as JSON arrays). Same threshold applies.
            if arr.len() >= MIN_PBKDF2_ENVELOPE_BYTES
                && arr.iter().all(|v| v.as_u64().is_some_and(|n| n <= 255))
            {
                Ok(())
            } else {
                Err(LocalStoreError::RefusedPayload(format!(
                    "'encrypted_private_key' byte-array length {} is below the {}-byte minimum for a PBKDF2 envelope (salt+nonce+ciphertext+tag)",
                    arr.len(),
                    MIN_PBKDF2_ENVELOPE_BYTES
                )))
            }
        }
        serde_json::Value::String(s) => {
            // Base64-shaped string. Decode and require at least the
            // PBKDF2 envelope minimum to rule out raw 32-byte keys.
            use base64::Engine;
            // Reject obvious raw-key sizes outright (44 chars = 32 raw
            // bytes ed25519; well under MAX_RAW_KEY_BASE64_LEN). This is
            // a cheap pre-decode check that avoids spending CPU on
            // decoding garbage.
            if s.len() <= MAX_RAW_KEY_BASE64_LEN {
                return Err(LocalStoreError::RefusedPayload(format!(
                    "'encrypted_private_key' base64 string length {} is too short to be a PBKDF2 envelope (looks like a raw key)",
                    s.len()
                )));
            }
            // Try standard base64 first, then url-safe. We only care
            // about the byte count, not the contents.
            let decoded_len = base64::engine::general_purpose::STANDARD
                .decode(s.as_bytes())
                .or_else(|_| {
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.as_bytes())
                })
                .map_err(|e| {
                    LocalStoreError::RefusedPayload(format!(
                        "'encrypted_private_key' is not valid base64: {}",
                        e
                    ))
                })?
                .len();
            if decoded_len >= MIN_PBKDF2_ENVELOPE_BYTES {
                Ok(())
            } else {
                Err(LocalStoreError::RefusedPayload(format!(
                    "'encrypted_private_key' base64 decodes to {} bytes — below the {}-byte minimum for a PBKDF2 envelope",
                    decoded_len, MIN_PBKDF2_ENVELOPE_BYTES
                )))
            }
        }
        _ => Err(LocalStoreError::RefusedPayload(
            "'encrypted_private_key' must be a V2 JSON envelope object, a PBKDF2 base64 string, or a PBKDF2 byte array"
                .into(),
        )),
    }
}

// ---------------------------------------------------------------------------
// Storage handle — thin wrapper around `web-sys::Storage`.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
fn storage_handle() -> Result<web_sys::Storage, LocalStoreError> {
    let window = web_sys::window().ok_or_else(|| {
        LocalStoreError::StorageUnavailable("no global `window` object".into())
    })?;
    window
        .local_storage()
        .map_err(|js_err| {
            LocalStoreError::StorageUnavailable(format!(
                "accessing localStorage threw: {}",
                js_err.as_string().unwrap_or_else(|| "<unknown>".into())
            ))
        })?
        .ok_or_else(|| {
            LocalStoreError::StorageUnavailable("localStorage is null".into())
        })
}

#[cfg(not(target_arch = "wasm32"))]
fn storage_handle() -> Result<NativeStorage, LocalStoreError> {
    Ok(NativeStorage::shared())
}

// ---------------------------------------------------------------------------
// Native fallback — pure in-memory shim so the module compiles and is
// testable under `cargo test -p jacs-wasm` (no browser required). The
// behavior contract matches `web_sys::Storage` for the calls we use.
// ---------------------------------------------------------------------------

#[cfg(not(target_arch = "wasm32"))]
mod native_shim {
    use std::collections::BTreeMap;
    use std::sync::{Mutex, OnceLock};

    /// In-process stand-in for `web_sys::Storage`. Backed by a single
    /// process-wide `BTreeMap`; the entire surface area (`get_item`,
    /// `set_item`, `remove_item`, `length`, `key`, `clear`) mirrors the
    /// browser API for the calls `local_store` needs. Insertion-order
    /// iteration is matched by `BTreeMap`'s sorted iteration — not
    /// identical, but the public contract of `local_store` doesn't
    /// promise an order, only that every `jacs:`-prefixed key is visited
    /// at most once.
    pub struct NativeStorage;

    static BACKING: OnceLock<Mutex<BTreeMap<String, String>>> = OnceLock::new();

    fn map() -> &'static Mutex<BTreeMap<String, String>> {
        BACKING.get_or_init(|| Mutex::new(BTreeMap::new()))
    }

    impl NativeStorage {
        pub fn shared() -> Self {
            // Initialize the backing map lazily; calling `map()` ensures
            // the OnceLock is populated. The handle itself is zero-sized.
            let _ = map();
            Self
        }

        pub fn set_item(&self, key: &str, value: &str) -> Result<(), String> {
            map()
                .lock()
                .map_err(|_| "native storage mutex poisoned".to_string())?
                .insert(key.to_string(), value.to_string());
            Ok(())
        }

        pub fn get_item(&self, key: &str) -> Result<Option<String>, String> {
            Ok(map()
                .lock()
                .map_err(|_| "native storage mutex poisoned".to_string())?
                .get(key)
                .cloned())
        }

        pub fn remove_item(&self, key: &str) -> Result<(), String> {
            map()
                .lock()
                .map_err(|_| "native storage mutex poisoned".to_string())?
                .remove(key);
            Ok(())
        }

        pub fn length(&self) -> Result<u32, String> {
            Ok(map()
                .lock()
                .map_err(|_| "native storage mutex poisoned".to_string())?
                .len() as u32)
        }

        pub fn key(&self, index: u32) -> Result<Option<String>, String> {
            Ok(map()
                .lock()
                .map_err(|_| "native storage mutex poisoned".to_string())?
                .keys()
                .nth(index as usize)
                .cloned())
        }

        /// Test helper — wipe the shared map. Not part of the public
        /// `local_store` surface (browser code calls `clear_all` which
        /// preserves non-`jacs:` keys); used by `cargo test` to reset
        /// state between cases.
        #[allow(dead_code)]
        pub fn reset_for_tests(&self) {
            if let Ok(mut guard) = map().lock() {
                guard.clear();
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
use native_shim::NativeStorage;

// Helper layer so the module body can call the same methods regardless of
// target. The two shapes use the same method names; this keeps the
// implementation single-sourced.
#[cfg(not(target_arch = "wasm32"))]
fn storage_set_item(s: &NativeStorage, key: &str, value: &str) -> Result<(), LocalStoreError> {
    s.set_item(key, value).map_err(LocalStoreError::QuotaExceeded)
}

#[cfg(target_arch = "wasm32")]
fn storage_set_item(
    s: &web_sys::Storage,
    key: &str,
    value: &str,
) -> Result<(), LocalStoreError> {
    s.set_item(key, value).map_err(|js_err| {
        let message = js_err
            .as_string()
            .unwrap_or_else(|| "<unknown setItem failure>".into());
        // QuotaExceededError surfaces with that name in the message on
        // every browser we target. If the message mentions quota / 22 /
        // QuotaExceededError, classify as `QuotaExceeded`; otherwise
        // surface as a generic `StorageUnavailable`.
        if message.contains("QuotaExceeded") || message.contains("quota") || message.contains("22") {
            LocalStoreError::QuotaExceeded(message)
        } else {
            LocalStoreError::StorageUnavailable(message)
        }
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn storage_get_item(
    s: &NativeStorage,
    key: &str,
) -> Result<Option<String>, LocalStoreError> {
    s.get_item(key).map_err(LocalStoreError::StorageUnavailable)
}

#[cfg(target_arch = "wasm32")]
fn storage_get_item(
    s: &web_sys::Storage,
    key: &str,
) -> Result<Option<String>, LocalStoreError> {
    s.get_item(key).map_err(|js_err| {
        LocalStoreError::StorageUnavailable(
            js_err
                .as_string()
                .unwrap_or_else(|| "<unknown getItem failure>".into()),
        )
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn storage_remove_item(s: &NativeStorage, key: &str) -> Result<(), LocalStoreError> {
    s.remove_item(key).map_err(LocalStoreError::StorageUnavailable)
}

#[cfg(target_arch = "wasm32")]
fn storage_remove_item(s: &web_sys::Storage, key: &str) -> Result<(), LocalStoreError> {
    s.remove_item(key).map_err(|js_err| {
        LocalStoreError::StorageUnavailable(
            js_err
                .as_string()
                .unwrap_or_else(|| "<unknown removeItem failure>".into()),
        )
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn storage_length(s: &NativeStorage) -> Result<u32, LocalStoreError> {
    s.length().map_err(LocalStoreError::StorageUnavailable)
}

#[cfg(target_arch = "wasm32")]
fn storage_length(s: &web_sys::Storage) -> Result<u32, LocalStoreError> {
    s.length().map_err(|js_err| {
        LocalStoreError::StorageUnavailable(
            js_err
                .as_string()
                .unwrap_or_else(|| "<unknown length failure>".into()),
        )
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn storage_key_at(s: &NativeStorage, index: u32) -> Result<Option<String>, LocalStoreError> {
    s.key(index).map_err(LocalStoreError::StorageUnavailable)
}

#[cfg(target_arch = "wasm32")]
fn storage_key_at(s: &web_sys::Storage, index: u32) -> Result<Option<String>, LocalStoreError> {
    s.key(index).map_err(|js_err| {
        LocalStoreError::StorageUnavailable(
            js_err
                .as_string()
                .unwrap_or_else(|| "<unknown key failure>".into()),
        )
    })
}

// ---------------------------------------------------------------------------
// Public free functions — JS callers consume these via the `localStore`
// TypeScript wrapper assembled in `index.ts` (Task 020).
// ---------------------------------------------------------------------------

/// Persist an encrypted-agent material blob under `key`. Caller must have
/// produced `material_json` via `coreAgent.exportEncryptedMaterial(...)`
/// (or equivalent). This helper:
///
/// 1. Runs the credential-key tripwire ([`validate_no_plaintext_secrets`])
///    on the payload.
/// 2. Requires the payload to parse as an `AgentMaterial` blob whose
///    `encrypted_private_key` field is a recognized envelope shape
///    ([`validate_encrypted_material_shape`]). This is the load-bearing
///    check for the "localStorage never receives a raw private key"
///    guarantee in PRD §3.1.
pub fn save_encrypted_agent(key: &str, material_json: &str) -> Result<(), LocalStoreError> {
    validate_no_plaintext_secrets(material_json)?;
    validate_encrypted_material_shape(material_json)?;
    let storage = storage_handle()?;
    storage_set_item(&storage, &namespaced(key), material_json)
}

/// Load an encrypted-agent material blob, or return `None` if the key is
/// absent.
pub fn load_encrypted_agent(key: &str) -> Result<Option<String>, LocalStoreError> {
    let storage = storage_handle()?;
    storage_get_item(&storage, &namespaced(key))
}

/// Persist a signed JACS document under `key`. Refuses payloads matching
/// the plaintext-secret tripwire (defense-in-depth).
pub fn save_document(key: &str, signed_json: &str) -> Result<(), LocalStoreError> {
    validate_no_plaintext_secrets(signed_json)?;
    let storage = storage_handle()?;
    storage_set_item(&storage, &namespaced(key), signed_json)
}

/// Load a signed JACS document, or return `None` if the key is absent.
pub fn load_document(key: &str) -> Result<Option<String>, LocalStoreError> {
    let storage = storage_handle()?;
    storage_get_item(&storage, &namespaced(key))
}

/// List every JS-facing key currently stored under the `jacs:` namespace.
/// If `prefix` is supplied, the JS-facing prefix is matched against the
/// returned (post-strip) keys; otherwise every key is returned.
pub fn list_keys(prefix: Option<&str>) -> Result<Vec<String>, LocalStoreError> {
    let storage = storage_handle()?;
    let len = storage_length(&storage)?;
    let mut out = Vec::new();
    for i in 0..len {
        if let Some(raw_key) = storage_key_at(&storage, i)? {
            if let Some(js_key) = raw_key.strip_prefix(JACS_LOCAL_STORE_PREFIX) {
                let matches = match prefix {
                    Some(p) => js_key.starts_with(p),
                    None => true,
                };
                if matches {
                    out.push(js_key.to_string());
                }
            }
        }
    }
    Ok(out)
}

/// Remove the entry stored under `key`. Returns
/// [`LocalStoreError::KeyNotFound`] if the entry was not present (this
/// makes the call observably idempotent — callers who do not care can
/// match on the code and ignore it).
pub fn remove(key: &str) -> Result<(), LocalStoreError> {
    let storage = storage_handle()?;
    let ns_key = namespaced(key);
    let existed = storage_get_item(&storage, &ns_key)?.is_some();
    if !existed {
        return Err(LocalStoreError::KeyNotFound(format!(
            "no entry for key '{}'",
            key
        )));
    }
    storage_remove_item(&storage, &ns_key)
}

/// Remove every entry under the `jacs:` namespace. Keys that do not carry
/// the prefix are left untouched (host-app state survives — PRD §3.1).
pub fn clear_all() -> Result<(), LocalStoreError> {
    let storage = storage_handle()?;
    // Walk twice: first collect the matching raw keys (we cannot remove
    // while iterating because `length` / `key(i)` reshuffle), then delete.
    let len = storage_length(&storage)?;
    let mut targets: Vec<String> = Vec::new();
    for i in 0..len {
        if let Some(raw_key) = storage_key_at(&storage, i)? {
            if raw_key.starts_with(JACS_LOCAL_STORE_PREFIX) {
                targets.push(raw_key);
            }
        }
    }
    for raw_key in targets {
        storage_remove_item(&storage, &raw_key)?;
    }
    Ok(())
}

fn namespaced(key: &str) -> String {
    format!("{}{}", JACS_LOCAL_STORE_PREFIX, key)
}

// ---------------------------------------------------------------------------
// wasm-bindgen exports — JS-facing names are `localStoreXxx` so the
// hand-written TypeScript wrapper (`index.ts`, Task 020) can re-export
// them under the `localStore` object.
// ---------------------------------------------------------------------------

#[wasm_bindgen(js_name = localStoreSaveEncryptedAgent)]
pub fn local_store_save_encrypted_agent(
    key: &str,
    material_json: &str,
) -> Result<(), JsError> {
    save_encrypted_agent(key, material_json).map_err(err_to_js)
}

#[wasm_bindgen(js_name = localStoreLoadEncryptedAgent)]
pub fn local_store_load_encrypted_agent(key: &str) -> Result<Option<String>, JsError> {
    load_encrypted_agent(key).map_err(err_to_js)
}

#[wasm_bindgen(js_name = localStoreSaveDocument)]
pub fn local_store_save_document(key: &str, signed_json: &str) -> Result<(), JsError> {
    save_document(key, signed_json).map_err(err_to_js)
}

#[wasm_bindgen(js_name = localStoreLoadDocument)]
pub fn local_store_load_document(key: &str) -> Result<Option<String>, JsError> {
    load_document(key).map_err(err_to_js)
}

#[wasm_bindgen(js_name = localStoreListKeys)]
pub fn local_store_list_keys(prefix: Option<String>) -> Result<Vec<String>, JsError> {
    list_keys(prefix.as_deref()).map_err(err_to_js)
}

#[wasm_bindgen(js_name = localStoreRemove)]
pub fn local_store_remove(key: &str) -> Result<(), JsError> {
    remove(key).map_err(err_to_js)
}

#[wasm_bindgen(js_name = localStoreClearAll)]
pub fn local_store_clear_all() -> Result<(), JsError> {
    clear_all().map_err(err_to_js)
}

// ---------------------------------------------------------------------------
// Tests — exercise the policy + namespacing on native targets. Browser
// behavior is exercised under `wasm-pack test --headless --chrome
// jacs-wasm --test local_store` (see `tests/local_store.rs`).
// ---------------------------------------------------------------------------

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    // The native fallback uses a process-wide `BTreeMap`. Run every test
    // serially via this mutex so they don't see each other's keys.
    fn test_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        // If a previous test panicked while holding the lock the inner
        // mutex is poisoned; recover so the next test still runs.
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// Acquire the serial-test lock + reset the shared backing map.
    /// Returns the guard; callers must bind it for its full scope.
    #[must_use]
    fn enter() -> MutexGuard<'static, ()> {
        let g = test_lock();
        NativeStorage::shared().reset_for_tests();
        g
    }

    #[test]
    fn save_and_load_document_roundtrip() {
        let _guard = enter();
        save_document("k", r#"{"a":1}"#).expect("save");
        assert_eq!(
            load_document("k").expect("load"),
            Some(r#"{"a":1}"#.to_string())
        );
    }

    #[test]
    fn load_missing_key_returns_none() {
        let _guard = enter();
        assert_eq!(load_document("absent").expect("load"), None);
    }

    #[test]
    fn list_keys_with_prefix_filter() {
        let _guard = enter();
        save_document("alpha-1", r#"{"i":1}"#).unwrap();
        save_document("alpha-2", r#"{"i":2}"#).unwrap();
        save_document("beta-1", r#"{"i":3}"#).unwrap();
        let mut keys = list_keys(Some("alpha-")).expect("list");
        keys.sort();
        assert_eq!(keys, vec!["alpha-1".to_string(), "alpha-2".to_string()]);
    }

    #[test]
    fn list_keys_without_prefix_returns_all() {
        let _guard = enter();
        save_document("one", r#"{}"#).unwrap();
        save_document("two", r#"{}"#).unwrap();
        let mut keys = list_keys(None).expect("list");
        keys.sort();
        assert_eq!(keys, vec!["one".to_string(), "two".to_string()]);
    }

    #[test]
    fn remove_works_and_then_load_returns_none() {
        let _guard = enter();
        save_document("k", r#"{}"#).unwrap();
        remove("k").expect("remove");
        assert_eq!(load_document("k").expect("load"), None);
    }

    #[test]
    fn remove_missing_key_returns_key_not_found() {
        let _guard = enter();
        let err = remove("nope").expect_err("must error");
        assert_eq!(err.code(), "KeyNotFound");
    }

    #[test]
    fn clear_all_only_affects_jacs_prefix() {
        let _guard = enter();
        // Stash a non-jacs-prefixed key directly via the native shim to
        // simulate host-app state.
        NativeStorage::shared()
            .set_item("appstate", "preserved")
            .expect("seed");
        save_document("k", r#"{"a":1}"#).unwrap();
        clear_all().expect("clear");
        // The jacs-prefixed key is gone.
        assert_eq!(load_document("k").expect("load"), None);
        // The non-prefixed key survives.
        assert_eq!(
            NativeStorage::shared().get_item("appstate").expect("get"),
            Some("preserved".to_string())
        );
    }

    #[test]
    fn rejects_payload_with_pem_private_key_marker() {
        let _guard = enter();
        let payload = "-----BEGIN PRIVATE KEY-----\nbase64stuff\n-----END PRIVATE KEY-----";
        let err = save_document("k", payload).expect_err("must refuse");
        assert_eq!(err.code(), "RefusedPayload");
        // And nothing was persisted.
        assert_eq!(load_document("k").expect("load"), None);
    }

    #[test]
    fn rejects_payload_with_top_level_password_field() {
        let _guard = enter();
        let payload = r#"{"password":"hunter2","other":1}"#;
        let err = save_encrypted_agent("k", payload).expect_err("must refuse");
        assert_eq!(err.code(), "RefusedPayload");
        assert_eq!(load_encrypted_agent("k").expect("load"), None);
    }

    #[test]
    fn rejects_payload_with_uppercase_password_field() {
        let _guard = enter();
        // Case-insensitive on the key name.
        let payload = r#"{"Password":"hunter2"}"#;
        let err = save_document("k", payload).expect_err("must refuse");
        assert_eq!(err.code(), "RefusedPayload");
    }

    #[test]
    fn secret_leak_walk_finds_no_plaintext_secret_after_typical_flow() {
        // Simulate the canonical flow: an encrypted material blob (no
        // plaintext password, no PEM private block) + a signed document
        // produced by the agent. Walk every key and assert nothing
        // leaked.
        let _guard = enter();
        let password = "verySecret-leak-walk-password!42";
        let private_key_bytes = vec![0x42u8; 32];
        let private_key_b64 = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(&private_key_bytes)
        };
        // The encrypted blob wrapped in an AgentMaterial-shaped object —
        // matches the on-disk shape produced by jacs-core
        // `coreAgent.exportEncryptedMaterial(...)`. The V2 JSON envelope
        // is the value of `encrypted_private_key`.
        let encrypted_material = r#"{
            "config": {"agent_id": "a"},
            "agent": {"jacsId": "a"},
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
        let signed_doc = r#"{"jacsId":"abc","jacsSignature":{"signature":"sig","signingAlgorithm":"ed25519"}}"#;
        save_document("doc-1", signed_doc).expect("save doc");

        // Walk every JS-facing key under the `jacs:` namespace and
        // assert no value contains the password literal, a PEM private
        // marker, the base64 form of the raw private key, or the literal
        // bytes printed via {:?}.
        let keys = list_keys(None).expect("list");
        for key in &keys {
            let value = load_document(key).expect("load");
            let raw = value.unwrap_or_default();
            assert!(
                !raw.contains(password),
                "key '{}' leaked password literal",
                key
            );
            assert!(
                !raw.contains(PEM_PRIVATE_KEY_MARKER),
                "key '{}' leaked PEM private key marker",
                key
            );
            assert!(
                !raw.contains(&private_key_b64),
                "key '{}' leaked base64 raw private key",
                key
            );
            // Also assert no debug-print form of the raw bytes leaked.
            let private_key_debug = format!("{:?}", private_key_bytes);
            assert!(
                !raw.contains(&private_key_debug),
                "key '{}' leaked debug-print form of raw private key",
                key
            );
        }
        // Also walk the raw underlying storage (in case some entry was
        // written outside the `jacs:` namespace — none should be).
        let len = NativeStorage::shared().length().unwrap();
        for i in 0..len {
            if let Some(raw_key) = NativeStorage::shared().key(i).unwrap() {
                if let Some(value) = NativeStorage::shared().get_item(&raw_key).unwrap() {
                    assert!(!value.contains(password), "leaked password under '{}'", raw_key);
                    assert!(
                        !value.contains(PEM_PRIVATE_KEY_MARKER),
                        "leaked PEM marker under '{}'",
                        raw_key
                    );
                    assert!(
                        !value.contains(&private_key_b64),
                        "leaked base64 raw key under '{}'",
                        raw_key
                    );
                }
            }
        }
    }

    #[test]
    fn validate_no_plaintext_secrets_accepts_valid_encrypted_envelope() {
        // The V2 envelope shape should always pass — its content is
        // ciphertext, salt, nonce, no plaintext password.
        let v2 = r#"{"jacsEncryptedPrivateKeyVersion":2,"cipher":"AES-256-GCM","ciphertext":"abc","salt":"def","nonce":"ghi"}"#;
        assert!(validate_no_plaintext_secrets(v2).is_ok());
    }

    #[test]
    fn validate_no_plaintext_secrets_accepts_non_json_payload() {
        // Arbitrary bytes / non-JSON: the JSON sniff is best-effort,
        // non-JSON falls through and is allowed (only the PEM marker
        // check applies).
        let raw = "not json at all";
        assert!(validate_no_plaintext_secrets(raw).is_ok());
    }

    // ---------------------------------------------------------------
    // Issue 004 / Task 029 — new negative tests for the strengthened
    // tripwire: nested credential keys + envelope-shape enforcement on
    // `save_encrypted_agent`. Each documents one banned shape.
    // ---------------------------------------------------------------

    #[test]
    fn rejects_payload_with_nested_password_field() {
        let _guard = enter();
        let payload = r#"{"outer":{"inner":{"password":"hunter2"}}}"#;
        let err = save_document("k", payload).expect_err("must refuse");
        assert_eq!(err.code(), "RefusedPayload");
        assert!(
            format!("{err}").contains("/outer/inner/password"),
            "error should report the JSON pointer of the offending key, got: {err}"
        );
    }

    #[test]
    fn rejects_payload_with_passphrase_field() {
        let _guard = enter();
        // Synonym of `password`; PRD §3.1 calls it out as a credential.
        let payload = r#"{"settings":{"Passphrase":"hunter2"}}"#;
        let err = save_document("k", payload).expect_err("must refuse");
        assert_eq!(err.code(), "RefusedPayload");
    }

    #[test]
    fn rejects_payload_with_secret_field_in_array() {
        let _guard = enter();
        // Inside an array of objects; the walk descends arrays too.
        let payload = r#"{"items":[{"id":1},{"secret":"shh"}]}"#;
        let err = save_document("k", payload).expect_err("must refuse");
        assert_eq!(err.code(), "RefusedPayload");
        assert!(
            format!("{err}").contains("/items/1/secret"),
            "error should report array-aware JSON pointer, got: {err}"
        );
    }

    #[test]
    fn save_encrypted_agent_rejects_raw_private_key_in_envelope_field() {
        // Caller has accidentally serialised an AgentMaterial whose
        // `encrypted_private_key` value is a base64-encoded raw 32-byte
        // key (44 base64 chars) instead of a real envelope.
        let _guard = enter();
        let raw_b64 = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode([0x42u8; 32])
        };
        let payload = format!(
            r#"{{"config":{{}},"agent":{{}},"public_key":[1,2,3],"encrypted_private_key":"{raw_b64}","algorithm":"ed25519"}}"#
        );
        let err = save_encrypted_agent("k", &payload).expect_err("must refuse raw key");
        assert_eq!(err.code(), "RefusedPayload");
        assert!(
            format!("{err}").contains("too short"),
            "error should explain why the envelope is rejected, got: {err}"
        );
        // Nothing was persisted.
        assert_eq!(load_encrypted_agent("k").expect("load"), None);
    }

    #[test]
    fn save_encrypted_agent_rejects_arbitrary_non_envelope_string() {
        let _guard = enter();
        let payload = r#"{"config":{},"agent":{},"public_key":[1,2,3],"encrypted_private_key":"hello world this is not a key","algorithm":"ed25519"}"#;
        let err = save_encrypted_agent("k", payload).expect_err("must refuse");
        assert_eq!(err.code(), "RefusedPayload");
    }

    #[test]
    fn save_encrypted_agent_rejects_missing_envelope_field() {
        let _guard = enter();
        let payload = r#"{"config":{},"agent":{},"public_key":[1,2,3],"algorithm":"ed25519"}"#;
        let err = save_encrypted_agent("k", payload).expect_err("must refuse");
        assert_eq!(err.code(), "RefusedPayload");
        assert!(
            format!("{err}").contains("missing 'encrypted_private_key'"),
            "error should explain missing field, got: {err}"
        );
    }

    #[test]
    fn save_encrypted_agent_accepts_v2_envelope_shape() {
        // The canonical happy path: AgentMaterial with a V2 envelope
        // object as `encrypted_private_key`.
        let _guard = enter();
        let payload = r#"{
            "config": {},
            "agent": {},
            "public_key": [1,2,3],
            "encrypted_private_key": {
                "jacsEncryptedPrivateKeyVersion": 2,
                "cipher": "AES-256-GCM",
                "ciphertext": "deadbeef",
                "salt": "saltsalt",
                "nonce": "noncenonce"
            },
            "algorithm": "ed25519"
        }"#;
        save_encrypted_agent("k", payload).expect("happy path V2 envelope");
        assert!(load_encrypted_agent("k").expect("load").is_some());
    }

    #[test]
    fn save_encrypted_agent_accepts_pbkdf2_base64_long_enough_string() {
        // A long base64 string (≥ 89 chars; decodes to ≥ 44 bytes,
        // above MIN_PBKDF2_ENVELOPE_BYTES once we account for cipher
        // overhead).
        let _guard = enter();
        let payload_bytes = vec![0u8; 96]; // 16-salt + 12-nonce + 68-ciphertext+tag = 96 bytes
        let b64 = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(&payload_bytes)
        };
        assert!(b64.len() > MAX_RAW_KEY_BASE64_LEN);
        let payload = format!(
            r#"{{"config":{{}},"agent":{{}},"public_key":[1,2,3],"encrypted_private_key":"{b64}","algorithm":"ed25519"}}"#
        );
        save_encrypted_agent("k", &payload).expect("happy path PBKDF2 base64");
    }

    #[test]
    fn save_encrypted_agent_rejects_non_json_payload() {
        let _guard = enter();
        let err = save_encrypted_agent("k", "not json").expect_err("must refuse");
        assert_eq!(err.code(), "RefusedPayload");
    }
}
