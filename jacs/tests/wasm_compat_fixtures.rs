//! Task 001 — Lock characterization fixtures for Ed25519 + pq2025 + envelopes.
//!
//! These fixtures are the cross-compat oracle for the jacs-core extraction
//! (Tasks 005-014). Every byte written here must remain readable, byte-exact,
//! after the protocol layer is moved to jacs-core. See `JACS_WASM_PRD.md` §4.5,
//! §5.2 and `JACS_WASM_PRD_TASKS/JACS_WASM_TASK_001.md`.
//!
//! ## Fixture set
//!
//! Under `jacs/tests/fixtures/wasm_compat/`:
//! - `ed25519.pkcs8.bin` — PKCS#8 v2 private key bytes (ring-emitted).
//! - `ed25519.public.bin` — raw 32-byte Ed25519 public key.
//! - `ed25519.signed.json` — `{ "canonical": "...", "signature_b64": "..." }`.
//!   The signature is over the JCS-canonical bytes of the embedded payload —
//!   Ed25519 is deterministic, so this byte-locks the wire format.
//! - `pq2025.private.bin` — `fips204::ml_dsa_87` private key bytes.
//! - `pq2025.public.bin` — `fips204::ml_dsa_87` public key bytes.
//! - `pq2025.signed.json` — `{ "canonical": "...", "signature_b64": "..." }`.
//!   Verify-only oracle (pq2025 is randomized, no signature byte-lock).
//! - `argon2id.encrypted.json` — current V2 JSON envelope (Argon2id KDF +
//!   AES-256-GCM) wrapping `ed25519.pkcs8.bin`. Produced by the current
//!   native writer (`encrypt_private_key_with_password`).
//! - `pbkdf2.encrypted.bin` — synthesized legacy raw-binary envelope
//!   (`salt || nonce || ciphertext`, PBKDF2-HMAC-SHA256 @ 100k iterations)
//!   wrapping `ed25519.pkcs8.bin`. The current writer no longer emits this
//!   format; the fixture exercises the legacy reader path.
//! - `canonical_inputs.json` / `canonical_outputs.json` — 10 sample payloads
//!   and their JCS-canonical bytes.
//! - `agreement.json` — minimal two-party signed agreement (synthetic).
//! - `agreement.signers.json` — `[{ "id": "...", "public_key_b64": "...",
//!   "algorithm": "ed25519" }, ...]`.
//!
//! ## Fixture password
//!
//! All encrypted envelopes use the fixed password `Test#Password!2026`.
//!
//! ## Regenerating
//!
//! ```bash
//! UPDATE_WASM_COMPAT_FIXTURES=1 cargo test -p jacs \
//!     --test wasm_compat_fixtures \
//!     -- --nocapture --include-ignored regenerate_wasm_compat_fixtures
//! ```
//!
//! Ed25519, canonical JSON, PBKDF2-HMAC-SHA256, and Argon2id are deterministic
//! given fixed inputs (PBKDF2 and Argon2id need a fixed salt + IV; Ed25519
//! sign is fully deterministic; canonicalization is deterministic). pq2025 +
//! Argon2id production writer use entropy from the OS RNG, so re-running the
//! generator produces different bytes — only the verification semantics are
//! locked, not the exact bytes. The regenerator commits new bytes only when
//! the user explicitly opts in.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use jacs::crypt::aes_encrypt::{
    decrypt_private_key_secure_with_password, encrypt_private_key_with_password,
};
use jacs::crypt::{pq2025, ringwrapper};
use jacs::protocol::canonicalize_json;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::OnceLock;

const FIXTURE_PASSWORD: &str = "Test#Password!2026";

fn fixtures_dir() -> &'static PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("wasm_compat")
    })
}

fn fixture_path(name: &str) -> PathBuf {
    fixtures_dir().join(name)
}

fn read_fixture(name: &str) -> Vec<u8> {
    let path = fixture_path(name);
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "wasm_compat fixture '{}' missing or unreadable ({}). \
             Regenerate with UPDATE_WASM_COMPAT_FIXTURES=1 \
             cargo test -p jacs --test wasm_compat_fixtures \
             -- --nocapture --include-ignored regenerate_wasm_compat_fixtures.",
            path.display(),
            e
        )
    })
}

fn read_fixture_json(name: &str) -> Value {
    serde_json::from_slice(&read_fixture(name)).expect("fixture not valid JSON")
}

/// 10 canonical-payload sample inputs.
///
/// Names mirror `binding-core/tests/fixtures/parity_inputs.json` where the
/// shape applies (simple_message, nested_message, empty_object, string_value,
/// numeric_value, boolean_value, null_value, unicode_ascii_safe). The
/// remaining two cover an empty array and a unicode-with-symbols case so the
/// canonical bytes lock these edge cases too.
fn canonical_input_specs() -> Vec<(&'static str, Value)> {
    vec![
        ("simple_message", json!({"action": "test", "value": 42})),
        (
            "nested_message",
            json!({"user": {"name": "Alice", "role": "admin"}, "items": [1, 2, 3]}),
        ),
        ("empty_object", json!({})),
        ("empty_array", json!([])),
        ("string_value", json!("hello world")),
        ("numeric_value", json!(12345)),
        ("boolean_value", json!(true)),
        ("null_value", Value::Null),
        (
            "unicode_ascii_safe",
            json!({"greeting": "hello", "code": "ABC-123"}),
        ),
        (
            "unicode_symbols",
            json!({"emoji": "πŸ”", "currency": "€", "math": "ℝ ⊂ β„‚"}),
        ),
    ]
}

// ============================================================================
// Tests (run unconditionally)
// ============================================================================

/// Ed25519 signatures are deterministic — the bytes captured at fixture time
/// must match what `ringwrapper::sign_string` produces today. Any drift here
/// is a wire-format regression and a release blocker for the wasm port.
#[test]
fn ed25519_fixture_sign_verify_roundtrip() {
    let pkcs8 = read_fixture("ed25519.pkcs8.bin");
    let public_key = read_fixture("ed25519.public.bin");
    let signed: Value = read_fixture_json("ed25519.signed.json");
    let canonical = signed["canonical"].as_str().expect("canonical string");
    let expected_sig_b64 = signed["signature_b64"]
        .as_str()
        .expect("signature_b64 string");

    let produced_sig_b64 =
        ringwrapper::sign_string(pkcs8, &canonical.to_string()).expect("sign_string");
    assert_eq!(
        produced_sig_b64, expected_sig_b64,
        "Ed25519 signature drift — ring no longer produces the locked bytes"
    );

    ringwrapper::verify_string(public_key, canonical, expected_sig_b64).expect("verify_string");
}

#[test]
fn pq2025_fixture_verify_only() {
    let public_key = read_fixture("pq2025.public.bin");
    let signed: Value = read_fixture_json("pq2025.signed.json");
    let canonical = signed["canonical"].as_str().expect("canonical string");
    let sig_b64 = signed["signature_b64"].as_str().expect("signature_b64");

    pq2025::verify_string(public_key, canonical, sig_b64).expect("pq2025 verify_string");
}

#[test]
fn argon2id_v2_envelope_fixture_decrypts() {
    let envelope = read_fixture("argon2id.encrypted.json");
    let expected_pkcs8 = read_fixture("ed25519.pkcs8.bin");
    let decrypted =
        decrypt_private_key_secure_with_password(&envelope, FIXTURE_PASSWORD).expect("decrypt v2");
    assert_eq!(
        decrypted.as_slice(),
        expected_pkcs8.as_slice(),
        "V2 Argon2id JSON envelope decrypt drift"
    );
}

#[test]
fn pbkdf2_legacy_envelope_fixture_decrypts() {
    let envelope = read_fixture("pbkdf2.encrypted.bin");
    let expected_pkcs8 = read_fixture("ed25519.pkcs8.bin");
    let decrypted = decrypt_private_key_secure_with_password(&envelope, FIXTURE_PASSWORD)
        .expect("decrypt legacy");
    assert_eq!(
        decrypted.as_slice(),
        expected_pkcs8.as_slice(),
        "Legacy raw-binary PBKDF2 envelope decrypt drift"
    );
}

#[test]
fn canonical_payload_goldens_match() {
    let inputs: Value = read_fixture_json("canonical_inputs.json");
    let outputs: Value = read_fixture_json("canonical_outputs.json");
    let inputs_arr = inputs.as_array().expect("inputs is array");
    let outputs_obj = outputs.as_object().expect("outputs is object map");
    assert_eq!(
        inputs_arr.len(),
        outputs_obj.len(),
        "canonical inputs/outputs length mismatch"
    );

    for entry in inputs_arr {
        let name = entry["name"].as_str().expect("name");
        let data = &entry["data"];
        let expected = outputs_obj
            .get(name)
            .unwrap_or_else(|| panic!("canonical output missing for '{name}'"))
            .as_str()
            .expect("output is string");
        let produced = canonicalize_json(data);
        assert_eq!(produced, expected, "canonical drift for '{name}'");
    }
}

#[test]
fn multi_party_agreement_fixture_verifies() {
    let agreement: Value = read_fixture_json("agreement.json");
    let signers: Value = read_fixture_json("agreement.signers.json");
    let signers_arr = signers.as_array().expect("signers is array");
    assert!(
        signers_arr.len() >= 2,
        "agreement fixture must have at least two signers"
    );

    let canonical_payload = agreement["canonical_payload"]
        .as_str()
        .expect("canonical_payload");
    let signatures = agreement["signatures"]
        .as_array()
        .expect("signatures is array");
    assert_eq!(
        signatures.len(),
        signers_arr.len(),
        "signers/signatures cardinality mismatch"
    );

    for entry in signatures {
        let signer_id = entry["signer_id"].as_str().expect("signer_id");
        let sig_b64 = entry["signature_b64"].as_str().expect("signature_b64");
        let signer = signers_arr
            .iter()
            .find(|s| s["id"].as_str() == Some(signer_id))
            .unwrap_or_else(|| panic!("no signer entry for id {signer_id}"));
        let public_key_b64 = signer["public_key_b64"]
            .as_str()
            .expect("signer public_key_b64");
        let public_key = B64.decode(public_key_b64).expect("base64 public key");
        ringwrapper::verify_string(public_key, canonical_payload, sig_b64)
            .unwrap_or_else(|e| panic!("signer {signer_id} verify failed: {e}"));
    }
}

// ============================================================================
// Regenerator (gated)
// ============================================================================

/// Regenerate every fixture under `jacs/tests/fixtures/wasm_compat/`.
///
/// Gated on the `UPDATE_WASM_COMPAT_FIXTURES` env var. Marked `#[ignore]` so
/// it does not run during normal `cargo test` invocations.
///
/// ```bash
/// UPDATE_WASM_COMPAT_FIXTURES=1 cargo test -p jacs \
///     --test wasm_compat_fixtures \
///     -- --nocapture --include-ignored regenerate_wasm_compat_fixtures
/// ```
#[test]
#[ignore = "regenerator — gated on UPDATE_WASM_COMPAT_FIXTURES"]
fn regenerate_wasm_compat_fixtures() {
    if std::env::var_os("UPDATE_WASM_COMPAT_FIXTURES").is_none() {
        panic!(
            "Refusing to overwrite fixtures without UPDATE_WASM_COMPAT_FIXTURES=1. \
             Run `UPDATE_WASM_COMPAT_FIXTURES=1 cargo test -p jacs \
             --test wasm_compat_fixtures -- --include-ignored \
             regenerate_wasm_compat_fixtures`."
        );
    }
    regen::regenerate_all();
}

// ============================================================================
// Regenerator internals — module so the unit tests above stay focused.
// ============================================================================

mod regen {
    use super::*;
    use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
    use pbkdf2::pbkdf2_hmac;
    use rand::{RngCore, SeedableRng, rngs::StdRng};
    use sha2::Sha256;

    const FIXTURE_PBKDF2_ITERATIONS: u32 = 100_000;
    const PBKDF2_SALT_SIZE: usize = 16;
    const AES_GCM_NONCE_SIZE: usize = 12;
    const AES_256_KEY_SIZE: usize = 32;

    pub fn regenerate_all() {
        let dir = super::fixtures_dir();
        std::fs::create_dir_all(dir).expect("mkdir wasm_compat");

        write_ed25519_fixtures();
        write_pq2025_fixtures();
        write_canonical_fixtures();
        // ed25519 fixtures must exist before envelopes (we encrypt the
        // pkcs8 bytes).
        write_argon2id_envelope();
        write_pbkdf2_envelope();
        write_agreement_fixtures();
    }

    fn write_json(path: std::path::PathBuf, value: &Value) {
        let mut bytes = serde_json::to_vec_pretty(value).expect("json serialize");
        bytes.push(b'\n');
        std::fs::write(&path, bytes)
            .unwrap_or_else(|e| panic!("write {} failed: {}", path.display(), e));
    }

    fn write_ed25519_fixtures() {
        // We generate a fresh keypair via ring, then sign the canonical bytes
        // of a fixed payload. Re-running flips the bytes (random keygen) but
        // the test suite only requires byte-equality at *verify* time against
        // whatever was committed.
        let (pkcs8, public) = ringwrapper::generate_keys().expect("ringwrapper generate");
        let payload = json!({"fixture": "wasm_compat::ed25519", "ts": "2026-05-16"});
        let canonical = canonicalize_json(&payload);
        let sig_b64 = ringwrapper::sign_string(pkcs8.clone(), &canonical).expect("sign");

        std::fs::write(super::fixture_path("ed25519.pkcs8.bin"), &pkcs8).expect("write pkcs8");
        std::fs::write(super::fixture_path("ed25519.public.bin"), &public).expect("write public");
        let signed = json!({
            "canonical": canonical,
            "signature_b64": sig_b64,
            "payload": payload,
        });
        write_json(super::fixture_path("ed25519.signed.json"), &signed);
    }

    fn write_pq2025_fixtures() {
        let (private_key, public_key) = pq2025::generate_keys().expect("pq2025 generate");
        let payload = json!({"fixture": "wasm_compat::pq2025", "ts": "2026-05-16"});
        let canonical = canonicalize_json(&payload);
        let sig_b64 = pq2025::sign_string(private_key.clone(), &canonical).expect("pq2025 sign");

        std::fs::write(super::fixture_path("pq2025.private.bin"), &private_key)
            .expect("write pq private");
        std::fs::write(super::fixture_path("pq2025.public.bin"), &public_key)
            .expect("write pq public");
        let signed = json!({
            "canonical": canonical,
            "signature_b64": sig_b64,
            "payload": payload,
        });
        write_json(super::fixture_path("pq2025.signed.json"), &signed);
    }

    fn write_canonical_fixtures() {
        let specs = canonical_input_specs();
        let inputs: Vec<_> = specs
            .iter()
            .map(|(name, data)| json!({"name": name, "data": data}))
            .collect();
        let mut outputs = serde_json::Map::new();
        for (name, data) in &specs {
            outputs.insert((*name).to_string(), Value::String(canonicalize_json(data)));
        }
        write_json(
            super::fixture_path("canonical_inputs.json"),
            &Value::Array(inputs),
        );
        write_json(
            super::fixture_path("canonical_outputs.json"),
            &Value::Object(outputs),
        );
    }

    fn write_argon2id_envelope() {
        let pkcs8 = std::fs::read(super::fixture_path("ed25519.pkcs8.bin"))
            .expect("ed25519.pkcs8.bin not present");
        let envelope = encrypt_private_key_with_password(&pkcs8, FIXTURE_PASSWORD)
            .expect("encrypt v2 envelope");
        std::fs::write(super::fixture_path("argon2id.encrypted.json"), envelope)
            .expect("write argon2id envelope");
    }

    /// Build a legacy `salt || nonce || ciphertext` envelope using
    /// PBKDF2-HMAC-SHA256 @ 100k iterations (the deprecated reader path).
    ///
    /// The current production writer emits V2 JSON / Argon2id; this generator
    /// reaches under the API so the fixture exercises the legacy reader path
    /// that jacs-core::envelope must continue to support.
    fn write_pbkdf2_envelope() {
        // Seeded RNG so re-running the generator twice in the same checkout
        // produces the same envelope bytes for this single fixture (Argon2id
        // and pq2025 still rotate — those use OS entropy by design).
        // Deterministic seed so re-running the regenerator twice yields the
        // same envelope bytes for this single fixture. Random-looking hex,
        // committed once and never rotated.
        let mut rng = StdRng::seed_from_u64(0xAC5_BA5E_5EED_F1FE_u64);
        let mut salt = [0u8; PBKDF2_SALT_SIZE];
        rng.fill_bytes(&mut salt);
        let mut nonce_bytes = [0u8; AES_GCM_NONCE_SIZE];
        rng.fill_bytes(&mut nonce_bytes);

        let pkcs8 = std::fs::read(super::fixture_path("ed25519.pkcs8.bin"))
            .expect("ed25519.pkcs8.bin not present");

        let mut key = [0u8; AES_256_KEY_SIZE];
        pbkdf2_hmac::<Sha256>(
            FIXTURE_PASSWORD.as_bytes(),
            &salt,
            FIXTURE_PBKDF2_ITERATIONS,
            &mut key,
        );
        let cipher_key = Key::<Aes256Gcm>::from_slice(&key);
        let cipher = Aes256Gcm::new(cipher_key);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, pkcs8.as_slice())
            .expect("aes encrypt");

        let mut envelope = Vec::with_capacity(salt.len() + nonce_bytes.len() + ciphertext.len());
        envelope.extend_from_slice(&salt);
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ciphertext);
        std::fs::write(super::fixture_path("pbkdf2.encrypted.bin"), envelope)
            .expect("write pbkdf2 envelope");
    }

    /// Synthetic two-party signed agreement. Each "signer" is a fresh Ed25519
    /// keypair; both sign the canonical bytes of the same agreement payload.
    /// This avoids the optional `agreements` feature flag while still locking
    /// the multi-party verification semantics. See `jacs::agreements` for the
    /// production multi-party flow.
    fn write_agreement_fixtures() {
        let payload = json!({
            "fixture": "wasm_compat::agreement",
            "subject": "Approve the wasm port",
            "agents": ["agent-alpha", "agent-beta"],
            "context": "Two-party agreement fixture for jacs-core::agreements cross-compat.",
        });
        let canonical_payload = canonicalize_json(&payload);

        let signers_meta = ["agent-alpha", "agent-beta"];
        let mut signers = Vec::with_capacity(signers_meta.len());
        let mut signatures = Vec::with_capacity(signers_meta.len());
        for id in signers_meta {
            let (pkcs8, public_key) =
                ringwrapper::generate_keys().expect("ringwrapper generate (agreement)");
            let sig_b64 = ringwrapper::sign_string(pkcs8, &canonical_payload).expect("sign");
            signers.push(json!({
                "id": id,
                "public_key_b64": B64.encode(&public_key),
                "algorithm": "ed25519",
            }));
            signatures.push(json!({
                "signer_id": id,
                "signature_b64": sig_b64,
            }));
        }
        let agreement = json!({
            "payload": payload,
            "canonical_payload": canonical_payload,
            "signatures": signatures,
        });
        write_json(super::fixture_path("agreement.json"), &agreement);
        write_json(
            super::fixture_path("agreement.signers.json"),
            &Value::Array(signers),
        );
    }
}
