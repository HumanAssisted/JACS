//! Wave 3 / Task 007: tests for the V2 Argon2id JSON envelope and the
//! legacy PBKDF2 raw-binary reader. The native fixtures from Task 001 are
//! the cross-compat oracle: any drift in either path breaks every existing
//! key on disk.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jacs_core::CoreError;
use jacs_core::envelope::{
    self, AES_GCM_NONCE_SIZE, MAX_ENCRYPTED_PRIVATE_KEY_BYTES, PBKDF2_ITERATIONS,
    PBKDF2_ITERATIONS_LEGACY, PBKDF2_SALT_SIZE, decrypt_private_key, derive_key_with_iterations,
    encrypt_private_key,
};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::time::{Duration, Instant};

const TEST_PASSWORD: &str = "Test#Password!2026";
const FIXTURE_PASSWORD: &str = "Test#Password!2026"; // matches Task 001 regenerator
const FIXTURE_PKCS8: &[u8] =
    include_bytes!("../../jacs/tests/fixtures/wasm_compat/ed25519.pkcs8.bin");
const FIXTURE_ARGON2ID: &[u8] =
    include_bytes!("../../jacs/tests/fixtures/wasm_compat/argon2id.encrypted.json");
const FIXTURE_PBKDF2: &[u8] =
    include_bytes!("../../jacs/tests/fixtures/wasm_compat/pbkdf2.encrypted.bin");

#[test]
fn argon2id_v2_encrypt_decrypt_roundtrip() {
    let plain = b"the quick brown fox jumps over the lazy dog";
    let envelope = encrypt_private_key(plain, TEST_PASSWORD).expect("encrypt");
    let decrypted = decrypt_private_key(&envelope, TEST_PASSWORD).expect("decrypt");
    assert_eq!(decrypted.as_slice(), plain);
}

#[test]
fn argon2id_v2_emits_json_envelope() {
    let plain = b"sample key bytes";
    let envelope = encrypt_private_key(plain, TEST_PASSWORD).expect("encrypt");
    assert_eq!(envelope.first(), Some(&b'{'), "V2 envelope is JSON");
    let json: serde_json::Value = serde_json::from_slice(&envelope).expect("envelope is JSON");
    assert_eq!(json["jacsEncryptedPrivateKeyVersion"], 2);
    assert_eq!(json["cipher"], "AES-256-GCM");
    assert_eq!(json["kdf"]["name"], "Argon2id");
    assert_eq!(json["kdf"]["version"], 19);
}

#[test]
fn argon2id_v2_wrong_password_fails() {
    let plain = b"sensitive material";
    let envelope = encrypt_private_key(plain, TEST_PASSWORD).expect("encrypt");
    let err = decrypt_private_key(&envelope, "wrong-password").expect_err("must fail");
    assert!(matches!(err, CoreError::InvalidPassword), "got {err:?}");
}

#[test]
fn argon2id_cost_above_profile_is_rejected_before_kdf_work() {
    let envelope = encrypt_private_key(b"sensitive material", TEST_PASSWORD).expect("encrypt");
    let mut json: serde_json::Value = serde_json::from_slice(&envelope).expect("envelope JSON");
    json["kdf"]["m_cost_kib"] = serde_json::json!(19_457);
    let mutated = serde_json::to_vec(&json).expect("mutated envelope");

    let started = Instant::now();
    let err = decrypt_private_key(&mutated, TEST_PASSWORD).expect_err("policy must reject");
    assert!(started.elapsed() < Duration::from_millis(100));
    match err {
        CoreError::MalformedEnvelope(reason) => {
            assert!(reason.contains("Argon2id parameter policy rejected"));
            assert!(reason.contains("mCostKib"));
        }
        other => panic!("expected a KDF policy rejection, got {other:?}"),
    }
}

#[test]
fn argon2id_time_and_parallelism_above_profile_are_rejected() {
    let envelope = encrypt_private_key(b"sensitive material", TEST_PASSWORD).expect("encrypt");
    for (field, value) in [("t_cost", 3), ("p_cost", 2)] {
        let mut json: serde_json::Value = serde_json::from_slice(&envelope).expect("envelope JSON");
        json["kdf"][field] = serde_json::json!(value);
        let mutated = serde_json::to_vec(&json).expect("mutated envelope");
        let err = decrypt_private_key(&mutated, TEST_PASSWORD).expect_err("policy must reject");
        assert!(
            matches!(err, CoreError::MalformedEnvelope(ref reason) if reason.contains("Argon2id parameter policy rejected")),
            "{field} returned {err:?}"
        );
    }
}

fn synthesize_argon2id_envelope(
    plain: &[u8],
    password: &str,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Vec<u8> {
    let salt = [0x5au8; 16];
    let nonce_bytes = [0xa5u8; 12];
    let params = Params::new(m_cost_kib, t_cost, p_cost, Some(32)).expect("valid test profile");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .expect("derive test key");
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plain)
        .expect("encrypt test envelope");
    serde_json::to_vec(&serde_json::json!({
        "jacsEncryptedPrivateKeyVersion": 2,
        "cipher": "AES-256-GCM",
        "kdf": {
            "name": "Argon2id",
            "version": 19,
            "m_cost_kib": m_cost_kib,
            "t_cost": t_cost,
            "p_cost": p_cost
        },
        "salt": URL_SAFE_NO_PAD.encode(salt),
        "nonce": URL_SAFE_NO_PAD.encode(nonce_bytes),
        "ciphertext": URL_SAFE_NO_PAD.encode(ciphertext)
    }))
    .expect("serialize test envelope")
}

#[test]
fn argon2id_intentional_minimum_profile_decrypts() {
    let plain = b"minimum accepted profile";
    let envelope = synthesize_argon2id_envelope(plain, TEST_PASSWORD, 8_192, 1, 1);
    let decrypted = decrypt_private_key(&envelope, TEST_PASSWORD).expect("minimum profile");
    assert_eq!(decrypted.as_slice(), plain);
}

#[test]
fn argon2id_envelope_rejects_duplicate_kdf_fields() {
    let envelope = encrypt_private_key(b"sensitive material", TEST_PASSWORD).expect("encrypt");
    let text = String::from_utf8(envelope).expect("JSON envelope");
    let duplicated = text.replacen(
        "\"m_cost_kib\":19456",
        "\"m_cost_kib\":8192,\"m_cost_kib\":19456",
        1,
    );
    assert_ne!(duplicated, text, "fixture field must be replaced");
    let err = decrypt_private_key(duplicated.as_bytes(), TEST_PASSWORD)
        .expect_err("duplicate KDF field must fail");
    assert!(
        matches!(err, CoreError::MalformedEnvelope(ref reason) if reason.contains("duplicate JSON object key") || reason.contains("duplicate field")),
        "got {err:?}"
    );
}

fn synthesize_legacy_pbkdf2_envelope(plain: &[u8], password: &str, iterations: u32) -> Vec<u8> {
    // Seeded RNG so the test is bit-stable.
    let mut rng = StdRng::seed_from_u64(0xCAFE_BABE);
    let mut salt = [0u8; PBKDF2_SALT_SIZE];
    rand::RngCore::fill_bytes(&mut rng, &mut salt);
    let mut nonce_bytes = [0u8; AES_GCM_NONCE_SIZE];
    rand::RngCore::fill_bytes(&mut rng, &mut nonce_bytes);

    let key = derive_key_with_iterations(password, &salt, iterations);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, plain).expect("encrypt");

    let mut out = Vec::with_capacity(PBKDF2_SALT_SIZE + AES_GCM_NONCE_SIZE + ct.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    out
}

#[test]
fn pbkdf2_legacy_raw_binary_decrypts_at_current_iterations() {
    let plain = b"legacy material";
    let env = synthesize_legacy_pbkdf2_envelope(plain, TEST_PASSWORD, PBKDF2_ITERATIONS);
    let decrypted = decrypt_private_key(&env, TEST_PASSWORD).expect("decrypt");
    assert_eq!(decrypted.as_slice(), plain);
}

#[test]
fn pbkdf2_legacy_100k_fallback_decrypts() {
    let plain = b"pre-0.6.0 material";
    let env = synthesize_legacy_pbkdf2_envelope(plain, TEST_PASSWORD, PBKDF2_ITERATIONS_LEGACY);
    let decrypted = decrypt_private_key(&env, TEST_PASSWORD).expect("legacy fallback decrypts");
    assert_eq!(decrypted.as_slice(), plain);
}

#[test]
fn truncated_envelope_fails_with_malformed_envelope() {
    // Shorter than MIN_ENCRYPTED_HEADER_SIZE (28) and not JSON.
    let env: &[u8] = &[1, 2, 3, 4, 5];
    let err = decrypt_private_key(env, TEST_PASSWORD).expect_err("must fail");
    assert!(
        matches!(err, CoreError::MalformedEnvelope(_)),
        "got {err:?}"
    );
}

#[test]
fn oversized_legacy_input_is_rejected_before_pbkdf2_or_aead_work() {
    let oversized = vec![0x01; MAX_ENCRYPTED_PRIVATE_KEY_BYTES + 1];
    let started = Instant::now();
    let error = decrypt_private_key(&oversized, TEST_PASSWORD)
        .expect_err("oversized legacy input must fail before KDF work");
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "size rejection unexpectedly performed expensive crypto"
    );
    assert!(
        matches!(error, CoreError::MalformedEnvelope(ref reason) if reason.contains("exceeds")),
        "unexpected error: {error:?}"
    );
}

#[test]
fn fixture_argon2id_envelope_decrypts_in_core() {
    let decrypted = decrypt_private_key(FIXTURE_ARGON2ID, FIXTURE_PASSWORD)
        .expect("Task 001 fixture decrypts via jacs-core");
    assert_eq!(decrypted.as_slice(), FIXTURE_PKCS8);
}

#[test]
fn fixture_pbkdf2_envelope_decrypts_in_core() {
    let decrypted = decrypt_private_key(FIXTURE_PBKDF2, FIXTURE_PASSWORD)
        .expect("Task 001 legacy fixture decrypts via jacs-core");
    assert_eq!(decrypted.as_slice(), FIXTURE_PKCS8);
}

#[test]
fn v2_envelope_with_unknown_kdf_returns_unsupported_algorithm() {
    // Hand-craft a JSON envelope with a bad KDF name to exercise the
    // UnsupportedAlgorithm path. The salt/nonce/ct don't matter — KDF
    // check fires first.
    let body = serde_json::json!({
        "jacsEncryptedPrivateKeyVersion": 2,
        "cipher": "AES-256-GCM",
        "kdf": {
            "name": "Scrypt",
            "version": 19,
            "m_cost_kib": 1024,
            "t_cost": 1,
            "p_cost": 1
        },
        "salt": URL_SAFE_NO_PAD.encode([0u8; 16]),
        "nonce": URL_SAFE_NO_PAD.encode([0u8; 12]),
        "ciphertext": URL_SAFE_NO_PAD.encode([0u8; 16])
    });
    let bytes = serde_json::to_vec(&body).unwrap();
    let err = decrypt_private_key(&bytes, "anything").expect_err("must fail");
    assert!(
        matches!(err, CoreError::UnsupportedAlgorithm(_)),
        "got {err:?}"
    );
}

#[test]
fn v2_envelope_with_wrong_version_returns_unsupported_algorithm() {
    let body = serde_json::json!({
        "jacsEncryptedPrivateKeyVersion": 99,
        "cipher": "AES-256-GCM",
        "kdf": {
            "name": "Argon2id",
            "version": 19,
            "m_cost_kib": 19456,
            "t_cost": 2,
            "p_cost": 1
        },
        "salt": URL_SAFE_NO_PAD.encode([0u8; 16]),
        "nonce": URL_SAFE_NO_PAD.encode([0u8; 12]),
        "ciphertext": URL_SAFE_NO_PAD.encode([0u8; 16])
    });
    let bytes = serde_json::to_vec(&body).unwrap();
    let err = decrypt_private_key(&bytes, "anything").expect_err("must fail");
    assert!(
        matches!(err, CoreError::UnsupportedAlgorithm(_)),
        "got {err:?}"
    );
}

// =========================================================================
// Wave 4 / Task 008 — reserved magic-prefix rejection.
//
// V1 supports two envelope formats: the V2 JSON Argon2id envelope (starts
// with `{`) and the legacy raw-binary PBKDF2 envelope (starts with the
// first byte of a random salt). Inputs that start with an ASCII prefix
// matching `^J[A-Z]{2}[0-9]$` (e.g. `JAA1`, `JAC2`) are reserved for
// future envelope formats and must be rejected as `UnsupportedAlgorithm`
// instead of being misclassified as legacy PBKDF2 truncation noise.
// =========================================================================

#[test]
fn argon2id_fixture_still_decrypts_after_magic_guard() {
    // V2 envelopes begin with `{`, so the magic-prefix guard must not
    // touch them. This is the cross-compat oracle.
    let decrypted = decrypt_private_key(FIXTURE_ARGON2ID, FIXTURE_PASSWORD)
        .expect("Argon2id fixture must still decrypt after the magic-prefix guard");
    assert_eq!(decrypted.as_slice(), FIXTURE_PKCS8);
}

#[test]
fn pbkdf2_fixture_still_decrypts_after_magic_guard() {
    // The legacy PBKDF2 fixture starts with random salt bytes, not a
    // reserved magic prefix; the guard must let it through.
    let decrypted = decrypt_private_key(FIXTURE_PBKDF2, FIXTURE_PASSWORD)
        .expect("PBKDF2 fixture must still decrypt after the magic-prefix guard");
    assert_eq!(decrypted.as_slice(), FIXTURE_PKCS8);
}

#[test]
fn reserved_jaa1_magic_prefix_rejected() {
    // 4-byte reserved prefix + 32 bytes of arbitrary tail. Long enough
    // that the legacy PBKDF2 reader *would* otherwise accept it as
    // "salt + nonce + ciphertext" and fail with InvalidPassword (an
    // attacker-controlled mislabeling). The magic-prefix guard fires
    // first and returns UnsupportedAlgorithm("JAA1").
    let mut input = b"JAA1".to_vec();
    input.extend_from_slice(&[0u8; 32]);
    let err = decrypt_private_key(&input, "anything").expect_err("must fail");
    match err {
        CoreError::UnsupportedAlgorithm(prefix) => {
            assert_eq!(
                prefix, "JAA1",
                "reserved-prefix variant must carry the prefix"
            );
        }
        other => panic!("expected UnsupportedAlgorithm(JAA1), got {other:?}"),
    }
}

#[test]
fn reserved_jac2_magic_prefix_rejected() {
    let mut input = b"JAC2".to_vec();
    input.extend_from_slice(&[0u8; 32]);
    let err = decrypt_private_key(&input, "anything").expect_err("must fail");
    match err {
        CoreError::UnsupportedAlgorithm(prefix) => assert_eq!(prefix, "JAC2"),
        other => panic!("expected UnsupportedAlgorithm(JAC2), got {other:?}"),
    }
}

#[test]
fn short_envelope_rejected() {
    // 1-3 byte inputs that aren't JSON (no `{`) and aren't a 4-byte
    // reserved prefix must still fail cleanly as MalformedEnvelope, not
    // panic.
    for input in [&[0u8][..], &[0u8, 0u8][..], &[0u8, 0u8, 0u8][..]] {
        let err = decrypt_private_key(input, "anything")
            .expect_err("short non-JSON input must be rejected");
        assert!(
            matches!(err, CoreError::MalformedEnvelope(_)),
            "got {err:?} for input len {}",
            input.len()
        );
    }
}

// Touch the no-warning unused-import lint by referencing the module.
#[allow(unused)]
fn _module_smoke() -> &'static str {
    envelope::PBKDF2_ITERATIONS.to_string().leak()
}
