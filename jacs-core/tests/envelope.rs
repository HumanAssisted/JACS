//! Wave 3 / Task 007: tests for the V2 Argon2id JSON envelope and the
//! legacy PBKDF2 raw-binary reader. The native fixtures from Task 001 are
//! the cross-compat oracle: any drift in either path breaks every existing
//! key on disk.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jacs_core::CoreError;
use jacs_core::envelope::{
    self, AES_GCM_NONCE_SIZE, PBKDF2_ITERATIONS, PBKDF2_ITERATIONS_LEGACY, PBKDF2_SALT_SIZE,
    decrypt_private_key, derive_key_with_iterations, encrypt_private_key,
};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::SeedableRng;
use rand::rngs::StdRng;

const TEST_PASSWORD: &str = "Test#Password!2026";
const FIXTURE_PASSWORD: &str = "Test#Password!2026"; // matches Task 001 regenerator
const FIXTURE_PKCS8: &[u8] = include_bytes!("../../jacs/tests/fixtures/wasm_compat/ed25519.pkcs8.bin");
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
    assert!(matches!(err, CoreError::MalformedEnvelope(_)), "got {err:?}");
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
    assert!(matches!(err, CoreError::UnsupportedAlgorithm(_)), "got {err:?}");
}

// Touch the no-warning unused-import lint by referencing the module.
#[allow(unused)]
fn _module_smoke() -> &'static str {
    envelope::PBKDF2_ITERATIONS.to_string().leak()
}
