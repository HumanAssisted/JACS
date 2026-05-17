//! Wave 3 / Task 007: confirm `jacs::crypt::aes_encrypt::
//! decrypt_private_key_secure_with_password` delegates to jacs-core and
//! still decrypts both Wave 0 fixtures (V2 Argon2id JSON envelope +
//! legacy raw-binary PBKDF2 envelope).

const FIXTURE_PASSWORD: &str = "Test#Password!2026";
const FIXTURE_PKCS8: &[u8] =
    include_bytes!("fixtures/wasm_compat/ed25519.pkcs8.bin");
const FIXTURE_ARGON2ID: &[u8] =
    include_bytes!("fixtures/wasm_compat/argon2id.encrypted.json");
const FIXTURE_PBKDF2: &[u8] =
    include_bytes!("fixtures/wasm_compat/pbkdf2.encrypted.bin");

#[test]
fn aes_encrypt_reexport_decrypts_argon2id_v2_fixture() {
    let decrypted = jacs::crypt::aes_encrypt::decrypt_private_key_secure_with_password(
        FIXTURE_ARGON2ID,
        FIXTURE_PASSWORD,
    )
    .expect("decrypt fixture");
    assert_eq!(decrypted.as_slice(), FIXTURE_PKCS8);
}

#[test]
fn aes_encrypt_reexport_decrypts_legacy_pbkdf2_fixture() {
    let decrypted = jacs::crypt::aes_encrypt::decrypt_private_key_secure_with_password(
        FIXTURE_PBKDF2,
        FIXTURE_PASSWORD,
    )
    .expect("decrypt legacy fixture");
    assert_eq!(decrypted.as_slice(), FIXTURE_PKCS8);
}

#[test]
fn aes_encrypt_reexport_emits_v2_envelope() {
    // encrypt_private_key_with_password must continue to emit the V2
    // JSON envelope so writes are forward-compatible with everything
    // that reads from disk.
    let plain = b"sample-key";
    let env = jacs::crypt::aes_encrypt::encrypt_private_key_with_password(
        plain,
        "Test#Password!2026",
    )
    .expect("encrypt");
    assert_eq!(env.first(), Some(&b'{'), "writer still emits JSON envelope");
    let json: serde_json::Value = serde_json::from_slice(&env).unwrap();
    assert_eq!(json["jacsEncryptedPrivateKeyVersion"], 2);
    assert_eq!(json["kdf"]["name"], "Argon2id");
}
